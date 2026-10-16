#![feature(allocator_api, btreemap_alloc)]
#[cfg(test)]
mod tests {
    use std::{
        alloc::{AllocError, Allocator, Layout, System},
        cell::RefCell,
        collections::BTreeMap,
        ptr::NonNull,
        rc::Rc,
    };
    #[derive(Default)]
    struct Stats {
        requests: Vec<(usize, usize)>,
        live: Vec<(usize, Layout)>,
        fail: Option<usize>,
        clones: usize,
    }
    struct Owner(Rc<RefCell<Stats>>);
    impl Clone for Owner {
        fn clone(&self) -> Self {
            self.0.borrow_mut().clones += 1;
            Self(self.0.clone())
        }
    }
    impl Owner {
        fn new() -> Self {
            Self(Rc::new(RefCell::new(Stats {
                requests: Vec::with_capacity(128),
                live: Vec::with_capacity(32768),
                ..Stats::default()
            })))
        }
        fn reset(&self, fail: Option<usize>) {
            let mut s = self.0.borrow_mut();
            s.requests.clear();
            s.fail = fail;
        }
        fn requests(&self) -> Vec<(usize, usize)> {
            self.0.borrow().requests.clone()
        }
        fn live(&self) -> usize {
            self.0.borrow().live.len()
        }
    }
    unsafe impl Allocator for Owner {
        fn allocate(&self, l: Layout) -> Result<NonNull<[u8]>, AllocError> {
            let mut s = self.0.borrow_mut();
            let n = s.requests.len();
            assert!(n < s.requests.capacity());
            s.requests.push((l.size(), l.align()));
            if s.fail == Some(n) {
                return Err(AllocError);
            }
            let p = System.allocate(l)?;
            assert!(s.live.len() < s.live.capacity());
            s.live.push((p.cast::<u8>().as_ptr() as usize, l));
            Ok(p)
        }
        unsafe fn deallocate(&self, p: NonNull<u8>, l: Layout) {
            let mut s = self.0.borrow_mut();
            let i = s
                .live
                .iter()
                .position(|(a, _)| *a == p.as_ptr() as usize)
                .expect("original live allocation");
            assert_eq!(s.live.swap_remove(i).1, l);
            unsafe { System.deallocate(p, l) };
        }
    }
    fn sequence(keys: Vec<u64>) {
        let ascending = keys.windows(2).all(|pair| pair[0] < pair[1]);
        let mut allocated_layouts = BTreeMap::new();
        let owner = Owner::new();
        let reference_owner = Owner::new();
        let mut map = BTreeMap::new_in(owner.clone());
        let mut reference = BTreeMap::new_in(reference_owner.clone());
        let mut maximum = 0;
        let mut failures = 0;
        for (i, key) in keys.into_iter().enumerate() {
            let value = key.wrapping_mul(37);
            reference_owner.reset(None);
            reference.insert(key, value);
            let expected = reference_owner.requests();
            owner.reset(None);
            let mut planned = Vec::new();
            map.try_visit_insert_layouts(&key, |layout| {
                planned.push((layout.size(), layout.align()));
                Ok::<_, ()>(())
            })
            .unwrap();
            assert!(owner.requests().is_empty(), "query allocated nodes");
            assert_eq!(planned, expected, "query differs from actual node requests");
            for stop in 0..planned.len() {
                let mut visited = 0;
                let result = map.try_visit_insert_layouts(&key, |_| {
                    if visited == stop {
                        return Err(stop);
                    }
                    visited += 1;
                    Ok(())
                });
                assert_eq!(result, Err(stop));
                assert!(owner.requests().is_empty());
            }
            maximum = maximum.max(expected.len());
            let before = if expected.is_empty() {
                Vec::new()
            } else {
                map.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>()
            };
            let retained = owner.live();
            for failure in 0..expected.len() {
                owner.reset(Some(failure));
                let e = map.try_insert_alloc(key, value).unwrap_err();
                assert_eq!((e.1, e.2), (key, value));
                assert_eq!(owner.requests(), expected[..=failure]);
                assert_eq!(owner.live(), retained);
                assert!(map.iter().map(|(k, v)| (*k, *v)).eq(before.iter().copied()));
                failures += 1;
            }
            owner.reset(None);
            assert_eq!(map.try_insert_alloc(key, value).unwrap(), None);
            if ascending {
                for layout in &expected {
                    *allocated_layouts.entry(*layout).or_insert(0usize) += 1;
                }
                check_sorted_quote(i + 1, &allocated_layouts);
                assert_eq!(owner.requests(), expected, "query made no backend requests");
            }
            let mut actual = owner.requests();
            let mut wanted = expected;
            actual.sort_unstable();
            wanted.sort_unstable();
            assert_eq!(actual, wanted);
            if i % 97 == 0 {
                assert!(map.iter().eq(reference.iter()));
            }
            if i % 113 == 0 {
                owner.reset(Some(0));
                assert_eq!(map.try_insert_alloc(key, value + 1).unwrap(), Some(value));
                assert!(owner.requests().is_empty());
                assert_eq!(map.try_insert_alloc(key, value).unwrap(), Some(value + 1));
                assert!(owner.requests().is_empty());
            }
        }
        assert!(
            maximum >= 4,
            "must cover full internal chain and new root, got {maximum}"
        );
        assert!(failures > 100);
        assert!(map.iter().eq(reference.iter()));
        drop(map);
        drop(reference);
        assert_eq!(owner.live(), 0);
        assert_eq!(reference_owner.live(), 0);
        eprintln!("exact-layout sequence max_reserved={maximum} forced_failures={failures}");
    }
    fn check_sorted_quote(count: usize, actual: &BTreeMap<(usize, usize), usize>) {
        let mut quoted = BTreeMap::new();
        BTreeMap::<u64, u64, Owner>::try_visit_sorted_build_layouts(count, |layout, number| {
            *quoted
                .entry((layout.size(), layout.align()))
                .or_insert(0usize) += number;
            Ok(())
        })
        .unwrap();
        assert_eq!(&quoted, actual, "fresh sorted build prefix {count}");
        if count == 256 {
            assert_eq!(quoted.values().copied().sum::<usize>(), 42);
            assert!(quoted.values().any(|count| *count == 36));
            assert!(quoted.values().any(|count| *count == 6));
        }
        let mut calls = 0;
        assert!(
            BTreeMap::<u64, u64, Owner>::try_visit_sorted_build_layouts(count, |_, _| {
                calls += 1;
                Err(AllocError)
            })
            .is_err()
        );
        assert_eq!(calls, 1, "visitor refusal stops without another layout");
    }
    #[test]
    fn ordered_all_split_levels_and_each_reservation_failure() {
        let mut called = false;
        BTreeMap::<u64, u64, Owner>::try_visit_sorted_build_layouts(0, |_, _| {
            called = true;
            Err(AllocError)
        })
        .unwrap();
        assert!(!called);
        assert!(
            BTreeMap::<u64, u64, Owner>::try_visit_sorted_build_layouts(
                usize::MAX,
                |layout, count| {
                    layout
                        .size()
                        .checked_mul(count)
                        .ok_or(AllocError)
                        .map(|_| ())
                }
            )
            .is_err(),
            "unsupported full-byte extent refuses with checked arithmetic"
        );
        sequence((0..8000).collect())
    }
    #[test]
    fn reverse_all_split_levels_and_each_reservation_failure() {
        sequence((0..8000).rev().collect())
    }
    #[test]
    fn shuffled_all_split_levels_and_each_reservation_failure() {
        let mut keys = (0..16000).collect::<Vec<_>>();
        let mut x = 19u64;
        for i in (1..keys.len()).rev() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            keys.swap(i, (x as usize) % (i + 1));
        }
        sequence(keys)
    }
    #[test]
    fn first_leaf_refusal_retains_owned_pair_and_zero_backing() {
        let a = Owner::new();
        let mut m = BTreeMap::new_in(a.clone());
        a.reset(Some(0));
        let (_, k, v) = m
            .try_insert_alloc(String::from("key"), String::from("value"))
            .unwrap_err();
        assert_eq!(k, "key");
        assert_eq!(v, "value");
        assert!(m.is_empty());
        assert_eq!(a.live(), 0);
        assert_eq!(a.requests().len(), 1);
    }
}

#[cfg(test)]
mod paid_owner_tests {
    use enclave_os_common::allocation::{AllocationPoolV1, PoolMapAllocator, SharedAllocationV1};
    use std::{
        alloc::{Allocator, Layout},
        collections::BTreeMap,
    };
    #[test]
    fn exact_alignment_original_pool_and_final_alias_refund() {
        let p = AllocationPoolV1::new(1 << 24).unwrap();
        let a = PoolMapAllocator::try_new(&p).unwrap();
        let metadata = p.used();
        assert!(metadata > 0);
        assert_eq!(
            metadata,
            PoolMapAllocator::required_metadata_bytes().unwrap()
        );
        for align in [1, 2, 8, 32, 64, 4096] {
            let l = Layout::from_size_align(97, align).unwrap();
            let quote = PoolMapAllocator::backend_layout(l).unwrap();
            let b = a.allocate(l).unwrap();
            assert_eq!((b.cast::<u8>().as_ptr() as usize) % align, 0);
            assert_eq!(p.used(), metadata + quote.size());
            unsafe { a.deallocate(b.cast(), l) };
            assert_eq!(p.used(), metadata);
        }
        let mut m = BTreeMap::new_in(a.clone());
        for k in 0..256u64 {
            m.try_insert_alloc(k, [k; 4]).unwrap();
        }
        assert!(p.used() > metadata);
        let r = SharedAllocationV1::reserve(&p, 0).unwrap();
        let m = r.try_finish(m).unwrap();
        a.activate_release_notification();
        let alias = m.clone();
        let held = p.used();
        drop(m);
        drop(a);
        assert_eq!(p.used(), held);
        assert_eq!(alias.len(), 256);
        drop(alias);
        assert_eq!(p.used(), 0);
    }
    #[test]
    fn admission_and_actual_backend_refusal_refund_before_publication() {
        let p = AllocationPoolV1::new(1).unwrap();
        assert!(PoolMapAllocator::try_new(&p).is_err());
        assert_eq!(p.used(), 0);
        let p = AllocationPoolV1::new(usize::MAX).unwrap();
        let a = PoolMapAllocator::try_new(&p).unwrap();
        let baseline = p.used();
        let huge = Layout::from_size_align(isize::MAX as usize - 4096, 1).unwrap();
        assert!(a.allocate(huge).is_err());
        assert_eq!(p.used(), baseline);
        let overflowing = Layout::from_size_align(isize::MAX as usize, 1).unwrap();
        assert!(PoolMapAllocator::backend_layout(overflowing).is_err());
        assert_eq!(p.used(), baseline);
        drop(a);
        assert_eq!(p.used(), 0);
    }
    fn copy_map(
        old: &BTreeMap<u64, [u64; 4], PoolMapAllocator>,
        p: &std::sync::Arc<AllocationPoolV1>,
    ) -> Result<BTreeMap<u64, [u64; 4], PoolMapAllocator>, ()> {
        let a = PoolMapAllocator::try_new(p).map_err(|_| ())?;
        let mut next = BTreeMap::new_in(a);
        for (k, v) in old {
            next.try_insert_alloc(*k, *v).map_err(|_| ())?;
        }
        Ok(next)
    }
    #[test]
    fn shared_clone_refusal_keeps_original_then_fallible_copy_uses_same_pool() {
        let p = AllocationPoolV1::new(1 << 22).unwrap();
        let a = PoolMapAllocator::try_new(&p).unwrap();
        let mut m = BTreeMap::new_in(a);
        for k in 0..64 {
            m.try_insert_alloc(k, [k; 4]).unwrap();
        }
        let mut current = SharedAllocationV1::reserve(&p, 0)
            .unwrap()
            .try_finish(m)
            .unwrap();
        let alias = current.clone();
        let baseline = p.used();
        let hold = p.reserve(p.capacity() - baseline).unwrap();
        assert!(current
            .try_make_unique_with(&p, 0, |m| copy_map(m, &p))
            .is_err());
        assert!(SharedAllocationV1::ptr_eq(&current, &alias));
        assert_eq!(current.len(), 64);
        assert_eq!(p.used(), p.capacity());
        drop(hold);
        assert_eq!(p.used(), baseline);
        let next = current
            .try_make_unique_with(&p, 0, |m| copy_map(m, &p))
            .unwrap();
        next.try_insert_alloc(64, [64; 4]).unwrap();
        assert_eq!(alias.len(), 64);
        assert_eq!(current.len(), 65);
        assert!(!SharedAllocationV1::ptr_eq(&current, &alias));
        drop(current);
        assert!(p.used() > 0);
        drop(alias);
        assert_eq!(p.used(), 0);
    }
    #[test]
    fn partial_physical_node_reservations_refund_without_mutation() {
        let p = AllocationPoolV1::new(1 << 22).unwrap();
        let a = PoolMapAllocator::try_new(&p).unwrap();
        let origin = p.used();
        let mut m = BTreeMap::new_in(a);
        for k in 0..11 {
            m.try_insert_alloc(k, k).unwrap();
        }
        let baseline = p.used();
        // A full root leaf needs its same leaf sibling plus a larger internal root.
        // The existing first leaf's exact charged layout provides only one sibling.
        let node = baseline - origin;
        assert!(node > 0);
        let held = p.reserve(p.capacity() - baseline - node).unwrap();
        assert!(m.try_insert_alloc(11, 11).is_err());
        assert_eq!(m.len(), 11);
        assert_eq!(p.used(), p.capacity() - node);
        drop(held);
        assert_eq!(p.used(), baseline);
        drop(m);
        assert_eq!(p.used(), 0);
    }
}
