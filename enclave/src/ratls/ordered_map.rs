//! Server adapter: empty startup allocates nothing; first admission binds the
//! actual immutable SDK pool. Native owning fixtures supply their explicit pool.
use enclave_os_common::allocation::{
    ordered_map::{PaidMapEntriesV1, PaidOrderedMapV1},
    AllocationPoolV1,
};
use std::sync::Arc;
pub(crate) struct OrderedMap<K, V> {
    inner: Option<PaidOrderedMapV1<K, V>>,
}
impl<K, V> Default for OrderedMap<K, V> {
    fn default() -> Self {
        Self { inner: None }
    }
}
impl<K: Ord, V> OrderedMap<K, V> {
    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        self.inner.as_ref()?.get(key)
    }
    pub(crate) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.inner.as_mut()?.get_mut(key)
    }
    pub(crate) fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }
    pub(crate) fn remove(&mut self, key: &K) -> Option<V> {
        self.inner.as_mut()?.remove(key)
    }
    pub(crate) fn iter(&self) -> impl DoubleEndedIterator<Item = (&K, &V)> {
        self.inner.iter().flat_map(PaidOrderedMapV1::iter)
    }
    pub(crate) fn after<'a>(&'a self, key: &'a K) -> impl Iterator<Item = (&'a K, &'a V)> {
        self.inner.iter().flat_map(move |map| map.after(key))
    }
    #[cfg(target_env = "sgx")]
    pub(crate) fn try_insert(&mut self, key: K, value: V) -> Result<Option<V>, (K, V)> {
        let Some(pool) = crate::local_allocation_pool() else {
            return Err((key, value));
        };
        self.insert_admitted(key, value, Some(&pool))
    }
    #[cfg(test)]
    pub(super) fn insert_for_fixture(
        &mut self,
        key: K,
        value: V,
        pool: &Arc<AllocationPoolV1>,
    ) -> Result<Option<V>, (K, V)> {
        self.insert_admitted(key, value, Some(pool))
    }
    fn insert_admitted(
        &mut self,
        key: K,
        value: V,
        pool: Option<&Arc<AllocationPoolV1>>,
    ) -> Result<Option<V>, (K, V)> {
        let Some(pool) = pool else {
            return Err((key, value));
        };
        if self.inner.as_ref().is_some_and(|map| !map.uses_pool(pool)) {
            return Err((key, value));
        }
        let map = self
            .inner
            .get_or_insert_with(|| PaidOrderedMapV1::new(Arc::clone(pool)));
        map.try_insert(key, value)
    }
}
impl<K: Ord, V> core::ops::Index<&K> for OrderedMap<K, V> {
    type Output = V;
    fn index(&self, key: &K) -> &V {
        self.get(key).expect("no entry found for key")
    }
}
pub(crate) struct Entries<K, V> {
    inner: Option<PaidMapEntriesV1<K, V>>,
}
impl<K, V> Iterator for Entries<K, V> {
    type Item = (K, V);
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.as_mut()?.next()
    }
}
impl<K, V> IntoIterator for OrderedMap<K, V> {
    type Item = (K, V);
    type IntoIter = Entries<K, V>;
    fn into_iter(self) -> Self::IntoIter {
        Entries {
            inner: self.inner.map(IntoIterator::into_iter),
        }
    }
}

#[cfg(test)]
pub(super) fn check() {
    use std::collections::BTreeMap;
    type Map = OrderedMap<u32, u64>;
    const ORACLE_STEPS: usize = 64;
    let oracle_pool = AllocationPoolV1::new(
        core::alloc::Layout::array::<(u32, u64)>(ORACLE_STEPS * 2)
            .unwrap()
            .size(),
    )
    .unwrap();
    let unit = core::alloc::Layout::array::<(u32, u64)>(1).unwrap().size();
    for maximum in [unit - 1, unit, unit + 1] {
        let pool = AllocationPoolV1::new(maximum).unwrap();
        let mut map = Map::default();
        let result = map.insert_admitted(3, 7, Some(&pool));
        assert_eq!(result.is_ok(), maximum >= unit);
        if maximum >= unit {
            assert_eq!(map.get(&3), Some(&7));
            assert_eq!(pool.used(), unit);
        }
        drop(map);
        assert_eq!(pool.used(), 0);
    }
    let pool = AllocationPoolV1::new(unit * 3).unwrap();
    let mut map = Map::default();
    map.insert_admitted(3, 7, Some(&pool)).unwrap();
    let blocker = pool.reserve_unpublished(1).unwrap();
    assert_eq!(map.insert_admitted(1, 9, Some(&pool)), Err((1, 9)));
    assert_eq!(
        map.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>(),
        vec![(3, 7)]
    );
    drop(blocker);
    map.insert_admitted(1, 9, Some(&pool)).unwrap();
    assert_eq!(pool.used(), unit * 2);
    assert_eq!(map.insert_admitted(3, 8, Some(&pool)), Ok(Some(7)));
    let foreign = AllocationPoolV1::new(pool.capacity()).unwrap();
    assert_eq!(map.insert_for_fixture(3, 9, &foreign), Err((3, 9)));
    assert_eq!(foreign.used(), 0);
    assert_eq!(map.get(&3), Some(&8));
    assert_eq!(map.remove(&1), Some(9));
    assert_eq!(map.remove(&3), Some(8));
    assert_eq!(pool.used(), unit * 2, "empty map retains backing");
    let mut entries = map.into_iter();
    assert!(entries.next().is_none());
    assert_eq!(pool.used(), unit * 2, "empty iterator still owns backing");
    drop(entries);
    assert_eq!(pool.used(), 0);
    assert!(core::alloc::Layout::array::<(u32, u64)>(usize::MAX).is_err());
    let mut map = Map::default();
    let mut reference = BTreeMap::new();
    // Deterministic real map operations compared with the original owner.
    for i in 0_u32..64 {
        let key = (i * 17) % 31;
        assert_eq!(
            map.insert_for_fixture(key, u64::from(i), &oracle_pool)
                .unwrap(),
            reference.insert(key, u64::from(i))
        );
        if i % 3 == 0 {
            let remove = (i * 7) % 31;
            assert_eq!(map.remove(&remove), reference.remove(&remove));
        }
        assert_eq!(
            map.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>(),
            reference.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>()
        );
        assert_eq!(
            map.after(&key).map(|(k, v)| (*k, *v)).collect::<Vec<_>>(),
            reference
                .range((core::ops::Bound::Excluded(key), core::ops::Bound::Unbounded))
                .map(|(k, v)| (*k, *v))
                .collect::<Vec<_>>()
        );
        assert_eq!(map.contains_key(&key), reference.contains_key(&key));
        if let Some(value) = map.get_mut(&key) {
            *value += 1;
            *reference.get_mut(&key).unwrap() += 1;
        }
    }
    assert_eq!(
        map.into_iter().collect::<Vec<_>>(),
        reference.into_iter().collect::<Vec<_>>()
    );
    #[derive(Eq, Debug)]
    struct Key {
        order: u32,
        identity: u32,
    }
    impl PartialEq for Key {
        fn eq(&self, other: &Self) -> bool {
            self.order == other.order
        }
    }
    impl PartialOrd for Key {
        fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }
    impl Ord for Key {
        fn cmp(&self, other: &Self) -> core::cmp::Ordering {
            self.order.cmp(&other.order)
        }
    }
    let mut actual = OrderedMap::default();
    let mut original = BTreeMap::new();
    for identity in [1, 2] {
        assert_eq!(
            actual
                .insert_for_fixture(Key { order: 1, identity }, identity, &oracle_pool)
                .unwrap(),
            original.insert(Key { order: 1, identity }, identity)
        );
    }
    assert_eq!(
        actual.iter().next().unwrap().0.identity,
        original.keys().next().unwrap().identity
    );
    assert_eq!(
        actual.iter().next().unwrap().0.identity,
        1,
        "original equivalent key retained"
    );
    let mut zero = OrderedMap::<(), ()>::default();
    assert_eq!(
        zero.insert_for_fixture((), (), &oracle_pool),
        Err(((), ())),
        "zero-sized tuples explicitly unsupported"
    );
    let mut set = OrderedMap::<u32, ()>::default();
    let mut reference = std::collections::BTreeSet::new();
    for i in 0_u32..64 {
        let key = (i * 17) % 31;
        assert_eq!(
            set.insert_for_fixture(key, (), &oracle_pool)
                .unwrap()
                .is_none(),
            reference.insert(key)
        );
        if i % 3 == 0 {
            let remove = (i * 7) % 31;
            assert_eq!(set.remove(&remove).is_some(), reference.remove(&remove));
        }
        assert_eq!(
            set.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
            reference.iter().copied().collect::<Vec<_>>()
        );
        assert_eq!(set.contains_key(&key), reference.contains(&key));
        if set.contains_key(&key) {
            assert_eq!(set[&key], ());
        }
    }
    let bytes = core::alloc::Layout::array::<(u32, ())>(1).unwrap().size();
    let pool = AllocationPoolV1::new(bytes).unwrap();
    let mut set = OrderedMap::<u32, ()>::default();
    set.insert_for_fixture(7, (), &pool).unwrap();
    assert_eq!(set.insert_for_fixture(8, (), &pool), Err((8, ())));
    assert!(set.contains_key(&7));
    assert!(!set.contains_key(&8));
    assert_eq!(pool.used(), bytes);
    drop(set);
    assert_eq!(pool.used(), 0);
    eprintln!("DISPATCH-SET-PAID: original set ordering/dedup/removal and real metadata refusal/refund PASS");
    eprintln!("SESSION-MAP-PAID: original ordered-map oracle, real backing peak/refusal/empty/iterator refund PASS");
}
