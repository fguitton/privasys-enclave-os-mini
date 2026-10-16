#![feature(allocator_api)]
extern crate hashbrown_tstd as hashbrown;
use std::alloc::{AllocError, Allocator, Global, Layout};
use std::collections::VecDeque;
use std::hash::RandomState;
use std::ptr::NonNull;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
#[derive(Default)]
struct Counts {
    live: AtomicUsize,
    calls: AtomicUsize,
    refuse: AtomicUsize,
}
#[derive(Clone)]
struct Original(Arc<Counts>);
impl Drop for Original {
    fn drop(&mut self) {
        if Arc::strong_count(&self.0) == 2 {
            assert_eq!(
                self.0.live.load(Ordering::SeqCst),
                0,
                "last origin must follow backing free"
            );
        }
    }
}
unsafe impl Allocator for Original {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let call = self.0.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.0.refuse.load(Ordering::SeqCst) {
            return Err(AllocError);
        }
        let block = Global.allocate(layout)?;
        self.0.live.fetch_add(layout.size(), Ordering::SeqCst);
        Ok(block)
    }
    unsafe fn deallocate(&self, pointer: NonNull<u8>, layout: Layout) {
        unsafe { Global.deallocate(pointer, layout) };
        self.0.live.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}
type Map = hashbrown::HashMap<u64, u64, RandomState, Original>;
fn cache(allocator: Original) -> Result<(Map, VecDeque<u64, Original>), AllocError> {
    let mut map = Map::with_hasher_in(RandomState::new(), allocator.clone());
    map.try_reserve(256).map_err(|_| AllocError)?;
    let mut queue = VecDeque::new_in(allocator);
    queue.try_reserve_exact(256).map_err(|_| AllocError)?;
    Ok((map, queue))
}
#[test]
fn original_backend_refuses_each_constructor_without_retained_backing() {
    for refusal in 1..=2 {
        let counts = Arc::new(Counts::default());
        counts.refuse.store(refusal, Ordering::SeqCst);
        assert!(cache(Original(counts.clone())).is_err());
        assert_eq!(counts.calls.load(Ordering::SeqCst), refusal);
        assert_eq!(counts.live.load(Ordering::SeqCst), 0);
        assert_eq!(Arc::strong_count(&counts), 1);
    }
}
#[test]
fn old_entries_and_backing_survive_refused_growth() {
    let counts = Arc::new(Counts::default());
    let mut map = Map::with_hasher_in(RandomState::new(), Original(counts.clone()));
    map.try_reserve(32).unwrap();
    let capacity = map.capacity();
    for key in 0..capacity as u64 {
        map.insert(key, key + 7);
    }
    let address = map.get(&0).map(|value| value as *const u64);
    let before = counts.live.load(Ordering::SeqCst);
    counts
        .refuse
        .store(counts.calls.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
    assert!(map.try_reserve(1).is_err());
    assert_eq!(map.len(), capacity);
    assert_eq!(counts.live.load(Ordering::SeqCst), before);
    assert_eq!(map.get(&0).map(|value| value as *const u64), address);
    for key in 0..capacity as u64 {
        assert_eq!(map.get(&key), Some(&(key + 7)));
    }
    drop(map);
    assert_eq!(counts.live.load(Ordering::SeqCst), 0);
    assert_eq!(Arc::strong_count(&counts), 1);
}
#[test]
fn original_origin_outlives_creator_and_cross_thread_backings() {
    let counts = Arc::new(Counts::default());
    let creator = Original(counts.clone());
    let (mut map, mut queue) = cache(creator.clone()).unwrap();
    for key in 0..256 {
        map.insert(key, key * 3);
        queue.push_back(key);
    }
    drop(creator);
    assert!(counts.live.load(Ordering::SeqCst) > 0);
    std::thread::spawn(move || {
        for key in 0..256 {
            assert_eq!(map.get(&key), Some(&(key * 3)));
            assert_eq!(queue.pop_front(), Some(key));
        }
        drop(map);
        drop(queue);
    })
    .join()
    .unwrap();
    assert_eq!(counts.live.load(Ordering::SeqCst), 0);
    assert_eq!(Arc::strong_count(&counts), 1);
}
