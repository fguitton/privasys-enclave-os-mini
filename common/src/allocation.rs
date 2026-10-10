//! Shared transient allocation admission. Numeric capacity grants no authority.
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub struct AllocationPoolV1 {
    capacity: usize,
    used: AtomicUsize,
}
impl AllocationPoolV1 {
    /// Construct from the caller's actual physical admission input. This is not
    /// a semantic guest-memory maximum or a promise about untracked allocator use.
    pub fn new(capacity: usize) -> Option<Arc<Self>> {
        if capacity == 0 { return None; }
        Some(Arc::new(Self { capacity, used: AtomicUsize::new(0) }))
    }
    pub fn capacity(&self) -> usize { self.capacity }
    pub fn used(&self) -> usize { self.used.load(Ordering::Acquire) }
    /// Reserve before allocation; a shared payload must retain the same lease
    /// through its final alias. Failed/zero/overflowing requests consume nothing.
    pub fn reserve(self: &Arc<Self>, bytes: usize) -> Option<AllocationLeaseV1> {
        if bytes == 0 { return None; }
        self.used.fetch_update(Ordering::AcqRel, Ordering::Acquire, |used|
            used.checked_add(bytes).filter(|next| *next <= self.capacity)).ok()?;
        Some(AllocationLeaseV1 { pool: self.clone(), bytes })
    }
}
/// Move-only physical allocation credit; it cannot read, sign or acknowledge data.
#[derive(Debug)]
pub struct AllocationLeaseV1 { pool: Arc<AllocationPoolV1>, bytes: usize }
impl AllocationLeaseV1 {
    pub fn bytes(&self) -> usize { self.bytes }
    pub fn covers(&self, pool: &Arc<AllocationPoolV1>, bytes: usize) -> bool {
        Arc::ptr_eq(&self.pool, pool) && self.bytes >= bytes
    }
}
impl Drop for AllocationLeaseV1 {
    fn drop(&mut self) { self.pool.used.fetch_sub(self.bytes, Ordering::AcqRel); }
}
#[cfg(test)]
pub(crate) fn check_allocation_owner() {
    assert!(AllocationPoolV1::new(0).is_none());
    let pool=AllocationPoolV1::new(9).unwrap();
    assert!(pool.reserve(0).is_none());
    let first=Arc::new(pool.reserve(7).unwrap());
    let alias=first.clone();let second=pool.reserve(2).unwrap();
    assert_eq!(pool.used(),9);assert!(pool.reserve(1).is_none());
    drop(first);assert_eq!(pool.used(),9);
    drop(second);assert_eq!(pool.used(),7);
    assert!(alias.covers(&pool,7));
    assert!(!alias.covers(&AllocationPoolV1::new(9).unwrap(),7));
    drop(alias);assert_eq!(pool.used(),0);
    let full=AllocationPoolV1::new(usize::MAX).unwrap();
    let held=full.reserve(usize::MAX).unwrap();assert!(full.reserve(1).is_none());
    drop(held);assert_eq!(full.used(),0);
}
