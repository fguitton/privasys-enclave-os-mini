//! Preadmitted cancellation FIFO. No allocation occurs after external adoption.
use enclave_os_common::allocation::{AllocationLeaseV1, AllocationPoolV1};
use std::sync::Arc;

pub(crate) struct Queue<T> {
    items: Vec<T>,
    credit: Option<AllocationLeaseV1>,
    pool: Option<Arc<AllocationPoolV1>>,
}
impl<T> Default for Queue<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            credit: None,
            pool: None,
        }
    }
}
impl<T> Queue<T> {
    pub(crate) fn bytes(capacity: usize) -> Option<usize> {
        let bytes = core::alloc::Layout::array::<T>(capacity).ok()?.size();
        (bytes != 0).then_some(bytes)
    }
    pub(crate) fn new(pool: &Arc<AllocationPoolV1>, capacity: usize) -> Option<Self> {
        let credit = pool.reserve_unpublished(Self::bytes(capacity)?)?;
        let mut items = Vec::new();
        items.try_reserve_exact(capacity).ok()?;
        if items.capacity() != capacity {
            drop(items);
            return None;
        }
        credit.activate_release_notification();
        Some(Self {
            items,
            credit: Some(credit),
            pool: Some(Arc::clone(pool)),
        })
    }
    pub(crate) fn prepared_for(&self, pool: &Arc<AllocationPoolV1>, capacity: usize) -> bool {
        self.pool
            .as_ref()
            .is_some_and(|original| Arc::ptr_eq(original, pool))
            && self.items.capacity() == capacity
    }
    pub(crate) fn has_admission(&self) -> bool {
        self.credit.is_some()
    }
    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    pub(crate) fn push_back(&mut self, value: T) {
        // The original pending + cancelled + extracted/terminal maximum is
        // checked before adoption; each pending marker moves at most once.
        assert!(
            self.items.len() < self.items.capacity(),
            "original cancellation debt bound"
        );
        self.items.push(value);
    }
    pub(crate) fn pop_front(&mut self) -> Option<T> {
        (!self.items.is_empty()).then(|| self.items.remove(0))
    }
}
pub(crate) struct Drain<T> {
    items: std::vec::IntoIter<T>,
    _credit: Option<AllocationLeaseV1>,
    _pool: Option<Arc<AllocationPoolV1>>,
}
impl<T> Iterator for Drain<T> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        self.items.next()
    }
}
impl<T> IntoIterator for Queue<T> {
    type Item = T;
    type IntoIter = Drain<T>;
    fn into_iter(self) -> Self::IntoIter {
        Drain {
            items: self.items.into_iter(),
            _credit: self.credit,
            _pool: self.pool,
        }
    }
}
