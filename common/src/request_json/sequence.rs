//! Caller-paid sequence backing; every child retains its separate admission.
use super::Refusal;
use crate::allocation::{AllocationLeaseV1, AllocationPoolV1};
use alloc::{sync::Arc, vec::Vec};

/// A sequence whose backing remains charged to its original physical pool.
/// Declaration order destroys children/backing before its credit.
pub struct Sequence<T> {
    values: Vec<T>,
    allocation: Option<AllocationLeaseV1>,
    pool: Arc<AllocationPoolV1>,
}
impl<T> Sequence<T> {
    #[must_use]
    pub fn new(pool: Arc<AllocationPoolV1>) -> Self {
        Self {
            values: Vec::new(),
            allocation: None,
            pool,
        }
    }
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.values
    }
    /// Mutate existing elements without changing the admitted backing.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.values
    }
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.values.capacity()
    }
    /// Append a separately admitted child, admitting any new backing first.
    /// During growth both physical buffers remain charged until the old buffer drops.
    /// # Errors
    /// Refuses unsupported zero-sized storage, checked geometry, pool exhaustion
    /// or allocator failure; the incoming child drops with its own admission.
    pub fn try_push(&mut self, value: T) -> Result<(), Refusal> {
        if core::mem::size_of::<T>() == 0 {
            return Err(Refusal::Unavailable);
        }
        if self.values.len() == self.values.capacity() {
            let capacity = self
                .values
                .len()
                .checked_add(1)
                .and_then(usize::checked_next_power_of_two)
                .ok_or(Refusal::Unavailable)?;
            let bytes = core::alloc::Layout::array::<T>(capacity)
                .map_err(|_| Refusal::Unavailable)?
                .size();
            let allocation = self
                .pool
                .reserve_unpublished(bytes)
                .ok_or(Refusal::Unavailable)?;
            let mut values = Vec::new();
            values
                .try_reserve_exact(capacity)
                .map_err(|_| Refusal::Unavailable)?;
            if values.capacity() != capacity {
                return Err(Refusal::Unavailable);
            }
            values.append(&mut self.values);
            drop(core::mem::replace(&mut self.values, values));
            drop(self.allocation.replace(allocation));
        }
        self.values.push(value);
        if let Some(allocation) = &self.allocation {
            allocation.activate_release_notification();
        }
        Ok(())
    }
}

/// Consuming iteration keeps the old backing charged while elements move out.
/// The iterator buffer drops before its original allocation credit.
pub struct IntoIter<T> {
    values: alloc::vec::IntoIter<T>,
    _allocation: Option<AllocationLeaseV1>,
    _pool: Arc<AllocationPoolV1>,
}
impl<T> Iterator for IntoIter<T> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        self.values.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.values.size_hint()
    }
}
impl<T> IntoIterator for Sequence<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            values: self.values.into_iter(),
            _allocation: self.allocation,
            _pool: self.pool,
        }
    }
}
