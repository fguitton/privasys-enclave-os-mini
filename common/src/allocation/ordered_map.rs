//! Fallible ordered metadata backing. Children require their own admission.
use super::{AllocationLeaseV1, AllocationPoolV1};
use alloc::{sync::Arc, vec::Vec};
use core::borrow::Borrow;

/// An ordered map bound permanently to the caller's original physical pool.
/// No operation implicitly clones keys, values or their independently owned children.
pub struct PaidOrderedMapV1<K, V> {
    entries: Vec<(K, V)>,
    allocation: Option<AllocationLeaseV1>,
    pool: Arc<AllocationPoolV1>,
}
/// Refused checked backing geometry, pool admission or allocator reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapAdmissionRefusedV1;
/// Failure of metadata admission or the caller's fallible child clone.
#[derive(Debug, PartialEq, Eq)]
pub enum MapCloneErrorV1<E> {
    Admission,
    Child(E),
    ChangedKey,
}
impl<K: Ord, V> PaidOrderedMapV1<K, V> {
    /// Empty construction clones no payload and allocates no metadata backing.
    #[must_use]
    pub fn new(pool: Arc<AllocationPoolV1>) -> Self {
        Self {
            entries: Vec::new(),
            allocation: None,
            pool,
        }
    }
    #[must_use]
    pub fn uses_pool(&self, pool: &Arc<AllocationPoolV1>) -> bool {
        Arc::ptr_eq(&self.pool, pool)
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Actual admitted tuple capacity, without any permission to grow children.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.entries.capacity()
    }
    /// Pre-admit an absolute tuple capacity before publishing external work.
    /// Existing backing remains live during growth; smaller requests do nothing.
    /// # Errors
    /// Refuses zero-sized tuple storage, overflow, pool exhaustion or allocation
    /// failure without changing entries or their existing backing.
    pub fn try_reserve_capacity(&mut self, capacity: usize) -> Result<(), MapAdmissionRefusedV1> {
        if core::mem::size_of::<(K, V)>() == 0 {
            return Err(MapAdmissionRefusedV1);
        }
        if capacity <= self.entries.capacity() {
            return Ok(());
        }
        self.reserve_backing(capacity)
            .map_err(|()| MapAdmissionRefusedV1)?;
        self.publish_backing();
        Ok(())
    }
    fn position<Q: Ord + ?Sized>(&self, key: &Q) -> Result<usize, usize>
    where
        K: Borrow<Q>,
    {
        self.entries
            .binary_search_by(|entry| entry.0.borrow().cmp(key))
    }
    #[must_use]
    pub fn get<Q: Ord + ?Sized>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
    {
        self.position(key).ok().map(|i| &self.entries[i].1)
    }
    pub fn get_mut<Q: Ord + ?Sized>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
    {
        self.position(key).ok().map(|i| &mut self.entries[i].1)
    }
    #[must_use]
    pub fn contains_key<Q: Ord + ?Sized>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
    {
        self.position(key).is_ok()
    }
    pub fn remove<Q: Ord + ?Sized>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
    {
        self.position(key).ok().map(|i| self.entries.remove(i).1)
    }
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&K, &V)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }
    /// Drop all children while retaining the admitted tuple backing for reuse.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
    /// Retain entries in ascending key order without allocating tuple backing.
    /// Any replacement child allocations made by the callback require their own admission.
    pub fn retain(&mut self, mut keep: impl FnMut(&K, &mut V) -> bool) {
        self.entries.retain_mut(|(key, value)| keep(key, value));
    }
    /// Borrow values in ascending key order. New child allocations remain caller-owned.
    pub fn values_mut(&mut self) -> impl DoubleEndedIterator<Item = &mut V> {
        self.entries.iter_mut().map(|(_, value)| value)
    }
    /// Borrow an ordered key range without allocating or cloning its entries.
    /// # Panics
    /// Like `BTreeMap::range`, panics for a reversed range or equal excluded bounds.
    pub fn range<R: core::ops::RangeBounds<K>>(
        &self,
        range: R,
    ) -> impl DoubleEndedIterator<Item = (&K, &V)> {
        use core::ops::Bound::{Excluded, Included, Unbounded};
        if let (Included(start) | Excluded(start), Included(end) | Excluded(end)) =
            (range.start_bound(), range.end_bound())
        {
            assert!(start <= end, "range start is greater than range end");
            if matches!(
                (range.start_bound(), range.end_bound()),
                (Excluded(_), Excluded(_))
            ) {
                assert!(start != end, "equal excluded range bounds");
            }
        }
        let start = match range.start_bound() {
            Unbounded => 0,
            Included(key) => self.entries.partition_point(|entry| &entry.0 < key),
            Excluded(key) => self.entries.partition_point(|entry| &entry.0 <= key),
        };
        let end = match range.end_bound() {
            Unbounded => self.entries.len(),
            Included(key) => self.entries.partition_point(|entry| &entry.0 <= key),
            Excluded(key) => self.entries.partition_point(|entry| &entry.0 < key),
        };
        self.entries[start..end]
            .iter()
            .map(|(key, value)| (key, value))
    }
    pub fn after(&self, key: &K) -> impl Iterator<Item = (&K, &V)> {
        let start = match self.position(key) {
            Ok(i) => i + 1,
            Err(i) => i,
        };
        self.entries[start..].iter().map(|(k, v)| (k, v))
    }
    /// Preserve the stored equivalent key as the original BTreeMap does.
    /// # Errors
    /// Returns the unchanged incoming pair on unsupported ZST storage, overflow,
    /// original-pool refusal or allocation failure; existing entries remain intact.
    pub fn try_insert(&mut self, key: K, value: V) -> Result<Option<V>, (K, V)> {
        if core::mem::size_of::<(K, V)>() == 0 {
            return Err((key, value));
        }
        let position = match self.position(&key) {
            Ok(i) => return Ok(Some(core::mem::replace(&mut self.entries[i].1, value))),
            Err(i) => i,
        };
        if self.entries.len() == self.entries.capacity() {
            let Some(capacity) = self
                .entries
                .len()
                .checked_add(1)
                .and_then(usize::checked_next_power_of_two)
            else {
                return Err((key, value));
            };
            if self.reserve_backing(capacity).is_err() {
                return Err((key, value));
            }
        }
        self.entries.insert(position, (key, value));
        self.publish_backing();
        Ok(None)
    }
    fn reserve_backing(&mut self, capacity: usize) -> Result<(), ()> {
        let bytes = core::alloc::Layout::array::<(K, V)>(capacity)
            .map_err(|_| ())?
            .size();
        if bytes == 0 {
            return Err(());
        }
        let allocation = self.pool.reserve_unpublished(bytes).ok_or(())?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(capacity).map_err(|_| ())?;
        if entries.capacity() != capacity {
            drop(entries);
            return Err(());
        }
        entries.append(&mut self.entries);
        drop(core::mem::replace(&mut self.entries, entries));
        drop(self.allocation.replace(allocation));
        Ok(())
    }
    fn publish_backing(&self) {
        if let Some(credit) = &self.allocation {
            credit.activate_release_notification();
        }
    }
    /// Pre-admit destination tuple backing before invoking the child copier.
    /// The callback MUST independently admit/retain all allocations it creates,
    /// or retain opaque already-paid aliases. This method pays only map backing.
    /// # Errors
    /// Preserves the source on admission/child failure or a changed cloned key.
    /// Partially copied children and backing are dropped before their credits.
    pub fn try_clone_with<E>(
        &self,
        mut child: impl FnMut(&K, &V, &Arc<AllocationPoolV1>) -> Result<(K, V), E>,
    ) -> Result<Self, MapCloneErrorV1<E>> {
        let mut result = Self::new(Arc::clone(&self.pool));
        if self.is_empty() {
            return Ok(result);
        }
        result
            .reserve_backing(self.len())
            .map_err(|_| MapCloneErrorV1::Admission)?;
        for (key, value) in &self.entries {
            let (copied_key, copied_value) =
                child(key, value, &self.pool).map_err(MapCloneErrorV1::Child)?;
            if copied_key.cmp(key) != core::cmp::Ordering::Equal {
                return Err(MapCloneErrorV1::ChangedKey);
            }
            result.entries.push((copied_key, copied_value));
        }
        result.publish_backing();
        Ok(result)
    }
}
// Pool/lease identity is local resource ownership, never part of value semantics.
impl<K: PartialEq, V: PartialEq> PartialEq for PaidOrderedMapV1<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}
impl<K: Eq, V: Eq> Eq for PaidOrderedMapV1<K, V> {}
impl<K: core::fmt::Debug, V: core::fmt::Debug> core::fmt::Debug for PaidOrderedMapV1<K, V> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_map()
            .entries(self.entries.iter().map(|(key, value)| (key, value)))
            .finish()
    }
}
impl<K: Ord, V> core::ops::Index<&K> for PaidOrderedMapV1<K, V> {
    type Output = V;
    fn index(&self, key: &K) -> &V {
        self.get(key).expect("no entry found for key")
    }
}
/// Consuming iteration retains tuple backing and its original pool through drop.
pub struct PaidMapEntriesV1<K, V> {
    entries: alloc::vec::IntoIter<(K, V)>,
    _allocation: Option<AllocationLeaseV1>,
    _pool: Arc<AllocationPoolV1>,
}
impl<K, V> Iterator for PaidMapEntriesV1<K, V> {
    type Item = (K, V);
    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next()
    }
}
impl<K, V> IntoIterator for PaidOrderedMapV1<K, V> {
    type Item = (K, V);
    type IntoIter = PaidMapEntriesV1<K, V>;
    fn into_iter(self) -> Self::IntoIter {
        PaidMapEntriesV1 {
            entries: self.entries.into_iter(),
            _allocation: self.allocation,
            _pool: self.pool,
        }
    }
}

#[cfg(test)]
pub(super) fn check() {
    let unit = core::alloc::Layout::array::<(u32, u64)>(3).unwrap().size();
    for maximum in [unit - 1, unit, unit + 1] {
        let pool = AllocationPoolV1::new(maximum).unwrap();
        let mut reserved = PaidOrderedMapV1::<u32, u64>::new(Arc::clone(&pool));
        assert_eq!(reserved.try_reserve_capacity(3).is_ok(), maximum >= unit);
        assert_eq!(pool.used(), if maximum >= unit { unit } else { 0 });
        if maximum >= unit {
            assert_eq!(reserved.capacity(), 3);
            reserved.try_insert(2, 20).unwrap();
            reserved.try_insert(1, 10).unwrap();
            reserved.try_insert(3, 30).unwrap();
            assert_eq!(pool.used(), unit);
            assert!(reserved.try_reserve_capacity(usize::MAX).is_err());
            assert_eq!(
                reserved.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>(),
                [(1, 10), (2, 20), (3, 30)]
            );
            assert!(reserved.try_reserve_capacity(0).is_ok());
            assert_eq!(pool.used(), unit);
        }
        drop(reserved);
        assert_eq!(pool.used(), 0);
    }
    check_borrowed_mutation();
    // Actual child backing carries independent credit; no plain Clone escape.
    struct Child {
        bytes: Vec<u8>,
        _credit: AllocationLeaseV1,
    }
    impl Child {
        fn new(pool: &Arc<AllocationPoolV1>, byte: u8) -> Result<Self, ()> {
            let credit = pool
                .reserve_unpublished(core::mem::size_of::<u8>())
                .ok_or(())?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(1).map_err(|_| ())?;
            assert_eq!(bytes.capacity(), 1);
            bytes.push(byte);
            credit.activate_release_notification();
            Ok(Self {
                bytes,
                _credit: credit,
            })
        }
    }
    let count = 2;
    let backing = core::alloc::Layout::array::<(u32, Child)>(count)
        .unwrap()
        .size();
    let pool = AllocationPoolV1::new(backing * 2 + count * 2).unwrap();
    let mut source = PaidOrderedMapV1::new(Arc::clone(&pool));
    for key in 0..u32::try_from(count).unwrap() {
        let value = Child::new(&pool, u8::try_from(key).unwrap()).unwrap();
        assert!(source.try_insert(key, value).is_ok());
    }
    let baseline = pool.used();
    assert_eq!(baseline, backing + count);
    let blocker = pool
        .reserve_unpublished(pool.capacity() - baseline - (backing - 1))
        .unwrap();
    let mut called = false;
    let refused = source.try_clone_with(|_, _, _| {
        called = true;
        Err::<(u32, Child), _>(())
    });
    assert!(matches!(refused, Err(MapCloneErrorV1::Admission)));
    assert!(!called);
    drop(blocker);
    assert_eq!(pool.used(), baseline);
    let mut copied = 0;
    let failed = source.try_clone_with(|key, value, pool| {
        if copied == 1 {
            return Err(());
        }
        copied += 1;
        Ok((*key, Child::new(pool, value.bytes[0])?))
    });
    assert!(matches!(failed, Err(MapCloneErrorV1::Child(()))));
    assert_eq!(pool.used(), baseline);
    let changed = source.try_clone_with(|key, value, pool| {
        Ok::<_, ()>((*key + 1, Child::new(pool, value.bytes[0])?))
    });
    assert!(matches!(changed, Err(MapCloneErrorV1::ChangedKey)));
    assert_eq!(pool.used(), baseline);
    let copied = source
        .try_clone_with(|key, value, pool| Ok::<_, ()>((*key, Child::new(pool, value.bytes[0])?)))
        .unwrap();
    assert_eq!(pool.used(), baseline * 2);
    assert_eq!(copied[&1].bytes, source[&1].bytes);
    drop(source);
    assert_eq!(pool.used(), baseline);
    drop(copied);
    assert_eq!(pool.used(), 0);
}

#[cfg(test)]
fn check_borrowed_mutation() {
    use alloc::collections::BTreeMap;
    use core::ops::Bound::{Excluded, Included, Unbounded};
    let entries: [(u32, u32); 5] = [(8, 80), (2, 20), (6, 60), (0, 0), (4, 40)];
    let capacity = entries.len().next_power_of_two();
    let backing = core::alloc::Layout::array::<(u32, u32)>(capacity)
        .unwrap()
        .size();
    let pool = AllocationPoolV1::new(backing.checked_mul(2).unwrap()).unwrap();
    let mut actual = PaidOrderedMapV1::new(Arc::clone(&pool));
    let mut expected = BTreeMap::new();
    for (key, value) in entries {
        assert_eq!(
            actual.try_insert(key, value).unwrap(),
            expected.insert(key, value)
        );
    }
    let admitted = pool.used();
    assert_eq!(admitted, backing);
    let other_pool = AllocationPoolV1::new(backing.checked_mul(2).unwrap()).unwrap();
    let mut other = PaidOrderedMapV1::new(Arc::clone(&other_pool));
    for (key, value) in &expected {
        other.try_insert(*key, *value).unwrap();
    }
    assert_eq!(actual, other);
    assert_eq!(alloc::format!("{actual:?}"), alloc::format!("{expected:?}"));
    assert!(!actual.uses_pool(&other_pool));
    other.get_mut(&0).map(|value| *value += 1).unwrap();
    assert_ne!(actual, other);
    drop(other);
    assert_eq!(other_pool.used(), 0);

    for low in 0..=10 {
        for high in low..=10 {
            for start in [Unbounded, Included(low), Excluded(low)] {
                for end in [Unbounded, Included(high), Excluded(high)] {
                    if low == high && matches!((&start, &end), (Excluded(_), Excluded(_))) {
                        continue;
                    }
                    assert!(actual.range((start, end)).eq(expected.range((start, end))));
                    assert!(actual
                        .range((start, end))
                        .rev()
                        .eq(expected.range((start, end)).rev()));
                    assert_eq!(pool.used(), admitted);
                }
            }
        }
    }
    for value in actual.values_mut() {
        *value += 1;
    }
    for value in expected.values_mut() {
        *value += 1;
    }
    actual.retain(|key, value| {
        *value += 1;
        key % 4 == 0
    });
    expected.retain(|key, value| {
        *value += 1;
        key % 4 == 0
    });
    assert!(actual.iter().eq(expected.iter()));
    assert_eq!(pool.used(), admitted);
    actual.clear();
    expected.clear();
    assert!(actual.iter().eq(expected.iter()));
    assert_eq!(pool.used(), admitted);
    assert_eq!(actual.try_insert(3, 30).unwrap(), expected.insert(3, 30));
    assert_eq!(pool.used(), admitted);
    assert!(actual.iter().eq(expected.iter()));
    drop(actual);
    assert_eq!(pool.used(), 0);
}
