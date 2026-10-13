//! Ordered transport metadata with explicit backing admission, not authority.
use enclave_os_common::allocation::{AllocationLeaseV1, AllocationPoolV1};
use std::sync::Arc;

pub(crate) struct OrderedMap<K, V> {
    entries: Vec<(K, V)>,
    allocation: Option<AllocationLeaseV1>,
}
impl<K, V> Default for OrderedMap<K, V> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            allocation: None,
        }
    }
}
impl<K: Ord, V> OrderedMap<K, V> {
    fn position(&self, key: &K) -> Result<usize, usize> {
        self.entries.binary_search_by(|entry| entry.0.cmp(key))
    }
    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        self.position(key).ok().map(|i| &self.entries[i].1)
    }
    pub(crate) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.position(key).ok().map(|i| &mut self.entries[i].1)
    }
    pub(crate) fn contains_key(&self, key: &K) -> bool {
        self.position(key).is_ok()
    }
    pub(crate) fn remove(&mut self, key: &K) -> Option<V> {
        self.position(key).ok().map(|i| self.entries.remove(i).1)
    }
    pub(crate) fn iter(&self) -> impl DoubleEndedIterator<Item = (&K, &V)> {
        self.entries.iter().map(|(key, value)| (key, value))
    }
    pub(crate) fn after(&self, key: &K) -> impl Iterator<Item = (&K, &V)> {
        let start = match self.position(key) {
            Ok(i) => i + 1,
            Err(i) => i,
        };
        self.entries[start..]
            .iter()
            .map(|(key, value)| (key, value))
    }
    pub(crate) fn try_insert(&mut self, key: K, value: V) -> Result<Option<V>, (K, V)> {
        #[cfg(target_env = "sgx")]
        let pool = match crate::local_allocation_pool() {
            Some(pool) => Some(pool),
            None => return Err((key, value)),
        };
        #[cfg(not(target_env = "sgx"))]
        let pool = None;
        self.insert_admitted(key, value, pool.as_ref())
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
        // Vec<ZST> reports usize::MAX capacity without calling grow.
        // Refuse this unsupported private-map representation before that path.
        if core::mem::size_of::<(K, V)>() == 0 {
            return Err((key, value));
        }
        let position = match self.position(&key) {
            Ok(i) => return Ok(Some(core::mem::replace(&mut self.entries[i].1, value))),
            Err(i) => i,
        };
        if self.entries.len() == self.entries.capacity() && self.grow(pool).is_err() {
            return Err((key, value));
        }
        self.entries.insert(position, (key, value));
        Ok(None)
    }
    fn grow(&mut self, pool: Option<&Arc<AllocationPoolV1>>) -> Result<(), ()> {
        let capacity = self
            .entries
            .len()
            .checked_add(1)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(())?;
        let backing = core::alloc::Layout::array::<(K, V)>(capacity)
            .map_err(|_| ())?
            .size();
        // This private transport map stores real nonzero metadata tuples;
        // zero-sized generic storage is unsupported, never charged as one byte.
        if backing == 0 {
            return Err(());
        }
        let allocation = pool
            .map(|pool| pool.reserve_unpublished(backing).ok_or(()))
            .transpose()?;
        // A separate allocation preserves the old map exactly on failure. Its
        // backing remains paid throughout copying/moving into the new buffer.
        let mut entries = Vec::new();
        entries.try_reserve_exact(capacity).map_err(|_| ())?;
        if entries.capacity() != capacity {
            drop(entries);
            return Err(());
        }
        entries.extend(self.entries.drain(..));
        drop(core::mem::replace(&mut self.entries, entries));
        drop(core::mem::replace(&mut self.allocation, allocation));
        if let Some(credit) = &self.allocation {
            credit.activate_release_notification();
        }
        Ok(())
    }
}
/// Consuming iteration keeps the vector allocation paid even after its last
/// item; no borrowed map or raw allocation handle escapes.
pub(crate) struct Entries<K, V> {
    entries: std::vec::IntoIter<(K, V)>,
    _allocation: Option<AllocationLeaseV1>,
}
impl<K, V> Iterator for Entries<K, V> {
    type Item = (K, V);
    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next()
    }
}
impl<K, V> IntoIterator for OrderedMap<K, V> {
    type Item = (K, V);
    type IntoIter = Entries<K, V>;
    fn into_iter(self) -> Self::IntoIter {
        Entries {
            entries: self.entries.into_iter(),
            _allocation: self.allocation,
        }
    }
}

#[cfg(test)]
pub(super) fn check() {
    use std::collections::BTreeMap;
    type Map = OrderedMap<u32, u64>;
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
            map.try_insert(key, u64::from(i)).unwrap(),
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
                .try_insert(Key { order: 1, identity }, identity)
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
        zero.try_insert((), ()),
        Err(((), ())),
        "zero-sized tuples explicitly unsupported"
    );
    eprintln!("SESSION-MAP-PAID: original ordered-map oracle, real backing peak/refusal/empty/iterator refund PASS");
}
