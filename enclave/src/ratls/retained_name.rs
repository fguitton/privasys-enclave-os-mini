//! Cache key text: one opaque paid payload shared by aliases, never a raw Arc.
use core::{borrow::Borrow, cmp::Ordering, fmt};
use enclave_os_common::allocation::{AllocationPoolV1, SharedAllocationV1};
use std::sync::Arc;

pub(crate) struct PaidName(SharedAllocationV1<String>);
impl PaidName {
    pub(crate) fn new(pool: &Arc<AllocationPoolV1>, text: &str) -> Option<Self> {
        // Both Arc layouts and the exact String backing are admitted before copy.
        // An empty key has no child allocation but still owns both Arc containers.
        let reservation = SharedAllocationV1::<String>::reserve(pool, text.len())?;
        let mut owned = String::new();
        owned.try_reserve_exact(text.len()).ok()?;
        if owned.capacity() != text.len() {
            return None;
        }
        owned.push_str(text);
        #[cfg(feature = "fallible-allocation-v1")]
        let retained = reservation.try_finish(owned).ok()?;
        // The default Arc constructor remains infallible, with its layouts paid.
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let retained = reservation.finish(owned);
        Some(Self(retained))
    }
    fn text(&self) -> &str {
        self.0.as_str()
    }
}
impl Clone for PaidName {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl Borrow<str> for PaidName {
    fn borrow(&self) -> &str {
        self.text()
    }
}
impl PartialEq for PaidName {
    fn eq(&self, other: &Self) -> bool {
        self.text() == other.text()
    }
}
impl Eq for PaidName {}
impl PartialOrd for PaidName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for PaidName {
    fn cmp(&self, other: &Self) -> Ordering {
        self.text().cmp(other.text())
    }
}
impl fmt::Debug for PaidName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.text().fmt(f)
    }
}

#[cfg(test)]
pub(super) fn check() {
    use super::ordered_map::OrderedMap;
    use core::alloc::Layout;
    use std::collections::BTreeMap;
    let text = "genuine-cache-key";
    let required = SharedAllocationV1::<String>::required_bytes(text.len()).unwrap();
    let short = AllocationPoolV1::new(required - 1).unwrap();
    assert!(PaidName::new(&short, text).is_none());
    assert_eq!(short.used(), 0);
    for available in [required, required + 1] {
        let pool = AllocationPoolV1::new(available).unwrap();
        let key = PaidName::new(&pool, text).unwrap();
        assert_eq!(pool.used(), required);
        assert_eq!(key.text(), text);
        let alias = key.clone();
        assert_eq!(pool.used(), required);
        drop(key);
        assert_eq!(pool.used(), required);
        assert_eq!(alias.text(), text);
        drop(alias);
        assert_eq!(pool.used(), 0);
    }
    let empty_bytes = SharedAllocationV1::<String>::required_bytes(0).unwrap();
    let empty_pool = AllocationPoolV1::new(empty_bytes).unwrap();
    let empty = PaidName::new(&empty_pool, "").unwrap();
    assert_eq!(empty.0.capacity(), 0);
    assert_eq!(empty_pool.used(), empty_bytes);
    drop(empty);
    assert_eq!(empty_pool.used(), 0);
    assert!(SharedAllocationV1::<String>::required_bytes(usize::MAX).is_none());

    // Comparator-equivalent incoming key is dropped, while the original key and
    // its credit remain in the map exactly as with the independent BTree owner.
    let tuple_bytes = Layout::array::<(PaidName, u8)>(1).unwrap().size();
    let pool = AllocationPoolV1::new(tuple_bytes + 2 * required).unwrap();
    let mut actual = OrderedMap::default();
    actual.prepare_from(&pool, 1).unwrap();
    let original = PaidName::new(&pool, text).unwrap();
    let alias = original.clone();
    let mut reference = BTreeMap::new();
    assert_eq!(
        actual.insert_prepared(original, 1),
        reference.insert(text, 1)
    );
    assert_eq!(pool.used(), tuple_bytes + required);
    let replacement = PaidName::new(&pool, text).unwrap();
    assert_eq!(pool.used(), tuple_bytes + 2 * required);
    assert_eq!(
        actual.insert_prepared(replacement, 2),
        reference.insert(text, 2)
    );
    assert_eq!(pool.used(), tuple_bytes + required);
    assert_eq!(actual.get(text), reference.get(text));
    assert!(SharedAllocationV1::ptr_eq(
        &actual.iter().next().unwrap().0 .0,
        &alias.0
    ));
    assert_eq!(actual.remove(text), reference.remove(text));
    assert_eq!(pool.used(), tuple_bytes + required);
    drop(actual);
    assert_eq!(pool.used(), required);
    drop(alias);
    assert_eq!(pool.used(), 0);
}
