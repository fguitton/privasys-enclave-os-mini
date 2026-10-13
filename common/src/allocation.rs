//! Shared transient allocation admission. Numeric capacity grants no authority.
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Debug)]
pub struct AllocationPoolV1 {
    capacity: usize,
    used: AtomicUsize,
    released: Option<fn()>,
}
impl AllocationPoolV1 {
    /// Construct from the caller's actual physical admission input. This is not
    /// a semantic guest-memory maximum or a promise about untracked allocator use.
    pub fn new(capacity: usize) -> Option<Arc<Self>> {
        Self::new_with_release(capacity, None)
    }
    /// Coalesced scheduling hint after actual credit release. The callback must
    /// never acquire owner/transport locks, allocate, wait or grant authority.
    pub fn new_with_release(capacity: usize, released: Option<fn()>) -> Option<Arc<Self>> {
        if capacity == 0 {
            return None;
        }
        Some(Arc::new(Self {
            capacity,
            used: AtomicUsize::new(0),
            released,
        }))
    }
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
    /// Reserve before allocation; a shared payload must retain the same lease
    /// through its final alias. Failed/zero/overflowing requests consume nothing.
    pub fn reserve(self: &Arc<Self>, bytes: usize) -> Option<AllocationLeaseV1> {
        self.reserve_with_notification(bytes, true)
    }
    /// Admission held only during construction/rollback must not rearm a waiter.
    /// Activate notification after real ownership publication, before sharing.
    pub fn reserve_unpublished(self: &Arc<Self>, bytes: usize) -> Option<AllocationLeaseV1> {
        self.reserve_with_notification(bytes, false)
    }
    fn reserve_with_notification(
        self: &Arc<Self>,
        bytes: usize,
        notify: bool,
    ) -> Option<AllocationLeaseV1> {
        if bytes == 0 {
            return None;
        }
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.capacity)
            })
            .ok()?;
        Some(AllocationLeaseV1 {
            pool: self.clone(),
            bytes,
            notify: AtomicBool::new(notify),
        })
    }
}
/// Move-only physical allocation credit; it cannot read, sign or acknowledge data.
#[derive(Debug)]
pub struct AllocationLeaseV1 {
    pool: Arc<AllocationPoolV1>,
    bytes: usize,
    notify: AtomicBool,
}
impl AllocationLeaseV1 {
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    /// Data ownership publication only; no permission, useful progress or ACK.
    pub fn activate_release_notification(&self) {
        self.notify.store(true, Ordering::Release);
    }
    pub fn covers(&self, pool: &Arc<AllocationPoolV1>, bytes: usize) -> bool {
        Arc::ptr_eq(&self.pool, pool) && self.bytes >= bytes
    }
}
impl Drop for AllocationLeaseV1 {
    fn drop(&mut self) {
        self.pool.used.fetch_sub(self.bytes, Ordering::AcqRel);
        if self.notify.load(Ordering::Acquire) {
            if let Some(released) = self.pool.released {
                released();
            }
        }
    }
}
/// Checked geometric Vec backing within the caller's existing byte maximum.
/// This is an allocation capacity, not an encoded wire or useful-data count.
/// Refuse impossible allocator layouts before physical admission/allocation.
pub fn bounded_vec_capacity(required: usize, maximum: usize) -> Option<usize> {
    if required == 0 || required > maximum { return None; }
    let capacity = match required.checked_next_power_of_two() {
        Some(next) if next <= maximum => next,
        _ => maximum,
    };
    core::alloc::Layout::array::<u8>(capacity).ok()?;
    Some(capacity)
}

/// Layout of the acquired alloc crate's `#[repr(C, align(2))] ArcInner<T>`.
/// This contract tracks requested allocator layouts, not allocator-private metadata.
/// Consumers must not substitute a copied pointer-count estimate.
pub fn shared_allocation_bytes<T>() -> Option<usize> {
    #[repr(C, align(2))]
    struct Header {
        strong: AtomicUsize,
        weak: AtomicUsize,
    }
    core::alloc::Layout::new::<Header>()
        .extend(core::alloc::Layout::new::<T>())
        .ok()
        .map(|(layout, _)| layout.pad_to_align().size())
}

/// Trusted local credit owner. Implementations retain their original admission
/// until Drop and never interpret byte capacity as semantic authority.
pub trait SharedAllocationCreditV1 {
    fn bytes(&self) -> usize;
    fn activate_release_notification(&self);
}
impl SharedAllocationCreditV1 for AllocationLeaseV1 {
    fn bytes(&self) -> usize { AllocationLeaseV1::bytes(self) }
    fn activate_release_notification(&self) { AllocationLeaseV1::activate_release_notification(self); }
}
/// Opaque shared payload: no raw Arc or Weak escapes this owner.
/// Both Arc layouts and declared retained children share the original credit.
pub struct SharedAllocationV1<T, C = AllocationLeaseV1> {
    payload: Option<Arc<T>>,
    credit: Option<Arc<C>>,
}
/// Admission precedes constructing the payload and its declared child storage.
pub struct SharedAllocationReservationV1<T, C = AllocationLeaseV1> {
    allocation: C,
    marker: core::marker::PhantomData<T>,
}
impl<T> SharedAllocationV1<T> {
    pub fn reserve(pool: &Arc<AllocationPoolV1>, retained_child_bytes: usize) -> Option<SharedAllocationReservationV1<T>> {
        Self::from_admission(pool.reserve_unpublished(Self::required_bytes(retained_child_bytes)?)?, retained_child_bytes)
    }
}
impl<T, C> SharedAllocationV1<T, C> {
    /// Complete requested payload/credit Arc layouts plus caller-owned children.
    pub fn required_bytes(retained_child_bytes: usize) -> Option<usize> {
        shared_allocation_bytes::<T>()?
            .checked_add(shared_allocation_bytes::<C>()?)?
            .checked_add(retained_child_bytes)
    }
    /// Identity comparison without exposing raw Arc or Weak ownership.
    #[must_use]
    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        match (&this.payload, &other.payload) { (Some(a), Some(b)) => Arc::ptr_eq(a,b), _ => false }
    }
    /// Exclusive construction-time access; fails as soon as a payload is shared.
    pub fn get_mut(&mut self) -> Option<&mut T> { self.payload.as_mut().and_then(Arc::get_mut) }
}
impl<T, C: SharedAllocationCreditV1> SharedAllocationV1<T, C> {
    /// Transfer an original provider admission; this never creates a new pool.
    pub fn from_admission(allocation: C, retained_child_bytes: usize) -> Option<SharedAllocationReservationV1<T,C>> {
        if allocation.bytes() < Self::required_bytes(retained_child_bytes)? { return None; }
        Some(SharedAllocationReservationV1 { allocation, marker: core::marker::PhantomData })
    }
    /// Called only after the original owner publishes actual retained work.
    pub fn activate_release_notification(&self) {
        if let Some(credit) = &self.credit { credit.activate_release_notification(); }
    }
}
impl<T, C: SharedAllocationCreditV1> SharedAllocationReservationV1<T,C> {
    pub fn finish(self, value: T) -> SharedAllocationV1<T,C> {
        let value = self.finish_unpublished(value);
        value.activate_release_notification();
        value
    }
    /// Keep rollback silent until the actual owning route publishes this value.
    pub fn finish_unpublished(self, value: T) -> SharedAllocationV1<T,C> {
        let payload = Arc::new(value);
        let credit = Arc::new(self.allocation);
        SharedAllocationV1 { payload: Some(payload), credit: Some(credit) }
    }
}
impl<T,C> Clone for SharedAllocationV1<T,C> {
    fn clone(&self) -> Self { Self { payload: self.payload.clone(), credit: self.credit.clone() } }
}
impl<T,C> core::ops::Deref for SharedAllocationV1<T,C> {
    type Target = T;
    fn deref(&self) -> &T { self.payload.as_deref().expect("live shared payload") }
}
impl<T,C> Drop for SharedAllocationV1<T,C> {
    fn drop(&mut self) {
        // Every alias releases its payload first. No external Weak is possible.
        drop(self.payload.take());
        if let Some(credit) = self.credit.take() {
            // Acquired Arc::into_inner frees the last Arc storage before the
            // moved credit (including every logical/physical lease) is dropped.
            drop(Arc::into_inner(credit));
        }
    }
}

#[cfg(test)]
pub(crate) fn check_allocation_owner() {
    assert_eq!(bounded_vec_capacity(0, 3), None);
    assert_eq!(bounded_vec_capacity(2, 3), Some(2));
    assert_eq!(bounded_vec_capacity(3, 3), Some(3));
    assert_eq!(bounded_vec_capacity(4, 3), None);
    assert_eq!(bounded_vec_capacity(usize::MAX, usize::MAX), None);
    struct ObservedDrop { pool: Arc<AllocationPoolV1>, expected: usize, dropped: Arc<AtomicBool> }
    impl Drop for ObservedDrop {
        fn drop(&mut self) {
            assert_eq!(self.pool.used(), self.expected, "payload dies while full credit is held");
            self.dropped.store(true, Ordering::Release);
        }
    }
    let bytes = shared_allocation_bytes::<ObservedDrop>().unwrap()
        + shared_allocation_bytes::<AllocationLeaseV1>().unwrap();
    let shared_pool = AllocationPoolV1::new(bytes).unwrap();
    let short = AllocationPoolV1::new(bytes - 1).unwrap();
    assert!(SharedAllocationV1::<ObservedDrop>::reserve(&short, 0).is_none());
    assert_eq!(short.used(), 0);
    assert!(SharedAllocationV1::<ObservedDrop>::reserve(&shared_pool, usize::MAX).is_none());
    let dropped = Arc::new(AtomicBool::new(false));
    let reservation = SharedAllocationV1::<ObservedDrop>::reserve(&shared_pool, 0).unwrap();
    assert_eq!(shared_pool.used(), bytes);
    let original = reservation.finish(ObservedDrop { pool: shared_pool.clone(), expected: bytes, dropped: dropped.clone() });
    let alias = original.clone();
    drop(original);
    assert!(!dropped.load(Ordering::Acquire));
    assert_eq!(shared_pool.used(), bytes, "cloning retains one actual allocation charge");
    drop(alias);
    assert!(dropped.load(Ordering::Acquire));
    assert_eq!(shared_pool.used(), 0);
    static RELEASED: AtomicUsize = AtomicUsize::new(0);
    fn released() {
        RELEASED.fetch_add(1, Ordering::AcqRel);
    }
    // A second real credit owner preserves silent rollback and exact alias lifetime.
    struct LocalCredit { lease: AllocationLeaseV1, _layout: [u8; 17] }
    impl SharedAllocationCreditV1 for LocalCredit {
        fn bytes(&self) -> usize { self.lease.bytes() }
        fn activate_release_notification(&self) { self.lease.activate_release_notification(); }
    }
    let local_bytes = SharedAllocationV1::<ObservedDrop, LocalCredit>::required_bytes(0).unwrap();
    let local_pool = AllocationPoolV1::new_with_release(local_bytes, Some(released)).unwrap();
    let local_releases = RELEASED.load(Ordering::Acquire);
    let make = || SharedAllocationV1::<ObservedDrop, LocalCredit>::from_admission(
        LocalCredit { lease: local_pool.reserve_unpublished(local_bytes).unwrap(), _layout: [0; 17] }, 0
    ).unwrap().finish_unpublished(ObservedDrop {
        pool: local_pool.clone(), expected: local_bytes, dropped: Arc::new(AtomicBool::new(false)),
    });
    drop(make());
    assert_eq!(local_pool.used(), 0);
    assert_eq!(RELEASED.load(Ordering::Acquire), local_releases, "unpublished rollback stays silent");
    let mut local = make();
    assert!(local.get_mut().is_some());
    let alias = local.clone();
    assert!(SharedAllocationV1::ptr_eq(&local, &alias));
    assert!(local.get_mut().is_none());
    assert_eq!(local_pool.used(), local_bytes, "custom owner aliases do not allocate");
    local.activate_release_notification();
    drop(local);
    assert_eq!(local_pool.used(), local_bytes);
    assert_eq!(RELEASED.load(Ordering::Acquire), local_releases);
    drop(alias);
    assert_eq!(local_pool.used(), 0);
    assert_eq!(RELEASED.load(Ordering::Acquire), local_releases + 1);
    let notified = AllocationPoolV1::new_with_release(7, Some(released)).unwrap();
    let before = RELEASED.load(Ordering::Acquire);
    // Actual partial admission and rollback do not fabricate a release event.
    let unpublished = notified.reserve_unpublished(3).unwrap();
    assert!(notified.reserve_unpublished(5).is_none());
    drop(unpublished);
    assert_eq!(notified.used(), 0);
    assert_eq!(RELEASED.load(Ordering::Acquire), before);
    let first = Arc::new(notified.reserve_unpublished(7).unwrap());
    let last = first.clone();
    first.activate_release_notification();
    assert!(notified.reserve(1).is_none());
    assert_eq!(RELEASED.load(Ordering::Acquire), before);
    drop(first);
    assert_eq!(RELEASED.load(Ordering::Acquire), before);
    drop(last);
    assert_eq!(RELEASED.load(Ordering::Acquire), before + 1);
    assert_eq!(notified.used(), 0);
    assert!(AllocationPoolV1::new(0).is_none());
    let pool = AllocationPoolV1::new(9).unwrap();
    assert!(pool.reserve(0).is_none());
    let first = Arc::new(pool.reserve(7).unwrap());
    let alias = first.clone();
    let second = pool.reserve(2).unwrap();
    assert_eq!(pool.used(), 9);
    assert!(pool.reserve(1).is_none());
    drop(first);
    assert_eq!(pool.used(), 9);
    drop(second);
    assert_eq!(pool.used(), 7);
    assert!(alias.covers(&pool, 7));
    assert!(!alias.covers(&AllocationPoolV1::new(9).unwrap(), 7));
    drop(alias);
    assert_eq!(pool.used(), 0);
    let full = AllocationPoolV1::new(usize::MAX).unwrap();
    let held = full.reserve(usize::MAX).unwrap();
    assert!(full.reserve(1).is_none());
    drop(held);
    assert_eq!(full.used(), 0);
}
