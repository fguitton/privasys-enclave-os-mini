//! Shared transient allocation admission. Numeric capacity grants no authority.
#[cfg(feature = "allocation-fault-fixture")]
mod fault;
#[cfg(feature = "std")]
mod growth;
mod mandatory;
#[cfg(feature = "fallible-allocation-v1")]
mod map_allocator;
/// Pool-bound fallible ordered metadata backing; child admission remains separate.
pub mod ordered_map;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(feature = "std")]
pub use growth::{GrowthCreditV1, GrowthLendV1};
pub use mandatory::{AdmissionV1, MandatoryAuthorityV1, MandatoryTokenV1, ReservedCreditV1};
#[cfg(feature = "fallible-allocation-v1")]
pub use map_allocator::PoolMapAllocator;

#[derive(Debug)]
pub struct AllocationPoolV1 {
    capacity: usize,
    /// Bytes below capacity that only mandatory cleanup tokens may use.
    floor: AtomicUsize,
    used: AtomicUsize,
    /// Serializes every admission against floor installation and removal, so
    /// no admission decides against a floor that changes before it commits.
    admission: AtomicBool,
    gross_reserved: AtomicUsize,
    released: Option<fn()>,
    #[cfg(feature = "allocation-fault-fixture")]
    fault: fault::Fault,
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
            floor: AtomicUsize::new(0),
            used: AtomicUsize::new(0),
            admission: AtomicBool::new(false),
            gross_reserved: AtomicUsize::new(0),
            released,
            #[cfg(feature = "allocation-fault-fixture")]
            fault: fault::Fault::default(),
        }))
    }
    /// Fallible measured startup root, before any child pool or loan exists.
    /// The acquired ArcInner<Self> request is admitted by reducing the supplied
    /// physical capacity BEFORE Arc allocates. Runtime retains this root for the
    /// process lifetime; this does not bound allocator-private heap overhead.
    /// Existing default/native constructor semantics remain unchanged.
    /// # Errors
    /// Returns None for unavailable metadata geometry, no remaining capacity,
    /// or actual Arc allocation refusal. No pool or partial credit escapes.
    #[cfg(feature = "fallible-allocation-v1")]
    pub fn try_new_with_release(capacity: usize, released: Option<fn()>) -> Option<Arc<Self>> {
        let root_bytes = shared_allocation_bytes::<Self>()?;
        let available = capacity
            .checked_sub(root_bytes)
            .filter(|bytes| *bytes != 0)?;
        Arc::try_new(Self {
            capacity: available,
            floor: AtomicUsize::new(0),
            used: AtomicUsize::new(0),
            admission: AtomicBool::new(false),
            gross_reserved: AtomicUsize::new(0),
            released,
            #[cfg(feature = "allocation-fault-fixture")]
            fault: fault::Fault::default(),
        })
        .ok()
    }
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
    /// Successful reservation bytes over this pool's lifetime, across all threads.
    /// Includes later backing-allocation failures and rollback; never decreases
    /// on release. This is neither actual allocated bytes nor a live/peak count.
    /// None means the monotonic observation overflowed; admission is unaffected.
    pub fn gross_reserved_bytes(&self) -> Option<usize> {
        let bytes = self.gross_reserved.load(Ordering::Acquire);
        (bytes != usize::MAX).then_some(bytes)
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
        self.reserve_backend_bytes(bytes)?;
        Some(AllocationLeaseV1 {
            pool: self.clone(),
            bytes,
            notify: AtomicBool::new(notify),
        })
    }
    // The same original-pool admission serves move-only leases and explicit
    // backend headers. Header owners retain the pool until actual free.
    fn reserve_backend_bytes(&self, bytes: usize) -> Option<()> {
        #[cfg(feature = "allocation-fault-fixture")]
        if self.fault.refuses() {
            return None;
        }
        #[cfg(feature = "std")]
        if let Some(admitted) = growth::admit_lent(self, bytes) {
            return admitted;
        }
        self.admit(bytes, false)
    }
    /// Admission up to the whole capacity, floor included, for a mandatory
    /// token's pre-reservation only.
    fn reserve_mandatory_bytes(&self, bytes: usize) -> Option<()> {
        self.admit(bytes, true)
    }
    /// Run `change` while no other admission or floor change can interleave.
    /// The section only reads and writes this pool's counters.
    fn serialized<R>(&self, change: impl FnOnce() -> R) -> R {
        while self
            .admission
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let result = change();
        self.admission.store(false, Ordering::Release);
        result
    }
    fn admit(&self, bytes: usize, mandatory: bool) -> Option<()> {
        if bytes == 0 {
            return None;
        }
        self.serialized(|| {
            let limit = if mandatory {
                self.capacity
            } else {
                self.capacity - self.floor.load(Ordering::Acquire)
            };
            // Releases stay lock-free and only lower `used`, so the update
            // retries over them rather than overwriting them.
            self.used
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_add(bytes).filter(|next| *next <= limit)
                })
                .ok()
                .map(|_| ())
        })?;
        // Saturation is an explicit unknown observation, never an admission cap.
        let _ = self
            .gross_reserved
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |total| {
                Some(total.saturating_add(bytes))
            });
        Some(())
    }
    fn release_backend_bytes(&self, bytes: usize, notify: bool) {
        #[cfg(feature = "std")]
        if growth::refund_lent(self, bytes) {
            return;
        }
        self.used.fetch_sub(bytes, Ordering::AcqRel);
        if notify {
            if let Some(released) = self.released {
                released();
            }
        }
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
    /// A lease over bytes a mandatory token already counted as used.
    fn already_reserved(pool: Arc<AllocationPoolV1>, bytes: usize) -> Self {
        Self {
            pool,
            bytes,
            notify: AtomicBool::new(false),
        }
    }
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
        self.pool
            .release_backend_bytes(self.bytes, self.notify.load(Ordering::Acquire));
    }
}
/// Checked geometric Vec backing within the caller's existing byte maximum.
/// This is an allocation capacity, not an encoded wire or useful-data count.
/// Refuse impossible allocator layouts before physical admission/allocation.
pub fn bounded_vec_capacity(required: usize, maximum: usize) -> Option<usize> {
    if required == 0 || required > maximum {
        return None;
    }
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
    shared_allocation_layout::<T>().map(|layout| layout.size())
}

/// Complete requested layout of the acquired ArcInner for one payload.
/// All Arc consumers derive both size and alignment from this owner.
pub fn shared_allocation_layout<T>() -> Option<core::alloc::Layout> {
    shared_allocation_layout_for_payload(core::alloc::Layout::new::<T>())
}

/// Complete acquired ArcInner request for a concrete supplier payload layout.
/// This uses the same header/padding owner as the typed form above.
pub fn shared_allocation_bytes_for_layout(payload: core::alloc::Layout) -> Option<usize> {
    shared_allocation_layout_for_payload(payload).map(|layout| layout.size())
}

fn shared_allocation_layout_for_payload(
    payload: core::alloc::Layout,
) -> Option<core::alloc::Layout> {
    #[repr(C, align(2))]
    struct Header {
        strong: AtomicUsize,
        weak: AtomicUsize,
    }
    core::alloc::Layout::new::<Header>()
        .extend(payload)
        .ok()
        .map(|(layout, _)| layout.pad_to_align())
}

/// Trusted local credit owner. Implementations retain their original admission
/// until Drop and never interpret byte capacity as semantic authority.
pub trait SharedAllocationCreditV1 {
    fn bytes(&self) -> usize;
    fn activate_release_notification(&self);
}
impl SharedAllocationCreditV1 for AllocationLeaseV1 {
    fn bytes(&self) -> usize {
        AllocationLeaseV1::bytes(self)
    }
    fn activate_release_notification(&self) {
        AllocationLeaseV1::activate_release_notification(self);
    }
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
    pub fn reserve(
        pool: &Arc<AllocationPoolV1>,
        retained_child_bytes: usize,
    ) -> Option<SharedAllocationReservationV1<T>> {
        Self::reserve_in(&AdmissionV1::Ordinary(pool.clone()), retained_child_bytes)
    }
    /// Reserve through `admission`: ordinary headroom or a mandatory token.
    pub fn reserve_in(
        admission: &AdmissionV1,
        retained_child_bytes: usize,
    ) -> Option<SharedAllocationReservationV1<T>> {
        Self::from_admission(
            admission.reserve_unpublished(Self::required_bytes(retained_child_bytes)?)?,
            retained_child_bytes,
        )
    }
}
/// Failure leaves the original shared value and all its aliases untouched.
#[cfg(feature = "fallible-allocation-v1")]
#[derive(Debug)]
pub enum SharedMutationErrorV1<E> {
    DifferentPool,
    Admission,
    Allocation,
    Clone(E),
}
#[cfg(feature = "fallible-allocation-v1")]
impl<T> SharedAllocationV1<T> {
    /// Reuse a unique payload or independently admit a complete shared copy.
    /// The callback must pay for its own children; this owner pays both Arcs.
    /// Release notification preserves the original publication disposition.
    /// # Errors
    /// Refuses a foreign pool, admission, clone failure or actual Arc refusal.
    pub fn try_make_unique_with<E>(
        &mut self,
        pool: &Arc<AllocationPoolV1>,
        retained_child_bytes: usize,
        clone: impl FnOnce(&T) -> Result<T, E>,
    ) -> Result<&mut T, SharedMutationErrorV1<E>> {
        self.try_make_unique_in(
            &AdmissionV1::Ordinary(pool.clone()),
            retained_child_bytes,
            clone,
        )
    }
    /// As [`Self::try_make_unique_with`], admitting a copy through `admission`.
    /// # Errors
    /// Refuses a foreign pool, admission, clone failure or actual Arc refusal.
    pub fn try_make_unique_in<E>(
        &mut self,
        admission: &AdmissionV1,
        retained_child_bytes: usize,
        clone: impl FnOnce(&T) -> Result<T, E>,
    ) -> Result<&mut T, SharedMutationErrorV1<E>> {
        let pool = admission.pool();
        let credit = self
            .credit
            .as_ref()
            .ok_or(SharedMutationErrorV1::Allocation)?;
        if !credit.covers(pool, credit.bytes()) {
            return Err(SharedMutationErrorV1::DifferentPool);
        }
        let notify = credit.notify.load(Ordering::Acquire);
        if self
            .payload
            .as_ref()
            .is_some_and(|value| Arc::strong_count(value) == 1)
        {
            let required = Self::required_bytes(retained_child_bytes)
                .ok_or(SharedMutationErrorV1::Admission)?;
            if credit.bytes() < required {
                return Err(SharedMutationErrorV1::Admission);
            }
            return self.get_mut().ok_or(SharedMutationErrorV1::Allocation);
        }
        let reservation = Self::reserve_in(admission, retained_child_bytes)
            .ok_or(SharedMutationErrorV1::Admission)?;
        let value = match clone(self) {
            Ok(value) => value,
            Err(error) => {
                drop(reservation);
                return Err(SharedMutationErrorV1::Clone(error));
            }
        };
        let replacement = reservation
            .try_finish_unpublished(value)
            .map_err(|_| SharedMutationErrorV1::Allocation)?;
        if notify {
            replacement.activate_release_notification();
        }
        *self = replacement;
        self.get_mut().ok_or(SharedMutationErrorV1::Allocation)
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
        match (&this.payload, &other.payload) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
    /// Exclusive construction-time access; fails as soon as a payload is shared.
    pub fn get_mut(&mut self) -> Option<&mut T> {
        self.payload.as_mut().and_then(Arc::get_mut)
    }
}
impl<T, C: SharedAllocationCreditV1> SharedAllocationV1<T, C> {
    /// Transfer an original provider admission; this never creates a new pool.
    pub fn from_admission(
        allocation: C,
        retained_child_bytes: usize,
    ) -> Option<SharedAllocationReservationV1<T, C>> {
        if allocation.bytes() < Self::required_bytes(retained_child_bytes)? {
            return None;
        }
        Some(SharedAllocationReservationV1 {
            allocation,
            marker: core::marker::PhantomData,
        })
    }
    /// Called only after the original owner publishes actual retained work.
    pub fn activate_release_notification(&self) {
        if let Some(credit) = &self.credit {
            credit.activate_release_notification();
        }
    }
}
impl<T, C: SharedAllocationCreditV1> SharedAllocationReservationV1<T, C> {
    pub fn finish(self, value: T) -> SharedAllocationV1<T, C> {
        let value = self.finish_unpublished(value);
        value.activate_release_notification();
        value
    }
    /// Fallibly allocate both admitted Arc containers, then publish the credit.
    /// The caller must separately own every child allocation of `value`.
    /// # Errors
    /// Returns allocator refusal after destroying the value and rolling back credit.
    #[cfg(feature = "fallible-allocation-v1")]
    pub fn try_finish(self, value: T) -> Result<SharedAllocationV1<T, C>, core::alloc::AllocError> {
        let value = self.try_finish_unpublished(value)?;
        value.activate_release_notification();
        Ok(value)
    }
    /// Fallible silent construction; no raw Arc or Weak can escape.
    /// Allocate the credit container unarmed, so allocation failure never drops
    /// the lease before the caller's payload or a retained container is freed.
    /// # Errors
    /// Refuses either real allocator request and refunds the original admission.
    #[cfg(feature = "fallible-allocation-v1")]
    pub fn try_finish_unpublished(
        self,
        value: T,
    ) -> Result<SharedAllocationV1<T, C>, core::alloc::AllocError> {
        let mut credit = match Arc::<C>::try_new_uninit() {
            Ok(credit) => credit,
            Err(error) => {
                drop(value);
                drop(self);
                return Err(error);
            }
        };
        let payload = match Arc::try_new(value) {
            Ok(payload) => payload,
            Err(error) => {
                // The failed Arc request already destroyed `value`. Release
                // uninitialized container backing before the still-owned lease.
                let _ = Arc::into_inner(credit);
                drop(self);
                return Err(error);
            }
        };
        Arc::get_mut(&mut credit)
            .expect("fresh unaliased credit")
            .write(self.allocation);
        // SAFETY: this locally unique Arc was just fully initialized. Neither
        // raw/Weak aliases nor uninitialized credit ever leave this function.
        let credit = unsafe { credit.assume_init() };
        Ok(SharedAllocationV1 {
            payload: Some(payload),
            credit: Some(credit),
        })
    }
    /// Keep rollback silent until the actual owning route publishes this value.
    pub fn finish_unpublished(self, value: T) -> SharedAllocationV1<T, C> {
        let payload = Arc::new(value);
        let credit = Arc::new(self.allocation);
        SharedAllocationV1 {
            payload: Some(payload),
            credit: Some(credit),
        }
    }
}
impl<T, C> Clone for SharedAllocationV1<T, C> {
    fn clone(&self) -> Self {
        Self {
            payload: self.payload.clone(),
            credit: self.credit.clone(),
        }
    }
}
impl<T, C> core::ops::Deref for SharedAllocationV1<T, C> {
    type Target = T;
    fn deref(&self) -> &T {
        self.payload.as_deref().expect("live shared payload")
    }
}
impl<T, C> Drop for SharedAllocationV1<T, C> {
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
    ordered_map::check();
    mandatory::check();
    #[cfg(feature = "std")]
    growth::check();
    #[cfg(all(feature = "std", feature = "allocation-fault-fixture"))]
    fault::check();
    assert_eq!(bounded_vec_capacity(0, 3), None);
    assert_eq!(bounded_vec_capacity(2, 3), Some(2));
    assert_eq!(bounded_vec_capacity(3, 3), Some(3));
    assert_eq!(bounded_vec_capacity(4, 3), None);
    assert_eq!(bounded_vec_capacity(usize::MAX, usize::MAX), None);
    struct ObservedDrop {
        pool: Arc<AllocationPoolV1>,
        expected: usize,
        dropped: Arc<AtomicBool>,
    }
    impl Drop for ObservedDrop {
        fn drop(&mut self) {
            assert_eq!(
                self.pool.used(),
                self.expected,
                "payload dies while full credit is held"
            );
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
    let original = reservation.finish(ObservedDrop {
        pool: shared_pool.clone(),
        expected: bytes,
        dropped: dropped.clone(),
    });
    let alias = original.clone();
    drop(original);
    assert!(!dropped.load(Ordering::Acquire));
    assert_eq!(
        shared_pool.used(),
        bytes,
        "cloning retains one actual allocation charge"
    );
    drop(alias);
    assert!(dropped.load(Ordering::Acquire));
    assert_eq!(shared_pool.used(), 0);
    static RELEASED: AtomicUsize = AtomicUsize::new(0);
    fn released() {
        RELEASED.fetch_add(1, Ordering::AcqRel);
    }
    // A second real credit owner preserves silent rollback and exact alias lifetime.
    struct LocalCredit {
        lease: AllocationLeaseV1,
        _layout: [u8; 17],
    }
    impl SharedAllocationCreditV1 for LocalCredit {
        fn bytes(&self) -> usize {
            self.lease.bytes()
        }
        fn activate_release_notification(&self) {
            self.lease.activate_release_notification();
        }
    }
    let local_bytes = SharedAllocationV1::<ObservedDrop, LocalCredit>::required_bytes(0).unwrap();
    let local_pool = AllocationPoolV1::new_with_release(local_bytes, Some(released)).unwrap();
    let local_releases = RELEASED.load(Ordering::Acquire);
    let make = || {
        SharedAllocationV1::<ObservedDrop, LocalCredit>::from_admission(
            LocalCredit {
                lease: local_pool.reserve_unpublished(local_bytes).unwrap(),
                _layout: [0; 17],
            },
            0,
        )
        .unwrap()
        .finish_unpublished(ObservedDrop {
            pool: local_pool.clone(),
            expected: local_bytes,
            dropped: Arc::new(AtomicBool::new(false)),
        })
    };
    drop(make());
    assert_eq!(local_pool.used(), 0);
    assert_eq!(
        RELEASED.load(Ordering::Acquire),
        local_releases,
        "unpublished rollback stays silent"
    );
    let mut local = make();
    assert!(local.get_mut().is_some());
    let alias = local.clone();
    assert!(SharedAllocationV1::ptr_eq(&local, &alias));
    assert!(local.get_mut().is_none());
    assert_eq!(
        local_pool.used(),
        local_bytes,
        "custom owner aliases do not allocate"
    );
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
    assert_eq!(pool.gross_reserved_bytes(), Some(0));
    assert!(pool.reserve(0).is_none());
    let first = Arc::new(pool.reserve(7).unwrap());
    let alias = first.clone();
    let second = pool.reserve(2).unwrap();
    assert_eq!(pool.used(), 9);
    assert_eq!(pool.gross_reserved_bytes(), Some(9));
    assert!(pool.reserve(1).is_none());
    assert_eq!(pool.gross_reserved_bytes(), Some(9));
    drop(first);
    assert_eq!(pool.used(), 9);
    drop(second);
    assert_eq!(pool.used(), 7);
    assert!(alias.covers(&pool, 7));
    assert!(!alias.covers(&AllocationPoolV1::new(9).unwrap(), 7));
    drop(alias);
    assert_eq!(pool.used(), 0);
    assert_eq!(pool.gross_reserved_bytes(), Some(9));
    drop(pool.reserve_unpublished(7).unwrap());
    assert_eq!(pool.used(), 0);
    assert_eq!(pool.gross_reserved_bytes(), Some(16));
    let full = AllocationPoolV1::new(usize::MAX).unwrap();
    let held = full.reserve(usize::MAX).unwrap();
    assert!(full.reserve(1).is_none());
    drop(held);
    assert_eq!(full.used(), 0);
    assert_eq!(full.gross_reserved_bytes(), None);
    drop(full.reserve(1).unwrap());
    assert_eq!(full.gross_reserved_bytes(), None);
}

// The SDK ABI exists only in the explicitly selected, source-verified sysroot.
#[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
mod escrow;
#[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
pub use escrow::LoanAllocator;
