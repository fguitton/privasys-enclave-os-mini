//! Explicit prepaid allocation loans for the verified opt-in SDK ABI.
//! The caller moves its original physical credit here. This is not a global
//! allocator and grants no caller, source, signing or publication authority.
use super::{AllocationLeaseV1, AllocationPoolV1, SharedAllocationV1};
use alloc::sync::Arc;
use core::{
    alloc::{AllocError, Allocator, Layout},
    mem::ManuallyDrop,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::alloc::{AllocationTicket, FallibleAllocationHooks, FallibleSystem};
enum Budget {
    Reserved(AllocationLeaseV1),
    Pool(Arc<AllocationPoolV1>),
}
struct LoanState {
    budget: Budget,
    used: AtomicUsize,
    peak: AtomicUsize,
    published: AtomicBool,
}
type Loan = SharedAllocationV1<LoanState>;
static HOOKS: FallibleAllocationHooks = FallibleAllocationHooks {
    admit,
    release,
    cancel,
};
static OWNERSHIP: std::alloc::OriginOperations = std::alloc::OriginOperations {
    retain: retain_origin,
    release: release_origin,
};
static OPERATIONS: std::alloc::AllocationOperations = std::alloc::AllocationOperations {
    allocate: allocate_owned,
    deallocate: deallocate_owned,
    resize: resize_owned,
};
fn borrow(ticket: AllocationTicket) -> ManuallyDrop<Loan> {
    // SAFETY: the private safe allocator holds the original pair; every issued
    // header keeps another exact pair until backend free. This borrow never
    // decrements those refs and is not exposed as a user-manufacturable owner.
    ManuallyDrop::new(unsafe {
        Loan::from_owned_raw_pair(RawSharedTicket {
            payload: ticket.owner,
            credit: ticket.loan,
        })
    })
}
fn admit(origin: AllocationTicket, layout: Layout) -> Result<AllocationTicket, AllocError> {
    let loan = borrow(origin);
    let used = match &loan.budget {
        Budget::Reserved(lease) => loan
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(layout.size())
                    .filter(|next| *next <= lease.bytes())
            })
            .map_err(|_| AllocError)?
            .checked_add(layout.size())
            .ok_or(AllocError)?,
        Budget::Pool(pool) => {
            pool.reserve_backend_bytes(layout.size())
                .ok_or(AllocError)?;
            loan.used.fetch_add(layout.size(), Ordering::AcqRel) + layout.size()
        }
    };
    loan.peak.fetch_max(used, Ordering::AcqRel);
    let ticket = loan.retain_raw_pair();
    Ok(AllocationTicket {
        owner: ticket.payload,
        loan: ticket.credit,
    })
}
fn release(ticket: AllocationTicket, layout: Layout) {
    refund(ticket, layout, true);
}
fn cancel(ticket: AllocationTicket, layout: Layout) {
    refund(ticket, layout, false);
}
fn refund(ticket: AllocationTicket, layout: Layout, backend_freed: bool) {
    let loan = unsafe {
        Loan::from_owned_raw_pair(RawSharedTicket {
            payload: ticket.owner,
            credit: ticket.loan,
        })
    };
    loan.used.fetch_sub(layout.size(), Ordering::AcqRel);
    if let Budget::Pool(pool) = &loan.budget {
        pool.release_backend_bytes(
            layout.size(),
            backend_freed && loan.published.load(Ordering::Acquire),
        );
    }
    drop(loan);
}
fn retain_origin(ticket: AllocationTicket) -> AllocationTicket {
    let loan = borrow(ticket);
    let pair = loan.retain_raw_pair();
    AllocationTicket {
        owner: pair.payload,
        loan: pair.credit,
    }
}
fn release_origin(ticket: AllocationTicket) {
    drop(unsafe {
        Loan::from_owned_raw_pair(RawSharedTicket {
            payload: ticket.owner,
            credit: ticket.loan,
        })
    });
}
fn allocate_owned(
    ticket: AllocationTicket,
    layout: Layout,
    zero: bool,
) -> Result<NonNull<[u8]>, ()> {
    let system = unsafe { FallibleSystem::new(&HOOKS, ticket) };
    if zero {
        system.allocate_zeroed(layout)
    } else {
        system.allocate(layout)
    }
    .map_err(|_| ())
}
unsafe fn deallocate_owned(ticket: AllocationTicket, pointer: NonNull<u8>, layout: Layout) {
    unsafe {
        FallibleSystem::new(&HOOKS, ticket).deallocate(pointer, layout);
    }
}
unsafe fn resize_owned(
    ticket: AllocationTicket,
    pointer: NonNull<u8>,
    old: Layout,
    new: Layout,
    zero: bool,
) -> Result<NonNull<[u8]>, ()> {
    let system = unsafe { FallibleSystem::new(&HOOKS, ticket) };
    unsafe {
        if new.size() < old.size() {
            system.shrink(pointer, old, new)
        } else if zero {
            system.grow_zeroed(pointer, old, new)
        } else {
            system.grow(pointer, old, new)
        }
    }
    .map_err(|_| ())
}
#[derive(Clone)]
pub struct LoanAllocator {
    system: FallibleSystem,
    owner: Loan,
}
impl LoanAllocator {
    /// Complete physical backend quote from the same SDK allocator owner.
    /// # Errors
    /// Refuses header/alignment layout arithmetic overflow.
    pub fn required_backend_bytes(layout: Layout) -> Result<usize, AllocError> {
        FallibleSystem::requested_backend_layout(layout).map(|layout| layout.size())
    }
    /// Move original physical credit into a loan with separately paid metadata.
    ///
    /// # Errors
    /// Refuses a foreign pool, insufficient metadata admission, or allocation
    /// failure. No child storage or original credit escapes on refusal.
    pub fn from_original_lease(
        pool: &Arc<AllocationPoolV1>,
        lease: AllocationLeaseV1,
    ) -> Result<Self, AllocError> {
        if !lease.covers(pool, lease.bytes()) {
            return Err(AllocError);
        }
        let allocator = Self::from_budget(pool, Budget::Reserved(lease))?;
        allocator.activate_release_notification();
        Ok(allocator)
    }
    fn from_budget(pool: &Arc<AllocationPoolV1>, budget: Budget) -> Result<Self, AllocError> {
        let reservation = SharedAllocationV1::<LoanState>::reserve(pool, 0).ok_or(AllocError)?;
        let owner = reservation.try_finish_unpublished(LoanState {
            budget,
            used: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            published: AtomicBool::new(false),
        })?;
        let ticket = owner.retain_raw_pair();
        let origin = AllocationTicket {
            owner: ticket.payload,
            loan: ticket.credit,
        };
        drop(unsafe { Loan::from_owned_raw_pair(ticket) });
        let system = unsafe { FallibleSystem::new(&HOOKS, origin) };
        Ok(Self { system, owner })
    }
    /// Admit each actual SDK backend layout from the original immutable pool.
    /// No guessed worker capacity, global allocator or semantic authority.
    /// # Errors
    /// Refuses origin metadata admission/allocation before exposing any origin.
    pub fn from_pool_unpublished(pool: &Arc<AllocationPoolV1>) -> Result<Self, AllocError> {
        Self::from_budget(pool, Budget::Pool(pool.clone()))
    }
    /// Actual separately paid origin metadata, before any child backend exists.
    pub fn required_origin_bytes() -> Option<usize> {
        SharedAllocationV1::<LoanState>::required_bytes(0)
    }
    /// Publish only after the owning SDK factory succeeds. Failed construction
    /// releases physical bytes without rearming a resource waiter.
    pub fn activate_release_notification(&self) {
        self.owner.published.store(true, Ordering::Release);
        self.owner.activate_release_notification();
    }
    /// Retained typed SDK allocator. Every callback and backing header keeps
    /// this same original paired origin independently of this wrapper's Drop.
    pub fn owned_allocator(&self) -> std::alloc::OwnedAllocator {
        let pair = self.owner.retain_raw_pair();
        unsafe {
            std::alloc::OwnedAllocator::from_retained_origin(
                AllocationTicket {
                    owner: pair.payload,
                    loan: pair.credit,
                },
                &OPERATIONS,
                &OWNERSHIP,
            )
        }
    }
    /// Measured peak of actual admitted backend layouts, excluding origin metadata.
    pub fn peak_used(&self) -> usize {
        self.owner.peak.load(Ordering::Acquire)
    }
    /// Exact C payload plus SDK side-record backing, with no pointer prefix.
    /// # Errors
    /// Refuses zero-size or overflowing layouts before original-pool admission.
    pub fn required_c_backend_bytes(layout: Layout) -> Result<usize, std::alloc::CAllocationError> {
        std::alloc::FallibleCSystem::requested_layout(layout).map(|layout| layout.size())
    }
    /// Allocate a move-only C-compatible owner from this original prepaid loan.
    /// Each SDK record retains its exact loan pair across thread/allocator Drop.
    /// # Errors
    /// Refuses budget, backend allocation, generation exhaustion or lock contention.
    pub fn allocate_c_owned(
        &self,
        layout: Layout,
        zero: bool,
        wake: fn(),
    ) -> Result<LoanCAllocation, std::alloc::CAllocationError> {
        let raw = self.owner.retain_raw_pair();
        let origin = AllocationTicket {
            owner: raw.payload,
            loan: raw.credit,
        };
        // Return only the temporary pair. The safe allocator still owns the
        // original identity while SDK admission issues each retained ticket.
        drop(unsafe { Loan::from_owned_raw_pair(raw) });
        let allocator = unsafe { std::alloc::FallibleCSystem::new(&HOOKS, origin) };
        allocator
            .allocate_owned(layout, zero, wake)
            .map(|allocation| LoanCAllocation {
                allocation,
                bytes: layout.size(),
                initialized: zero,
            })
    }
    /// Backend bytes currently lent, including SDK header/alignment.
    #[must_use]
    pub fn used(&self) -> usize {
        self.owner.used.load(Ordering::Acquire)
    }
}
/// Move-only initialized-byte access over the original SDK-owned C record.
/// No raw handle, allocation owner or credit can be cloned independently.
pub struct LoanCAllocation {
    allocation: std::alloc::OwnedCAllocation,
    bytes: usize,
    initialized: bool,
}
impl LoanCAllocation {
    /// Initialize every admitted byte without reading an uninitialized payload.
    pub fn fill(&mut self, byte: u8) {
        // SAFETY: the exact length was captured from successful SDK allocation;
        // this exclusive move-only owner has not been resized or released.
        unsafe {
            self.allocation.as_ptr().write_bytes(byte, self.bytes);
        }
        self.initialized = true;
    }
    /// Borrow only fully initialized bytes while the original owner remains live.
    pub fn bytes(&self) -> Option<&[u8]> {
        if !self.initialized {
            return None;
        }
        // SAFETY: initialization and extent are tracked by the only owning API;
        // shared borrowing excludes resize and the owner's final Drop.
        Some(unsafe { core::slice::from_raw_parts(self.allocation.as_ptr(), self.bytes) })
    }
    /// A failed resize leaves the original extent and initialization unchanged.
    /// # Errors
    /// Propagates original SDK admission, layout and contention refusal.
    pub fn resize(
        &mut self,
        layout: Layout,
        zero: bool,
    ) -> Result<(), std::alloc::CAllocationError> {
        let initialized = self.initialized && (layout.size() <= self.bytes || zero);
        self.allocation.resize(layout, zero)?;
        self.bytes = layout.size();
        self.initialized = initialized;
        Ok(())
    }
}

unsafe impl Allocator for LoanAllocator {
    fn allocate(&self, l: Layout) -> Result<NonNull<[u8]>, AllocError> {
        self.system.allocate(l)
    }
    fn allocate_zeroed(&self, l: Layout) -> Result<NonNull<[u8]>, AllocError> {
        self.system.allocate_zeroed(l)
    }
    unsafe fn deallocate(&self, p: NonNull<u8>, l: Layout) {
        unsafe { self.system.deallocate(p, l) }
    }
    unsafe fn grow(
        &self,
        p: NonNull<u8>,
        o: Layout,
        n: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        unsafe { self.system.grow(p, o, n) }
    }
    unsafe fn grow_zeroed(
        &self,
        p: NonNull<u8>,
        o: Layout,
        n: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        unsafe { self.system.grow_zeroed(p, o, n) }
    }
    unsafe fn shrink(
        &self,
        p: NonNull<u8>,
        o: Layout,
        n: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        unsafe { self.system.shrink(p, o, n) }
    }
}

#[repr(C)]
struct RawSharedTicket {
    payload: usize,
    credit: usize,
}
impl<T, C> SharedAllocationV1<T, C> {
    /// Transfer one additional exact paired strong ownership to a private
    /// allocator header; no raw Weak and no independent payload owner escapes.
    fn retain_raw_pair(&self) -> RawSharedTicket {
        RawSharedTicket {
            payload: Arc::into_raw(self.payload.as_ref().unwrap().clone()) as usize,
            credit: Arc::into_raw(self.credit.as_ref().unwrap().clone()) as usize,
        }
    }
    /// # Safety
    /// Exactly one live retain_raw_pair ticket of this T/C must be consumed;
    /// no unrelated/raw/duplicated pointer or reconstructed weak is admitted.
    unsafe fn from_owned_raw_pair(ticket: RawSharedTicket) -> Self {
        Self {
            payload: Some(unsafe { Arc::from_raw(ticket.payload as *const T) }),
            credit: Some(unsafe { Arc::from_raw(ticket.credit as *const C) }),
        }
    }
}
