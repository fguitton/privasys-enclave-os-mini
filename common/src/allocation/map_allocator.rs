//! Physically fallible node backing from one original pool.
use super::{AdmissionV1, AllocationLeaseV1, AllocationPoolV1, SharedAllocationV1};
use alloc::sync::Arc;
use core::{
    alloc::{AllocError, Allocator, Layout},
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};
use std::alloc::System;

struct Origin {
    admission: AdmissionV1,
    published: AtomicBool,
}

/// Allocator for a retained map. Each node owns its exact backend lease.
/// Clone retains the same origin; it never clones tree nodes or reserves bytes.
#[derive(Clone)]
pub struct PoolMapAllocator {
    origin: SharedAllocationV1<Origin>,
}

#[repr(C)]
struct Header {
    lease: AllocationLeaseV1,
}

impl PoolMapAllocator {
    /// Exact fixed metadata backing for the original pool owner.
    /// # Errors
    /// Refuses unsupported Arc geometry or byte-count overflow.
    pub fn required_metadata_bytes() -> Result<usize, AllocError> {
        SharedAllocationV1::<Origin>::required_bytes(0).ok_or(AllocError)
    }

    /// Admit both origin Arc layouts before creating an empty map allocator.
    /// # Errors
    /// Refuses metadata admission or actual Arc allocation without publishing.
    pub fn try_new(pool: &Arc<AllocationPoolV1>) -> Result<Self, AllocError> {
        Self::try_new_in(&AdmissionV1::Ordinary(pool.clone()))
    }

    /// As [`Self::try_new`], with the origin and every node admitted through
    /// `admission`: a mandatory token's credit while it lives.
    /// # Errors
    /// Refuses metadata admission or actual Arc allocation without publishing.
    pub fn try_new_in(admission: &AdmissionV1) -> Result<Self, AllocError> {
        let reservation = SharedAllocationV1::reserve_in(admission, 0).ok_or(AllocError)?;
        let origin = reservation.try_finish_unpublished(Origin {
            admission: admission.clone(),
            published: AtomicBool::new(false),
        })?;
        Ok(Self { origin })
    }

    /// Publish only after the owning map and all its backing are installed.
    pub fn activate_release_notification(&self) {
        self.origin.published.store(true, Ordering::Release);
        self.origin.activate_release_notification();
    }

    /// Current publication disposition of this same original allocator origin.
    /// Independent metadata admissions use it only after their backing is freed.
    #[must_use]
    pub fn release_notification_active(&self) -> bool {
        self.origin.published.load(Ordering::Acquire)
    }

    /// Exact requested backend layout, including lease and alignment padding.
    /// # Errors
    /// Refuses header-plus-node geometry overflow before admission/allocation.
    pub fn backend_layout(node: Layout) -> Result<Layout, AllocError> {
        Self::geometry(node).map(|(layout, _)| layout)
    }

    fn geometry(node: Layout) -> Result<(Layout, usize), AllocError> {
        Layout::new::<Header>()
            .extend(node)
            .map(|(layout, offset)| (layout.pad_to_align(), offset))
            .map_err(|_| AllocError)
    }
}

// SAFETY: allocations admit and retain the exact original-pool backend layout.
// The returned region has the requested alignment and size. Only its owning
// map can free it; all allocator aliases retain the same immutable origin.
unsafe impl Allocator for PoolMapAllocator {
    fn allocate(&self, node: Layout) -> Result<NonNull<[u8]>, AllocError> {
        if node.size() == 0 {
            let pointer = NonNull::new(node.align() as *mut u8).ok_or(AllocError)?;
            return Ok(NonNull::slice_from_raw_parts(pointer, 0));
        }
        let (backend, offset) = Self::geometry(node)?;
        let lease = self
            .origin
            .admission
            .reserve_unpublished(backend.size())
            .ok_or(AllocError)?;
        let allocation = System.allocate(backend)?;
        let base = allocation.cast::<u8>();
        // SAFETY: backend includes the aligned Header and requested node region.
        unsafe {
            base.cast::<Header>().as_ptr().write(Header { lease });
        }
        // SAFETY: checked Layout::extend placed this in the allocated region.
        let pointer = unsafe { NonNull::new_unchecked(base.as_ptr().add(offset)) };
        Ok(NonNull::slice_from_raw_parts(pointer, node.size()))
    }

    unsafe fn deallocate(&self, pointer: NonNull<u8>, node: Layout) {
        if node.size() == 0 {
            return;
        }
        let (backend, offset) = Self::geometry(node).expect("original valid map layout");
        // SAFETY: Allocator caller provides the same live pointer/layout issued
        // here; checked offset addresses its exclusively owned original header.
        let base = unsafe { NonNull::new_unchecked(pointer.as_ptr().sub(offset)) };
        let Header { lease } = unsafe { base.cast::<Header>().as_ptr().read() };
        // SAFETY: exact backend allocation is freed before any credit is released.
        unsafe {
            System.deallocate(base, backend);
        }
        if self.origin.published.load(Ordering::Acquire) {
            lease.activate_release_notification();
        }
        drop(lease);
    }
}
