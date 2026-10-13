//! One SDK-heap-rooted admission owner shared by adopter and Mini buffers.
//! It bounds registered allocations, not all allocator/runtime use or EPC.
use enclave_os_common::allocation::{AllocationLeaseV1, AllocationPoolV1};
use std::sync::{Arc, OnceLock};
static POOL: OnceLock<Option<Arc<AllocationPoolV1>>> = OnceLock::new();
static RELEASED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
fn released() {
    RELEASED.store(true, std::sync::atomic::Ordering::Release);
    crate::notify_honest_stream_ingress();
    crate::notify_deferred_ingress();
}
/// Drain an actual credit release event, never free bytes or owner authority.
pub fn take_local_allocation_release() -> bool {
    RELEASED.swap(false, std::sync::atomic::Ordering::AcqRel)
}
/// Actual immutable SDK heap capacity; caller policies may select tighter caps.
/// This does not fabricate memory for the semantic Wasm1TiB profile.
pub fn local_allocation_pool() -> Option<Arc<AllocationPoolV1>> {
    POOL.get_or_init(|| {
        AllocationPoolV1::new_with_release(crate::enclave_heap_bytes(), Some(released))
    })
    .clone()
}
/// Reservation must remain owned until the actual allocation and last alias die.
pub fn reserve_local_allocation(bytes: usize) -> Option<AllocationLeaseV1> {
    local_allocation_pool()?.reserve(bytes)
}

#[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
pub use enclave_os_common::allocation::LoanAllocator;
