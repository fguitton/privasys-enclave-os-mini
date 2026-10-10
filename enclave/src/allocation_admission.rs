//! One SDK-heap-rooted admission owner shared by adopter and Mini buffers.
//! It bounds registered allocations, not all allocator/runtime use or EPC.
use enclave_os_common::allocation::{AllocationPoolV1,AllocationLeaseV1};
use std::sync::{Arc,OnceLock};
static POOL:OnceLock<Option<Arc<AllocationPoolV1>>>=OnceLock::new();
/// Actual immutable SDK heap capacity; caller policies may select tighter caps.
/// This does not fabricate memory for the semantic Wasm1TiB profile.
pub fn local_allocation_pool()->Option<Arc<AllocationPoolV1>> {
    POOL.get_or_init(||AllocationPoolV1::new(crate::enclave_heap_bytes())).clone()
}
/// Reservation must remain owned until the actual allocation and last alias die.
pub fn reserve_local_allocation(bytes:usize)->Option<AllocationLeaseV1>{
    local_allocation_pool()?.reserve(bytes)
}
