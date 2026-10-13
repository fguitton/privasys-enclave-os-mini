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

/// Install measured-TCS waiter storage before configuration, TLS or workers.
/// The admitted allocator and backing remain owned for the enclave process.
/// # Errors
/// Refuses physical admission, layout/allocator failure, or any legacy futex use.
#[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
pub fn initialize_fixed_futex_storage() -> Result<(), &'static str> {
    static ADMISSION: OnceLock<LoanAllocator> = OnceLock::new();
    let layout = std::sync::fixed_futex_layout().map_err(|_| "futex layout refused")?;
    let bytes = LoanAllocator::required_backend_bytes(layout).map_err(|_| "futex backend quote refused")?;
    let pool = local_allocation_pool().ok_or("futex physical pool unavailable")?;
    if ADMISSION.get().is_none() {
        let credit = pool.reserve_unpublished(bytes).ok_or("futex physical admission refused")?;
        let allocator = LoanAllocator::from_original_lease(&pool, credit).map_err(|_| "futex allocator metadata refused")?;
        ADMISSION.set(allocator).map_err(|_| "futex startup already in progress")?;
    }
    // A failed install ends this process's initialization; no live backend can
    // be replaced and no acquired budget is reset to mask prior legacy use.
    std::sync::initialize_fixed_futex(ADMISSION.get().ok_or("futex allocator absent")?)
        .map_err(|_| "futex backend already used or storage refused")
}

/// Reuse only a completed startup installation on later ECALLs.
/// No waiter, retry, or backend replacement occurs while startup is in flight.
/// # Errors
/// Refuses concurrent incomplete startup and permanently retains failed startup.
#[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
pub fn initialize_fixed_futex_storage_once() -> Result<(), &'static str> {
    use std::sync::atomic::{AtomicU8, Ordering};
    #[repr(u8)]
    enum Startup { Idle, Installing, Ready, Failed }
    static STARTUP: AtomicU8 = AtomicU8::new(Startup::Idle as u8);
    match STARTUP.compare_exchange(
        Startup::Idle as u8, Startup::Installing as u8,
        Ordering::AcqRel, Ordering::Acquire,
    ) {
        Ok(_) => {
            let result = initialize_fixed_futex_storage();
            let next = if result.is_ok() { Startup::Ready } else { Startup::Failed };
            STARTUP.store(next as u8, Ordering::Release);
            result
        }
        Err(value) if value == Startup::Ready as u8 => Ok(()),
        Err(value) if value == Startup::Installing as u8 => Err("futex startup still in progress"),
        Err(_) => Err("futex startup previously failed"),
    }
}
