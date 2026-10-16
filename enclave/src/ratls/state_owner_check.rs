//! Current state slot factory and consuming carrier ownership checks.
//! Structural probes claim no TLS keys or protocol authority; Session separately
//! checks the actual traffic-state allocation across repeated encrypted records.
use super::client_hello_owner_check::{without_global, Original};
use enclave_os_common::allocation::AllocationPoolV1;
use rustls::internal::state::{Counters, SlotProbe};
use std::alloc::Layout;
use std::sync::Arc;

fn metadata_bytes() -> usize {
    #[cfg(target_vendor = "teaclave")]
    {
        enclave_os_common::allocation::LoanAllocator::required_origin_bytes().unwrap()
    }
    #[cfg(not(target_vendor = "teaclave"))]
    {
        enclave_os_common::allocation::PoolMapAllocator::required_metadata_bytes().unwrap()
    }
}
fn backend_bytes(layout: Layout) -> usize {
    #[cfg(target_vendor = "teaclave")]
    {
        enclave_os_common::allocation::LoanAllocator::required_backend_bytes(layout).unwrap()
    }
    #[cfg(not(target_vendor = "teaclave"))]
    {
        enclave_os_common::allocation::PoolMapAllocator::backend_layout(layout)
            .unwrap()
            .size()
    }
}
fn refused<T>(result: Result<T, rustls::Error>) {
    assert!(matches!(result, Err(rustls::Error::AllocationFailed)));
}
pub(super) fn check() {
    let layout = SlotProbe::<Original>::layout();
    let backend = backend_bytes(layout);
    let metadata = metadata_bytes();
    for delta in [-1_isize, 0, 1] {
        let capacity = metadata
            .checked_add(backend)
            .unwrap()
            .checked_add_signed(delta)
            .unwrap();
        let pool = AllocationPoolV1::new(capacity).unwrap();
        let origin = Original::new(&pool);
        assert_eq!(pool.used(), metadata);
        let counters = Arc::new(Counters::default());
        origin.arm(None);
        let result = without_global(|| SlotProbe::try_new_in(origin.clone(), &counters));
        if delta < 0 {
            refused(result);
            assert_eq!(
                counters.normalized(),
                0,
                "refusal must precede owned normalization"
            );
            assert_eq!(counters.dropped(), 1);
            assert_eq!(origin.backend_bytes(), 0);
            assert_eq!(pool.used(), metadata);
        } else {
            let mut slot = result.unwrap();
            assert_eq!(counters.normalized(), 1);
            assert_eq!(counters.dropped(), 0);
            let address = slot.allocation();
            assert_eq!(address.1, layout);
            assert_eq!(origin.backend_bytes(), backend);
            assert_eq!(pool.used(), metadata + backend);
            origin.arm(Some(0));
            for _ in 0..32 {
                slot = without_global(|| slot.stay()).unwrap();
                assert_eq!(slot.allocation(), address);
                assert_eq!(origin.requests(), 0, "Stay must request no new slot");
                assert_eq!(counters.dropped(), 0);
            }
            assert!(matches!(
                without_global(|| slot.fail()),
                Err(rustls::Error::HandshakeNotComplete)
            ));
            assert_eq!(
                counters.dropped(),
                1,
                "consumed concrete value drops once on error"
            );
            assert_eq!(origin.backend_bytes(), 0);
            assert_eq!(pool.used(), metadata);
        }
        drop(origin);
        assert_eq!(pool.used(), 0);
    }
    let pool = AllocationPoolV1::new(metadata + backend).unwrap();
    let origin = Original::new(&pool);
    let counters = Arc::new(Counters::default());
    origin.arm(Some(0));
    refused(without_global(|| {
        SlotProbe::try_new_in(origin.clone(), &counters)
    }));
    assert_eq!(origin.requests(), 1);
    assert_eq!(counters.normalized(), 0);
    assert_eq!(counters.dropped(), 1);
    assert_eq!(pool.used(), metadata);
    origin.arm(None);
    let slot = without_global(|| SlotProbe::try_new_in(origin.clone(), &counters)).unwrap();
    let alias = origin.clone();
    drop(origin);
    assert_eq!(pool.used(), metadata + backend);
    drop(slot);
    assert_eq!(pool.used(), metadata);
    drop(alias);
    assert_eq!(pool.used(), 0);
    check_erased();
}
fn erased(
    allocator: rustls::RetainedAllocator,
    counters: &Arc<Counters>,
) -> rustls::internal::state::RetainedProbe {
    #[cfg(target_vendor = "teaclave")]
    let slot_allocator = allocator.clone();
    #[cfg(not(target_vendor = "teaclave"))]
    let slot_allocator = allocator;
    SlotProbe::try_new_in(slot_allocator, counters)
        .unwrap()
        .into_retained(allocator)
}
#[cfg(not(target_vendor = "teaclave"))]
fn check_erased() {
    // Native erased carrier has the explicit Global capability. Original-pool
    // factory failure and normalization are proven separately above.
    let counters = Arc::new(Counters::default());
    let mut state = erased(std::alloc::Global, &counters);
    let before = state.allocation();
    for _ in 0..32 {
        state = state.stay().unwrap();
        assert_eq!(state.allocation(), before);
    }
    let next = state.next().unwrap();
    assert_ne!(next.allocation().0, before.0);
    assert_eq!(next.allocation().1, before.1);
    assert_eq!(counters.dropped(), 1);
    let before = next.allocation();
    let next = next.into_external().unwrap();
    assert_eq!(next.allocation(), before);
    assert!(matches!(
        next.fail(),
        Err(rustls::Error::HandshakeNotComplete)
    ));
    assert_eq!(counters.dropped(), 2);
}
#[cfg(target_vendor = "teaclave")]
fn check_erased() {
    use enclave_os_common::allocation::LoanAllocator;
    let metadata = LoanAllocator::required_origin_bytes().unwrap();
    let layout = SlotProbe::<rustls::RetainedAllocator>::layout();
    let backend = LoanAllocator::required_backend_bytes(layout).unwrap();
    for delta in [-1_isize, 0, 1] {
        let capacity = metadata
            .checked_add(backend.checked_mul(2).unwrap())
            .unwrap()
            .checked_add_signed(delta)
            .unwrap();
        let pool = AllocationPoolV1::new(capacity).unwrap();
        let origin = LoanAllocator::from_pool_unpublished(&pool).unwrap();
        let allocator = origin.owned_allocator();
        let counters = Arc::new(Counters::default());
        let mut state = erased(allocator.clone(), &counters);
        let before = state.allocation();
        for _ in 0..32 {
            state = state.stay().unwrap();
            assert_eq!(state.allocation(), before);
            assert_eq!(pool.used(), metadata + backend);
        }
        let next = state.next();
        if delta < 0 {
            refused(next);
            assert_eq!(
                counters.dropped(),
                2,
                "refused next input and consumed prior state drop once"
            );
            assert_eq!(pool.used(), metadata);
        } else {
            let next = next.unwrap();
            assert_ne!(next.allocation().0, before.0);
            assert_eq!(next.allocation().1, layout);
            assert_eq!(counters.dropped(), 1);
            assert_eq!(pool.used(), metadata + backend);
            let before = next.allocation();
            let next = next.into_external().unwrap();
            assert_eq!(next.allocation(), before);
            drop(origin);
            assert_eq!(pool.used(), metadata + backend);
            assert!(matches!(
                next.fail(),
                Err(rustls::Error::HandshakeNotComplete)
            ));
            assert_eq!(counters.dropped(), 2);
            assert_eq!(pool.used(), metadata);
            drop(allocator);
            assert_eq!(pool.used(), 0);
            continue;
        }
        drop(allocator);
        drop(origin);
        assert_eq!(pool.used(), 0);
    }
}
