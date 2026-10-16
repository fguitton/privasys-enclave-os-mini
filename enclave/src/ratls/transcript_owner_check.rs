//! Existing Session/signed owner's live transcript byte allocation checks.
use super::client_hello_owner_check::{without_global, Original};
use enclave_os_common::allocation::{shared_allocation_bytes, AllocationPoolV1};
use rustls::internal::msgs::handshake::RetainedHandshakeBuffer;
use std::sync::Arc;

fn provider() -> &'static dyn rustls::crypto::hash::Hash {
    rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
        .tls13()
        .unwrap()
        .common
        .hash_provider
}
fn allocation_refused<T>(result: Result<T, rustls::Error>) {
    assert!(matches!(
        result,
        Err(rustls::Error::InvalidMessage(
            rustls::InvalidMessage::AllocationFailed
        ))
    ));
}
fn expected_hash(bytes: &[u8]) -> ring::digest::Digest {
    ring::digest::digest(&ring::digest::SHA256, bytes)
}
fn message_hash(bytes: &[u8]) -> Vec<u8> {
    let digest = expected_hash(bytes);
    // Independent RFC8446 message_hash framing, before any live transition.
    let mut expected = vec![0xfe, 0, 0, u8::try_from(digest.as_ref().len()).unwrap()];
    expected.extend_from_slice(digest.as_ref());
    expected
}
fn with_context_allocation<T>(origin: &Original, action: impl FnOnce() -> T) -> T {
    #[cfg(test)]
    {
        // Obtain the actual dynamic provider Layout outside the measured scope.
        // The native capability is explicitly Global, separate from generic bytes.
        let context = provider().start(origin.context_allocator()).unwrap();
        let layout = context.allocation_layout();
        drop(context);
        crate::ratls::session::retained_tls_config::check_one_native_context(layout, action)
    }
    #[cfg(not(test))]
    {
        let _ = origin;
        action()
    }
}
fn check_buffer(origin: &Original, pool: &Arc<AllocationPoolV1>, metadata: usize) -> usize {
    let bytes = [7; 1024];
    let mut buffer = RetainedHandshakeBuffer::new_in(origin.clone(), origin.context_allocator());
    origin.arm(Some(0));
    allocation_refused(without_global(|| buffer.try_add(&bytes)));
    assert!(buffer.bytes().is_empty());
    assert_eq!(pool.used(), metadata);
    origin.arm(None);
    without_global(|| buffer.try_add(&bytes)).unwrap();
    assert_eq!(buffer.bytes(), bytes);
    let backing = origin.backend_bytes();
    assert_eq!(pool.used(), metadata + backing);
    origin.arm(None);
    let copy = without_global(|| buffer.try_clone()).unwrap();
    let requests = origin.requests();
    assert_eq!(copy.bytes(), buffer.bytes());
    assert_eq!(pool.used(), metadata + origin.backend_bytes());
    drop(copy);
    for refusal in 0..requests {
        origin.arm(Some(refusal));
        allocation_refused(without_global(|| buffer.try_clone()));
        assert_eq!(buffer.bytes(), bytes);
        assert_eq!(origin.backend_bytes(), backing);
        assert_eq!(pool.used(), metadata + backing);
    }
    origin.arm(None);
    drop(buffer);
    assert_eq!(pool.used(), metadata);
    backing
}
fn check_running(
    origin: &Original,
    pool: &Arc<AllocationPoolV1>,
    metadata: usize,
    context_backing: usize,
) {
    let first = [9; 2048];
    let extra = [3; 2048];
    let mut buffer = RetainedHandshakeBuffer::new_in(origin.clone(), origin.context_allocator());
    buffer.retain_client_auth();
    without_global(|| buffer.try_add(&first)).unwrap();
    let mut running = buffer.start_hash(provider()).unwrap();
    let backing = origin.backend_bytes();
    assert_eq!(pool.used(), metadata + backing + context_backing);
    let previous = running.current_hash();
    assert_eq!(previous.as_ref(), expected_hash(&first).as_ref());
    origin.arm(Some(0));
    allocation_refused(without_global(|| running.try_add(&extra)));
    assert_eq!(running.current_hash().as_ref(), previous.as_ref());
    assert_eq!(running.client_auth_bytes().unwrap(), first);
    assert_eq!(pool.used(), metadata + backing + context_backing);
    origin.arm(None);
    without_global(|| running.try_add(&extra)).unwrap();
    let mut all = first.to_vec();
    all.extend_from_slice(&extra);
    assert_eq!(
        running.current_hash().as_ref(),
        expected_hash(&all).as_ref()
    );
    assert_eq!(running.client_auth_bytes().unwrap(), all);
    let original_backing = origin.backend_bytes();
    origin.arm(None);
    let copy = running.try_clone().unwrap();
    let requests = origin.requests();
    assert_eq!(
        copy.current_hash().as_ref(),
        running.current_hash().as_ref()
    );
    assert_eq!(copy.client_auth_bytes(), running.client_auth_bytes());
    drop(copy);
    for refusal in 0..requests {
        origin.arm(Some(refusal));
        allocation_refused(without_global(|| running.try_clone()));
        assert_eq!(
            running.current_hash().as_ref(),
            expected_hash(&all).as_ref()
        );
        assert_eq!(running.client_auth_bytes().unwrap(), all);
        assert_eq!(pool.used(), metadata + original_backing + context_backing);
    }
    origin.arm(None);
    drop(running);
    assert_eq!(pool.used(), metadata);
}
fn check_hrr(
    origin: &Original,
    pool: &Arc<AllocationPoolV1>,
    metadata: usize,
    context_backing: usize,
) {
    let original = [11; 2048];
    let mut buffer = RetainedHandshakeBuffer::new_in(origin.clone(), origin.context_allocator());
    buffer.retain_client_auth();
    without_global(|| buffer.try_add(&original)).unwrap();
    let mut running = buffer.start_hash(provider()).unwrap();
    let before = running.current_hash();
    let backing = origin.backend_bytes();
    assert_eq!(pool.used(), metadata + backing + context_backing);
    let expected = message_hash(&original);
    origin.arm(Some(0));
    allocation_refused(with_context_allocation(origin, || running.try_rollup()));
    assert_eq!(running.current_hash().as_ref(), before.as_ref());
    assert_eq!(running.client_auth_bytes().unwrap(), original);
    assert_eq!(pool.used(), metadata + backing + context_backing);
    origin.arm(None);
    running.try_rollup().unwrap();
    assert_eq!(
        running.current_hash().as_ref(),
        expected_hash(&expected).as_ref()
    );
    let mut retained = original.to_vec();
    retained.extend_from_slice(&expected);
    assert_eq!(running.client_auth_bytes().unwrap(), retained);
    let before_transfer = origin.backend_bytes();
    let copy = running.try_clone().unwrap();
    origin.arm(Some(0));
    allocation_refused(copy.try_into_hrr());
    assert_eq!(origin.backend_bytes(), before_transfer);
    assert_eq!(pool.used(), metadata + before_transfer + context_backing);
    origin.arm(None);
    let expected = message_hash(&expected);
    let hrr = running.try_into_hrr().unwrap();
    assert_eq!(hrr.bytes(), expected);
    assert_eq!(pool.used(), metadata + origin.backend_bytes());
    drop(hrr);
    assert_eq!(pool.used(), metadata);
}
fn check_discard(
    origin: &Original,
    pool: &Arc<AllocationPoolV1>,
    metadata: usize,
    context_backing: usize,
) {
    let mut buffer = RetainedHandshakeBuffer::new_in(origin.clone(), origin.context_allocator());
    without_global(|| buffer.try_add(b"no client authentication")).unwrap();
    let mut running = buffer.start_hash(provider()).unwrap();
    assert_eq!(pool.used(), metadata + context_backing);
    assert!(running.client_auth_bytes().is_none());
    origin.arm(Some(0));
    without_global(|| running.try_add(b"following bytes")).unwrap();
    assert_eq!(origin.requests(), 0);
    assert_eq!(pool.used(), metadata + context_backing);
    origin.arm(None);
    drop(running);
}
fn check_bounds(required: usize) {
    let root = shared_allocation_bytes::<AllocationPoolV1>().unwrap();
    for extra in [-1_isize, 0, 1] {
        let capacity = root
            .checked_add(required)
            .unwrap()
            .checked_add_signed(extra)
            .unwrap();
        let pool = AllocationPoolV1::try_new_with_release(capacity, None).unwrap();
        let origin = Original::new(&pool);
        let metadata = pool.used();
        let mut buffer =
            RetainedHandshakeBuffer::new_in(origin.clone(), origin.context_allocator());
        let result = without_global(|| buffer.try_add(&[7; 1024]));
        if extra < 0 {
            allocation_refused(result);
            assert!(buffer.bytes().is_empty());
        } else {
            result.unwrap();
            assert_eq!(buffer.bytes(), [7; 1024]);
            assert_eq!(pool.used(), required);
        }
        drop(buffer);
        assert_eq!(pool.used(), metadata);
        drop(origin);
        assert_eq!(pool.used(), 0);
    }
}
// This is a real SDK context-Box proof; native generic payload tests do not
// stand in for this selected OwnedAllocator path.
#[cfg(target_vendor = "teaclave")]
fn check_context_ownership(pool: &Arc<AllocationPoolV1>) -> usize {
    use enclave_os_common::allocation::LoanAllocator;
    let before = pool.used();
    let origin = LoanAllocator::from_pool_unpublished(pool).unwrap();
    let allocator = origin.owned_allocator();
    let metadata = pool.used();
    let mut context = provider().start(allocator.clone()).unwrap();
    let layout = context.allocation_layout();
    let backend = LoanAllocator::required_backend_bytes(layout).unwrap();
    assert_eq!(pool.used(), metadata + backend);
    context.update(b"original context prefix");
    let mut fork = context.fork(allocator.clone()).unwrap();
    assert_eq!(pool.used(), metadata + backend * 2);
    fork.update(b" and fork suffix");
    assert_eq!(
        fork.finish().as_ref(),
        expected_hash(b"original context prefix and fork suffix").as_ref()
    );
    assert_eq!(pool.used(), metadata + backend);
    assert_eq!(
        context.fork_finish().as_ref(),
        expected_hash(b"original context prefix").as_ref()
    );
    drop(origin);
    drop(allocator);
    assert_eq!(
        pool.used(),
        metadata + backend,
        "context retains the original origin after factory aliases drop"
    );
    assert_eq!(
        context.finish().as_ref(),
        expected_hash(b"original context prefix").as_ref()
    );
    assert_eq!(pool.used(), before);
    check_context_bounds(backend);
    std::println!("TLS-HASH-CONTEXT-SIM: original-pool start/fork/finish and HRR refusal/refund");
    backend
}
#[cfg(target_vendor = "teaclave")]
fn context_refused<T>(result: Result<T, rustls::Error>) {
    assert!(matches!(result, Err(rustls::Error::AllocationFailed)));
}
#[cfg(target_vendor = "teaclave")]
fn check_context_bounds(backend: usize) {
    use enclave_os_common::allocation::LoanAllocator;
    let root = shared_allocation_bytes::<AllocationPoolV1>().unwrap();
    let metadata = LoanAllocator::required_origin_bytes().unwrap();
    // The first exact context is affordable; a second one is the independent
    // physical boundary used by fork and HRR replacement before mutation.
    for extra in [-1_isize, 0, 1] {
        let capacity = root
            .checked_add(metadata)
            .unwrap()
            .checked_add(backend.checked_mul(2).unwrap())
            .unwrap()
            .checked_add_signed(extra)
            .unwrap();
        let pool = AllocationPoolV1::try_new_with_release(capacity, None).unwrap();
        let origin = Original::new(&pool);
        let admitted_metadata = pool.used();
        assert_eq!(admitted_metadata, metadata);
        let mut buffer =
            RetainedHandshakeBuffer::new_in(origin.clone(), origin.context_allocator());
        buffer.try_add(b"prefix").unwrap();
        // Do not retain client-auth bytes: only the context survives this move.
        let mut running = buffer.start_hash(provider()).unwrap();
        assert_eq!(pool.used(), metadata + backend);
        let before = running.current_hash();
        if extra < 0 {
            context_refused(running.try_clone());
            assert_eq!(running.current_hash().as_ref(), before.as_ref());
            context_refused(running.try_rollup());
            assert_eq!(running.current_hash().as_ref(), before.as_ref());
            assert!(running.client_auth_bytes().is_none());
            assert_eq!(pool.used(), metadata + backend);
        } else {
            let copy = running.try_clone().unwrap();
            assert_eq!(copy.current_hash().as_ref(), before.as_ref());
            assert_eq!(pool.used(), metadata + backend * 2);
            drop(copy);
            assert_eq!(pool.used(), metadata + backend);
            running.try_rollup().unwrap();
            assert_eq!(
                running.current_hash().as_ref(),
                expected_hash(&message_hash(b"prefix")).as_ref()
            );
            assert_eq!(pool.used(), metadata + backend);
        }
        drop(running);
        assert_eq!(pool.used(), admitted_metadata);
        drop(origin);
        assert_eq!(pool.used(), 0);
    }
    let capacity = root
        .checked_add(metadata)
        .unwrap()
        .checked_add(backend)
        .unwrap()
        - 1;
    let pool = AllocationPoolV1::try_new_with_release(capacity, None).unwrap();
    let origin = LoanAllocator::from_pool_unpublished(&pool).unwrap();
    context_refused(provider().start(origin.owned_allocator()));
    assert_eq!(pool.used(), metadata);
    drop(origin);
    assert_eq!(pool.used(), 0);
}
#[cfg(test)]
pub(super) fn check() {
    let pool = AllocationPoolV1::new(1024 * 1024).unwrap();
    check_in(&pool);
    assert_eq!(pool.used(), 0);
}
pub(super) fn check_in(pool: &Arc<AllocationPoolV1>) {
    #[cfg(target_vendor = "teaclave")]
    let context_backing = check_context_ownership(pool);
    #[cfg(not(target_vendor = "teaclave"))]
    let context_backing = 0; // Native context capability is explicitly Global.
    let before = pool.used();
    let origin = Original::new(pool);
    let metadata = pool.used();
    let alias = origin.clone();
    let backing = check_buffer(&origin, pool, metadata);
    check_running(&origin, pool, metadata, context_backing);
    check_hrr(&origin, pool, metadata, context_backing);
    check_discard(&origin, pool, metadata, context_backing);
    check_bounds(
        metadata
            .checked_sub(before)
            .unwrap()
            .checked_add(backing)
            .unwrap(),
    );
    drop(origin);
    assert_eq!(pool.used(), metadata);
    drop(alias);
    assert_eq!(pool.used(), before);
}
