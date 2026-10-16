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
fn check_buffer(origin: &Original, pool: &Arc<AllocationPoolV1>, metadata: usize) -> usize {
    let bytes = [7; 1024];
    let mut buffer = RetainedHandshakeBuffer::new_in(origin.clone());
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
fn check_running(origin: &Original, pool: &Arc<AllocationPoolV1>, metadata: usize) {
    let first = [9; 2048];
    let extra = [3; 2048];
    let mut buffer = RetainedHandshakeBuffer::new_in(origin.clone());
    buffer.retain_client_auth();
    without_global(|| buffer.try_add(&first)).unwrap();
    let mut running = buffer.start_hash(provider());
    let backing = origin.backend_bytes();
    let previous = running.current_hash();
    assert_eq!(previous.as_ref(), expected_hash(&first).as_ref());
    origin.arm(Some(0));
    allocation_refused(without_global(|| running.try_add(&extra)));
    assert_eq!(running.current_hash().as_ref(), previous.as_ref());
    assert_eq!(running.client_auth_bytes().unwrap(), first);
    assert_eq!(pool.used(), metadata + backing);
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
        assert_eq!(pool.used(), metadata + original_backing);
    }
    origin.arm(None);
    drop(running);
    assert_eq!(pool.used(), metadata);
}
fn check_hrr(origin: &Original, pool: &Arc<AllocationPoolV1>, metadata: usize) {
    let original = [11; 2048];
    let mut buffer = RetainedHandshakeBuffer::new_in(origin.clone());
    buffer.retain_client_auth();
    without_global(|| buffer.try_add(&original)).unwrap();
    let mut running = buffer.start_hash(provider());
    let before = running.current_hash();
    let backing = origin.backend_bytes();
    let expected = message_hash(&original);
    origin.arm(Some(0));
    allocation_refused(without_global(|| running.try_rollup()));
    assert_eq!(running.current_hash().as_ref(), before.as_ref());
    assert_eq!(running.client_auth_bytes().unwrap(), original);
    assert_eq!(pool.used(), metadata + backing);
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
    assert_eq!(pool.used(), metadata + before_transfer);
    origin.arm(None);
    let expected = message_hash(&expected);
    let hrr = running.try_into_hrr().unwrap();
    assert_eq!(hrr.bytes(), expected);
    assert_eq!(pool.used(), metadata + origin.backend_bytes());
    drop(hrr);
    assert_eq!(pool.used(), metadata);
}
fn check_discard(origin: &Original, pool: &Arc<AllocationPoolV1>, metadata: usize) {
    let mut buffer = RetainedHandshakeBuffer::new_in(origin.clone());
    without_global(|| buffer.try_add(b"no client authentication")).unwrap();
    let mut running = buffer.start_hash(provider());
    assert_eq!(pool.used(), metadata);
    assert!(running.client_auth_bytes().is_none());
    origin.arm(Some(0));
    without_global(|| running.try_add(b"following bytes")).unwrap();
    assert_eq!(origin.requests(), 0);
    assert_eq!(pool.used(), metadata);
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
        let mut buffer = RetainedHandshakeBuffer::new_in(origin.clone());
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
#[cfg(test)]
pub(super) fn check() {
    let pool = AllocationPoolV1::new(1024 * 1024).unwrap();
    check_in(&pool);
    assert_eq!(pool.used(), 0);
}
pub(super) fn check_in(pool: &Arc<AllocationPoolV1>) {
    let before = pool.used();
    let origin = Original::new(pool);
    let metadata = pool.used();
    let alias = origin.clone();
    let backing = check_buffer(&origin, pool, metadata);
    check_running(&origin, pool, metadata);
    check_hrr(&origin, pool, metadata);
    check_discard(&origin, pool, metadata);
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
