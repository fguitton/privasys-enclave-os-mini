//! Current send transaction assertions shared by existing Session and signed owners.
use super::client_hello_owner_check::{without_global, Original};
use enclave_os_common::allocation::AllocationPoolV1;
use rustls::internal::send::{QueueProbe, RecordProbe};
use std::sync::Arc;

fn values<A: std::alloc::Allocator + Clone>(queue: &QueueProbe<A>) -> Vec<Vec<u8>> {
    queue.chunks().map(<[u8]>::to_vec).collect()
}
fn setup(origin: &Original) -> QueueProbe<Original> {
    let mut queue = QueueProbe::new_in(origin.clone());
    without_global(|| queue.try_append(&[b"prefix"])).unwrap();
    queue.consume(1);
    without_global(|| queue.set_pending(b"pending")).unwrap();
    queue
}
fn assert_values(queue: &QueueProbe<Original>, records: &[&[u8]]) {
    let expected = std::iter::once(&b"refix"[..])
        .chain(std::iter::once(&b"pending"[..]))
        .chain(records.iter().copied())
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    assert_eq!(values(queue), expected);
    assert!(queue.pending().is_none());
}
fn queue_checks(pool: &Arc<AllocationPoolV1>) {
    let before = pool.used();
    let origin = Original::new(pool);
    let metadata = pool.used();
    let payloads: [&[u8]; 8] = [
        b"a",
        b"bb",
        b"ccc",
        b"dddd",
        b"eeeee",
        b"ffffff",
        b"ggggggg",
        b"hhhhhhhh",
    ];
    let capacity = setup(&origin).descriptor_capacity();
    assert_eq!(pool.used(), metadata);
    let growth_count = capacity.checked_sub(2).unwrap().checked_add(1).unwrap();
    assert!(
        growth_count <= payloads.len(),
        "fixed observer fixture covers actual initial capacity"
    );
    for count in [1, 2, growth_count] {
        let records = &payloads[..count];
        let mut queue = setup(&origin);
        let old_pointer = queue.first().unwrap().as_ptr();
        let old_capacity = queue.descriptor_capacity();
        origin.arm(None);
        without_global(|| queue.try_append(records)).unwrap();
        let requests = origin.requests();
        let grew = 2 + count > old_capacity;
        assert_eq!(requests, count + usize::from(count > 1 || grew));
        assert_eq!(queue.first().unwrap().as_ptr(), old_pointer);
        if grew {
            assert!(queue.descriptor_capacity() >= old_capacity * 2);
        } else {
            assert_eq!(queue.descriptor_capacity(), old_capacity);
        }
        assert_values(&queue, records);
        drop(queue);
        assert_eq!(pool.used(), metadata);
        for refusal in 0..requests {
            origin.arm(None);
            let mut queue = setup(&origin);
            let before_values = values(&queue);
            let before_pending = queue.pending().unwrap().to_vec();
            let before_pointer = queue.first().unwrap().as_ptr();
            let before_charge = pool.used();
            let before_backing = origin.backend_bytes();
            origin.arm(Some(refusal));
            assert!(without_global(|| queue.try_append(records)).is_err());
            assert_eq!(origin.requests(), refusal + 1);
            assert_eq!(values(&queue), before_values);
            assert_eq!(queue.pending(), Some(before_pending.as_slice()));
            assert_eq!(queue.first().unwrap().as_ptr(), before_pointer);
            assert_eq!(queue.descriptor_capacity(), old_capacity);
            assert_eq!(origin.backend_bytes(), before_backing);
            assert_eq!(pool.used(), before_charge);
            origin.arm(None);
            without_global(|| queue.try_append(records)).unwrap();
            assert_values(&queue, records);
            drop(queue);
            assert_eq!(pool.used(), metadata);
        }
    }
    origin.arm(None);
    let mut queue = setup(&origin);
    let before_values = values(&queue);
    let before_charge = pool.used();
    let blocker = pool
        .reserve_unpublished(pool.capacity() - pool.used())
        .unwrap();
    assert!(without_global(|| queue.try_append(&[b"backend refusal"])).is_err());
    assert_eq!(values(&queue), before_values);
    assert_eq!(queue.pending(), Some(&b"pending"[..]));
    drop(blocker);
    assert_eq!(pool.used(), before_charge);
    without_global(|| queue.try_append(&[b"backend retry"])).unwrap();
    let returned = queue.pop().unwrap();
    assert_eq!(returned.as_slice(), b"refix");
    drop(queue);
    drop(origin);
    assert!(
        pool.used() > before,
        "returned owner retains real backing and original origin"
    );
    drop(returned);
    assert_eq!(pool.used(), before);
}
fn chunks(probe: &RecordProbe) -> Vec<Vec<u8>> {
    probe.chunks().map(<[u8]>::to_vec).collect()
}
pub(super) fn record_count(mut bytes: &[u8]) -> usize {
    let mut count = 0;
    while !bytes.is_empty() {
        assert!(bytes.len() >= 5);
        let length = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
        assert!(bytes.len() >= 5 + length);
        bytes = &bytes[5 + length..];
        count += 1;
    }
    count
}
fn record_checks(pool: &Arc<AllocationPoolV1>) {
    let before = pool.used();
    let origin = Original::new(pool);
    let metadata = pool.used();
    let mut probe = RecordProbe::new_in(origin.context_allocator(), u64::MAX);
    probe.queue(b"old queued record").unwrap();
    probe.queue_pending().unwrap();
    let snapshot = probe.snapshot();
    let old = chunks(&probe);
    let pending = probe.pending().unwrap().to_vec();
    let short = probe.close(&mut []);
    let Err(rustls::unbuffered::EncryptError::InsufficientSize(required)) = short else {
        core::panic!("exact short-close refusal")
    };
    assert_eq!(probe.snapshot(), snapshot);
    assert_eq!(chunks(&probe), old);
    assert_eq!(probe.pending(), Some(pending.as_slice()));
    let mut output = vec![0; required.required_size];
    let written = probe.close(&mut output).unwrap();
    assert_eq!(written, output.len());
    assert_eq!(record_count(&output), 3, "old, pending, exactly one close");
    let closed = probe.snapshot();
    assert_eq!(closed.sequence, snapshot.sequence + 1);
    assert!(closed.closed && closed.fatal);
    assert_eq!(probe.close(&mut output).unwrap(), 0);
    assert_eq!(probe.snapshot(), closed);
    drop(probe);

    let mut failing = RecordProbe::failing_on_in(origin.context_allocator(), 3);
    failing.queue(b"old queued record").unwrap();
    failing.queue_pending().unwrap();
    let old = chunks(&failing);
    let pending = failing.pending().unwrap().to_vec();
    let before_failure = failing.snapshot();
    let charge = pool.used();
    let data = [9; 32_768];
    assert!(matches!(
        failing.queue(&data),
        Err(rustls::Error::EncryptError)
    ));
    let failed = failing.snapshot();
    assert_eq!(
        failed.sequence, 4,
        "two attempted batch nonces are consumed"
    );
    assert!(!failed.active);
    assert_eq!(failed.queued_bytes, before_failure.queued_bytes);
    assert_eq!(failed.pending_bytes, before_failure.pending_bytes);
    assert_eq!(chunks(&failing), old);
    assert_eq!(failing.pending(), Some(pending.as_slice()));
    assert_eq!(
        pool.used(),
        charge,
        "all unpublished staged records were freed"
    );
    assert!(matches!(
        failing.queue(b"retry"),
        Err(rustls::Error::EncryptError)
    ));
    assert_eq!(failing.snapshot(), failed);
    assert_eq!(pool.used(), charge);
    drop(failing);
    assert_eq!(pool.used(), metadata);

    #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
    {
        let mut probe = RecordProbe::new_in(origin.context_allocator(), u64::MAX);
        probe.queue(b"old").unwrap();
        probe.queue_pending().unwrap();
        let snapshot = probe.snapshot();
        let old = chunks(&probe);
        let pending = probe.pending().unwrap().to_vec();
        let charge = pool.used();
        let blocker = pool.reserve_unpublished(pool.capacity() - charge).unwrap();
        let mut output = [0; 65_536];
        assert!(matches!(
            probe.write(&[7; 32_768], &mut output),
            Err(rustls::unbuffered::EncryptError::Tls(
                rustls::Error::AllocationFailed
            ))
        ));
        assert_eq!(probe.snapshot(), snapshot);
        assert_eq!(chunks(&probe), old);
        assert_eq!(probe.pending(), Some(pending.as_slice()));
        assert!(matches!(
            probe.queue_pending(),
            Err(rustls::Error::AllocationFailed)
        ));
        assert_eq!(probe.snapshot(), snapshot);
        assert_eq!(probe.pending(), Some(pending.as_slice()));
        drop(blocker);
        assert_eq!(pool.used(), charge);
        assert!(probe.write(&[7; 32_768], &mut output).is_ok());
        drop(probe);

        let mut probe = RecordProbe::new_in(origin.context_allocator(), u64::MAX);
        probe.buffer_before_handshake(&[8; 32_768]).unwrap();
        let snapshot = probe.snapshot();
        let plaintext = probe.plaintext().map(<[u8]>::to_vec).collect::<Vec<_>>();
        let charge = pool.used();
        let blocker = pool.reserve_unpublished(pool.capacity() - charge).unwrap();
        assert!(matches!(
            probe.start_traffic(),
            Err(rustls::Error::AllocationFailed)
        ));
        assert_eq!(probe.snapshot(), snapshot);
        assert_eq!(
            probe.plaintext().map(<[u8]>::to_vec).collect::<Vec<_>>(),
            plaintext
        );
        drop(blocker);
        assert_eq!(pool.used(), charge);
        probe.start_traffic().unwrap();
        assert!(probe.plaintext().next().is_none());
        assert!(probe.snapshot().traffic);
        drop(probe);
    }
    if let Some(mut probe) = RecordProbe::exhausted_tls12_in(origin.context_allocator()) {
        let snapshot = probe.snapshot();
        let Err(rustls::unbuffered::EncryptError::InsufficientSize(required)) =
            probe.write(b"x", &mut [])
        else {
            core::panic!("TLS12 close size refusal")
        };
        assert_eq!(probe.snapshot(), snapshot);
        let mut output = vec![0; required.required_size];
        assert!(matches!(
            probe.write(b"x", &mut output),
            Err(rustls::unbuffered::EncryptError::EncryptExhausted)
        ));
        let written = probe.close(&mut output).unwrap();
        assert_eq!(record_count(&output[..written]), 1);
        assert_eq!(probe.close(&mut output).unwrap(), 0);
    }
    drop(origin);
    assert_eq!(pool.used(), before);
}
#[cfg(test)]
pub(super) fn check() {
    let pool = AllocationPoolV1::new(1024 * 1024).unwrap();
    check_in(&pool);
    assert_eq!(pool.used(), 0);
}
pub(super) fn check_in(pool: &Arc<AllocationPoolV1>) {
    queue_checks(pool);
    record_checks(pool);
}
