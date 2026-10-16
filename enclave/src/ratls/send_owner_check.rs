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
    flight_checks(pool);
    key_update_checks(pool);
    parsed_handshake_checks(pool);
}

fn flight_checks(pool: &Arc<AllocationPoolV1>) {
    use rustls::internal::send::FlightProbe;
    let before = pool.used();
    let origin = Original::new(pool);
    let metadata = pool.used();
    let input = [7; 32];
    // Independent TLS handshake wire: Finished(type20,u24 length32), then Done.
    let expected = [&[20, 0, 0, 32][..], &input].concat();
    for existing in [false, true] {
        let setup = || {
            let mut probe =
                FlightProbe::new_in(origin.clone(), origin.context_allocator()).unwrap();
            if existing {
                without_global(|| probe.add_finished(&input)).unwrap();
            }
            probe
        };
        let mut probe = setup();
        origin.arm(None);
        without_global(|| probe.add_finished(&input)).unwrap();
        let requests = origin.requests();
        assert_eq!(requests, 2, "actual flight and retained transcript backing");
        assert_eq!(
            probe.bytes(),
            if existing {
                [&expected[..], &expected[..]].concat()
            } else {
                expected.clone()
            }
        );
        drop(probe);
        for refused in 0..requests {
            origin.arm(None);
            let mut probe = setup();
            let bytes = probe.bytes().to_vec();
            let hash = probe.hash();
            let pointer = probe.body_pointer();
            let charge = pool.used();
            let backing = origin.backend_bytes();
            origin.arm(Some(refused));
            let expected_error = if refused == 0 {
                rustls::Error::AllocationFailed
            } else {
                // Preserve the existing transcript owner's public error kind.
                rustls::Error::InvalidMessage(rustls::InvalidMessage::AllocationFailed)
            };
            assert_eq!(
                without_global(|| probe.add_finished(&input)).err(),
                Some(expected_error)
            );
            assert_eq!(probe.bytes(), bytes);
            assert_eq!(probe.hash().as_ref(), hash.as_ref());
            assert_eq!(probe.body_pointer(), pointer);
            assert_eq!(pool.used(), charge, "refusal drops all staged growth");
            assert_eq!(origin.backend_bytes(), backing);
            assert_eq!(origin.requests(), refused + 1);
            origin.arm(None);
            without_global(|| probe.add_finished(&input)).unwrap();
            without_global(|| probe.add_done()).unwrap();
            let mut expected_retry = bytes;
            expected_retry.extend_from_slice(&expected);
            expected_retry.extend_from_slice(&[14, 0, 0, 0]);
            assert_eq!(probe.bytes(), expected_retry);
            drop(probe);
        }
    }
    origin.arm(None);
    let mut fitting = FlightProbe::new_in(origin.clone(), origin.context_allocator()).unwrap();
    without_global(|| fitting.add_finished(&input)).unwrap();
    without_global(|| fitting.add_finished(&input)).unwrap();
    without_global(|| fitting.add_done()).unwrap();
    let pointer = fitting.body_pointer();
    let charge = pool.used();
    origin.arm(Some(0));
    without_global(|| fitting.add_done()).unwrap();
    assert_eq!(
        origin.requests(),
        0,
        "capacity-fit flight has no backing requests"
    );
    assert_eq!(fitting.body_pointer(), pointer);
    assert_eq!(pool.used(), charge);
    drop(fitting);
    origin.arm(None);
    // A real original-pool backend refusal must precede body/hash mutation.
    let mut probe = FlightProbe::new_in(origin.clone(), origin.context_allocator()).unwrap();
    let hash = probe.hash();
    let blocker = pool
        .reserve_unpublished(pool.capacity() - pool.used())
        .unwrap();
    assert!(without_global(|| probe.add_finished(&input)).is_err());
    assert!(probe.bytes().is_empty());
    assert_eq!(probe.hash().as_ref(), hash.as_ref());
    drop(blocker);
    without_global(|| probe.add_finished(&input)).unwrap();
    assert_eq!(probe.bytes(), expected);
    drop(probe);
    assert_eq!(pool.used(), metadata);
    drop(origin);
    assert_eq!(pool.used(), before);
}

fn key_update_checks(pool: &Arc<AllocationPoolV1>) {
    use rustls::internal::send::observe_key_update;
    for requested in [false, true] {
        // Independent TLS1.3 handshake type24/u24 length1/u8 request wire.
        let plaintext = [24, 0, 0, 1, u8::from(requested)];
        without_global(|| observe_key_update(requested, |bytes| assert_eq!(bytes, plaintext)));
        let mut expected = plaintext.to_vec();
        expected.push(u8::from(rustls::ContentType::Handshake));
        let aad = rustls::crypto::cipher::make_tls13_aad(
            expected.len() + ring::aead::AES_256_GCM.tag_len(),
        );
        ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &[7; 32]).unwrap(),
        )
        .seal_in_place_append_tag(
            ring::aead::Nonce::assume_unique_for_key([0; 12]),
            ring::aead::Aad::from(aad),
            &mut expected,
        )
        .unwrap();
        let mut wire = vec![23, 3, 3];
        wire.extend_from_slice(&u16::try_from(expected.len()).unwrap().to_be_bytes());
        wire.extend_from_slice(&expected);

        let before = pool.used();
        let origin = Original::new(pool);
        let mut probe = RecordProbe::new_in(origin.context_allocator(), u64::MAX);
        #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
        {
            let state = probe.snapshot();
            let charge = pool.used();
            let blocker = pool.reserve_unpublished(pool.capacity() - charge).unwrap();
            let refusal = without_global(|| {
                if requested {
                    probe.queue_request()
                } else {
                    probe.queue_pending()
                }
            });
            assert_eq!(refusal.err(), Some(rustls::Error::AllocationFailed));
            assert_eq!(
                probe.snapshot(),
                state,
                "admission precedes nonce/queue/pending changes"
            );
            drop(blocker);
            assert_eq!(pool.used(), charge);
        }
        let send = || {
            if requested {
                probe.queue_request()
            } else {
                probe.queue_pending()
            }
        };
        #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
        without_global(send).unwrap();
        #[cfg(not(any(target_env = "sgx", target_vendor = "teaclave")))]
        {
            let mut send = send;
            send().unwrap();
        }
        assert_eq!(probe.snapshot().sequence, 1);
        if !requested {
            assert_eq!(probe.pending(), Some(wire.as_slice()));
            probe.flush_pending().unwrap();
        }
        let output = probe.pop().unwrap();
        assert_eq!(output.as_slice(), wire);
        assert!(
            probe.pop().is_none(),
            "one current notification/request record"
        );
        drop(probe);
        drop(origin);
        #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
        assert!(
            pool.used() > before,
            "returned actual output retains its original payer"
        );
        drop(output);
        assert_eq!(pool.used(), before);
    }
    #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
    std::println!("TLS-KEYUPDATE-SERIALIZATION-SIM: inline-current-codec request-notify independent-wire original-pool refusal-before-nonce retained-output final-refund PASS");
}

fn parsed_handshake_checks(pool: &Arc<AllocationPoolV1>) {
    use rustls::internal::send::{visit_message_in, ParsedHandshakeProbe};
    let wire = [14, 0, 0, 0];
    let malformed = [14, 0, 0, 1, 0];
    let before = pool.used();
    let origin = Original::new(pool);
    let metadata = pool.used();
    origin.arm(Some(0));
    assert_eq!(
        without_global(|| ParsedHandshakeProbe::read_in(
            &malformed,
            origin.clone(),
            origin.context_allocator(),
        ))
        .err(),
        Some(rustls::InvalidMessage::TrailingData("ServerHelloDone")),
    );
    assert_eq!(
        origin.requests(),
        0,
        "malformed precedence before fixed owner"
    );
    origin.arm(None);
    let read = || ParsedHandshakeProbe::read_in(&wire, origin.clone(), origin.context_allocator());
    let probe = without_global(read).unwrap();
    let required = pool.used() - metadata;
    assert_eq!(required, origin.backend_bytes());
    assert!(required >= probe.layout().size());
    assert_eq!(
        probe.handshake_type(),
        rustls::HandshakeType::ServerHelloDone
    );
    drop(probe);
    assert_eq!(pool.used(), metadata);
    for available in [required - 1, required, required + 1] {
        let held = pool
            .reserve_unpublished(pool.capacity() - metadata - available)
            .unwrap();
        origin.arm(None);
        let result = without_global(read);
        if available < required {
            assert_eq!(result.err(), Some(rustls::InvalidMessage::AllocationFailed));
        } else {
            drop(result.unwrap());
        }
        drop(held);
        assert_eq!(pool.used(), metadata);
    }
    origin.arm(Some(0));
    assert_eq!(
        without_global(read).err(),
        Some(rustls::InvalidMessage::AllocationFailed)
    );
    assert_eq!(pool.used(), metadata);
    for available in [required - 1, required, required + 1] {
        origin.arm(None);
        let probe = without_global(read).unwrap();
        let charge = pool.used();
        let held = pool
            .reserve_unpublished(pool.capacity() - charge - available)
            .unwrap();
        let owned = without_global(|| probe.try_into_owned());
        if available < required {
            assert_eq!(owned.err(), Some(rustls::InvalidMessage::AllocationFailed));
        } else {
            let owned = owned.unwrap();
            assert_eq!(
                owned.handshake_type(),
                rustls::HandshakeType::ServerHelloDone
            );
            drop(owned);
        }
        drop(held);
        assert_eq!(
            pool.used(),
            metadata,
            "conversion drops/refunds both bounded owners"
        );
    }
    let held = pool
        .reserve_unpublished(pool.capacity() - metadata)
        .unwrap();
    for (typ, bytes) in [
        (rustls::ContentType::ApplicationData, &b"application"[..]),
        (rustls::ContentType::Alert, &[1, 0][..]),
        (rustls::ContentType::ChangeCipherSpec, &[1][..]),
    ] {
        without_global(|| {
            visit_message_in(typ, bytes, origin.context_allocator(), |parsed, encoded| {
                assert_eq!(parsed, None);
                assert_eq!(encoded, bytes);
            })
        })
        .unwrap();
    }
    #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
    {
        let mut published = false;
        let result = without_global(|| {
            visit_message_in(
                rustls::ContentType::Handshake,
                &wire,
                origin.context_allocator(),
                |_, _| published = true,
            )
        });
        assert_eq!(result.err(), Some(rustls::InvalidMessage::AllocationFailed));
        assert!(!published);
    }
    drop(held);
    let visit = || {
        visit_message_in(
            rustls::ContentType::Handshake,
            &wire,
            origin.context_allocator(),
            |parsed, encoded| {
                assert_eq!(parsed, Some(rustls::HandshakeType::ServerHelloDone));
                assert_eq!(encoded, wire);
                assert_eq!(
                    encoded.as_ptr(),
                    wire.as_ptr(),
                    "unchanged borrowed transcript encoding"
                );
            },
        )
    };
    #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
    without_global(visit).unwrap();
    #[cfg(not(any(target_env = "sgx", target_vendor = "teaclave")))]
    visit().unwrap();
    origin.arm(None);
    let returned = without_global(read).unwrap();
    drop(origin);
    assert!(
        pool.used() > before,
        "actual parsed backing retains original origin"
    );
    drop(returned);
    assert_eq!(pool.used(), before);
    #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
    std::println!("TLS-PARSED-HANDSHAKE-SIM: original-pool exact-layout malformed-before-admission overlap refusal unchanged-encoding no-nonhandshake-owner retained-drop final-refund PASS");
}
