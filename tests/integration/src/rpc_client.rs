// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Native contract tests for the enclave-side bounded RPC client.

use enclave_os_common::queue::{SpscConsumer, SpscProducer, SpscQueueHeader};
use enclave_os_common::rpc::{
    self, HonestRpcIdentity, LoadOpaqueStreamTip, OpaqueStreamCodecError, PersistOpaqueStreamBatch,
    PersistedOpaqueStreamBatch, RpcMethod,
};
use std::collections::BTreeSet;
use std::sync::{mpsc, Arc, Barrier};
use std::thread;
use std::time::Duration;

#[path = "../../../enclave/src/rpc_client.rs"]
#[allow(dead_code)]
mod enclave_rpc_client;

use enclave_rpc_client::{PolledExecutionRpcError, PolledOpaqueStreamError, RpcClient};

/// Native stand-in for the ABI notification. The queues remain the observable
/// transport boundary in these tests.
#[no_mangle]
pub extern "C" fn ocall_notify() -> u32 {
    0
}

fn queue(capacity: u64) -> (SpscProducer, SpscConsumer) {
    let header = Box::into_raw(Box::new(SpscQueueHeader::new(capacity)));
    let buffer = Box::into_raw(vec![0_u8; capacity as usize].into_boxed_slice()) as *mut u8;
    // SAFETY: both allocations are intentionally retained for the test
    // process, have the advertised capacity and are used by one producer and
    // one consumer only.
    unsafe {
        (
            SpscProducer::from_raw(header, buffer),
            SpscConsumer::from_raw(header, buffer),
        )
    }
}

fn client(request_capacity: u64) -> (RpcClient, SpscConsumer, SpscProducer) {
    let (request_tx, request_rx) = queue(request_capacity);
    let (response_tx, response_rx) = queue(4096);
    (
        RpcClient::new(request_tx, response_rx),
        request_rx,
        response_tx,
    )
}

fn batch(payload_len: usize) -> PersistOpaqueStreamBatch {
    PersistOpaqueStreamBatch {
        node_id: 4,
        node_generation: 7,
        stream_id: [0x11; 32],
        persistence_epoch: 3,
        batch_id: 1,
        expected_previous_durable_id: 0,
        payload_digest: [0x22; 32],
        payload: vec![0x33; payload_len],
    }
}

fn batch_for(stream_marker: u8, payload_len: usize) -> PersistOpaqueStreamBatch {
    let mut batch = batch(payload_len);
    batch.stream_id = [stream_marker; 32];
    batch.payload_digest = [stream_marker.wrapping_add(1); 32];
    batch.payload = vec![stream_marker.wrapping_add(2); payload_len];
    batch
}

fn decode_request(request_rx: &SpscConsumer) -> (HonestRpcIdentity, PersistOpaqueStreamBatch) {
    let request = request_rx.try_recv().expect("submitted request");
    let framed = rpc::decode_honest_request(&request).expect("Honest request");
    let decoded = rpc::decode_persist_opaque_stream_batch(framed.payload)
        .expect("opaque stream request")
        .into_request();
    (framed.identity, decoded)
}

fn acknowledgement(identity: HonestRpcIdentity, batch: &PersistOpaqueStreamBatch) -> Vec<u8> {
    let payload = rpc::encode_persisted_opaque_stream_batch(PersistedOpaqueStreamBatch {
        batch_id: batch.batch_id,
        durable_id: batch.batch_id,
        payload_digest: batch.payload_digest,
    });
    rpc::encode_honest_response(identity, 0, &payload).expect("Honest response")
}

fn submit_persistence_until_reserved(
    client: &RpcClient,
    batch: &PersistOpaqueStreamBatch,
) -> enclave_rpc_client::PendingOpaqueStreamBatch {
    for _ in 0..10_000 {
        match client.try_persist_opaque_stream_batch(batch) {
            Ok(pending) => return pending,
            Err(PolledOpaqueStreamError::Busy) => thread::yield_now(),
            Err(error) => panic!("persistence submission failed: {error:?}"),
        }
    }
    panic!("persistence submission remained contended")
}

#[test]
fn occupied_stream_and_synchronous_call_remain_exclusive() {
    let (client, request_rx, _response_tx) = client(4096);
    let _pending = client.try_persist_opaque_stream_batch(&batch(16)).unwrap();

    let invalid = batch(0);
    assert_eq!(
        client
            .try_persist_opaque_stream_batch(&invalid)
            .unwrap_err(),
        PolledOpaqueStreamError::Busy
    );
    assert_eq!(
        client
            .load_opaque_stream_tip(LoadOpaqueStreamTip {
                node_id: 4,
                node_generation: 7,
                stream_id: [0x44; 32],
                persistence_epoch: 3,
            })
            .unwrap_err(),
        PolledOpaqueStreamError::Busy,
        "synchronous calls remain excluded while persistence is outstanding",
    );

    assert!(
        request_rx.try_recv().is_some(),
        "first request was submitted"
    );
    assert!(
        request_rx.try_recv().is_none(),
        "Busy retry must not enqueue a frame"
    );
}

#[test]
fn opaque_encoding_failure_releases_slot_without_sending() {
    let (client, request_rx, _response_tx) = client(4096);
    assert_eq!(
        client
            .try_persist_opaque_stream_batch(&batch(0))
            .unwrap_err(),
        PolledOpaqueStreamError::InvalidRequest(OpaqueStreamCodecError::PayloadBound)
    );
    assert!(request_rx.try_recv().is_none());

    let _pending = client.try_persist_opaque_stream_batch(&batch(16)).unwrap();
    assert!(request_rx.try_recv().is_some(), "reservation was released");
}

#[test]
fn honest_envelope_failure_releases_slot_without_sending() {
    let (client, request_rx, _response_tx) = client(4096);
    // The opaque-stream bound is wider than the Honest RPC envelope. Adding
    // the opaque header therefore makes this inner-valid payload fail at the
    // second encoding layer.
    assert_eq!(
        client
            .try_persist_opaque_stream_batch(&batch(rpc::MAX_HONEST_RPC_PAYLOAD_BYTES))
            .unwrap_err(),
        PolledOpaqueStreamError::InvalidRequest(OpaqueStreamCodecError::BatchBound)
    );
    assert!(request_rx.try_recv().is_none());

    let _pending = client.try_persist_opaque_stream_batch(&batch(16)).unwrap();
    assert!(request_rx.try_recv().is_some(), "reservation was released");
}

#[test]
fn queue_full_failure_releases_slot_and_writes_no_partial_frame() {
    let (request_tx, request_rx) = queue(4096);
    request_tx.try_send(&vec![0x44; 4092]).unwrap();
    let (_response_tx, response_rx) = queue(4096);
    let client = RpcClient::new(request_tx, response_rx);

    assert_eq!(
        client
            .try_persist_opaque_stream_batch(&batch(16))
            .unwrap_err(),
        PolledOpaqueStreamError::QueueFull
    );
    assert_eq!(request_rx.try_recv().unwrap(), vec![0x44; 4092]);
    assert!(request_rx.try_recv().is_none(), "failed send was atomic");

    let _pending = client.try_persist_opaque_stream_batch(&batch(16)).unwrap();
    assert!(request_rx.try_recv().is_some(), "reservation was released");
}

#[test]
fn successful_acknowledgement_releases_only_the_matching_slot() {
    let (client, request_rx, response_tx) = client(4096);
    let submitted = batch(16);
    let pending = client.try_persist_opaque_stream_batch(&submitted).unwrap();
    let request = request_rx.try_recv().unwrap();
    let framed = rpc::decode_honest_request(&request).unwrap();
    let decoded = rpc::decode_persist_opaque_stream_batch(framed.payload).unwrap();
    assert_eq!(decoded.request(), &submitted);
    assert_eq!(decoded.canonical_bytes(), framed.payload);

    let acknowledgement =
        rpc::encode_persisted_opaque_stream_batch(rpc::PersistedOpaqueStreamBatch {
            batch_id: submitted.batch_id,
            durable_id: submitted.batch_id,
            payload_digest: submitted.payload_digest,
        });
    response_tx
        .try_send(&rpc::encode_honest_response(framed.identity, 0, &acknowledgement).unwrap())
        .unwrap();
    assert_eq!(
        client
            .poll_persist_opaque_stream_batch(&pending)
            .unwrap()
            .unwrap(),
        rpc::PersistedOpaqueStreamBatch {
            batch_id: submitted.batch_id,
            durable_id: submitted.batch_id,
            payload_digest: submitted.payload_digest,
        }
    );

    let _pending = client.try_persist_opaque_stream_batch(&submitted).unwrap();
    assert!(
        request_rx.try_recv().is_some(),
        "acknowledgement released slot"
    );
}

#[test]
fn two_streams_complete_in_reverse_response_order_without_cross_acknowledgement() {
    let (client, request_rx, response_tx) = client(16 * 1024);
    let first = batch_for(0x31, 16);
    let second = batch_for(0x41, 16);
    let first_pending = client.try_persist_opaque_stream_batch(&first).unwrap();
    let second_pending = client.try_persist_opaque_stream_batch(&second).unwrap();
    let (first_identity, first_request) = decode_request(&request_rx);
    let (second_identity, second_request) = decode_request(&request_rx);
    assert_eq!(first_request, first);
    assert_eq!(second_request, second);

    let invalid_third = batch_for(0x51, 0);
    assert_eq!(
        client
            .try_persist_opaque_stream_batch(&invalid_third)
            .unwrap_err(),
        PolledOpaqueStreamError::Busy,
        "the third request must be refused before its invalid payload is encoded",
    );
    assert!(request_rx.try_recv().is_none());

    response_tx
        .try_send(&acknowledgement(second_identity, &second))
        .unwrap();
    response_tx
        .try_send(&acknowledgement(first_identity, &first))
        .unwrap();
    assert_eq!(
        client
            .poll_persist_opaque_stream_batch(&first_pending)
            .unwrap(),
        None,
        "the second response is parked for its exact token",
    );
    assert_eq!(
        client
            .poll_persist_opaque_stream_batch(&second_pending)
            .unwrap(),
        Some(PersistedOpaqueStreamBatch {
            batch_id: second.batch_id,
            durable_id: second.batch_id,
            payload_digest: second.payload_digest,
        }),
    );

    let third = batch_for(0x51, 16);
    let _third_pending = client.try_persist_opaque_stream_batch(&third).unwrap();
    assert!(
        request_rx.try_recv().is_some(),
        "only the matching completed slot was released",
    );
    assert_eq!(
        client
            .poll_persist_opaque_stream_batch(&first_pending)
            .unwrap(),
        Some(PersistedOpaqueStreamBatch {
            batch_id: first.batch_id,
            durable_id: first.batch_id,
            payload_digest: first.payload_digest,
        }),
    );
}

#[test]
fn inactive_responses_never_evict_a_parked_live_response() {
    let (client, request_rx, response_tx) = client(16 * 1024);
    let first = batch_for(0x61, 16);
    let second = batch_for(0x71, 16);
    let first_pending = client.try_persist_opaque_stream_batch(&first).unwrap();
    let second_pending = client.try_persist_opaque_stream_batch(&second).unwrap();
    let (first_identity, _) = decode_request(&request_rx);
    let (second_identity, _) = decode_request(&request_rx);

    response_tx
        .try_send(&acknowledgement(second_identity, &second))
        .unwrap();
    assert_eq!(
        client
            .poll_persist_opaque_stream_batch(&first_pending)
            .unwrap(),
        None,
    );

    for offset in 1..=8 {
        let mut inactive = first_identity;
        inactive.operation_id = first_identity.operation_id + 1_000 + offset;
        response_tx
            .try_send(&acknowledgement(inactive, &first))
            .unwrap();
        assert_eq!(
            client
                .poll_persist_opaque_stream_batch(&first_pending)
                .unwrap(),
            None,
            "inactive response {offset} is dropped without consuming a live token",
        );
    }

    assert_eq!(
        client
            .poll_persist_opaque_stream_batch(&second_pending)
            .unwrap(),
        Some(PersistedOpaqueStreamBatch {
            batch_id: second.batch_id,
            durable_id: second.batch_id,
            payload_digest: second.payload_digest,
        }),
        "the parked live response survives inactive traffic",
    );
    response_tx
        .try_send(&acknowledgement(first_identity, &first))
        .unwrap();
    assert!(client
        .poll_persist_opaque_stream_batch(&first_pending)
        .unwrap()
        .is_some());
}

#[test]
fn wrong_full_identity_fails_only_the_operation_id_it_addresses() {
    let (client, request_rx, response_tx) = client(16 * 1024);
    let first = batch_for(0x81, 16);
    let second = batch_for(0x91, 16);
    let first_pending = client.try_persist_opaque_stream_batch(&first).unwrap();
    let second_pending = client.try_persist_opaque_stream_batch(&second).unwrap();
    let (first_identity, _) = decode_request(&request_rx);
    let (second_identity, _) = decode_request(&request_rx);

    let mut wrong_second_identity = second_identity;
    wrong_second_identity.node_generation += 1;
    response_tx
        .try_send(&acknowledgement(wrong_second_identity, &second))
        .unwrap();
    assert_eq!(
        client
            .poll_persist_opaque_stream_batch(&first_pending)
            .unwrap(),
        None,
    );
    assert_eq!(
        client
            .poll_persist_opaque_stream_batch(&second_pending)
            .unwrap_err(),
        PolledOpaqueStreamError::UnexpectedResponse,
    );

    let replacement = batch_for(0xa1, 16);
    let _replacement_pending = client
        .try_persist_opaque_stream_batch(&replacement)
        .unwrap();
    assert!(request_rx.try_recv().is_some());
    response_tx
        .try_send(&acknowledgement(first_identity, &first))
        .unwrap();
    assert!(client
        .poll_persist_opaque_stream_batch(&first_pending)
        .unwrap()
        .is_some());
}

#[test]
fn abandoned_execution_response_cannot_terminate_its_successor() {
    let (client, request_rx, response_tx) = client(16 * 1024);
    let first = client.try_execution_net_close(4, 7, 11).unwrap();
    let first_request = request_rx.try_recv().unwrap();
    let first_identity = rpc::decode_honest_request(&first_request).unwrap().identity;
    client.abandon_execution_rpc(first).unwrap();

    let second = client.try_execution_net_close(4, 7, 12).unwrap();
    let second_request = request_rx.try_recv().unwrap();
    let second_identity = rpc::decode_honest_request(&second_request)
        .unwrap()
        .identity;
    assert_eq!(
        client.try_execution_net_close(4, 7, 13).unwrap_err(),
        PolledExecutionRpcError::Busy,
        "execution remains single-flight",
    );

    response_tx
        .try_send(&rpc::encode_honest_response(first_identity, 0, &[]).unwrap())
        .unwrap();
    response_tx
        .try_send(&rpc::encode_honest_response(second_identity, 0, &[]).unwrap())
        .unwrap();
    assert!(client.poll_execution_rpc(&second).unwrap().is_none());
    let completion = client
        .poll_execution_rpc(&second)
        .unwrap()
        .expect("successor response");
    assert_eq!(completion.status(), 0);
    assert!(completion.payload().is_empty());
}

#[test]
fn concurrent_distinct_stream_and_log_writers_preserve_request_frames() {
    let (client, request_rx, _response_tx) = client(64 * 1024);
    let client = Arc::new(client);
    let barrier = Arc::new(Barrier::new(4));
    let first = batch_for(0xb1, 128);
    let second = batch_for(0xc1, 128);

    let first_worker = {
        let client = Arc::clone(&client);
        let barrier = Arc::clone(&barrier);
        let first = first.clone();
        thread::spawn(move || {
            barrier.wait();
            submit_persistence_until_reserved(&client, &first)
        })
    };
    let second_worker = {
        let client = Arc::clone(&client);
        let barrier = Arc::clone(&barrier);
        let second = second.clone();
        thread::spawn(move || {
            barrier.wait();
            submit_persistence_until_reserved(&client, &second)
        })
    };
    let log_worker = {
        let client = Arc::clone(&client);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            client.log(3, "concurrent-log");
        })
    };

    barrier.wait();
    let first_pending = first_worker.join().expect("first persistence worker");
    let second_pending = second_worker.join().expect("second persistence worker");
    log_worker.join().expect("log worker");

    let mut operation_ids = BTreeSet::new();
    let mut streams = BTreeSet::new();
    let mut observed_log = false;
    for _ in 0..3 {
        let request = request_rx.try_recv().expect("complete request frame");
        if let Ok(framed) = rpc::decode_honest_request(&request) {
            assert_eq!(framed.identity.method, RpcMethod::PersistOpaqueStreamBatch);
            operation_ids.insert(framed.identity.operation_id);
            let decoded = rpc::decode_persist_opaque_stream_batch(framed.payload)
                .expect("canonical persistence payload");
            streams.insert(decoded.request().stream_id);
        } else {
            let (operation_id, method, payload) =
                rpc::decode_request(&request).expect("complete legacy frame");
            assert_eq!(method, RpcMethod::Log);
            assert_eq!(rpc::decode_log_req(payload), Some((3, "concurrent-log")));
            operation_ids.insert(operation_id);
            observed_log = true;
        }
    }
    assert!(request_rx.try_recv().is_none());
    assert!(observed_log);
    assert_eq!(operation_ids.len(), 3, "operation IDs are never reused");
    assert_eq!(streams, BTreeSet::from([[0xb1; 32], [0xc1; 32]]));

    drop((first_pending, second_pending));
}

#[test]
fn dropped_persistence_token_reuses_only_its_slot_and_late_duplicates_are_inert() {
    let (client, request_rx, response_tx) = client(32 * 1024);
    let first = batch_for(0xd1, 16);
    let second = batch_for(0xe1, 16);
    let first_pending = client.try_persist_opaque_stream_batch(&first).unwrap();
    let second_pending = client.try_persist_opaque_stream_batch(&second).unwrap();
    let (first_identity, _) = decode_request(&request_rx);
    let (second_identity, _) = decode_request(&request_rx);

    drop(first_pending);
    let first_successor = client.try_persist_opaque_stream_batch(&first).unwrap();
    let (successor_identity, _) = decode_request(&request_rx);
    assert_ne!(first_identity.operation_id, successor_identity.operation_id);

    response_tx
        .try_send(&acknowledgement(first_identity, &first))
        .unwrap();
    response_tx
        .try_send(&acknowledgement(second_identity, &second))
        .unwrap();
    response_tx
        .try_send(&acknowledgement(second_identity, &second))
        .unwrap();
    response_tx
        .try_send(&acknowledgement(successor_identity, &first))
        .unwrap();

    assert_eq!(
        client
            .poll_persist_opaque_stream_batch(&first_successor)
            .unwrap(),
        None,
        "late response for the dropped token is inactive",
    );
    assert_eq!(
        client
            .poll_persist_opaque_stream_batch(&first_successor)
            .unwrap(),
        None,
        "the other live response is parked",
    );
    assert_eq!(
        client
            .poll_persist_opaque_stream_batch(&first_successor)
            .unwrap(),
        None,
        "a duplicate cannot evict or consume the parked response",
    );
    assert!(client
        .poll_persist_opaque_stream_batch(&first_successor)
        .unwrap()
        .is_some());
    assert!(client
        .poll_persist_opaque_stream_batch(&second_pending)
        .unwrap()
        .is_some());

    // A response duplicated after completion remains inactive and cannot be
    // charged to the request that reuses the freed slot.
    let third = batch_for(0xf1, 16);
    let third_pending = client.try_persist_opaque_stream_batch(&third).unwrap();
    let (third_identity, _) = decode_request(&request_rx);
    response_tx
        .try_send(&acknowledgement(second_identity, &second))
        .unwrap();
    response_tx
        .try_send(&acknowledgement(third_identity, &third))
        .unwrap();
    assert!(client
        .poll_persist_opaque_stream_batch(&third_pending)
        .unwrap()
        .is_none());
    assert!(client
        .poll_persist_opaque_stream_batch(&third_pending)
        .unwrap()
        .is_some());
}

#[test]
fn unattributable_malformed_response_terminates_only_the_polling_operation() {
    let (client, request_rx, response_tx) = client(32 * 1024);
    let first = batch_for(0x21, 16);
    let second = batch_for(0x22, 16);
    let first_pending = client.try_persist_opaque_stream_batch(&first).unwrap();
    let second_pending = client.try_persist_opaque_stream_batch(&second).unwrap();
    let (_first_identity, _) = decode_request(&request_rx);
    let (second_identity, _) = decode_request(&request_rx);

    response_tx.try_send(&[0xff, 0x01, 0x02]).unwrap();
    assert_eq!(
        client
            .poll_persist_opaque_stream_batch(&first_pending)
            .unwrap_err(),
        PolledOpaqueStreamError::MalformedResponse,
    );

    let replacement = batch_for(0x23, 16);
    let replacement_pending = client
        .try_persist_opaque_stream_batch(&replacement)
        .expect("malformed response cleared only the addressed slot");
    let (replacement_identity, _) = decode_request(&request_rx);
    response_tx
        .try_send(&acknowledgement(second_identity, &second))
        .unwrap();
    response_tx
        .try_send(&acknowledgement(replacement_identity, &replacement))
        .unwrap();
    assert!(client
        .poll_persist_opaque_stream_batch(&second_pending)
        .unwrap()
        .is_some());
    assert!(client
        .poll_persist_opaque_stream_batch(&replacement_pending)
        .unwrap()
        .is_some());
}

#[test]
fn polled_paths_report_lock_contention_as_busy_and_completed_tokens_as_not_pending() {
    let (client, request_rx, response_tx) = client(32 * 1024);
    let submitted = batch_for(0x24, 16);

    let state_guard = client.hold_request_state_for_test();
    assert_eq!(
        client
            .try_persist_opaque_stream_batch(&submitted)
            .unwrap_err(),
        PolledOpaqueStreamError::Busy,
        "reservation never blocks behind a competing TCS",
    );
    drop(state_guard);

    let producer_guard = client.hold_request_producer_for_test();
    assert_eq!(
        client
            .try_persist_opaque_stream_batch(&submitted)
            .unwrap_err(),
        PolledOpaqueStreamError::Busy,
        "submission never blocks behind another producer",
    );
    drop(producer_guard);

    let pending = client.try_persist_opaque_stream_batch(&submitted).unwrap();
    let (identity, _) = decode_request(&request_rx);
    let state_guard = client.hold_request_state_for_test();
    assert_eq!(
        client
            .poll_persist_opaque_stream_batch(&pending)
            .unwrap_err(),
        PolledOpaqueStreamError::Busy,
        "poll contention is distinct from an inactive token",
    );
    drop(state_guard);

    response_tx
        .try_send(&acknowledgement(identity, &submitted))
        .unwrap();
    assert!(client
        .poll_persist_opaque_stream_batch(&pending)
        .unwrap()
        .is_some());
    assert_eq!(
        client
            .poll_persist_opaque_stream_batch(&pending)
            .unwrap_err(),
        PolledOpaqueStreamError::NotPending,
    );

    let producer_guard = client.hold_request_producer_for_test();
    assert_eq!(
        client.try_execution_net_close(4, 7, 31).unwrap_err(),
        PolledExecutionRpcError::Busy,
        "execution submission also remains bounded on producer contention",
    );
    drop(producer_guard);
    let _execution = client.try_execution_net_close(4, 7, 32).unwrap();
    assert!(
        request_rx.try_recv().is_some(),
        "execution slot was cleared"
    );
}

#[test]
fn token_drop_never_waits_for_routing_lock_and_next_turn_lazily_reclaims_slot() {
    let (client, request_rx, response_tx) = client(32 * 1024);
    let retained = batch_for(0x26, 16);
    let submitted = batch_for(0x25, 16);
    let retained_pending = client.try_persist_opaque_stream_batch(&retained).unwrap();
    let pending = client.try_persist_opaque_stream_batch(&submitted).unwrap();
    let (_retained_identity, _) = decode_request(&request_rx);
    let (retired_identity, _) = decode_request(&request_rx);
    response_tx
        .try_send(&acknowledgement(retired_identity, &submitted))
        .unwrap();
    assert!(client
        .poll_persist_opaque_stream_batch(&retained_pending)
        .unwrap()
        .is_none());
    assert_eq!(client.stashed_response_count_for_test(), 1);

    let state_guard = client.hold_request_state_for_test();
    let (started_tx, started_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let dropper = thread::spawn(move || {
        started_tx.send(()).unwrap();
        drop(pending);
        finished_tx.send(()).unwrap();
    });
    started_rx.recv().unwrap();
    finished_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("persistence token Drop must not wait for request-state lock");
    drop(state_guard);
    dropper.join().unwrap();

    let successor = client
        .try_persist_opaque_stream_batch(&submitted)
        .expect("next reservation prunes and reuses the retired persistence slot");
    let (successor_identity, _) = decode_request(&request_rx);
    assert_eq!(
        client.stashed_response_count_for_test(),
        0,
        "lazy reclamation removes the exact retired stash entry",
    );
    response_tx
        .try_send(&acknowledgement(retired_identity, &submitted))
        .unwrap();
    response_tx
        .try_send(&acknowledgement(successor_identity, &submitted))
        .unwrap();
    assert_eq!(
        client.poll_persist_opaque_stream_batch(&successor).unwrap(),
        None,
        "late response remains inactive after lazy slot reclamation",
    );
    assert!(client
        .poll_persist_opaque_stream_batch(&successor)
        .unwrap()
        .is_some());
    drop(retained_pending);

    let execution = client.try_execution_net_close(4, 7, 41).unwrap();
    let execution_request = request_rx.try_recv().expect("execution request");
    let retired_execution_identity = rpc::decode_honest_request(&execution_request)
        .unwrap()
        .identity;
    let state_guard = client.hold_request_state_for_test();
    let (started_tx, started_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let dropper = thread::spawn(move || {
        started_tx.send(()).unwrap();
        drop(execution);
        finished_tx.send(()).unwrap();
    });
    started_rx.recv().unwrap();
    finished_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("execution token Drop must not wait for request-state lock");
    drop(state_guard);
    dropper.join().unwrap();

    let execution_successor = client
        .try_execution_net_close(4, 7, 42)
        .expect("next reservation prunes and reuses the retired execution slot");
    let execution_request = request_rx.try_recv().expect("successor execution request");
    let successor_execution_identity = rpc::decode_honest_request(&execution_request)
        .unwrap()
        .identity;
    response_tx
        .try_send(
            &rpc::encode_honest_response(retired_execution_identity, 0, &[])
                .expect("late execution response"),
        )
        .unwrap();
    response_tx
        .try_send(
            &rpc::encode_honest_response(successor_execution_identity, 0, &[])
                .expect("successor execution response"),
        )
        .unwrap();
    assert!(client
        .poll_execution_rpc(&execution_successor)
        .unwrap()
        .is_none());
    assert!(client
        .poll_execution_rpc(&execution_successor)
        .unwrap()
        .is_some());
    assert_eq!(
        client
            .abandon_execution_rpc(execution_successor)
            .unwrap_err(),
        PolledExecutionRpcError::NotPending,
        "an exact completion atomically retires the abandonment marker",
    );
}

#[test]
fn execution_abandonment_rejects_a_different_client_but_retires_the_origin_slot() {
    let (origin, origin_request_rx, _origin_response_tx) = client(16 * 1024);
    let (other, _other_request_rx, _other_response_tx) = client(16 * 1024);
    let pending = origin.try_execution_net_close(4, 7, 51).unwrap();
    assert!(origin_request_rx.try_recv().is_some());

    assert_eq!(
        other.abandon_execution_rpc(pending).unwrap_err(),
        PolledExecutionRpcError::NotPending,
        "a queue pair cannot claim another client's reservation",
    );

    let _successor = origin
        .try_execution_net_close(4, 7, 52)
        .expect("consuming the token still retires its exact origin slot");
    assert!(origin_request_rx.try_recv().is_some());
}
