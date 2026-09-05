// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Native contract tests for the enclave-side bounded RPC client.

use enclave_os_common::queue::{SpscConsumer, SpscProducer, SpscQueueHeader};
use enclave_os_common::rpc::{self, OpaqueStreamCodecError, PersistOpaqueStreamBatch};

#[path = "../../../enclave/src/rpc_client.rs"]
#[allow(dead_code)]
mod enclave_rpc_client;

use enclave_rpc_client::{PolledOpaqueStreamError, RpcClient};

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

#[test]
fn occupied_slot_short_circuits_before_validation_and_sends_nothing() {
    let (client, request_rx, _response_tx) = client(4096);
    let _pending = client.try_persist_opaque_stream_batch(&batch(16)).unwrap();

    let invalid = batch(0);
    assert_eq!(
        client
            .try_persist_opaque_stream_batch(&invalid)
            .unwrap_err(),
        PolledOpaqueStreamError::Busy
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

    client.try_persist_opaque_stream_batch(&batch(16)).unwrap();
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

    client.try_persist_opaque_stream_batch(&batch(16)).unwrap();
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

    client.try_persist_opaque_stream_batch(&batch(16)).unwrap();
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

    client.try_persist_opaque_stream_batch(&submitted).unwrap();
    assert!(
        request_rx.try_recv().is_some(),
        "acknowledgement released slot"
    );
}
