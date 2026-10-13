//! Exercise the real client with delayed host replies and overlapping callers.
#[allow(dead_code)]
#[path = "../../../enclave/src/rpc_client.rs"]
mod client;

#[path = "../../../enclave/src/ratls/retained_quote.rs"]
mod retained_quote;

use super::*;
use crate::queue::{SpscConsumer, SpscProducer, SpscQueueHeader};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

// Native ABI stubs supply scheduling hints only; no SGX OCALL bridge executes.
thread_local! {
    static WAIT_RESULT: std::cell::Cell<(u32, i32)> = const { std::cell::Cell::new((0, 0)) };
    static WAIT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
#[no_mangle]
extern "C" fn ocall_notify() -> u32 {
    0
}

#[no_mangle]
extern "C" fn ocall_notify_execution_waiter() -> u32 {
    0
}

#[no_mangle]
extern "C" fn ocall_wait_execution_response(result: *mut i32, maximum_micros: u64) -> u32 {
    assert!((1..=1_000).contains(&maximum_micros));
    WAIT_CALLS.with(|calls| calls.set(calls.get() + 1));
    let (transport, hint) = WAIT_RESULT.with(std::cell::Cell::get);
    if transport == 0 {
        // SAFETY: production caller supplies its writable local scalar result.
        unsafe {
            result.write(hint);
        }
    }
    transport
}

fn queue() -> (SpscProducer, SpscConsumer) {
    let header = Box::leak(Box::new(SpscQueueHeader::new(8192)));
    let bytes = Box::leak(vec![0; 8192].into_boxed_slice());
    // Both endpoints outlive the fixture threads and each has one active owner.
    unsafe {
        (
            SpscProducer::from_raw(header, bytes.as_mut_ptr()),
            SpscConsumer::from_raw(header, bytes.as_ptr()),
        )
    }
}

fn receive(queue: &SpscConsumer) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(bytes) = queue.try_recv() {
            return bytes;
        }
        assert!(Instant::now() < deadline, "missing fixture request");
        std::thread::yield_now();
    }
}

pub(super) fn check_synchronous_ownership() {
    check_actual_capacity_refusal();
    check_paid_qe_exchange();
    check_synchronous_pair(false);
    check_synchronous_pair(true);
    check_polled_owner();
    check_failed_acknowledgement();
    check_completion_wait();
    check_rejected_wait();
    check_worker_storage_reservation();
    check_ready_recheck();
}

fn check_actual_capacity_refusal() {
    let (tx, host_rx) = queue();
    let maximum = tx.max_message_bytes();
    let (host_tx, rx) = queue();
    let rpc = client::RpcClient::new(tx, rx);
    let too_large = vec![41; maximum];
    assert_eq!(rpc.kv_put(b"t", b"k", &too_large), Err(-22));
    assert!(host_rx.try_recv().is_none());
    assert!(matches!(
        rpc.try_execution_net_send(3, 8, 7, &too_large),
        Err(client::PolledExecutionRpcError::InvalidRequest),
    ));
    assert!(host_rx.try_recv().is_none());
    let host = std::thread::spawn(move || {
        let raw = receive(&host_rx);
        let (id, method, _) = decode_request(&raw).unwrap();
        assert_eq!(method, RpcMethod::KvPut);
        host_tx.send_bounded(&encode_response(id, 0, &[])).unwrap();
    });
    rpc.kv_put(b"t", b"k", b"real bounded value").unwrap();
    host.join().unwrap();
}

fn check_synchronous_pair(durable_first: bool) {
    // Hold an ordinary module call while another TCS attempts a journal read
    // and write. Neither may mistake local contention for a storage failure.
    let (tx, host_rx) = queue();
    let (host_tx, rx) = queue();
    let rpc = Arc::new(client::RpcClient::new(tx, rx));
    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let host = std::thread::spawn(move || {
        let request = receive(&host_rx);
        let (id, method, _) = decode_request(&request).unwrap();
        assert_eq!(
            method,
            if durable_first {
                RpcMethod::KvPutDurable
            } else {
                RpcMethod::GetCurrentTime
            }
        );
        held_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let payload = if durable_first {
            Vec::new()
        } else {
            encode_u64(123)
        };
        host_tx.send(&encode_response(id, 0, &payload));
        for (expected, status) in [(RpcMethod::KvGet, 1), (RpcMethod::KvPutDurable, 0)] {
            let request = receive(&host_rx);
            let (next, method, _) = decode_request(&request).unwrap();
            assert!(next > id);
            assert_eq!(method, expected);
            host_tx.send(&encode_response(next, status, &[]));
        }
        assert!(host_rx.try_recv().is_none());
    });
    let worker_rpc = Arc::clone(&rpc);
    let worker = std::thread::spawn(move || {
        if durable_first {
            worker_rpc
                .kv_put_durable(b"artifact", b"index", b"sealed")
                .map(|()| 123)
        } else {
            worker_rpc.get_current_time()
        }
    });
    held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let journal = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        let read = rpc.kv_get(b"honest.bft-runtime", b"journal");
        let write = rpc.kv_put_durable(b"honest.bft-runtime", b"journal", b"sealed");
        done_tx.send((read, write)).unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let waiting = done_rx.recv_timeout(Duration::from_millis(50));
    release_tx.send(()).unwrap();
    assert!(matches!(waiting, Err(mpsc::RecvTimeoutError::Timeout)));
    assert_eq!(worker.join().unwrap(), Ok(123));
    assert_eq!(
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        (Ok(None), Ok(()))
    );
    journal.join().unwrap();
    host.join().unwrap();
}

fn check_polled_owner() {
    let (tx, host_rx) = queue();
    let (host_tx, rx) = queue();
    let rpc = client::RpcClient::new(tx, rx);
    let pending = rpc.try_execution_net_close(1, 1, 7).unwrap();
    assert_eq!(rpc.kv_get(b"journal", b"key"), Err(-16));
    assert_eq!(rpc.kv_put_durable(b"journal", b"key", b"sealed"), Err(-16));
    let request = receive(&host_rx);
    let request = decode_honest_request(&request).unwrap();
    host_tx.send(&encode_honest_response(request.identity, 0, &[]).unwrap());
    assert_eq!(
        rpc.poll_execution_rpc(&pending).unwrap().unwrap().status(),
        0
    );
    assert!(host_rx.try_recv().is_none());
}

fn check_failed_acknowledgement() {
    for corrupt_id in [false, true] {
        let (tx, host_rx) = queue();
        let (host_tx, rx) = queue();
        let rpc = client::RpcClient::new(tx, rx);
        let host = std::thread::spawn(move || {
            let request = receive(&host_rx);
            let (id, method, _) = decode_request(&request).unwrap();
            assert_eq!(method, RpcMethod::KvPutDurable);
            host_tx.send(&encode_response(id + u64::from(corrupt_id), -5, &[]));
            assert!(host_rx.try_recv().is_none());
        });
        assert_eq!(
            rpc.kv_put_durable(b"journal", b"key", b"sealed"),
            Err(if corrupt_id { -1 } else { -5 })
        );
        host.join().unwrap();
    }
}

fn check_completion_wait() {
    for hint in [0, 1] {
        WAIT_RESULT.with(|value| value.set((0, hint)));
        let (tx, host_rx) = queue();
        let (host_tx, rx) = queue();
        let rpc = client::RpcClient::new(tx, rx);
        let pending = rpc.try_execution_net_close(3, 8, 7).unwrap();
        let request = receive(&host_rx);
        let identity = decode_honest_request(&request).unwrap().identity;
        assert!(rpc.poll_execution_rpc(&pending).unwrap().is_none());
        rpc.wait_execution_rpc(&pending, 1_000).unwrap();
        assert!(
            rpc.poll_execution_rpc(&pending).unwrap().is_none(),
            "host hint creates no response"
        );
        host_tx.send(&encode_honest_response(identity, 0, b"exact frame").unwrap());
        let result = rpc.poll_execution_rpc(&pending).unwrap().unwrap();
        assert_eq!(result.status(), 0);
        assert_eq!(result.payload(), b"exact frame");
        assert_eq!(
            rpc.wait_execution_rpc(&pending, 1_000),
            Err(client::PolledExecutionRpcError::NotPending)
        );
    }
    let (tx, host_rx) = queue();
    let (host_tx, rx) = queue();
    let rpc = client::RpcClient::new(tx, rx);
    let pending = rpc.try_execution_net_close(3, 8, 7).unwrap();
    let request = receive(&host_rx);
    let mut identity = decode_honest_request(&request).unwrap().identity;
    identity.operation_id += 1;
    host_tx.send(&encode_honest_response(identity, 0, &[]).unwrap());
    assert!(matches!(
        rpc.poll_execution_rpc(&pending),
        Err(client::PolledExecutionRpcError::UnexpectedResponse)
    ));
    assert_eq!(
        rpc.wait_execution_rpc(&pending, 1_000),
        Err(client::PolledExecutionRpcError::NotPending)
    );
    println!("EXECUTION-RPC-WAIT: exact token, empty hints, timeout hints, substituted identity PASS; native ABI stubs, SGX bridge separate");
}

fn check_rejected_wait() {
    for (transport, hint) in [(1, 0), (0, -1), (0, 2)] {
        WAIT_RESULT.with(|value| value.set((transport, hint)));
        let (tx, host_rx) = queue();
        let (_host_tx, rx) = queue();
        let rpc = client::RpcClient::new(tx, rx);
        let pending = rpc.try_execution_net_close(3, 8, 7).unwrap();
        receive(&host_rx);
        let before = WAIT_CALLS.with(std::cell::Cell::get);
        for maximum in [0, 1_001] {
            assert_eq!(
                rpc.wait_execution_rpc(&pending, maximum),
                Err(client::PolledExecutionRpcError::InvalidRequest)
            );
        }
        assert_eq!(WAIT_CALLS.with(std::cell::Cell::get), before);
        assert_eq!(
            rpc.wait_execution_rpc(&pending, 1_000),
            Err(client::PolledExecutionRpcError::WaitUnavailable)
        );
        assert!(rpc.poll_execution_rpc(&pending).unwrap().is_none());
        rpc.abandon_execution_rpc(pending).unwrap();
    }
    WAIT_RESULT.with(|value| value.set((0, 0)));
}

fn check_worker_storage_reservation() {
    check_get_batch_codec();
    assert!(!honest_role_allows_method(
        RpcRole::Control,
        RpcMethod::WorkerStorage
    ));
    assert!(!honest_role_allows_method(
        RpcRole::Execution,
        RpcMethod::KvPutDurable
    ));
    let (tx, host_rx) = queue();
    let (host_tx, rx) = queue();
    let rpc = client::RpcClient::new(tx, rx);
    let payload = encode_kv_get_req(b"honest.accepted-artifact-chunks-v1", b"exact scoped key");
    let pending = rpc
        .try_execution_storage(3, 8, WorkerStorageOperation::Get, &payload)
        .unwrap();
    assert!(matches!(
        rpc.try_execution_net_close(3, 8, 7),
        Err(client::PolledExecutionRpcError::Busy)
    ));
    let message = receive(&host_rx);
    let request = decode_honest_request(&message).unwrap();
    assert_eq!(request.identity.method, RpcMethod::WorkerStorage);
    assert_eq!(
        pending.diagnostic_operation_id(),
        request.identity.operation_id
    );
    assert_eq!(
        decode_worker_storage_request(request.payload),
        Some((WorkerStorageOperation::Get, payload.as_slice()))
    );
    host_tx.send(&encode_honest_response(request.identity, 0, b"sealed value").unwrap());
    assert_eq!(
        rpc.poll_execution_rpc(&pending).unwrap().unwrap().payload(),
        b"sealed value"
    );
    let network = rpc.try_execution_net_close(3, 8, 7).unwrap();
    let message = receive(&host_rx);
    let request = decode_honest_request(&message).unwrap();
    host_tx.send(&encode_honest_response(request.identity, 0, &[]).unwrap());
    rpc.poll_execution_rpc(&network).unwrap().unwrap();
    assert!(decode_worker_storage_request(&[255]).is_none());
    assert!(encode_worker_storage_request(
        WorkerStorageOperation::Get,
        &vec![0; MAX_HONEST_RPC_PAYLOAD_BYTES]
    )
    .is_err());
    let key = vec![7; MAX_WORKER_STORAGE_BATCH_KEY_BYTES];
    let framing = WORKER_STORAGE_BATCH_HEADER_BYTES
        + 1
        + WORKER_STORAGE_BATCH_RECORD_HEADER_BYTES
        + key.len();
    let value = vec![9; MAX_WORKER_STORAGE_BATCH_BYTES - framing + 1];
    for length in [value.len() - 2, value.len() - 1] {
        let records = [(key.as_slice(), &value[..length])];
        let wire = encode_worker_storage_put_batch(b"t", &records).unwrap();
        assert_eq!(
            worker_storage_put_batch_encoded_len(b"t", &records),
            Some(wire.len())
        );
        assert_eq!(decode_worker_storage_put_batch(&wire).unwrap().1, records);
        let mut trailing = wire;
        trailing.push(0);
        assert!(decode_worker_storage_put_batch(&trailing).is_none());
    }
    assert!(encode_worker_storage_put_batch(b"t", &[(key.as_slice(), value.as_slice())]).is_none());
    assert!(
        encode_worker_storage_put_batch(b"t", &[(vec![0; key.len() + 1].as_slice(), b"v")])
            .is_none()
    );
    assert!(worker_storage_put_batch_encoded_len(b"t", &[]).is_none());
    for count in [
        MAX_WORKER_STORAGE_BATCH_RECORDS - 1,
        MAX_WORKER_STORAGE_BATCH_RECORDS,
    ] {
        let records = vec![(b"k".as_slice(), b"v".as_slice()); count];
        let wire = encode_worker_storage_put_batch(b"t", &records).unwrap();
        assert_eq!(decode_worker_storage_put_batch(&wire).unwrap().1, records);
    }
    let excessive = vec![(b"k".as_slice(), b"v".as_slice()); MAX_WORKER_STORAGE_BATCH_RECORDS + 1];
    assert!(encode_worker_storage_put_batch(b"t", &excessive).is_none());
    println!("WORKER-STORAGE-RPC: actual framedtoken/role/size/nestedBusy/releasednetworkreservation PASS");
}

fn check_ready_recheck() {
    WAIT_CALLS.with(|value| value.set(0));
    let (tx, host_rx) = queue();
    let (host_tx, rx) = queue();
    let rpc = client::RpcClient::new(tx, rx);
    let pending = rpc
        .try_execution_storage(3, 8, WorkerStorageOperation::Get, b"bounded")
        .unwrap();
    let message = receive(&host_rx);
    let identity = decode_honest_request(&message).unwrap().identity;
    let mut empty = 0;
    let ready = rpc
        .recheck_execution_rpc_with(&pending, 64, || {
            empty += 1;
            if empty == 3 {
                host_tx.send(&encode_honest_response(identity, 0, b"ready sealed value").unwrap());
            }
        })
        .unwrap();
    assert_eq!(ready.0, 4, "only four actual polls consumed");
    let ready = ready.1.unwrap();
    assert_eq!(ready.payload(), b"ready sealed value");
    assert_eq!(empty, 3);
    assert_eq!(
        WAIT_CALLS.with(std::cell::Cell::get),
        0,
        "fast ready frame never parks or calls wait OCALL"
    );
    let pending = rpc.try_execution_net_close(3, 8, 7).unwrap();
    let message = receive(&host_rx);
    let identity = decode_honest_request(&message).unwrap().identity;
    let mut empty = 0;
    assert!(rpc
        .recheck_execution_rpc_with(&pending, 64, || empty += 1)
        .unwrap()
        .1
        .is_none());
    assert_eq!(
        empty,
        usize::try_from(client::EXECUTION_READY_RECHECK_POLLS).unwrap()
    );
    rpc.wait_execution_rpc(&pending, 1000).unwrap();
    assert_eq!(WAIT_CALLS.with(std::cell::Cell::get), 1);
    host_tx.send(&encode_honest_response(identity, 0, b"event completed").unwrap());
    assert_eq!(
        rpc.recheck_execution_rpc(&pending, 64)
            .unwrap()
            .1
            .unwrap()
            .payload(),
        b"event completed"
    );
    assert!(matches!(
        rpc.recheck_execution_rpc(&pending, 64),
        Err(client::PolledExecutionRpcError::NotPending)
    ));
    println!("EXECUTION-READY-RECHECK: actual exact queue fastcompletion skipsOCALL, finiteempty64 thenretainedwait, eventcompletion PASS");
}

fn check_get_batch_codec() {
    let capacity = crate::queue::max_message_bytes(crate::queue::DEFAULT_QUEUE_CAPACITY);
    let scope = [7; 32];
    let key = b"key".as_slice();
    let maximum = 128 * 1024 + 36 + 1024; // Independent existing canonical-node v2 vector.
    assert_eq!(
        worker_get_batch_response_demand(&[maximum; 8]),
        Some(1_057_090)
    );
    assert!(
        worker_get_batch_encoded_len(scope, b"t", &[(key, maximum); 8], capacity, capacity)
            .is_none()
    );
    let group = [(key, maximum); 7];
    let wire = encode_worker_get_batch(scope, b"t", &group, capacity, capacity).unwrap();
    let (count, length) =
        worker_get_batch_geometry(b"t", key.len(), maximum, capacity, capacity).unwrap();
    assert_eq!(count, group.len());
    assert_eq!(
        length,
        wire.len(),
        "size-only owner must match actual codec bytes"
    );
    assert_eq!(
        worker_get_batch_request_demand(b"t".len(), group.iter().map(|(key, _)| key.len())),
        Some(wire.len())
    );
    // Real maximum table/key/count encoding and heterogeneous keys exercise
    // the shared size owner, not a second handwritten length formula.
    let max_table = vec![b't'; MAX_WORKER_STORAGE_BATCH_TABLE_BYTES];
    let max_key = vec![b'k'; MAX_WORKER_STORAGE_BATCH_KEY_BYTES];
    let max_records = vec![(max_key.as_slice(), 1); MAX_WORKER_STORAGE_BATCH_RECORDS];
    let max_encoded =
        encode_worker_get_batch(scope, &max_table, &max_records, capacity, capacity).unwrap();
    assert_eq!(
        worker_get_batch_request_demand(
            max_table.len(),
            max_records.iter().map(|(key, _)| key.len())
        ),
        Some(max_encoded.len())
    );
    assert_eq!(
        decode_worker_get_batch(&max_encoded, capacity, capacity)
            .unwrap()
            .2,
        max_records
    );
    let mixed = [(key, 1), (max_key.as_slice(), 1)];
    let mixed_encoded = encode_worker_get_batch(scope, b"t", &mixed, capacity, capacity).unwrap();
    assert_eq!(
        worker_get_batch_request_demand(1, mixed.iter().map(|(key, _)| key.len())),
        Some(mixed_encoded.len())
    );
    assert!(worker_get_batch_request_demand(0, [key.len()]).is_none());
    assert!(worker_get_batch_request_demand(usize::MAX, [key.len()]).is_none());
    assert!(worker_get_batch_request_demand(1, core::iter::empty()).is_none());
    assert!(worker_get_batch_request_demand(1, [0]).is_none());
    assert!(worker_get_batch_request_demand(1, [usize::MAX]).is_none());
    assert!(worker_get_batch_request_demand(
        1,
        core::iter::repeat_n(key.len(), MAX_WORKER_STORAGE_BATCH_RECORDS + 1)
    )
    .is_none());

    for count in [
        MAX_WORKER_STORAGE_BATCH_RECORDS - 1,
        MAX_WORKER_STORAGE_BATCH_RECORDS,
    ] {
        let records = vec![(key, 5); count];
        let encoded = encode_worker_get_batch(scope, b"t", &records, capacity, capacity).unwrap();
        assert_eq!(
            decode_worker_get_batch(&encoded, capacity, capacity)
                .unwrap()
                .2,
            records
        );
    }
    let excessive = vec![(key, 5); MAX_WORKER_STORAGE_BATCH_RECORDS + 1];
    assert!(encode_worker_get_batch(scope, b"t", &excessive, capacity, capacity).is_none());
    assert!(worker_get_batch_geometry(b"", key.len(), 5, capacity, capacity).is_none());
    assert!(worker_get_batch_geometry(b"t", 0, 5, capacity, capacity).is_none());
    assert!(worker_get_batch_geometry(b"t", usize::MAX, 5, capacity, capacity).is_none());
    assert!(worker_get_batch_geometry(b"t", key.len(), usize::MAX, capacity, capacity).is_none());
    assert!(worker_get_batch_geometry(b"t", key.len(), 5, 0, capacity).is_none());
    let (decoded_scope, table, requests) =
        decode_worker_get_batch(&wire, capacity, capacity).unwrap();
    assert_eq!(decoded_scope, scope);
    assert_eq!(table, b"t");
    assert_eq!(requests, group);
    for cut in 0..wire.len() {
        assert!(decode_worker_get_batch(&wire[..cut], capacity, capacity).is_none());
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(decode_worker_get_batch(&trailing, capacity, capacity).is_none());
    assert!(encode_worker_get_batch([0; 32], b"t", &group, capacity, capacity).is_none());
    assert!(worker_get_batch_encoded_len(scope, b"t", &[(key, 0)], capacity, capacity).is_none());
    let value = [9; 5];
    let reply = encode_worker_get_batch_response(&[&value, &value], &[5, 5], capacity).unwrap();
    assert_eq!(
        decode_worker_get_batch_response(&reply, &[5, 5]).unwrap(),
        [value.as_slice(), value.as_slice()]
    );
    for cut in 0..reply.len() {
        assert!(decode_worker_get_batch_response(&reply[..cut], &[5, 5]).is_none());
    }
    assert!(decode_worker_get_batch_response(&reply, &[4, 5]).is_none());
    let mut tail = reply;
    tail.push(0);
    assert!(decode_worker_get_batch_response(&tail, &[5, 5]).is_none());
    let request_length =
        worker_get_batch_encoded_len(scope, b"t", &[(key, 5)], capacity, capacity).unwrap();
    let request_frame = request_length + 1 + HONEST_REQ_HEADER_SIZE;
    let reply_frame = 2 + 4 + 5 + HONEST_RESP_HEADER_SIZE;
    assert_eq!(
        worker_get_batch_geometry(b"t", key.len(), 5, request_frame, reply_frame),
        Some((1, request_length))
    );
    assert_eq!(
        worker_get_batch_geometry(b"t", key.len(), 5, request_frame + 1, reply_frame),
        Some((1, request_length))
    );
    assert_eq!(
        worker_get_batch_geometry(b"t", key.len(), 5, request_frame, reply_frame + 1),
        Some((1, request_length))
    );
    assert_eq!(
        worker_get_batch_geometry(b"t", key.len(), 5, request_frame + 1, reply_frame + 1),
        Some((1, request_length))
    );
    assert!(
        worker_get_batch_geometry(b"t", key.len(), 5, request_frame - 1, reply_frame).is_none()
    );
    assert!(
        worker_get_batch_geometry(b"t", key.len(), 5, request_frame, reply_frame - 1).is_none()
    );
    assert!(
        worker_get_batch_encoded_len(scope, b"t", &[(key, 5)], request_frame, reply_frame)
            .is_some()
    );
    assert!(
        worker_get_batch_encoded_len(scope, b"t", &[(key, 5)], request_frame - 1, reply_frame)
            .is_none()
    );
    assert!(
        worker_get_batch_encoded_len(scope, b"t", &[(key, 5)], request_frame, reply_frame - 1)
            .is_none()
    );
}

fn check_paid_qe_exchange() {
    use crate::allocation::{AllocationPoolV1, SharedAllocationV1};
    let (tx, host_rx) = queue();
    let (host_tx, rx) = queue();
    let rpc = Arc::new(client::RpcClient::new(tx, rx));
    let report = b"original-report-bytes";
    let working = rpc.qe_working_bytes(report.len()).unwrap();
    let short = AllocationPoolV1::new(working - 1).unwrap();
    assert_eq!(rpc.with_qe_quote(&short, report, |_| Ok(())), Err(-12));
    assert_eq!(short.used(), 0);
    assert!(host_rx.try_recv().is_none());
    assert!(rpc.qe_working_bytes(usize::MAX).is_none());
    let quote = b"actual-opaque-host-quote";
    let retained = SharedAllocationV1::<Vec<u8>>::required_bytes(quote.len()).unwrap();
    let pool = AllocationPoolV1::new(working + retained).unwrap();
    let child_pool = pool.clone();
    let child_rpc = rpc.clone();
    let job = std::thread::spawn(move || {
        child_rpc.with_qe_quote(&child_pool, report, |bytes| {
            assert_eq!(child_pool.used(), working);
            retained_quote::RetainedQuote::copy_from(&child_pool, bytes).ok_or(-12)
        })
    });
    let request = receive(&host_rx);
    let (id, method, payload) = decode_request(&request).unwrap();
    assert_eq!(method, RpcMethod::QeGetQuote);
    assert_eq!(payload, report);
    assert_eq!(request, encode_request(id, method, report));
    // Original malformed/wrong-ID wait behavior remains; no fresh operation.
    host_tx.send(&[0]);
    host_tx.send(&encode_response(id + 1, 0, quote));
    host_tx.send(&encode_response(id, 0, quote));
    let held = job.join().unwrap().unwrap();
    assert_eq!(held.bytes(), quote);
    assert_eq!(pool.used(), retained);
    let alias = held.clone();
    drop(held);
    assert_eq!(pool.used(), retained);
    drop(alias);
    assert_eq!(pool.used(), 0);
    let required = rpc.qe_working_bytes(0).unwrap();
    for maximum in [required, required + 1] {
        let pool = AllocationPoolV1::new(maximum).unwrap();
        let child_pool = pool.clone();
        let child_rpc = rpc.clone();
        let job = std::thread::spawn(move || {
            child_rpc.with_qe_target_info(&child_pool, |bytes| {
                assert_eq!(child_pool.used(), required);
                Ok(bytes.len())
            })
        });
        let request = receive(&host_rx);
        let (id, method, payload) = decode_request(&request).unwrap();
        assert_eq!(method, RpcMethod::QeGetTargetInfo);
        assert!(payload.is_empty());
        host_tx.send(&encode_response(id, 0, b"fixed-target"));
        assert_eq!(job.join().unwrap(), Ok(b"fixed-target".len()));
        assert_eq!(pool.used(), 0);
    }
    // A callback may issue a second real request while the outer response
    // remains borrowed. Admit both working buffers and the retained quote.
    let outer_working = rpc.qe_working_bytes(0).unwrap();
    let nested_working = rpc.qe_working_bytes(report.len()).unwrap();
    let maximum = outer_working
        .checked_add(nested_working)
        .and_then(|bytes| bytes.checked_add(retained))
        .unwrap();
    let pool = AllocationPoolV1::new(maximum).unwrap();
    let child_pool = pool.clone();
    let child_rpc = rpc.clone();
    let job = std::thread::spawn(move || {
        child_rpc.with_qe_target_info(&child_pool, |outer| {
            assert_eq!(outer, b"outer-target");
            assert_eq!(child_pool.used(), outer_working);
            let quote = child_rpc.with_qe_quote(&child_pool, report, |bytes| {
                assert_eq!(child_pool.used(), outer_working + nested_working);
                retained_quote::RetainedQuote::copy_from(&child_pool, bytes).ok_or(-12)
            })?;
            assert_eq!(outer, b"outer-target");
            assert_eq!(child_pool.used(), outer_working + retained);
            Ok(quote)
        })
    });
    let outer_request = receive(&host_rx);
    let (outer_id, method, payload) = decode_request(&outer_request).unwrap();
    assert_eq!(method, RpcMethod::QeGetTargetInfo);
    assert!(payload.is_empty());
    host_tx.send(&encode_response(outer_id, 0, b"outer-target"));
    let nested_request = receive(&host_rx);
    let (nested_id, method, payload) = decode_request(&nested_request).unwrap();
    assert_ne!(nested_id, outer_id);
    assert_eq!(method, RpcMethod::QeGetQuote);
    assert_eq!(payload, report);
    assert_eq!(nested_request, encode_request(nested_id, method, report));
    host_tx.send(&encode_response(nested_id, 0, quote));
    let held = job.join().unwrap().unwrap();
    assert_eq!(held.bytes(), quote);
    assert_eq!(pool.used(), retained);
    drop(held);
    assert_eq!(pool.used(), 0);
    // The real queue refuses short output before copying/consuming the frame.
    let mut short = [42; 8];
    let (send, receive) = queue();
    send.send(b"unchanged");
    let positions = send.diagnostic_positions();
    assert_eq!(receive.try_recv_into(&mut short), Err(9));
    assert_eq!(short, [42; 8]);
    assert_eq!(send.diagnostic_positions(), positions);
    let mut exact = [0; 9];
    assert_eq!(receive.try_recv_into(&mut exact), Ok(Some(9)));
    assert_eq!(&exact, b"unchanged");
}
