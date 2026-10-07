//! Exercise the real client with delayed host replies and overlapping callers.
#[allow(dead_code)]
#[path = "../../../enclave/src/rpc_client.rs"]
mod client;

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
    check_synchronous_pair(false);
    check_synchronous_pair(true);
    check_polled_owner();
    check_failed_acknowledgement();
    check_completion_wait();
    check_rejected_wait();
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
