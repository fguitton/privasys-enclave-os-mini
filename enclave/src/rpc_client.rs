// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Enclave-side RPC client.
//!
//! Wraps the SPSC queues to provide typed host calls. Legacy Mini services use
//! the synchronous interface. Honest's execution networking uses a separate
//! polled interface: submission performs one `try_send`, and each poll performs
//! at most one `try_recv`. BFT sealed-state persistence uses durable KV.
//!
//! This replaces all the individual OCALL wrappers with a single
//! message-passing channel.

use core::sync::atomic::{AtomicU64, Ordering};
use std::string::String;
use std::sync::Mutex;
use std::vec::Vec;

use enclave_os_common::queue::{SpscConsumer, SpscProducer};
use enclave_os_common::rpc::{self, HonestRpcFrameError, HonestRpcIdentity, RpcMethod, RpcRole};

// One backing primitive shared by this transport boundary and sealed configuration.
#[path = "sealed_config/backing.rs"]
pub(crate) mod config_buffer;

/// Opaque host-stored key/value pairs returned by a bounded scan.
pub type KvEntries = Vec<(Vec<u8>, Vec<u8>)>;

/// Move-only response retaining its actual original-pool frame backing.
/// The payload is a read-only range; no Global payload copy is returned.
pub(crate) struct ConfigResponse {
    frame: config_buffer::ConfigBytes,
    payload: core::ops::Range<usize>,
}
impl ConfigResponse {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.frame[self.payload.clone()]
    }
}

// ---------------------------------------------------------------------------
//  External: queue notification and bounded completion hints
// ---------------------------------------------------------------------------

extern "C" {
    fn ocall_notify() -> u32;
    fn ocall_notify_execution_waiter() -> u32;
    fn ocall_wait_execution_response(result: *mut i32, maximum_micros: u64) -> u32;
}

/// Notify the host that there is a pending request.
#[inline]
fn notify_host() {
    unsafe {
        ocall_notify();
    }
}

/// Wake an execution response waiter after a trusted fence/stop publication.
/// This carries no epoch or authority; exact response and fence checks remain
/// mandatory on return. No spare enclave TCS is needed for host completion.
pub fn notify_execution_waiter() {
    // SAFETY: no pointers or payload; pinned generated EDL notification bridge.
    unsafe {
        ocall_notify_execution_waiter();
    }
}

// ---------------------------------------------------------------------------
//  RPC client state
// ---------------------------------------------------------------------------

/// Global request ID counter (monotonically increasing).
static NEXT_REQ_ID: AtomicU64 = AtomicU64::new(1);
/// Maximum queue polls in one immediate execution readiness turn.
pub const EXECUTION_READY_RECHECK_POLLS: u64 = 64;

fn next_req_id() -> Option<u64> {
    NEXT_REQ_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .ok()
        .filter(|request_id| *request_id != 0)
}

/// Enclave-side RPC client for calling host services.
pub struct RpcClient {
    /// Legacy module calls and BFT persistence can originate on different TCSs.
    /// Serialize complete synchronous exchanges, including response ownership.
    /// Polled execution operations still use the non-blocking reservation below.
    synchronous_exchange: Mutex<()>,
    /// Sends requests to the host.
    request_tx: SpscProducer,
    /// Receives responses from the host.
    response_rx: SpscConsumer,
    /// Zero when idle, otherwise the only request allowed on these SPSC
    /// endpoints. This prevents a legacy synchronous call from stealing the
    /// response of a polled control operation.
    in_flight_request_id: AtomicU64,
}

// Request encoding and raw response coexist. The decoded payload is borrowed;
// a callback that retains it must admit its own child before copying.
#[cfg(all(not(feature = "mock"), not(feature = "sgx-sim-attestation")))]
struct QeWorking {
    request: Vec<u8>,
    response: Vec<u8>,
    _allocation: enclave_os_common::allocation::AllocationLeaseV1,
}
#[cfg(all(not(feature = "mock"), not(feature = "sgx-sim-attestation")))]
impl QeWorking {
    fn new(
        pool: &std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
        request: usize,
        response: usize,
    ) -> Option<Self> {
        let allocation = pool.reserve_unpublished(request.checked_add(response)?)?;
        let mut request_bytes = Vec::new();
        request_bytes.try_reserve_exact(request).ok()?;
        if request_bytes.capacity() != request {
            return None;
        }
        let mut response_bytes = Vec::new();
        response_bytes.try_reserve_exact(response).ok()?;
        if response_bytes.capacity() != response {
            return None;
        }
        response_bytes.resize(response, 0);
        allocation.activate_release_notification();
        Some(Self {
            request: request_bytes,
            response: response_bytes,
            _allocation: allocation,
        })
    }
}

/// Token owned by the execution worker while one host operation is in flight.
///
/// Its complete framed identity is private; only the submitting client may
/// poll it.
#[derive(Debug)]
pub struct PendingExecutionRpc {
    identity: HonestRpcIdentity,
}

impl PendingExecutionRpc {
    /// Inert diagnostic join key; exposes no polling or submission authority.
    pub const fn diagnostic_operation_id(&self) -> u64 {
        self.identity.operation_id
    }
}

/// One bounded execution response returned by a single non-blocking poll.
#[derive(Debug)]
pub struct ExecutionRpcCompletion {
    status: i32,
    payload: Vec<u8>,
}

impl ExecutionRpcCompletion {
    #[must_use]
    pub const fn status(&self) -> i32 {
        self.status
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Move already validated response bytes without a second payload copy.
    #[must_use]
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

/// Fail-closed errors from the role-owned execution submit/poll interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolledExecutionRpcError {
    MethodDenied,
    InvalidRequest,
    Busy,
    OperationIdExhausted,
    QueueFull,
    NotPending,
    MalformedResponse,
    UnexpectedResponse,
    WaitUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestReserveError {
    Busy,
    OperationIdExhausted,
}

// The exact-size callback may refuse after request publication. Keep the
// existing reservation through the whole exchange and release on every exit.
struct RequestReservation<'a> {
    client: &'a RpcClient,
    id: u64,
}
impl Drop for RequestReservation<'_> {
    fn drop(&mut self) {
        self.client.release_request(self.id);
    }
}

// SAFETY: RpcClient uses SPSC queues backed by shared memory pointers.
// Complete synchronous exchanges are serialized. Polled operations reserve the
// endpoints atomically and have a single owning execution thread.
// The raw pointers inside SpscProducer/SpscConsumer point to host memory
// that remains valid for the enclave's lifetime.
unsafe impl Send for RpcClient {}
unsafe impl Sync for RpcClient {}

impl RpcClient {
    /// Create a client from the queue endpoints.
    ///
    /// - `request_tx`: producer for `enc_to_host` (enclave writes, host reads)
    /// - `response_rx`: consumer for `host_to_enc` (host writes, enclave reads)
    pub fn new(request_tx: SpscProducer, response_rx: SpscConsumer) -> Self {
        Self {
            synchronous_exchange: Mutex::new(()),
            request_tx,
            response_rx,
            in_flight_request_id: AtomicU64::new(0),
        }
    }

    /// Immutable endpoint sizes; metadata grants no IO or owner authority.
    pub fn queue_geometry(&self) -> (usize, usize) {
        (
            self.request_tx.max_message_bytes(),
            self.response_rx.max_message_bytes(),
        )
    }

    fn try_reserve_request(&self) -> Result<u64, RequestReserveError> {
        let request_id = next_req_id().ok_or(RequestReserveError::OperationIdExhausted)?;
        self.in_flight_request_id
            .compare_exchange(0, request_id, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| request_id)
            .map_err(|_| RequestReserveError::Busy)
    }

    fn release_request(&self, request_id: u64) {
        let _ = self.in_flight_request_id.compare_exchange(
            request_id,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    // ====================================================================
    //  Polled execution-plane networking
    // ====================================================================

    fn try_execution_request(
        &self,
        node_id: u64,
        node_generation: u64,
        method: RpcMethod,
        payload: &[u8],
    ) -> Result<PendingExecutionRpc, PolledExecutionRpcError> {
        if !rpc::honest_role_allows_method(RpcRole::Execution, method) {
            return Err(PolledExecutionRpcError::MethodDenied);
        }
        if !rpc::framed_payload_len_valid(
            payload.len(),
            rpc::HONEST_REQ_HEADER_SIZE,
            self.request_tx.max_message_bytes(),
        ) {
            return Err(PolledExecutionRpcError::InvalidRequest);
        }
        let operation_id = self.try_reserve_request().map_err(|error| match error {
            RequestReserveError::Busy => PolledExecutionRpcError::Busy,
            RequestReserveError::OperationIdExhausted => {
                PolledExecutionRpcError::OperationIdExhausted
            }
        })?;
        let identity = HonestRpcIdentity {
            role: RpcRole::Execution,
            node_id,
            node_generation,
            operation_id,
            method,
        };
        let message = rpc::encode_honest_request(identity, payload).map_err(|_| {
            self.release_request(operation_id);
            PolledExecutionRpcError::InvalidRequest
        })?;
        if self.request_tx.try_send(&message).is_err() {
            self.release_request(operation_id);
            return Err(PolledExecutionRpcError::QueueFull);
        }
        notify_host();
        Ok(PendingExecutionRpc { identity })
    }

    /// Try to submit one execution-owned non-blocking connect.
    pub fn try_execution_net_tcp_connect(
        &self,
        node_id: u64,
        node_generation: u64,
        host: &str,
        port: u16,
    ) -> Result<PendingExecutionRpc, PolledExecutionRpcError> {
        self.try_execution_request(
            node_id,
            node_generation,
            RpcMethod::NetTcpConnect,
            &rpc::encode_net_tcp_connect_req(host, port),
        )
    }

    /// Try to submit one execution-owned bounded send.
    pub fn try_execution_net_send(
        &self,
        node_id: u64,
        node_generation: u64,
        fd: i32,
        bytes: &[u8],
    ) -> Result<PendingExecutionRpc, PolledExecutionRpcError> {
        self.try_execution_request(
            node_id,
            node_generation,
            RpcMethod::NetSend,
            &rpc::encode_net_send_req(fd, bytes),
        )
    }

    /// Submit one explicitly execution-owned private storage operation. It
    /// reserves the same worker endpoint as network I/O, so nesting is Busy.
    pub fn try_execution_storage(
        &self,
        node_id: u64,
        node_generation: u64,
        operation: rpc::WorkerStorageOperation,
        payload: &[u8],
    ) -> Result<PendingExecutionRpc, PolledExecutionRpcError> {
        let payload = rpc::encode_worker_storage_request(operation, payload)
            .map_err(|_| PolledExecutionRpcError::InvalidRequest)?;
        self.try_execution_request(node_id, node_generation, RpcMethod::WorkerStorage, &payload)
    }

    /// Try to submit one execution-owned bounded receive.
    pub fn try_execution_net_recv(
        &self,
        node_id: u64,
        node_generation: u64,
        fd: i32,
        maximum_length: u32,
    ) -> Result<PendingExecutionRpc, PolledExecutionRpcError> {
        self.try_execution_request(
            node_id,
            node_generation,
            RpcMethod::NetRecv,
            &rpc::encode_net_recv_req(fd, maximum_length),
        )
    }

    /// Try to submit one execution-owned socket close.
    pub fn try_execution_net_close(
        &self,
        node_id: u64,
        node_generation: u64,
        fd: i32,
    ) -> Result<PendingExecutionRpc, PolledExecutionRpcError> {
        self.try_execution_request(
            node_id,
            node_generation,
            RpcMethod::NetClose,
            &rpc::encode_net_close_req(fd),
        )
    }

    /// Poll one exact execution operation without waiting.
    ///
    /// A response with any substituted role, generation, operation or method
    /// consumes and terminates the operation fail-closed.
    pub fn poll_execution_rpc(
        &self,
        pending: &PendingExecutionRpc,
    ) -> Result<Option<ExecutionRpcCompletion>, PolledExecutionRpcError> {
        if self.in_flight_request_id.load(Ordering::Acquire) != pending.identity.operation_id {
            return Err(PolledExecutionRpcError::NotPending);
        }
        let Some(raw_response) = self.response_rx.try_recv() else {
            return Ok(None);
        };
        self.release_request(pending.identity.operation_id);
        let response =
            rpc::decode_honest_response_for(&raw_response, pending.identity).map_err(|error| {
                match error {
                    HonestRpcFrameError::UnexpectedIdentity => {
                        PolledExecutionRpcError::UnexpectedResponse
                    }
                    _ => PolledExecutionRpcError::MalformedResponse,
                }
            })?;
        Ok(Some(ExecutionRpcCompletion {
            status: response.status,
            payload: response.payload.to_vec(),
        }))
    }

    /// A finite immediate readiness turn before host parking. The count is
    /// actual queue reads; callers reserve the maximum before entering and may
    /// refund only reads that were never attempted. Errors retain all charges.
    pub fn recheck_execution_rpc(
        &self,
        pending: &PendingExecutionRpc,
        maximum_polls: u64,
    ) -> Result<(u64, Option<ExecutionRpcCompletion>), PolledExecutionRpcError> {
        self.recheck_execution_rpc_with(pending, maximum_polls, core::hint::spin_loop)
    }

    pub(crate) fn recheck_execution_rpc_with(
        &self,
        pending: &PendingExecutionRpc,
        maximum_polls: u64,
        mut empty: impl FnMut(),
    ) -> Result<(u64, Option<ExecutionRpcCompletion>), PolledExecutionRpcError> {
        if maximum_polls == 0 || maximum_polls > EXECUTION_READY_RECHECK_POLLS {
            return Err(PolledExecutionRpcError::InvalidRequest);
        }
        for polls in 1..=maximum_polls {
            if let Some(completion) = self.poll_execution_rpc(pending)? {
                return Ok((polls, Some(completion)));
            }
            empty();
        }
        Ok((maximum_polls, None))
    }

    /// Wait only for an untrusted retained publication hint. The caller polls
    /// the exact pending frame before and after this call and rechecks its fence.
    /// No response bytes, completion identity or authority come from this OCALL.
    pub fn wait_execution_rpc(
        &self,
        pending: &PendingExecutionRpc,
        maximum_micros: u64,
    ) -> Result<(), PolledExecutionRpcError> {
        if self.in_flight_request_id.load(Ordering::Acquire) != pending.identity.operation_id {
            return Err(PolledExecutionRpcError::NotPending);
        }
        if maximum_micros == 0 || maximum_micros > 1_000 {
            return Err(PolledExecutionRpcError::InvalidRequest);
        }
        let mut result = -1;
        // SAFETY: writable local result, scalar bounded interval, pinned EDL.
        let status = unsafe { ocall_wait_execution_response(&mut result, maximum_micros) };
        if status == 0 && matches!(result, 0 | 1) {
            Ok(())
        } else {
            Err(PolledExecutionRpcError::WaitUnavailable)
        }
    }

    /// Abandon one exact execution operation after its committed fence or
    /// local budget expires.
    ///
    /// A late response remains framed with the abandoned identity. A future
    /// operation can consume it only as an explicit `UnexpectedResponse`;
    /// it can never be accepted for the new operation.
    pub fn abandon_execution_rpc(
        &self,
        pending: PendingExecutionRpc,
    ) -> Result<(), PolledExecutionRpcError> {
        self.in_flight_request_id
            .compare_exchange(
                pending.identity.operation_id,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| PolledExecutionRpcError::NotPending)
    }

    // ====================================================================
    //  Core RPC call
    // ====================================================================

    /// Send an RPC request and wait for the matching response.
    ///
    /// Returns `(status, payload)` from the host's response.
    fn call(&self, method: RpcMethod, payload: &[u8]) -> (i32, Vec<u8>) {
        if !rpc::framed_payload_len_valid(
            payload.len(),
            rpc::REQ_HEADER_SIZE,
            self.request_tx.max_message_bytes(),
        ) {
            return (-22, Vec::new());
        }
        let Ok(_exchange) = self.synchronous_exchange.lock() else {
            return (-1, Vec::new());
        };
        let req_id = match self.try_reserve_request() {
            Ok(request_id) => request_id,
            // A polled execution operation owns its response across calls.
            // Never wait for or consume that operation's response here.
            Err(RequestReserveError::Busy) => return (-16, Vec::new()),
            Err(RequestReserveError::OperationIdExhausted) => return (-75, Vec::new()),
        };
        let Some(msg) = rpc::encode_request_bounded(
            req_id,
            method,
            payload,
            self.request_tx.max_message_bytes(),
        ) else {
            self.release_request(req_id);
            return (-22, Vec::new());
        };

        if self.request_tx.send_bounded(&msg).is_err() {
            self.release_request(req_id);
            return (-22, Vec::new());
        }

        // Wake the host dispatcher
        notify_host();

        // Wait for response
        loop {
            let resp_raw = self.response_rx.recv();
            if let Some((resp_id, status, resp_payload)) = rpc::decode_response(&resp_raw) {
                if resp_id == req_id {
                    self.release_request(req_id);
                    return (status, resp_payload.to_vec());
                }
                // Mismatched ID – shouldn't happen in SPSC, but be safe
                // In a single-threaded enclave, responses arrive in order.
            }
            // Malformed response – try again
        }
    }

    /// The config persistence exchange uses the existing synchronous request
    /// reservation/queue/ID codec with caller-admitted request/response backing.
    fn call_config(
        &self,
        pool: &std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
        method: RpcMethod,
        parts: &[&[u8]],
    ) -> Result<(i32, ConfigResponse), i32> {
        let payload_len = parts
            .iter()
            .try_fold(0_usize, |length, part| length.checked_add(part.len()))
            .ok_or(-22)?;
        let request_maximum = self.request_tx.max_message_bytes();
        if !rpc::framed_payload_len_valid(payload_len, rpc::REQ_HEADER_SIZE, request_maximum) {
            return Err(-22);
        }
        let frame_len = rpc::REQ_HEADER_SIZE.checked_add(payload_len).ok_or(-22)?;
        let _exchange = self.synchronous_exchange.lock().map_err(|_| -1)?;
        let request_id = self.try_reserve_request().map_err(|error| match error {
            RequestReserveError::Busy => -16,
            RequestReserveError::OperationIdExhausted => -75,
        })?;
        let result =
            self.exchange_config(pool, request_id, method, parts, frame_len, request_maximum);
        self.release_request(request_id);
        result
    }

    // One current supplied-buffer exchange, shared by the real reservation
    // owner and its existing signed fixture. It neither creates IDs nor grants
    // any host persistence or application authority.
    fn exchange_config(
        &self,
        pool: &std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
        request_id: u64,
        method: RpcMethod,
        parts: &[&[u8]],
        frame_len: usize,
        request_maximum: usize,
    ) -> Result<(i32, ConfigResponse), i32> {
        (|| {
            let origin = config_buffer::ConfigAllocator::try_new(pool).map_err(|_| -12)?;
            let mut request = origin.try_zeroed(frame_len).map_err(|_| -12)?;
            // This response queue's actual usable maximum owns the complete
            // receive storage admitted before a request can be published.
            let mut response = origin
                .try_zeroed(self.response_rx.max_message_bytes())
                .map_err(|_| -12)?;
            let length = rpc::encode_request_parts_into_bounded(
                request_id,
                method,
                parts,
                request_maximum,
                request.as_mut_slice(),
            )
            .ok_or(-22)?;
            if self.request_tx.send_bounded(&request[..length]).is_err() {
                return Err(-22);
            }
            notify_host();
            loop {
                let Some(length) = self
                    .response_rx
                    .try_recv_into(response.as_mut_slice())
                    .map_err(|_| -22)?
                else {
                    std::thread::yield_now();
                    continue;
                };
                if let Some((response_id, status, payload)) =
                    rpc::decode_response(&response[..length])
                {
                    if response_id == request_id {
                        let end = rpc::RESP_HEADER_SIZE
                            .checked_add(payload.len())
                            .ok_or(-22)?;
                        response.activate_release_notification();
                        return Ok((
                            status,
                            ConfigResponse {
                                frame: response,
                                payload: rpc::RESP_HEADER_SIZE..end,
                            },
                        ));
                    }
                }
                // Preserve the current malformed/mismatched reply discard and
                // retry behavior, reusing the same admitted response backing.
            }
        })()
    }

    pub(crate) fn config_kv_get(
        &self,
        pool: &std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
        table: &[u8],
        key: &[u8],
    ) -> Result<Option<ConfigResponse>, i32> {
        let table_len = u16::try_from(table.len()).map_err(|_| -22)?.to_le_bytes();
        let (status, response) =
            self.call_config(pool, RpcMethod::KvGet, &[&table_len, table, key])?;
        match status {
            0 => Ok(Some(response)),
            1 => Ok(None),
            other => Err(other),
        }
    }

    pub(crate) fn config_kv_put(
        &self,
        pool: &std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
        table: &[u8],
        key: &[u8],
        value: &[u8],
    ) -> Result<(), i32> {
        let table_len = u16::try_from(table.len()).map_err(|_| -22)?.to_le_bytes();
        let key_len = u32::try_from(key.len()).map_err(|_| -22)?.to_le_bytes();
        let (status, _) = self.call_config(
            pool,
            RpcMethod::KvPut,
            &[&table_len, table, &key_len, key, value],
        )?;
        if status == 0 {
            Ok(())
        } else {
            Err(status)
        }
    }

    // ====================================================================
    //  Network calls
    // ====================================================================

    /// Create a TCP listener on `port` with `backlog`. Returns fd.
    pub fn net_tcp_listen(&self, port: u16, backlog: i32) -> Result<i32, i32> {
        let payload = rpc::encode_net_tcp_listen_req(port, backlog);
        let (status, resp) = self.call(RpcMethod::NetTcpListen, &payload);
        if status == 0 {
            Ok(rpc::decode_fd(&resp).unwrap_or(-1))
        } else {
            Err(status)
        }
    }

    /// Accept a connection on listener `fd`. Returns (client_fd, peer_addr).
    pub fn net_tcp_accept(&self, listener_fd: i32) -> Result<(i32, String), i32> {
        let payload = rpc::encode_net_tcp_accept_req(listener_fd);
        let (status, resp) = self.call(RpcMethod::NetTcpAccept, &payload);
        if status == 0 {
            match rpc::decode_net_tcp_accept_resp(&resp) {
                Some((fd, addr)) => Ok((fd, addr)),
                None => Err(-1),
            }
        } else {
            Err(status)
        }
    }

    /// Connect to `host:port`. Returns fd.
    pub fn net_tcp_connect(&self, host: &str, port: u16) -> Result<i32, i32> {
        let payload = rpc::encode_net_tcp_connect_req(host, port);
        let (status, resp) = self.call(RpcMethod::NetTcpConnect, &payload);
        if status == 0 {
            Ok(rpc::decode_fd(&resp).unwrap_or(-1))
        } else {
            Err(status)
        }
    }

    /// Send `data` on `fd`. Returns bytes sent.
    pub fn net_send(&self, fd: i32, data: &[u8]) -> Result<usize, i32> {
        let payload = rpc::encode_net_send_req(fd, data);
        let (status, resp) = self.call(RpcMethod::NetSend, &payload);
        if status == 0 {
            Ok(rpc::decode_i32(&resp).unwrap_or(0) as usize)
        } else {
            Err(status)
        }
    }

    /// Receive up to `max_len` bytes from `fd`.
    pub fn net_recv(&self, fd: i32, max_len: u32) -> Result<Vec<u8>, i32> {
        let payload = rpc::encode_net_recv_req(fd, max_len);
        let (status, resp) = self.call(RpcMethod::NetRecv, &payload);
        if status == 0 {
            Ok(resp)
        } else {
            Err(status)
        }
    }

    /// Close socket `fd`.
    pub fn net_close(&self, fd: i32) {
        let payload = rpc::encode_net_close_req(fd);
        let _ = self.call(RpcMethod::NetClose, &payload);
    }

    // ====================================================================
    //  KV store calls
    // ====================================================================

    /// Store an encrypted KV pair in the given table.
    pub fn kv_put(&self, table: &[u8], enc_key: &[u8], enc_val: &[u8]) -> Result<(), i32> {
        let payload = rpc::encode_kv_put_req(table, enc_key, enc_val);
        let (status, _) = self.call(RpcMethod::KvPut, &payload);
        if status == 0 {
            Ok(())
        } else {
            Err(status)
        }
    }

    /// Synchronous control persistence, serialized with other synchronous calls.
    /// Queue pressure and malformed/stale replies fail closed. The host must
    /// acknowledge only after the synchronous ciphertext write completes.
    /// Active consensus scheduling should use a separate polled adapter.
    pub fn kv_put_durable(&self, table: &[u8], key: &[u8], value: &[u8]) -> Result<(), i32> {
        let payload = rpc::encode_durable_kv_put_req(table, key, value).ok_or(-22)?;
        if !rpc::framed_payload_len_valid(
            payload.len(),
            rpc::REQ_HEADER_SIZE,
            self.request_tx.max_message_bytes(),
        ) {
            return Err(-22);
        }
        let _exchange = self.synchronous_exchange.lock().map_err(|_| -1)?;
        let request_id = self.try_reserve_request().map_err(|error| match error {
            RequestReserveError::Busy => -16,
            RequestReserveError::OperationIdExhausted => -75,
        })?;
        let message = rpc::encode_request(request_id, RpcMethod::KvPutDurable, &payload);
        if self.request_tx.try_send(&message).is_err() {
            self.release_request(request_id);
            return Err(-11);
        }
        notify_host();
        let response = self.response_rx.recv();
        self.release_request(request_id);
        rpc::decode_durable_kv_put_response(&response, request_id)
    }

    /// Get an encrypted value from the given table. Returns `Ok(None)` if not found (status == 1).
    pub fn kv_get(&self, table: &[u8], enc_key: &[u8]) -> Result<Option<Vec<u8>>, i32> {
        let payload = rpc::encode_kv_get_req(table, enc_key);
        let (status, resp) = self.call(RpcMethod::KvGet, &payload);
        match status {
            0 => Ok(Some(resp)),
            1 => Ok(None),
            _ => Err(status),
        }
    }

    /// Receive a KV reply into an exact-sized caller-owned buffer. The factory
    /// is called only for a matching successful response, after bounded header
    /// validation. Request/ID ownership is identical to the synchronous call.
    pub fn kv_get_into<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        table: &[u8],
        key: &[u8],
        mut owner: impl FnMut(usize) -> Result<B, i32>,
    ) -> Result<Option<(B, core::ops::Range<usize>)>, i32> {
        let payload = rpc::encode_kv_get_req(table, key);
        let maximum = self.request_tx.max_message_bytes();
        if !rpc::framed_payload_len_valid(payload.len(), rpc::REQ_HEADER_SIZE, maximum) {
            return Err(-22);
        }
        let _exchange = self.synchronous_exchange.lock().map_err(|_| -1)?;
        let request_id = self.try_reserve_request().map_err(|error| match error {
            RequestReserveError::Busy => -16,
            RequestReserveError::OperationIdExhausted => -75,
        })?;
        let _reservation = RequestReservation {
            client: self,
            id: request_id,
        };
        let request = rpc::encode_request_bounded(request_id, RpcMethod::KvGet, &payload, maximum)
            .ok_or(-22)?;
        self.request_tx.send_bounded(&request).map_err(|_| -22)?;
        notify_host();
        self.receive_kv_into(request_id, &mut owner)
    }

    fn receive_kv_into<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        request_id: u64,
        owner: &mut impl FnMut(usize) -> Result<B, i32>,
    ) -> Result<Option<(B, core::ops::Range<usize>)>, i32> {
        loop {
            // Empty storage queries the current complete frame without consuming
            // it. Empty malformed messages are consumed as before. The next
            // operation revalidates framing, never trusts this sampled length.
            if self.response_rx.try_recv_into(&mut []).is_ok() {
                std::thread::yield_now();
                continue;
            }
            let mut status_only = None;
            let mut received_length = None;
            let frame = self
                .response_rx
                .try_recv_with::<{ rpc::RESP_HEADER_SIZE }, B, i32>(|length, prefix| {
                    let Some((id, status, _)) = rpc::decode_response_header(prefix, length) else {
                        return Ok(None);
                    };
                    if id != request_id {
                        return Ok(None);
                    }
                    if status != 0 {
                        status_only = Some(status);
                        return Ok(None);
                    }
                    received_length = Some(length);
                    owner(length).map(Some)
                })
                .map_err(|error| match error {
                    enclave_os_common::queue::ReceiveOwnerError::Owner(error) => error,
                    enclave_os_common::queue::ReceiveOwnerError::TooShort => -22,
                })?;
            if let Some(status) = status_only {
                return if status == 1 { Ok(None) } else { Err(status) };
            }
            let Some(frame) = frame else {
                continue;
            };
            // Shared memory is untrusted: validate the actual copied header
            // within the received wire extent, never the owner's spare capacity.
            // AsRef and AsMut providers must both cover that exact copied prefix.
            let length = received_length.ok_or(-22)?;
            let bytes = frame.as_ref().get(..length).ok_or(-22)?;
            let Some((id, status, payload)) = rpc::decode_response_header(bytes, length) else {
                continue;
            };
            if id != request_id {
                continue;
            }
            return match status {
                0 => Ok(Some((frame, payload))),
                1 => Ok(None),
                other => Err(other),
            };
        }
    }

    /// Delete an entry from the given table. Returns true if it existed.
    pub fn kv_delete(&self, table: &[u8], enc_key: &[u8]) -> Result<bool, i32> {
        let payload = rpc::encode_kv_delete_req(table, enc_key);
        let (status, _) = self.call(RpcMethod::KvDelete, &payload);
        match status {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(status),
        }
    }

    /// List keys in the given table, optionally filtered by prefix.
    pub fn kv_list_keys(&self, table: &[u8], prefix: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
        let payload = rpc::encode_kv_list_keys_req(table, prefix);
        let (status, resp) = self.call(RpcMethod::KvListKeys, &payload);
        if status == 0 {
            Ok(rpc::decode_kv_list_keys_resp(&resp).unwrap_or_default())
        } else {
            Err(status)
        }
    }

    /// Apply a batch of puts/deletes atomically in the given table.
    pub fn kv_write_batch(&self, table: &[u8], ops: &[rpc::KvBatchOp]) -> Result<(), i32> {
        let payload = rpc::encode_kv_write_batch_req(table, ops);
        let (status, _) = self.call(RpcMethod::KvWriteBatch, &payload);
        if status == 0 {
            Ok(())
        } else {
            Err(status)
        }
    }

    /// Borrow bounded put records through the original synchronous KvWriteBatch.
    /// A successful staged write reply is not a durable publication barrier.
    pub fn kv_put_batch_borrowed(
        &self,
        table: &[u8],
        records: &[(&[u8], &[u8])],
        bounds: rpc::KvPutBatchBounds,
    ) -> Result<(), i32> {
        let payload = rpc::encode_kv_put_batch_req_borrowed(table, records, bounds).ok_or(-22)?;
        let (status, _) = self.call(RpcMethod::KvWriteBatch, &payload);
        if status == 0 {
            Ok(())
        } else {
            Err(status)
        }
    }

    /// Fetch several keys in one round trip. Results are in request order.
    pub fn kv_multi_get(&self, table: &[u8], keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, i32> {
        let payload = rpc::encode_kv_multi_get_req(table, keys);
        let (status, resp) = self.call(RpcMethod::KvMultiGet, &payload);
        if status == 0 {
            rpc::decode_kv_multi_get_resp(&resp).ok_or(-1)
        } else {
            Err(status)
        }
    }

    /// Small opaque-value batches with request-bound allocation and shape.
    pub fn kv_multi_get_bounded(
        &self,
        table: &[u8],
        keys: &[&[u8]],
        maxima: &[usize],
    ) -> Result<Vec<Option<Vec<u8>>>, i32> {
        if table.is_empty()
            || table.len() > 256
            || keys.len() != maxima.len()
            || !rpc::bounded_kv_limits_valid(maxima)
            || keys.iter().any(|key| key.is_empty() || key.len() > 256)
        {
            return Err(-22);
        }
        let payload = rpc::encode_kv_multi_get_req(table, keys);
        let (status, response) = self.call(RpcMethod::KvMultiGet, &payload);
        if status != 0 {
            return Err(status);
        }
        rpc::decode_kv_multi_get_resp_bounded(&response, maxima).ok_or(-1)
    }

    /// Range scan `[start, end)`, ascending, up to `limit` entries.
    pub fn kv_scan(
        &self,
        table: &[u8],
        start: &[u8],
        end: &[u8],
        limit: u32,
    ) -> Result<KvEntries, i32> {
        let payload = rpc::encode_kv_scan_req(table, start, end, limit);
        let (status, resp) = self.call(RpcMethod::KvScan, &payload);
        if status == 0 {
            rpc::decode_kv_scan_resp(&resp).ok_or(-1)
        } else {
            Err(status)
        }
    }

    // ====================================================================
    //  Utility calls
    // ====================================================================

    /// Get current UNIX timestamp from the host.
    pub fn get_current_time(&self) -> Result<u64, i32> {
        let (status, resp) = self.call(RpcMethod::GetCurrentTime, &[]);
        if status == 0 {
            Ok(rpc::decode_u64(&resp).unwrap_or(0))
        } else {
            Err(status)
        }
    }

    /// Log a message via the host.
    pub fn log(&self, level: u8, message: &str) {
        let payload = rpc::encode_log_req(level as i32, message);
        // Fire-and-forget: we still wait for the response to maintain ordering,
        // but we discard the result.
        let _ = self.call(RpcMethod::Log, &payload);
    }

    /// Signal shutdown to the host.
    pub fn shutdown(&self) {
        let _ = self.call(RpcMethod::Shutdown, &[]);
    }

    // ====================================================================
    //  DCAP attestation calls
    // ====================================================================

    /// Actual simultaneous request/raw-response backing for a QE exchange.
    /// Geometry comes from this client's immutable queue endpoints.
    #[cfg(all(not(feature = "mock"), not(feature = "sgx-sim-attestation")))]
    pub(crate) fn qe_working_bytes(&self, payload: usize) -> Option<usize> {
        if !rpc::framed_payload_len_valid(
            payload,
            rpc::REQ_HEADER_SIZE,
            self.request_tx.max_message_bytes(),
        ) {
            return None;
        }
        rpc::REQ_HEADER_SIZE
            .checked_add(payload)?
            .checked_add(self.response_rx.max_message_bytes())
    }

    #[cfg(all(not(feature = "mock"), not(feature = "sgx-sim-attestation")))]
    pub(crate) fn with_qe_target_info<T>(
        &self,
        pool: &std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
        accept: impl FnOnce(&[u8]) -> Result<T, i32>,
    ) -> Result<T, i32> {
        self.qe_call_admitted(pool, RpcMethod::QeGetTargetInfo, &[], accept)
    }

    #[cfg(all(not(feature = "mock"), not(feature = "sgx-sim-attestation")))]
    pub(crate) fn with_qe_quote<T>(
        &self,
        pool: &std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
        report: &[u8],
        accept: impl FnOnce(&[u8]) -> Result<T, i32>,
    ) -> Result<T, i32> {
        self.qe_call_admitted(pool, RpcMethod::QeGetQuote, report, accept)
    }

    #[cfg(all(not(feature = "mock"), not(feature = "sgx-sim-attestation")))]
    fn qe_call_admitted<T>(
        &self,
        pool: &std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
        method: RpcMethod,
        payload: &[u8],
        accept: impl FnOnce(&[u8]) -> Result<T, i32>,
    ) -> Result<T, i32> {
        self.qe_working_bytes(payload.len()).ok_or(-22)?;
        let request_length = rpc::REQ_HEADER_SIZE.checked_add(payload.len()).ok_or(-22)?;
        let mut working =
            QeWorking::new(pool, request_length, self.response_rx.max_message_bytes())
                .ok_or(-12)?;
        let exchange = self.synchronous_exchange.lock().map_err(|_| -1)?;
        let req_id = self.try_reserve_request().map_err(|error| match error {
            RequestReserveError::Busy => -16,
            RequestReserveError::OperationIdExhausted => -75,
        })?;
        if rpc::encode_request_into_bounded(
            req_id,
            method,
            payload,
            self.request_tx.max_message_bytes(),
            &mut working.request,
        )
        .is_none()
        {
            self.release_request(req_id);
            return Err(-22);
        }
        if self.request_tx.send_bounded(&working.request).is_err() {
            self.release_request(req_id);
            return Err(-22);
        }
        notify_host();
        loop {
            let count = match self.response_rx.try_recv_into(&mut working.response) {
                Ok(Some(count)) => count,
                Ok(None) => {
                    core::hint::spin_loop();
                    continue;
                }
                Err(_) => {
                    self.release_request(req_id);
                    return Err(-22);
                }
            };
            if let Some((response_id, status, bytes)) =
                rpc::decode_response(&working.response[..count])
            {
                if response_id == req_id {
                    self.release_request(req_id);
                    // The paid response belongs to working, independently of
                    // the exchange. Callers may start another RPC while they
                    // inspect these bytes; both working buffers stay admitted.
                    drop(exchange);
                    return if status == 0 {
                        accept(bytes)
                    } else {
                        Err(status)
                    };
                }
            }
            // Preserve original legacy wait semantics for malformed/mismatched
            // replies. No extra receive allocation, acquisition or request ID.
        }
    }

    /// Get the Quoting Enclave's target info (512-byte `sgx_target_info_t`).
    ///
    /// The enclave needs this to call `sgx_create_report()` targeting the QE,
    /// which then signs the report as a DCAP Quote v3.
    pub fn qe_get_target_info(&self) -> Result<Vec<u8>, i32> {
        let (status, resp) = self.call(RpcMethod::QeGetTargetInfo, &[]);
        if status == 0 {
            Ok(resp)
        } else {
            Err(status)
        }
    }

    /// Get a DCAP Quote v3 from a raw SGX report (432 bytes).
    ///
    /// The host calls `sgx_qe_get_quote()` which engages the Quoting Enclave
    /// to sign the report. Returns the full DCAP quote (typically ~4-5 KB).
    pub fn qe_get_quote(&self, report_bytes: &[u8]) -> Result<Vec<u8>, i32> {
        let (status, resp) = self.call(RpcMethod::QeGetQuote, report_bytes);
        if status == 0 {
            Ok(resp)
        } else {
            Err(status)
        }
    }
}

#[cfg(all(
    feature = "sgx-sim-attestation",
    feature = "fallible-allocation-v1",
    target_vendor = "teaclave"
))]
pub(crate) fn check_config_buffers(
    pool: &std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
) -> Result<(), &'static str> {
    use config_buffer::ConfigAllocator;
    use enclave_os_common::queue::{SpscQueueHeader, MIN_SHARED_QUEUE_CAPACITY};
    let capacity =
        usize::try_from(MIN_SHARED_QUEUE_CAPACITY).map_err(|_| "config queue fixture size")?;
    let request_header = SpscQueueHeader::new(MIN_SHARED_QUEUE_CAPACITY);
    let response_header = SpscQueueHeader::new(MIN_SHARED_QUEUE_CAPACITY);
    let mut request_backing = vec![0_u8; capacity];
    let mut response_backing = vec![0_u8; capacity];
    // SAFETY: these actual fixture allocations and immutable headers remain at
    // stable addresses until every handle/client below is dropped. Endpoints
    // have one producer/consumer and use the original validated capacity. They
    // are private protocol buffers, never registered as a trusted host/store.
    let (request_tx, request_rx, response_tx, response_rx) = unsafe {
        (
            SpscProducer::from_raw_with_capacity(
                &request_header,
                request_backing.as_mut_ptr(),
                MIN_SHARED_QUEUE_CAPACITY,
            ),
            SpscConsumer::from_raw_with_capacity(
                &request_header,
                request_backing.as_ptr(),
                MIN_SHARED_QUEUE_CAPACITY,
            ),
            SpscProducer::from_raw_with_capacity(
                &response_header,
                response_backing.as_mut_ptr(),
                MIN_SHARED_QUEUE_CAPACITY,
            ),
            SpscConsumer::from_raw_with_capacity(
                &response_header,
                response_backing.as_ptr(),
                MIN_SHARED_QUEUE_CAPACITY,
            ),
        )
    };
    let client = RpcClient::new(request_tx, response_rx);
    let id = client
        .try_reserve_request()
        .map_err(|_| "config test request reservation")?;
    let table = b"system";
    let key = [7_u8; ring::digest::SHA256_OUTPUT_LEN];
    let table_len = u16::try_from(table.len())
        .map_err(|_| "config test table width")?
        .to_le_bytes();
    let parts: &[&[u8]] = &[&table_len, table, &key];
    let frame_len = rpc::REQ_HEADER_SIZE + table_len.len() + table.len() + key.len();
    let response_maximum = client.response_rx.max_message_bytes();
    let demand = ConfigAllocator::metadata_bytes()?
        .checked_add(ConfigAllocator::backing_bytes(frame_len)?)
        .and_then(|n| n.checked_add(ConfigAllocator::backing_bytes(response_maximum).ok()?))
        .ok_or("config working geometry")?;
    let before = pool.used();
    if !matches!(client.call_config(pool, RpcMethod::KvGet, parts), Err(-16))
        || pool.used() != before
        || request_rx.try_recv().is_some()
    {
        return Err("config busy changed request or admitted backing");
    }
    let short = enclave_os_common::allocation::AllocationPoolV1::new(demand - 1)
        .ok_or("config short working pool")?;
    if client
        .exchange_config(
            &short,
            id,
            RpcMethod::KvGet,
            parts,
            frame_len,
            client.request_tx.max_message_bytes(),
        )
        .is_ok()
        || short.used() != 0
        || request_rx.try_recv().is_some()
    {
        return Err("config prepublication working refusal changed queue or leaked");
    }
    // Drive the production exchange with existing raw response codec. Queued
    // malformed and mismatched IDs must be discarded before the matching frame.
    response_tx
        .send_bounded(b"bad")
        .map_err(|_| "config malformed fixture queue")?;
    let wrong = rpc::encode_response(
        id.checked_add(1).ok_or("config fixture ID overflow")?,
        0,
        b"wrong",
    );
    response_tx
        .send_bounded(&wrong)
        .map_err(|_| "config wrong-ID fixture queue")?;
    let response = rpc::encode_response(id, 0, b"current-sealed-input");
    response_tx
        .send_bounded(&response)
        .map_err(|_| "config matching fixture queue")?;
    let (status, output) = client
        .exchange_config(
            pool,
            id,
            RpcMethod::KvGet,
            parts,
            frame_len,
            client.request_tx.max_message_bytes(),
        )
        .map_err(|_| "config actual exchange")?;
    if status != 0
        || output.as_slice() != b"current-sealed-input"
        || output.as_slice().as_ptr() != output.frame.as_slice()[rpc::RESP_HEADER_SIZE..].as_ptr()
        || pool.used()
            != before
                + ConfigAllocator::metadata_bytes()?
                + ConfigAllocator::backing_bytes(response_maximum)?
    {
        return Err("config response detached or wrong original backing");
    }
    let request = request_rx
        .try_recv()
        .ok_or("config original request missing")?;
    let (observed_id, method, payload) =
        rpc::decode_request(&request).ok_or("config original request codec")?;
    if observed_id != id
        || method != RpcMethod::KvGet
        || rpc::decode_kv_get_req(payload) != Some((table.as_slice(), key.as_slice()))
    {
        return Err("config actual request wire changed");
    }
    drop(output);
    if pool.used() != before {
        return Err("config working/response final refund");
    }
    client.release_request(id);
    let next = client
        .try_reserve_request()
        .map_err(|_| "config reservation not released")?;
    client.release_request(next);
    check_kv_reply_owner(&client, &response_tx)?;
    check_kv_received_extent(&client, &response_tx, &mut response_backing)?;
    drop(client);
    drop(request_rx);
    drop(response_tx);
    drop(request_backing);
    drop(response_backing);
    Ok(())
}

// Existing signed config/RPC owner exercises this same production receiver.
// Vec here is protocol test storage, not evidence of selected pool admission.
#[cfg(all(
    feature = "sgx-sim-attestation",
    feature = "fallible-allocation-v1",
    target_vendor = "teaclave"
))]
fn check_kv_reply_owner(
    client: &RpcClient,
    response_tx: &SpscProducer,
) -> Result<(), &'static str> {
    let id = client
        .try_reserve_request()
        .map_err(|_| "source request reservation")?;
    let reservation = RequestReservation { client, id };
    let mut malformed = rpc::encode_response(id, 0, b"");
    malformed[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    for wire in [
        b"short".to_vec(),
        malformed,
        rpc::encode_response(id + 1, 0, b"wrong"),
        rpc::encode_response(id, 0, b"refuse"),
    ] {
        response_tx
            .send_bounded(&wire)
            .map_err(|_| "source refusal fixture queue")?;
    }
    let mut calls = 0;
    let refused = client.receive_kv_into::<Vec<u8>>(id, &mut |length| {
        calls += 1;
        if length != rpc::RESP_HEADER_SIZE + b"refuse".len() {
            return Err(-22);
        }
        Err(-12)
    });
    if !matches!(refused, Err(-12)) || calls != 1 || !client.response_rx.is_empty() {
        return Err("source refusal did not consume matching frame exactly once");
    }
    drop(reservation);
    let retry = client
        .try_reserve_request()
        .map_err(|_| "source retry request slot")?;
    let reservation = RequestReservation { client, id: retry };
    let mut wire = rpc::encode_response(retry, 0, b"payload");
    wire.push(99); // Existing response parser permits a trailing frame byte.
    response_tx
        .send_bounded(&wire)
        .map_err(|_| "source retry fixture queue")?;
    let mut allocated = 0;
    let (output, range) = client
        .receive_kv_into(retry, &mut |length| {
            allocated = length;
            Ok(vec![0; length])
        })
        .map_err(|_| "source retry receiver")?
        .ok_or("source retry absent")?;
    if allocated != wire.len() || output != wire || &output[range] != b"payload" {
        return Err("source exact reply geometry or trailing semantics changed");
    }
    drop(reservation);
    for status in [1, -5] {
        let id = client
            .try_reserve_request()
            .map_err(|_| "source status reservation")?;
        let reservation = RequestReservation { client, id };
        response_tx
            .send_bounded(&rpc::encode_response(id, status, b"ignored"))
            .map_err(|_| "source status fixture queue")?;
        let result = client.receive_kv_into::<Vec<u8>>(id, &mut |_| Err(-12));
        drop(reservation);
        if (status == 1 && !matches!(result, Ok(None)))
            || (status == -5 && !matches!(result, Err(-5)))
        {
            return Err("source status must precede successful-payload admission");
        }
    }
    Ok(())
}

// Same signed owner, same receiver: unused provided-buffer tail is never wire.
#[cfg(all(
    feature = "sgx-sim-attestation",
    feature = "fallible-allocation-v1",
    target_vendor = "teaclave"
))]
fn check_kv_received_extent(
    client: &RpcClient,
    response_tx: &SpscProducer,
    response_backing: &mut Vec<u8>,
) -> Result<(), &'static str> {
    for mutate_after_prefix in [false, true] {
        let id = client
            .try_reserve_request()
            .map_err(|_| "source extent reservation")?;
        let _reservation = RequestReservation { client, id };
        let mut invalid = rpc::encode_response(id, 0, b"bad");
        let forged = u32::try_from(invalid.len() + 1).map_err(|_| "source forged extent")?;
        if !mutate_after_prefix {
            invalid[12..16].copy_from_slice(&forged.to_le_bytes());
        }
        response_tx
            .send_bounded(&invalid)
            .map_err(|_| "source forged queue")?;
        // The valid successor proves that a malformed copied header is consumed,
        // not accepted from zero tail and not left poisoning this request's head.
        let mut valid = rpc::encode_response(id, 0, b"real");
        valid.push(99); // The existing within-frame trailing byte remains allowed.
        response_tx
            .send_bounded(&valid)
            .map_err(|_| "source valid extent queue")?;
        let mut calls = 0;
        let (output, payload) = client
            .receive_kv_into(id, &mut |length| {
                calls += 1;
                if mutate_after_prefix && calls == 1 {
                    // Safe mutation of the fixture's own retained queue allocation,
                    // after bounded prefix inspection but before the real payload copy.
                    let tail = response_tx.diagnostic_positions().1;
                    let offset =
                        tail.wrapping_add(enclave_os_common::queue::MSG_HEADER_SIZE as u64 + 12);
                    for (index, byte) in forged.to_le_bytes().iter().enumerate() {
                        let at = offset.wrapping_add(index as u64) % response_backing.len() as u64;
                        response_backing[usize::try_from(at).map_err(|_| -22)?] = *byte;
                    }
                }
                Ok(vec![0_u8; length + rpc::RESP_HEADER_SIZE * 2])
            })
            .map_err(|_| "source exact received extent")?
            .ok_or("source extent missing")?;
        if calls != if mutate_after_prefix { 2 } else { 1 }
            || &output[payload] != b"real"
            || output[..valid.len()] != valid
            || !output[valid.len()..].iter().all(|byte| *byte == 0)
            || !client.response_rx.is_empty()
        {
            return Err("source unread provided tail accepted or framing changed");
        }
    }
    Ok(())
}
