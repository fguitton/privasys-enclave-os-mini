// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Enclave-side RPC client.
//!
//! Wraps the SPSC queues to provide typed host calls. Legacy Mini services use
//! the synchronous interface. Honest's control-plane opaque persistence uses a
//! separate polled interface: submission performs one `try_send`, and each
//! poll performs at most one `try_recv`.
//!
//! This replaces all the individual OCALL wrappers with a single
//! message-passing channel.

use core::sync::atomic::{AtomicU64, Ordering};
use std::string::String;
use std::vec::Vec;

use enclave_os_common::queue::{SpscConsumer, SpscProducer};
use enclave_os_common::rpc::{
    self, HonestRpcFrameError, HonestRpcIdentity, LoadOpaqueStreamTip, OpaqueStreamCodecError,
    OpaqueStreamTip, PersistOpaqueStreamBatch, PersistedOpaqueStreamBatch, RpcMethod, RpcRole,
};

// ---------------------------------------------------------------------------
//  External: the single OCALL
// ---------------------------------------------------------------------------

extern "C" {
    fn ocall_notify() -> u32;
}

/// Notify the host that there is a pending request.
#[inline]
fn notify_host() {
    unsafe {
        ocall_notify();
    }
}

// ---------------------------------------------------------------------------
//  RPC client state
// ---------------------------------------------------------------------------

/// Global request ID counter (monotonically increasing).
static NEXT_REQ_ID: AtomicU64 = AtomicU64::new(1);

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
    /// Sends requests to the host.
    request_tx: SpscProducer,
    /// Receives responses from the host.
    response_rx: SpscConsumer,
    /// Zero when idle, otherwise the only request allowed on these SPSC
    /// endpoints. This prevents a legacy synchronous call from stealing the
    /// response of a polled control operation.
    in_flight_request_id: AtomicU64,
}

/// Token owned by the control scheduler while one opaque batch is in flight.
///
/// It deliberately exposes no request ID: callers can only return it to the
/// same [`RpcClient`] for a bounded poll.
#[derive(Debug)]
pub struct PendingOpaqueStreamBatch {
    identity: HonestRpcIdentity,
    batch_id: u64,
    payload_digest: [u8; 32],
}

/// Token owned by the execution worker while one host operation is in flight.
///
/// Its complete framed identity is private; only the submitting client may
/// poll it.
#[derive(Debug)]
pub struct PendingExecutionRpc {
    identity: HonestRpcIdentity,
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
}

/// Fail-closed errors from the opaque-stream persistence interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolledOpaqueStreamError {
    InvalidRequest(OpaqueStreamCodecError),
    Busy,
    OperationIdExhausted,
    QueueFull,
    NotPending,
    MalformedResponse,
    UnexpectedResponse,
    HostStatus(i32),
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestReserveError {
    Busy,
    OperationIdExhausted,
}

// SAFETY: RpcClient uses SPSC queues backed by shared memory pointers.
// In the SGX enclave, it is accessed from a single thread only.
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
            request_tx,
            response_rx,
            in_flight_request_id: AtomicU64::new(0),
        }
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
    //  Polled control-plane persistence
    // ====================================================================

    /// Try to submit one atomic opaque stream batch without waiting for queue
    /// capacity or a host response.
    pub fn try_persist_opaque_stream_batch(
        &self,
        batch: &PersistOpaqueStreamBatch,
    ) -> Result<PendingOpaqueStreamBatch, PolledOpaqueStreamError> {
        let payload = rpc::encode_persist_opaque_stream_batch(batch)
            .map_err(PolledOpaqueStreamError::InvalidRequest)?;
        let request_id = self.try_reserve_request().map_err(|error| match error {
            RequestReserveError::Busy => PolledOpaqueStreamError::Busy,
            RequestReserveError::OperationIdExhausted => {
                PolledOpaqueStreamError::OperationIdExhausted
            }
        })?;
        let identity = HonestRpcIdentity {
            role: RpcRole::Control,
            node_id: batch.node_id,
            node_generation: batch.node_generation,
            operation_id: request_id,
            method: RpcMethod::PersistOpaqueStreamBatch,
        };
        let message = rpc::encode_honest_request(identity, &payload).map_err(|_| {
            self.release_request(request_id);
            PolledOpaqueStreamError::InvalidRequest(OpaqueStreamCodecError::BatchBound)
        })?;
        if self.request_tx.try_send(&message).is_err() {
            self.release_request(request_id);
            return Err(PolledOpaqueStreamError::QueueFull);
        }
        notify_host();
        Ok(PendingOpaqueStreamBatch {
            identity,
            batch_id: batch.batch_id,
            payload_digest: batch.payload_digest,
        })
    }

    /// Poll one submitted opaque stream batch.
    ///
    /// `Ok(None)` means the host has not replied. Every call consumes at most
    /// one response frame and never waits. A malformed, stale, mismatched or
    /// negative response terminates the operation fail-closed.
    pub fn poll_persist_opaque_stream_batch(
        &self,
        pending: &PendingOpaqueStreamBatch,
    ) -> Result<Option<PersistedOpaqueStreamBatch>, PolledOpaqueStreamError> {
        if self.in_flight_request_id.load(Ordering::Acquire) != pending.identity.operation_id {
            return Err(PolledOpaqueStreamError::NotPending);
        }
        let Some(raw_response) = self.response_rx.try_recv() else {
            return Ok(None);
        };
        self.release_request(pending.identity.operation_id);

        let response =
            rpc::decode_honest_response_for(&raw_response, pending.identity).map_err(|error| {
                match error {
                    HonestRpcFrameError::UnexpectedIdentity => {
                        PolledOpaqueStreamError::UnexpectedResponse
                    }
                    _ => PolledOpaqueStreamError::MalformedResponse,
                }
            })?;
        if response.status != 0 {
            return Err(PolledOpaqueStreamError::HostStatus(response.status));
        }
        let persisted = rpc::decode_persisted_opaque_stream_batch(response.payload)
            .ok_or(PolledOpaqueStreamError::MalformedResponse)?;
        if persisted.batch_id != pending.batch_id
            || persisted.durable_id != pending.batch_id
            || persisted.payload_digest != pending.payload_digest
        {
            return Err(PolledOpaqueStreamError::UnexpectedResponse);
        }
        Ok(Some(persisted))
    }

    /// Load the current tip of one opaque stream. The enclave remains
    /// responsible for authenticating any returned digest and payload.
    pub fn load_opaque_stream_tip(
        &self,
        request: LoadOpaqueStreamTip,
    ) -> Result<Option<OpaqueStreamTip>, PolledOpaqueStreamError> {
        let payload = rpc::encode_load_opaque_stream_tip(request)
            .map_err(PolledOpaqueStreamError::InvalidRequest)?;
        let (status, response) = self.call(RpcMethod::LoadOpaqueStreamTip, &payload);
        match status {
            0 => rpc::decode_opaque_stream_tip(&response)
                .map(Some)
                .map_err(PolledOpaqueStreamError::InvalidRequest),
            1 => Ok(None),
            status => Err(PolledOpaqueStreamError::HostStatus(status)),
        }
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
        let req_id = match self.try_reserve_request() {
            Ok(request_id) => request_id,
            // Legacy callers cannot safely interleave with a polled opaque
            // operation. Return EBUSY instead of blocking the control TCS.
            Err(RequestReserveError::Busy) => return (-16, Vec::new()),
            Err(RequestReserveError::OperationIdExhausted) => return (-75, Vec::new()),
        };
        let msg = rpc::encode_request(req_id, method, payload);

        // Send
        self.request_tx.send(&msg);

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
