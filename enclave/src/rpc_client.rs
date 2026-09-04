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
use std::sync::Mutex;
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
    /// Outstanding polled operations; a zero entry is free.
    ///
    /// This was one slot, which made the two consensus lanes mutually
    /// exclusive: both persist through the polled opaque-stream interface, so
    /// whichever submitted first refused the other for its whole lifetime.
    /// Measured at 208 deferrals in a 29 s campaign, split 106 application and
    /// 102 control, every one of them `PolledOpaqueStreamError::Busy` with
    /// `control_rpc=true` naming the holder.
    ///
    /// Widening this is only sound because [`Self::stashed_responses`] makes a
    /// frame attributable before it is consumed; without that, concurrent
    /// pollers would take each other's replies and fail closed on them.
    in_flight_polled_request_ids: [AtomicU64; MAX_IN_FLIGHT_POLLED],
    /// Zero when idle, otherwise the outstanding synchronous `call`.
    ///
    /// Held separately from the polled reservation. Sharing one slot made a
    /// polled persistence batch exclude every synchronous sealed write for its
    /// whole lifetime, which serialised the two consensus lanes onto one host
    /// slot: measured at 208 persistence deferrals in a 29 s campaign, split
    /// 106 application and 102 control. Interleaving is only safe because
    /// [`Self::stashed_responses`] makes responses attributable.
    in_flight_sync_request_id: AtomicU64,
    /// Response frames belonging to another outstanding operation, held until
    /// that operation collects them.
    ///
    /// Every waiter reads one queue, so any of them can dequeue another's
    /// reply. Previously that could not happen because only one operation was
    /// ever outstanding; the synchronous path therefore discarded unmatched
    /// frames and the polled paths fail-closed on them. Once several
    /// operations are in flight, discarding would lose a persistence response,
    /// so a frame that is not ours is parked here instead of dropped.
    stashed_responses: Mutex<Vec<(u64, Vec<u8>)>>,
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

/// Polled operations that may be outstanding at once. Two consensus lanes
/// persist concurrently; the spare capacity covers the execution interface
/// without letting unbounded work accumulate.
const MAX_IN_FLIGHT_POLLED: usize = 4;

const DRAIN_SPINS: u32 = 100_000;

impl RpcClient {
    /// Create a client from the queue endpoints.
    ///
    /// - `request_tx`: producer for `enc_to_host` (enclave writes, host reads)
    /// - `response_rx`: consumer for `host_to_enc` (host writes, enclave reads)
    pub fn new(request_tx: SpscProducer, response_rx: SpscConsumer) -> Self {
        Self {
            request_tx,
            response_rx,
            in_flight_polled_request_ids: [const { AtomicU64::new(0) }; MAX_IN_FLIGHT_POLLED],
            in_flight_sync_request_id: AtomicU64::new(0),
            stashed_responses: Mutex::new(Vec::new()),
        }
    }

    /// Reserve one polled operation. `Busy` once every slot is taken, which
    /// bounds outstanding work exactly as the single slot did — just at more
    /// than one.
    fn try_reserve_request(&self) -> Result<u64, RequestReserveError> {
        let request_id = next_req_id().ok_or(RequestReserveError::OperationIdExhausted)?;
        for slot in &self.in_flight_polled_request_ids {
            if slot
                .compare_exchange(0, request_id, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(request_id);
            }
        }
        Err(RequestReserveError::Busy)
    }

    fn release_request(&self, request_id: u64) {
        for slot in &self.in_flight_polled_request_ids {
            Self::release_slot(slot, request_id);
        }
    }

    /// Whether `request_id` is still an outstanding polled operation.
    fn polled_request_is_in_flight(&self, request_id: u64) -> bool {
        self.in_flight_polled_request_ids
            .iter()
            .any(|slot| slot.load(Ordering::Acquire) == request_id)
    }

    fn try_reserve_slot(slot: &AtomicU64) -> Result<u64, RequestReserveError> {
        let request_id = next_req_id().ok_or(RequestReserveError::OperationIdExhausted)?;
        slot.compare_exchange(0, request_id, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| request_id)
            .map_err(|_| RequestReserveError::Busy)
    }

    fn release_slot(slot: &AtomicU64, request_id: u64) {
        let _ = slot.compare_exchange(request_id, 0, Ordering::AcqRel, Ordering::Acquire);
    }

    /// The request id a response frame answers, whichever framing it uses.
    ///
    /// Two waiters now read one queue, so a frame must be attributable before
    /// it is consumed. `has_honest_rpc_magic` is the discriminator; a frame
    /// that decodes as neither framing is unattributable and is dropped by the
    /// caller exactly as before.
    fn frame_request_id(raw: &[u8]) -> Option<u64> {
        if rpc::has_honest_rpc_magic(raw) {
            rpc::decode_honest_response(raw)
                .ok()
                .map(|response| response.identity.operation_id)
        } else {
            rpc::decode_response(raw).map(|(request_id, _, _)| request_id)
        }
    }

    /// Take the stashed frame that answers `request_id`, if one is parked.
    fn take_stashed_response(&self, request_id: u64) -> Option<Vec<u8>> {
        Self::take_from_stash(&self.stashed_responses, request_id)
    }

    fn take_from_stash(
        stash: &Mutex<Vec<(u64, Vec<u8>)>>,
        request_id: u64,
    ) -> Option<Vec<u8>> {
        let mut stash = stash.lock().ok()?;
        let position = stash.iter().position(|(id, _)| *id == request_id)?;
        Some(stash.remove(position).1)
    }

    /// Hold a frame that belongs to the other waiter.
    ///
    /// At most two operations are outstanding — one polled, one synchronous —
    /// so one slot is sufficient. An occupied stash means a frame arrived for
    /// an operation that never collected it; dropping the older one keeps this
    /// bounded, and the abandoned operation fails closed on its own identity
    /// check rather than consuming someone else's reply.
    fn stash_response(&self, request_id: u64, frame: Vec<u8>) {
        Self::put_in_stash(&self.stashed_responses, request_id, frame);
    }

    fn put_in_stash(stash: &Mutex<Vec<(u64, Vec<u8>)>>, request_id: u64, frame: Vec<u8>) {
        let Ok(mut stash) = stash.lock() else {
            return;
        };
        // One entry per operation: a second frame for an id already parked
        // means the host answered twice, and the newer answer is the one the
        // identity check should judge.
        if let Some(existing) = stash.iter_mut().find(|(id, _)| *id == request_id) {
            existing.1 = frame;
            return;
        }
        // Bounded by the number of operations that can be outstanding. If a
        // frame arrives for an operation that has already gone away, drop the
        // oldest rather than growing without limit; that operation fails
        // closed on its own identity check instead of consuming another's.
        if stash.len() >= MAX_IN_FLIGHT_POLLED + 1 {
            stash.remove(0);
        }
        stash.push((request_id, frame));
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
        if !self.polled_request_is_in_flight(pending.identity.operation_id) {
            return Err(PolledOpaqueStreamError::NotPending);
        }
        // A synchronous call sharing this queue may have parked our reply.
        let raw_response = match self.take_stashed_response(pending.identity.operation_id) {
            Some(stashed) => stashed,
            None => {
                let Some(raw_response) = self.response_rx.try_recv() else {
                    return Ok(None);
                };
                // Not ours: park it for the synchronous caller and report no
                // progress. Consuming it here would both lose that reply and
                // fail this operation closed on an identity that was never
                // meant for it.
                match Self::frame_request_id(&raw_response) {
                    Some(other_id) if other_id != pending.identity.operation_id => {
                        self.stash_response(other_id, raw_response);
                        return Ok(None);
                    }
                    _ => raw_response,
                }
            }
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
            // `call` reports a local reservation conflict as EBUSY. That is not
            // a host verdict: the polled operation holding the slot will finish
            // and the caller may retry, so name it as the transient it is.
            -16 => Err(PolledOpaqueStreamError::Busy),
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
        if !self.polled_request_is_in_flight(pending.identity.operation_id) {
            return Err(PolledExecutionRpcError::NotPending);
        }
        // Same attribution rule as the opaque-stream poll above.
        let raw_response = match self.take_stashed_response(pending.identity.operation_id) {
            Some(stashed) => stashed,
            None => {
                let Some(raw_response) = self.response_rx.try_recv() else {
                    return Ok(None);
                };
                match Self::frame_request_id(&raw_response) {
                    Some(other_id) if other_id != pending.identity.operation_id => {
                        self.stash_response(other_id, raw_response);
                        return Ok(None);
                    }
                    _ => raw_response,
                }
            }
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
        let operation_id = pending.identity.operation_id;
        let released = self
            .in_flight_polled_request_ids
            .iter()
            .any(|slot| {
                slot.compare_exchange(operation_id, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            });
        if !released {
            return Err(PolledExecutionRpcError::NotPending);
        }
        // Drop any reply already parked for the abandoned operation, so it
        // cannot be handed to a later operation that reuses this slot.
        let _ = self.take_stashed_response(operation_id);
        Ok(())
    }

    // ====================================================================
    //  Core RPC call
    // ====================================================================

    /// Send an RPC request and wait for the matching response.
    ///
    /// Returns `(status, payload)` from the host's response.
    fn call(&self, method: RpcMethod, payload: &[u8]) -> (i32, Vec<u8>) {
        // Reserves the synchronous slot only. A polled operation no longer
        // excludes this path; see `in_flight_sync_request_id`.
        let req_id = match Self::try_reserve_slot(&self.in_flight_sync_request_id) {
            Ok(request_id) => request_id,
            // Another synchronous call is already outstanding. Return EBUSY
            // instead of blocking the control TCS.
            Err(RequestReserveError::Busy) => return (-16, Vec::new()),
            Err(RequestReserveError::OperationIdExhausted) => return (-75, Vec::new()),
        };
        let msg = rpc::encode_request(req_id, method, payload);

        // Send
        self.request_tx.send(&msg);

        // Wake the host dispatcher
        notify_host();

        // A polled operation may have already parked this reply.
        if let Some(stashed) = self.take_stashed_response(req_id) {
            Self::release_slot(&self.in_flight_sync_request_id, req_id);
            if let Some((_, status, resp_payload)) = rpc::decode_response(&stashed) {
                return (status, resp_payload.to_vec());
            }
            return (-71, Vec::new());
        }

        // Wait for response
        loop {
            let resp_raw = self.response_rx.recv();
            if let Some((resp_id, status, resp_payload)) = rpc::decode_response(&resp_raw) {
                if resp_id == req_id {
                    Self::release_slot(&self.in_flight_sync_request_id, req_id);
                    return (status, resp_payload.to_vec());
                }
            }
            // Not ours. It belongs to the polled operation now running
            // alongside this call, so park it rather than dropping it — the
            // poll would otherwise wait forever for a reply already consumed.
            // A frame that decodes as neither framing is unattributable and is
            // discarded, exactly as before.
            match Self::frame_request_id(&resp_raw) {
                Some(other_id) => self.stash_response(other_id, resp_raw),
                None => continue,
            }
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
    /// Emit one host log line.
    ///
    /// This is genuinely one-way: reserving an in-flight request would return
    /// EBUSY whenever a polled opaque operation is outstanding, which silences
    /// the enclave exactly while persistence is in flight — when its
    /// diagnostics matter most. The host does not reply to `Log`, so nothing
    /// enters the shared response queue for a polled operation to mis-consume.
    ///
    /// The dispatcher continuously polls this ring with a bounded timed
    /// backoff. `ocall_notify` is currently an ABI-compatibility call and does
    /// not wake that separate thread, so invoking it once per line only adds
    /// an enclave exit. Let ordinary log bursts be consumed by the live poller
    /// without one transition per message; [`Self::drain_requests`] provides
    /// the explicit shutdown boundary.
    pub fn log(&self, level: u8, message: &str) {
        let Some(request_id) = next_req_id() else {
            return;
        };
        let payload = rpc::encode_log_req(level as i32, message);
        let msg = rpc::encode_request(request_id, RpcMethod::Log, &payload);
        self.request_tx.send(&msg);
    }

    /// Wait, bounded, until the host has consumed everything this enclave has
    /// queued.
    ///
    /// The log lane is one-way, so a line emitted immediately before shutdown
    /// would otherwise be discarded with the ring. Call this before ending a
    /// long-lived ECALL so the enclave's last words survive.
    pub fn drain_requests(&self) {
        for _ in 0..DRAIN_SPINS {
            if self.request_tx.pending_bytes() == 0 {
                return;
            }
            notify_host();
            core::hint::spin_loop();
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use enclave_os_common::rpc::encode_honest_response;

    fn identity(operation_id: u64) -> HonestRpcIdentity {
        HonestRpcIdentity {
            role: RpcRole::Control,
            node_id: 7,
            node_generation: 1,
            operation_id,
            method: RpcMethod::PersistOpaqueStreamBatch,
        }
    }

    #[test]
    fn a_frame_is_attributed_to_its_operation_in_either_framing() {
        // Attribution is what makes two outstanding operations safe: a frame
        // must be assignable to one of them before it is consumed.
        let polled = encode_honest_response(identity(41), 0, &[]).expect("honest response");
        assert_eq!(RpcClient::frame_request_id(&polled), Some(41));

        let synchronous = rpc::encode_response(42, 0, &[]);
        assert_eq!(RpcClient::frame_request_id(&synchronous), Some(42));

        // The two framings must not be confused for one another.
        assert!(rpc::has_honest_rpc_magic(&polled));
        assert!(!rpc::has_honest_rpc_magic(&synchronous));

        // An unattributable frame stays unattributable rather than being
        // charged to whichever waiter happens to look at it.
        assert_eq!(RpcClient::frame_request_id(&[]), None);
        assert_eq!(RpcClient::frame_request_id(&[0xff; 3]), None);
    }

    #[test]
    fn a_stashed_frame_is_returned_only_to_the_operation_it_answers() {
        let stash: Mutex<Vec<(u64, Vec<u8>)>> = Mutex::new(Vec::new());

        assert_eq!(RpcClient::take_from_stash(&stash, 41), None);

        RpcClient::put_in_stash(&stash, 41, alloc_frame(0xa1));
        // The other waiter must not be able to collect it.
        assert_eq!(RpcClient::take_from_stash(&stash, 42), None);
        // And it must still be there afterwards.
        assert_eq!(RpcClient::take_from_stash(&stash, 41), Some(alloc_frame(0xa1)));
        // Taken exactly once.
        assert_eq!(RpcClient::take_from_stash(&stash, 41), None);
    }

    #[test]
    fn either_completion_order_delivers_both_replies() {
        // The regression this guards: with one slot the synchronous path
        // discarded frames that were not its own, so a persistence reply
        // dequeued by a synchronous caller was lost and its poll waited
        // forever. Both interleavings must now deliver both replies.
        for (first, second) in [(41_u64, 42_u64), (42, 41)] {
            let stash: Mutex<Vec<(u64, Vec<u8>)>> = Mutex::new(Vec::new());

            // The waiter for `second` dequeues `first`'s reply and parks it.
            RpcClient::put_in_stash(&stash, first, alloc_frame(0xb2));
            // `second`'s own reply is still on the queue, so it makes no
            // progress from the stash.
            assert_eq!(RpcClient::take_from_stash(&stash, second), None);
            // `first` collects what was parked for it.
            assert_eq!(
                RpcClient::take_from_stash(&stash, first),
                Some(alloc_frame(0xb2)),
                "the parked reply must reach the operation it answers",
            );
        }
    }

    fn alloc_frame(marker: u8) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.push(marker);
        frame
    }
}
