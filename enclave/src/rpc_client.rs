// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Enclave-side RPC client.
//!
//! Wraps the SPSC queues to provide typed host calls. Legacy Mini services use
//! the synchronous interface. Honest's control-plane opaque persistence uses a
//! separate polled interface: submission performs one `try_send`, and each
//! poll performs at most one `try_recv`.
//!
//! A client is installed over a fresh request/response ring pair. Operation
//! IDs are globally monotonic and never reused for that enclave-process
//! lifetime; a process restart installs fresh rings before the counter begins
//! again. Thus an old response cannot collide with a new lifetime. Within one
//! lifetime, only an ID in the active reservation table is eligible: late or
//! host-forged future IDs are both discarded before any semantic validation.
//!
//! This replaces all the individual OCALL wrappers with a single
//! message-passing channel.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::string::String;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
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
    /// Serializes every enclave writer to the request ring.
    ///
    /// Polled APIs use `try_lock` and report `Busy`; blocking legacy/log paths
    /// acquire this only for one bounded `try_send` attempt and release it
    /// before waiting or retrying.
    request_tx_lock: Mutex<()>,
    /// Bounded reservation and response-routing state for this queue pair.
    ///
    /// The control scheduler may pipeline one control and one application
    /// persistence request. Synchronous calls and execution requests retain
    /// their historical single-flight behavior. The mutex serializes the one
    /// response consumer while keeping the underlying queue SPSC.
    request_state: Mutex<RpcRequestState>,
    /// Allocation identity binds consuming APIs to the client whose fresh
    /// ring pair owns the reservation, without requiring a shared-state lock.
    client_identity: Arc<()>,
}

/// Exactly two outstanding persistence operations: one per independent
/// control/application stream. Distinctness is the complete durable stream
/// identity below, not merely the current batch or operation ID. Execution
/// keeps exclusive use of this table and therefore still remains single-flight.
const MAX_IN_FLIGHT_PERSISTENCE_REQUESTS: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OpaqueStreamReservationKey {
    node_id: u64,
    node_generation: u64,
    stream_id: [u8; 32],
    persistence_epoch: u64,
}

impl From<&PersistOpaqueStreamBatch> for OpaqueStreamReservationKey {
    fn from(batch: &PersistOpaqueStreamBatch) -> Self {
        Self {
            node_id: batch.node_id,
            node_generation: batch.node_generation,
            stream_id: batch.stream_id,
            persistence_epoch: batch.persistence_epoch,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolledRequestKind {
    OpaqueStream(OpaqueStreamReservationKey),
    Execution,
}

#[derive(Debug)]
struct ActivePolledRequest {
    request_id: u64,
    kind: PolledRequestKind,
    /// Shared only with the unique custody token for this request. Token Drop
    /// publishes retirement without waiting for the response-routing mutex.
    retired: Arc<AtomicBool>,
}

#[derive(Debug)]
struct RpcRequestState {
    synchronous_request_id: u64,
    polled_requests: [Option<ActivePolledRequest>; MAX_IN_FLIGHT_PERSISTENCE_REQUESTS],
    /// At most one response per active operation ID. Inactive and duplicate
    /// frames are dropped, and a live entry is never evicted to make room.
    stashed_responses: Vec<(u64, Vec<u8>)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestStateAccessError {
    Contended,
    NotPending,
}

#[derive(Debug)]
struct PendingPolledReservation {
    retired: Arc<AtomicBool>,
    client_identity: Arc<()>,
}

impl PendingPolledReservation {
    /// Retire this token exactly once without acquiring the routing mutex.
    fn retire(&self) -> bool {
        !self.retired.swap(true, Ordering::AcqRel)
    }
}

impl Drop for PendingPolledReservation {
    fn drop(&mut self) {
        // Token destruction can run on either enclave TCS and must never wait
        // behind the response-routing mutex. The next state owner observes
        // this Release store with Acquire and prunes the exact slot and stash.
        self.retired.store(true, Ordering::Release);
    }
}

impl RpcRequestState {
    fn new() -> Self {
        Self {
            synchronous_request_id: 0,
            polled_requests: [const { None }; MAX_IN_FLIGHT_PERSISTENCE_REQUESTS],
            stashed_responses: Vec::new(),
        }
    }

    fn polled_request_is_active(&self, request_id: u64) -> bool {
        self.polled_requests
            .iter()
            .flatten()
            .any(|active| active.request_id == request_id)
    }

    /// Apply token retirement before making any admission or routing
    /// decision. Work is bounded by the two-slot table. Removing the exact
    /// stash entry prevents an abandoned reply from occupying live capacity.
    fn prune_retired(&mut self) {
        let mut retired_ids = [0_u64; MAX_IN_FLIGHT_PERSISTENCE_REQUESTS];
        let mut retired_count = 0;
        for slot in &mut self.polled_requests {
            let Some(active) = slot.as_ref() else {
                continue;
            };
            if active.retired.load(Ordering::Acquire) {
                retired_ids[retired_count] = active.request_id;
                retired_count += 1;
                *slot = None;
            }
        }
        if retired_count != 0 {
            self.stashed_responses
                .retain(|(stashed_id, _)| !retired_ids[..retired_count].contains(stashed_id));
        }
    }

    fn release_polled_request(&mut self, request_id: u64) -> bool {
        let Some(slot) = self.polled_requests.iter_mut().find(|slot| {
            slot.as_ref()
                .is_some_and(|active| active.request_id == request_id)
        }) else {
            return false;
        };
        let active = slot.take().expect("matching polled request disappeared");
        // Exact completion and explicit retirement share the same marker, so
        // later token destruction is idempotent and `abandon` can preserve
        // NotPending without reacquiring this mutex.
        active.retired.store(true, Ordering::Release);
        self.stashed_responses
            .retain(|(stashed_id, _)| *stashed_id != request_id);
        true
    }
}

/// Token owned by the control scheduler while one opaque batch is in flight.
///
/// It deliberately exposes no request ID: callers can only return it to the
/// same [`RpcClient`] for a bounded poll. Dropping it abandons and retires its
/// exact reservation without blocking; the next routing turn reclaims its
/// slot, and a later response is discarded under its inactive ID.
#[derive(Debug)]
#[must_use = "a submitted persistence operation must be polled or deliberately abandoned"]
pub struct PendingOpaqueStreamBatch {
    identity: HonestRpcIdentity,
    batch_id: u64,
    payload_digest: [u8; 32],
    _reservation: PendingPolledReservation,
}

/// Token owned by the execution worker while one host operation is in flight.
///
/// Its complete framed identity is private; only the submitting client may
/// poll it. Dropping it abandons and retires its exact reservation; a later
/// routing turn reclaims the slot, and a later response is discarded under
/// its inactive ID.
#[derive(Debug)]
#[must_use = "a submitted execution operation must be completed or deliberately abandoned"]
pub struct PendingExecutionRpc {
    identity: HonestRpcIdentity,
    _reservation: PendingPolledReservation,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestSendError {
    Contended,
    QueueFull,
}

// SAFETY: RpcClient uses SPSC queues backed by shared-memory pointers that
// remain valid for the enclave's lifetime. All logical producers serialize
// each bounded write with `request_tx_lock`. All polled consumers serialize
// each bounded read with `request_state`; synchronous consumption
// is admitted only while no polled operation is active. The host remains the
// single consumer of the request ring and single producer of the response
// ring, so the physical queues retain their SPSC contract.
unsafe impl Send for RpcClient {}
unsafe impl Sync for RpcClient {}

const DRAIN_SPINS: u32 = 100_000;

impl RpcClient {
    /// Create a client from the queue endpoints.
    ///
    /// - `request_tx`: producer for `enc_to_host` (enclave writes, host reads)
    /// - `response_rx`: consumer for `host_to_enc` (host writes, enclave reads)
    ///
    /// Both endpoints must belong to one freshly initialized, empty ring pair.
    /// In particular, a process restart must not reuse a response ring holding
    /// frames from the previous operation-ID lifetime.
    pub fn new(request_tx: SpscProducer, response_rx: SpscConsumer) -> Self {
        Self {
            request_tx,
            response_rx,
            request_tx_lock: Mutex::new(()),
            request_state: Mutex::new(RpcRequestState::new()),
            client_identity: Arc::new(()),
        }
    }

    fn request_state(&self) -> MutexGuard<'_, RpcRequestState> {
        let mut state = self
            .request_state
            .lock()
            .expect("RPC request state mutex poisoned");
        state.prune_retired();
        state
    }

    fn try_request_state(
        &self,
    ) -> Result<MutexGuard<'_, RpcRequestState>, RequestStateAccessError> {
        let mut state = match self.request_state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Err(RequestStateAccessError::Contended),
            Err(TryLockError::Poisoned(_)) => std::panic!("RPC request state mutex poisoned"),
        };
        state.prune_retired();
        Ok(state)
    }

    fn try_reserve_polled_request(
        &self,
        kind: PolledRequestKind,
    ) -> Result<(u64, PendingPolledReservation), RequestReserveError> {
        let mut state = self
            .try_request_state()
            .map_err(|_| RequestReserveError::Busy)?;
        if state.synchronous_request_id != 0 {
            return Err(RequestReserveError::Busy);
        }
        match kind {
            PolledRequestKind::OpaqueStream(key) => {
                if state.polled_requests.iter().flatten().any(|active| {
                    matches!(active.kind, PolledRequestKind::Execution)
                        || active.kind == PolledRequestKind::OpaqueStream(key)
                }) {
                    return Err(RequestReserveError::Busy);
                }
            }
            PolledRequestKind::Execution => {
                if state.polled_requests.iter().any(Option::is_some) {
                    return Err(RequestReserveError::Busy);
                }
            }
        }
        let Some(slot) = state.polled_requests.iter_mut().find(|slot| slot.is_none()) else {
            return Err(RequestReserveError::Busy);
        };
        let request_id = next_req_id().ok_or(RequestReserveError::OperationIdExhausted)?;
        let retired = Arc::new(AtomicBool::new(false));
        let reservation = PendingPolledReservation {
            retired: Arc::clone(&retired),
            client_identity: Arc::clone(&self.client_identity),
        };
        *slot = Some(ActivePolledRequest {
            request_id,
            kind,
            retired,
        });
        Ok((request_id, reservation))
    }

    fn try_reserve_synchronous_request(&self) -> Result<u64, RequestReserveError> {
        let mut state = self.request_state();
        if state.synchronous_request_id != 0 || state.polled_requests.iter().any(Option::is_some) {
            return Err(RequestReserveError::Busy);
        }
        let request_id = next_req_id().ok_or(RequestReserveError::OperationIdExhausted)?;
        state.synchronous_request_id = request_id;
        Ok(request_id)
    }

    /// Conservatively report whether a synchronous request could be admitted
    /// at this instant.
    ///
    /// This is only a preparation hint for callers whose request payload is
    /// expensive to construct. It neither reserves a request ID nor touches
    /// either queue, and the later synchronous reservation remains the
    /// authoritative admission decision. Published token retirement may be
    /// observed without pruning its slot; the real reservation turn performs
    /// that bounded mutation before it can admit a synchronous operation.
    #[must_use]
    pub fn synchronous_request_may_be_available(&self) -> bool {
        let state = match self.request_state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return false,
            Err(TryLockError::Poisoned(_)) => std::panic!("RPC request state mutex poisoned"),
        };
        if state.synchronous_request_id != 0
            || state
                .polled_requests
                .iter()
                .flatten()
                .any(|active| !active.retired.load(Ordering::Acquire))
        {
            return false;
        }
        drop(state);

        // The producer can become occupied after this guard is released. The
        // actual request reservation and send handle that race; this check
        // merely avoids expensive preparation when contention is already
        // visible.
        match self.request_tx_lock.try_lock() {
            Ok(producer) => {
                drop(producer);
                true
            }
            Err(TryLockError::WouldBlock) => false,
            Err(TryLockError::Poisoned(_)) => std::panic!("RPC request producer mutex poisoned"),
        }
    }

    fn release_synchronous_request(&self, request_id: u64) {
        let mut state = self.request_state();
        if state.synchronous_request_id == request_id {
            state.synchronous_request_id = 0;
        }
    }

    fn honest_response_request_id(raw: &[u8]) -> Option<u64> {
        rpc::decode_honest_response(raw)
            .ok()
            .map(|response| response.identity.operation_id)
    }

    /// Return at most one response for this operation.
    ///
    /// A response for another active operation is parked without evicting an
    /// earlier live response. A late response for an operation already
    /// completed or abandoned is discarded. The complete response identity
    /// and persistence acknowledgement remain validated by the caller.
    fn poll_polled_response(
        &self,
        request_id: u64,
    ) -> Result<Option<Vec<u8>>, RequestStateAccessError> {
        let mut state = self.try_request_state()?;
        if !state.polled_request_is_active(request_id) {
            return Err(RequestStateAccessError::NotPending);
        }
        if let Some(position) = state
            .stashed_responses
            .iter()
            .position(|(stashed_id, _)| *stashed_id == request_id)
        {
            let response = state.stashed_responses.remove(position).1;
            let released = state.release_polled_request(request_id);
            debug_assert!(released);
            return Ok(Some(response));
        }
        let Some(response) = self.response_rx.try_recv() else {
            return Ok(None);
        };
        match Self::honest_response_request_id(&response) {
            Some(response_id) if response_id == request_id => {
                let released = state.release_polled_request(request_id);
                debug_assert!(released);
                Ok(Some(response))
            }
            Some(response_id) if state.polled_request_is_active(response_id) => {
                // Keep the first response for an active operation. A duplicate
                // cannot acknowledge twice and must not displace another live
                // operation's response.
                if !state
                    .stashed_responses
                    .iter()
                    .any(|(stashed_id, _)| *stashed_id == response_id)
                {
                    assert!(
                        state.stashed_responses.len() < MAX_IN_FLIGHT_PERSISTENCE_REQUESTS,
                        "active RPC response stash exceeded its reservation bound"
                    );
                    state.stashed_responses.push((response_id, response));
                }
                Ok(None)
            }
            Some(_) => {
                // Globally monotonic operation IDs are never reused. A reply
                // for an inactive ID is either late or forged for a future
                // ID; either way it carries no authority for current work and
                // is discarded before any future reservation can exist.
                Ok(None)
            }
            None => {
                // Preserve the historical fail-closed rule for an
                // unattributable frame: terminate the operation whose poll
                // consumed it and let its exact decoder report the error.
                let released = state.release_polled_request(request_id);
                debug_assert!(released);
                Ok(Some(response))
            }
        }
    }

    /// Attempt one atomic request-ring write without waiting for either the
    /// logical producer or ring capacity.
    fn try_send_request(&self, message: &[u8]) -> Result<(), RequestSendError> {
        let _producer = match self.request_tx_lock.try_lock() {
            Ok(producer) => producer,
            Err(TryLockError::WouldBlock) => return Err(RequestSendError::Contended),
            Err(TryLockError::Poisoned(_)) => std::panic!("RPC request producer mutex poisoned"),
        };
        self.request_tx
            .try_send(message)
            .map_err(|()| RequestSendError::QueueFull)
    }

    /// Send one legacy or one-way request while releasing the producer mutex
    /// between bounded attempts. Encoding and response waiting happen outside
    /// this critical section.
    fn send_request(&self, message: &[u8]) {
        loop {
            match self.try_send_request(message) {
                Ok(()) => return,
                Err(RequestSendError::Contended | RequestSendError::QueueFull) => {
                    core::hint::spin_loop();
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn hold_request_producer_for_test(&self) -> impl Drop + '_ {
        self.request_tx_lock
            .lock()
            .expect("RPC request producer mutex poisoned")
    }

    #[cfg(test)]
    pub(crate) fn hold_request_state_for_test(&self) -> impl Drop + '_ {
        self.request_state()
    }

    #[cfg(test)]
    pub(crate) fn stashed_response_count_for_test(&self) -> usize {
        self.request_state().stashed_responses.len()
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
        let (request_id, reservation) = self
            .try_reserve_polled_request(PolledRequestKind::OpaqueStream(
                OpaqueStreamReservationKey::from(batch),
            ))
            .map_err(|error| match error {
                RequestReserveError::Busy => PolledOpaqueStreamError::Busy,
                RequestReserveError::OperationIdExhausted => {
                    PolledOpaqueStreamError::OperationIdExhausted
                }
            })?;
        // Reserve before encoding: a competing persistence retry can carry a
        // multi-megabyte snapshot, and copying it only to discover that both
        // bounded slots are occupied needlessly starves consensus progress.
        // The local guard releases this exact reservation on every failure or
        // unwind before custody transfers into the returned token.
        let payload = rpc::encode_persist_opaque_stream_batch(batch)
            .map_err(PolledOpaqueStreamError::InvalidRequest)?;
        let identity = HonestRpcIdentity {
            role: RpcRole::Control,
            node_id: batch.node_id,
            node_generation: batch.node_generation,
            operation_id: request_id,
            method: RpcMethod::PersistOpaqueStreamBatch,
        };
        let message = rpc::encode_honest_request(identity, &payload).map_err(|_| {
            PolledOpaqueStreamError::InvalidRequest(OpaqueStreamCodecError::BatchBound)
        })?;
        self.try_send_request(&message)
            .map_err(|error| match error {
                RequestSendError::Contended => PolledOpaqueStreamError::Busy,
                RequestSendError::QueueFull => PolledOpaqueStreamError::QueueFull,
            })?;
        notify_host();
        Ok(PendingOpaqueStreamBatch {
            identity,
            batch_id: batch.batch_id,
            payload_digest: batch.payload_digest,
            _reservation: reservation,
        })
    }

    /// Poll one submitted opaque stream batch.
    ///
    /// `Ok(None)` means no exact reply was available. Every call consumes at
    /// most one response frame and never waits. A reply for another live
    /// operation is parked, and an inactive late reply is discarded. An
    /// unattributable malformed frame is charged only to this polling
    /// operation; an attributable exact mismatch or negative response also
    /// terminates this operation fail-closed.
    pub fn poll_persist_opaque_stream_batch(
        &self,
        pending: &PendingOpaqueStreamBatch,
    ) -> Result<Option<PersistedOpaqueStreamBatch>, PolledOpaqueStreamError> {
        let Some(raw_response) = self
            .poll_polled_response(pending.identity.operation_id)
            .map_err(|error| match error {
                RequestStateAccessError::Contended => PolledOpaqueStreamError::Busy,
                RequestStateAccessError::NotPending => PolledOpaqueStreamError::NotPending,
            })?
        else {
            return Ok(None);
        };

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
        let (operation_id, reservation) = self
            .try_reserve_polled_request(PolledRequestKind::Execution)
            .map_err(|error| match error {
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
        let message = rpc::encode_honest_request(identity, payload)
            .map_err(|_| PolledExecutionRpcError::InvalidRequest)?;
        self.try_send_request(&message)
            .map_err(|error| match error {
                RequestSendError::Contended => PolledExecutionRpcError::Busy,
                RequestSendError::QueueFull => PolledExecutionRpcError::QueueFull,
            })?;
        notify_host();
        Ok(PendingExecutionRpc {
            identity,
            _reservation: reservation,
        })
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
        let Some(raw_response) = self
            .poll_polled_response(pending.identity.operation_id)
            .map_err(|error| match error {
                RequestStateAccessError::Contended => PolledExecutionRpcError::Busy,
                RequestStateAccessError::NotPending => PolledExecutionRpcError::NotPending,
            })?
        else {
            return Ok(None);
        };
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
    /// A late response remains framed with the abandoned identity and is
    /// discarded as inactive; it can never be accepted for a new operation.
    /// Returns `NotPending` after exact completion or when invoked through a
    /// different client/ring pair. Consuming the token still retires its
    /// origin reservation in the latter case.
    pub fn abandon_execution_rpc(
        &self,
        pending: PendingExecutionRpc,
    ) -> Result<(), PolledExecutionRpcError> {
        if !Arc::ptr_eq(&self.client_identity, &pending._reservation.client_identity) {
            // Consuming the token still retires its origin reservation via
            // Drop, but a different queue pair cannot report that operation
            // as one of its own active requests.
            return Err(PolledExecutionRpcError::NotPending);
        }
        pending
            ._reservation
            .retire()
            .then_some(())
            .ok_or(PolledExecutionRpcError::NotPending)
    }

    // ====================================================================
    //  Core RPC call
    // ====================================================================

    /// Send an RPC request and wait for the matching response.
    ///
    /// Returns `(status, payload)` from the host's response.
    fn call(&self, method: RpcMethod, payload: &[u8]) -> (i32, Vec<u8>) {
        let req_id = match self.try_reserve_synchronous_request() {
            Ok(request_id) => request_id,
            // Legacy callers cannot safely interleave with a polled opaque
            // operation. Return EBUSY instead of blocking the control TCS.
            Err(RequestReserveError::Busy) => return (-16, Vec::new()),
            Err(RequestReserveError::OperationIdExhausted) => return (-75, Vec::new()),
        };
        let msg = rpc::encode_request(req_id, method, payload);

        // Send
        self.send_request(&msg);

        // Wake the host dispatcher
        notify_host();

        // Wait for response
        loop {
            let resp_raw = self.response_rx.recv();
            if let Some((resp_id, status, resp_payload)) = rpc::decode_response(&resp_raw) {
                if resp_id == req_id {
                    self.release_synchronous_request(req_id);
                    return (status, resp_payload.to_vec());
                }
                // Mismatched ID cannot belong to another response-producing
                // request: synchronous admission is exclusive. Ignore it as
                // malformed or late legacy traffic and continue fail-closed.
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
        self.send_request(&msg);
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
