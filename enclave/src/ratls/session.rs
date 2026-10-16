// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! RA-TLS session management — pure bytes-in / bytes-out interface.
//!
//! The session receives raw TCP bytes from the data channel (via the
//! enclave event loop) and emits raw TCP bytes to send back. No OCALLs
//! are performed — all network I/O is handled by the host TCP proxy.
//!
//! This design:
//! - Eliminates per-byte OCALL round-trips (huge perf win)
//! - Decouples TLS logic from transport (testable, composable)
//! - Supports future multi-threading (sessions are `Send`)

use super::cert_store::ConfigurationLease;
use crate::enclave_log_error;
use enclave_os_common::protocol;
use std::vec::Vec;

/// Validated credit bookkeeping only. An absent/handshaking session is passed
/// as None by the server; callers still perform its original invalid teardown.
/// Scheduling only, after an actual TLS feed. Missing, handshaking, revoked or
/// failed sessions never suppress an adopter control opportunity.
pub(crate) fn current_data_session(session: Option<&mut RaTlsSession>) -> bool {
    session.is_some_and(|session| {
        session.require_current_configuration().is_ok()
            && !session.attestation_failed()
            && session.channel_binder_bytes().is_some()
    })
}

pub(crate) fn response_credit(
    payload: &[u8],
    window: Option<&mut enclave_os_common::channel::TcpWriteWindow>,
    established: Option<&RaTlsSession>,
) -> (bool, bool) {
    let Some(written) = enclave_os_common::channel::decode_tcp_write_credit(payload) else {
        return (false, false);
    };
    let Some(window) = window else {
        return (false, false);
    };
    let before = window.available();
    let valid = window.acknowledge(written);
    (
        valid,
        valid
            && window.available() > before
            && established.is_some_and(RaTlsSession::has_pending_response),
    )
}

#[path = "tls_output.rs"]
mod tls_output;
pub use tls_output::TlsOutput;
#[path = "cancellation.rs"]
pub(crate) mod cancellation;
#[path = "channel_output.rs"]
pub(crate) mod channel_output;
#[path = "http_request.rs"]
mod http_request;
#[cfg(any(test, target_env = "sgx", target_vendor = "teaclave"))]
#[path = "leaf_key.rs"]
pub(crate) mod leaf_key;
#[path = "retained_evidence.rs"]
pub(crate) mod retained_evidence;

#[cfg(any(test, target_env = "sgx", target_vendor = "teaclave"))]
#[path = "attest_response.rs"]
pub(crate) mod attest_response;
#[cfg(any(test, target_env = "sgx", target_vendor = "teaclave"))]
#[path = "decoded_attest.rs"]
pub(crate) mod decoded_attest;
#[path = "ordered_map.rs"]
pub(crate) mod ordered_map;
#[path = "pending_client.rs"]
pub(crate) mod pending_client;
#[cfg(any(test, target_env = "sgx", target_vendor = "teaclave"))]
#[path = "quote_time.rs"]
pub(crate) mod quote_time;
#[path = "retained_certificate.rs"]
pub(crate) mod retained_certificate;
#[cfg(any(test, target_env = "sgx", target_vendor = "teaclave"))]
#[path = "retained_name.rs"]
pub(crate) mod retained_name;
#[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
#[path = "retained_quote.rs"]
pub(crate) mod retained_quote;
#[path = "retained_tls_config.rs"]
pub(crate) mod retained_tls_config;
pub use http_request::PaidHttpRequest;

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;

type StreamChunk = (Vec<u8>, usize);
pub(crate) type StreamAllocation = enclave_os_common::allocation::SharedAllocationV1<StreamOwner>;
/// Data-only retained geometry; no stream or request authority.
pub(crate) struct StreamOwner {
    pool: std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
    bytes: usize,
}
impl StreamOwner {
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
    pub(crate) fn reserve_slot(
        &self,
        bytes: usize,
    ) -> Option<enclave_os_common::allocation::AllocationLeaseV1> {
        self.pool.reserve_unpublished(bytes)
    }
}

/// A TLS session backed by a rustls `ServerConnection`.
///
/// The session does NOT own a socket. It operates on raw byte buffers:
/// - `feed_tls_bytes()`: feed raw TCP bytes (encrypted) into the TLS engine
/// - `recv_http_request()`: extract a decoded HTTP/1.1 request
/// - `send_http_response()`: encrypt and emit an HTTP/1.1 response
/// - `close_notify()`: produce the TLS close_notify alert
///
/// All methods that produce network output return the raw TLS bytes that
/// must be sent to the peer (via the data channel → TCP proxy).
pub struct RaTlsSession {
    /// TLS connection state (rustls ServerConnection).
    tls_conn: retained_tls_config::RetainedConnection,
    /// Accumulation buffer for incomplete application-level frames.
    read_buf: Vec<u8>,
    read_allocation: Option<enclave_os_common::allocation::AllocationLeaseV1>,
    read_offset: usize,
    stream_chunks: Option<std::collections::VecDeque<StreamChunk>>,
    // Retained after logical EOF because finish_stream_input can preserve the
    // inherited allocation for a following request. Slot/work aliases share it.
    stream_allocation: Option<StreamAllocation>,
    response: Option<PendingResponse>,
    /// Exact v2 leaf served on this connection (evidence is exchanged separately).
    local_cert_der: retained_certificate::RetainedCertificate,
    /// SNI and endpoint identity selected with the served leaf.
    server_name: Option<String>,
    attested_endpoint: Option<enclave_os_common::modules::AttestedEndpointIdentity>,
    /// Attestation tag of this connection: "none" until the client asks for
    /// evidence after the handshake, then "deterministic" or "challenge".
    attestation: &'static str,
    /// Client context issued in the last attest response that required
    /// client evidence (mutual leg), consumed by the present message.
    client_context: Option<[u8; 32]>,
    channel_binder_cache: std::sync::OnceLock<[u8; RaTlsSession::CHANNEL_BINDER_BYTES]>,
    /// The peer's evidence accepted at present time (binding verified).
    peer_evidence: Option<retained_evidence::RetainedEvidence>,
    local_evidence: Option<retained_evidence::RetainedEvidence>,
    attestation_failed: bool,
    configuration: ConfigurationLease,
    /// FIDO2 identity, set after a successful FIDO2 ceremony on this
    /// session.  When present, subsequent requests on this TLS session
    /// are authenticated without tokens.
    fido2_identity: Option<FidoIdentity>,
}

#[cfg(feature = "diagnostic-transfer-profile")]
static CONTROL_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "diagnostic-transfer-profile")]
static CONTROL_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(feature = "diagnostic-transfer-profile")]
pub fn measure_control<T>(action: impl FnOnce() -> T) -> T {
    use std::sync::atomic::Ordering;
    let start = std::time::Instant::now();
    let result = action();
    let elapsed = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let _ = CONTROL_NS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
        Some(old.saturating_add(elapsed))
    });
    let _ = CONTROL_CALLS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
        Some(old.saturating_add(1))
    });
    result
}

#[cfg(feature = "diagnostic-transfer-profile")]
fn control_cost() -> (u64, u64) {
    use std::sync::atomic::Ordering;
    (
        CONTROL_NS.load(Ordering::Relaxed),
        CONTROL_CALLS.load(Ordering::Relaxed),
    )
}

/// Own the admitted body once, and encrypt at most 32 KiB per control turn.
/// HTTP and TLS never materialize additional whole-body copies.
#[cfg(feature = "diagnostic-transfer-profile")]
struct ResponseCost {
    started: std::time::Instant,
    encryption_ns: u128,
    control_at_open: (u64, u64),
    steps: u64,
    tls_bytes: usize,
}
pub(crate) const TLS_RESPONSE_STEP_BYTES: usize = 64 * 1024;
/// Compare the existing output allocation step against socket counter units.
/// A target that cannot represent the step cannot advertise readiness.
pub(crate) fn response_socket_credit_ready(available: u64) -> bool {
    u64::try_from(TLS_RESPONSE_STEP_BYTES).is_ok_and(|step| available >= step)
}

// Independent plaintext scheduling policy, not a maximum Rustls expansion.
// Record fragmentation, separate body parts and pending TLS control records
// can consume more than this headroom. The actual ciphertext bound is enforced
// by TlsOutput::bounded and append, including all previously queued records.
const TLS_RESPONSE_STEP_HEADROOM_BYTES: usize = 4 * 1024;
const TLS_RESPONSE_PLAINTEXT_STEP_BYTES: usize =
    match TLS_RESPONSE_STEP_BYTES.checked_sub(TLS_RESPONSE_STEP_HEADROOM_BYTES) {
        Some(bytes) if bytes > 0 => bytes,
        _ => core::panic!("invalid TLS response plaintext policy"),
    };
const MAX_RESPONSE_HEADER_BYTES: usize = 32 * 1024;
struct PendingResponse {
    #[cfg(feature = "diagnostic-transfer-profile")]
    cost: Option<ResponseCost>,
    head: Vec<u8>,
    // Header backing is destroyed before this move-only physical credit.
    _header_allocation: Option<enclave_os_common::allocation::AllocationLeaseV1>,
    body: crate::HttpResponsePayload,
    offset: usize,
    close: bool,
    shutdown: bool,
}

/// Ordinary dispatch retains copied context children through the whole callback.
/// Borrowing this data does not grant application authority or transfer credit.
pub(crate) struct PaidRequestContext {
    context: enclave_os_common::modules::RequestContext,
    _allocation: Option<enclave_os_common::allocation::AllocationLeaseV1>,
}
impl core::ops::Deref for PaidRequestContext {
    type Target = enclave_os_common::modules::RequestContext;
    fn deref(&self) -> &Self::Target {
        &self.context
    }
}

/// Identity extracted from a successful FIDO2 registration or
/// authentication ceremony.
#[derive(Debug, Clone)]
pub struct FidoIdentity {
    /// Opaque user handle.
    pub user_handle: String,
    /// Credential ID used (base64url).
    pub credential_id: String,
    /// When the FIDO2 ceremony completed (unix timestamp).
    pub authenticated_at: u64,
}

// SAFETY: RaTlsSession contains only owned types. rustls::ServerConnection
// is Send. Ready for future multi-threaded worker dispatch.
unsafe impl Send for RaTlsSession {}

impl RaTlsSession {
    /// Create a session retaining its admitted certificate owner.
    pub(crate) fn new(
        tls_conn: retained_tls_config::RetainedConnection,
        local_cert_der: retained_certificate::RetainedCertificate,
        server_name: Option<String>,
        attested_endpoint: Option<enclave_os_common::modules::AttestedEndpointIdentity>,
        configuration: ConfigurationLease,
    ) -> Self {
        Self {
            tls_conn,
            read_buf: Vec::new(),
            read_allocation: None,
            read_offset: 0,
            stream_chunks: None,
            stream_allocation: None,
            response: None,
            local_cert_der,
            server_name,
            attested_endpoint,
            attestation: "none",
            client_context: None,
            channel_binder_cache: std::sync::OnceLock::new(),
            peer_evidence: None,
            local_evidence: None,
            attestation_failed: false,
            configuration,
            fido2_identity: None,
        }
    }

    /// Whether the TLS handshake is still in progress.
    pub fn is_handshaking(&self) -> bool {
        self.tls_conn.is_handshaking()
    }

    // ================================================================
    //  Bytes in → TLS engine
    // ================================================================

    /// Feed raw TCP bytes (encrypted) into the TLS engine.
    ///
    /// After calling this, check:
    /// - `collect_tls_output()` for bytes to send back (handshake msgs,
    ///   encrypted app data, NewSessionTicket, etc.)
    /// - `recv_http_request()` for decoded HTTP/1.1 requests
    ///
    /// Returns an error on fatal TLS protocol errors.
    pub fn feed_tls_bytes(&mut self, data: &[u8]) -> Result<(), &'static str> {
        self.require_current_configuration()?;
        if data.is_empty() {
            return Ok(());
        }

        let mut cursor = std::io::Cursor::new(data);
        let len = data.len();

        // Feed all received bytes into rustls. read_tls may only
        // consume a portion per call (internal deframer buffer limit),
        // so loop until the cursor is fully drained.
        //
        // IMPORTANT: Do NOT call read_tls on an exhausted cursor.
        // Cursor::read() returns Ok(0), and rustls interprets that as
        // TCP EOF — corrupting the connection state.
        while (cursor.position() as usize) < len {
            match self.tls_conn.read_tls(&mut cursor) {
                Ok(0) => break,
                Ok(_) => {
                    self.tls_conn.process_new_packets().map_err(|e| {
                        enclave_log_error!("process_new_packets error: {:?}", e);
                        "TLS process_new_packets failed"
                    })?;

                    // Drain decrypted plaintext into read_buf after each
                    // record to prevent the internal rustls plaintext
                    // buffer from filling up ("received plaintext buffer full").
                    self.drain_plaintext()?;
                }
                Err(e) => {
                    enclave_log_error!("read_tls failed: {:?}", e);
                    return Err("TLS read_tls failed");
                }
            }
        }
        Ok(())
    }

    // ================================================================
    //  TLS engine → bytes out
    // ================================================================

    /// Collect all pending TLS output (handshake messages, encrypted
    /// application data, post-handshake alerts, NewSessionTicket, etc.)
    ///
    /// The caller must send the returned bytes to the peer via the data
    /// channel.  Returns an empty Vec if there is nothing to send.
    pub fn collect_tls_output(&mut self) -> Result<TlsOutput, &'static str> {
        let mut output = TlsOutput::default();
        let mut buf = [0u8; Self::PLAINTEXT_READ_CHUNK_BYTES];
        loop {
            let mut cursor = std::io::Cursor::new(&mut buf[..]);
            match self.tls_conn.write_tls(&mut cursor) {
                Ok(0) => break,
                Ok(n) => output.append(&buf[..n])?,
                Err(_) => return Err("TLS write_tls failed"),
            }
        }
        Ok(output)
    }

    // ================================================================
    //  Application data: read (decrypt)
    // ================================================================

    /// Try to receive a complete HTTP/1.1 request from decrypted
    /// application data.
    ///
    /// Call this after `feed_tls_bytes()`. Returns:
    /// - `Ok(Some(request))` — a complete HTTP request is available
    /// - `Ok(None)` — more data needed (partial request)
    /// - `Err` — fatal TLS or parse error
    pub fn recv_http_request(&mut self) -> Result<Option<PaidHttpRequest>, &'static str> {
        self.require_current_configuration()?;
        // Drain any available decrypted plaintext into read_buf
        self.drain_plaintext()?;

        #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
        let pool = Some(crate::local_allocation_pool().ok_or("SDK heap unavailable")?);
        #[cfg(not(any(target_env = "sgx", target_vendor = "teaclave")))]
        let pool = None;
        match PaidHttpRequest::parse(&self.read_buf[self.read_offset..], pool.as_ref())? {
            Some((request, consumed)) => {
                self.read_offset += consumed;
                Ok(Some(request))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn stream_head(
        &mut self,
    ) -> Result<Option<(PaidHttpRequest, usize, usize)>, &'static str> {
        self.require_current_configuration()?;
        #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
        let pool = Some(crate::local_allocation_pool().ok_or("SDK heap unavailable")?);
        #[cfg(not(any(target_env = "sgx", target_vendor = "teaclave")))]
        let pool = None;
        PaidHttpRequest::parse_head(&self.read_buf[self.read_offset..], pool.as_ref())
    }
    pub(crate) fn validate_stream_head(&self) -> bool {
        #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
        let Some(pool) = crate::local_allocation_pool() else {
            return false;
        };
        #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
        let pool = Some(pool);
        #[cfg(not(any(target_env = "sgx", target_vendor = "teaclave")))]
        let pool = None;
        matches!(
            PaidHttpRequest::parse_head(&self.read_buf[self.read_offset..], pool.as_ref()),
            Ok(Some(_))
        )
    }
    // Reuse the old parser Vec plus full-body copy allowance. This is a
    // physical capacity bound; unread bytes keep the original separate cap.
    pub(crate) const STREAM_INPUT_CAPACITY: usize =
        (protocol::MAX_BODY_SIZE + crate::MAX_STREAM_INGRESS_FRAGMENT).next_power_of_two()
            + protocol::MAX_BODY_SIZE;
    // At most one inherited short segment plus capacity / fragment full segments.
    const STREAM_CHUNK_SLOTS: usize =
        Self::STREAM_INPUT_CAPACITY / crate::MAX_STREAM_INGRESS_FRAGMENT + 1;
    fn stream_child_bytes() -> Option<usize> {
        let queue = core::alloc::Layout::array::<StreamChunk>(Self::STREAM_CHUNK_SLOTS)
            .ok()?
            .size();
        Self::STREAM_INPUT_CAPACITY
            .checked_add(crate::MAX_STREAM_INGRESS_FRAGMENT)?
            .checked_add(queue)
    }
    pub(crate) fn stream_allocation_bytes() -> Option<usize> {
        StreamAllocation::required_bytes(Self::stream_child_bytes()?)
    }
    // Native actual TLS fixtures use an explicit bounded inert resource pool;
    // production SGX always supplies the SDK-rooted owner below.
    pub(crate) fn admit_stream_allocation(
        &mut self,
        pool: &std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
    ) -> Result<StreamAllocation, &'static str> {
        let bytes = Self::stream_allocation_bytes().ok_or("stream allocation geometry overflow")?;
        if let Some(lease) = &self.stream_allocation {
            if !std::sync::Arc::ptr_eq(&lease.pool, pool) || lease.bytes != bytes {
                return Err("foreign stream allocation pool");
            }
            return Ok(lease.clone());
        }
        let reservation = StreamAllocation::reserve(
            pool,
            Self::stream_child_bytes().ok_or("stream allocation geometry overflow")?,
        )
        .ok_or("stream allocation admission exhausted")?;
        let lease = reservation.finish(StreamOwner {
            pool: pool.clone(),
            bytes,
        });
        self.stream_allocation = Some(lease.clone());
        Ok(lease)
    }
    #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
    pub(crate) fn reserve_stream_allocation(&mut self) -> Result<StreamAllocation, &'static str> {
        let pool = crate::local_allocation_pool().ok_or("SDK heap unavailable")?;
        self.admit_stream_allocation(&pool)
    }
    pub(crate) fn consume_stream_head(&mut self, bytes: usize) -> Result<(), &'static str> {
        #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
        self.reserve_stream_allocation()?;
        let offset = self
            .read_offset
            .checked_add(bytes)
            .ok_or("stream header overflow")?;
        if offset > self.read_buf.len()
            || self.read_buf.capacity()
                > (protocol::MAX_BODY_SIZE + crate::MAX_STREAM_INGRESS_FRAGMENT).next_power_of_two()
        {
            return Err("stream inherited input capacity exceeded bound");
        }
        let mut chunks = self.stream_chunks.take().unwrap_or_default();
        chunks.clear();
        if chunks.capacity() == 0 {
            chunks
                .try_reserve_exact(Self::STREAM_CHUNK_SLOTS)
                .map_err(|_| "stream queue allocation failed")?;
        }
        if chunks.capacity() != Self::STREAM_CHUNK_SLOTS {
            return Err("stream queue capacity exceeded admission");
        }
        // The pre-admitted stream owner now covers this inherited backing.
        // Transfer coverage only after that real reservation has succeeded.
        let bytes = std::mem::take(&mut self.read_buf);
        if self.stream_allocation.is_some() {
            drop(self.read_allocation.take());
        }
        self.read_offset = 0;
        if bytes.len() > offset {
            chunks.push_back((bytes, offset));
        }
        self.stream_chunks = Some(chunks);
        Ok(())
    }
    pub(crate) fn stream_fragment(&mut self, maximum: usize) -> Vec<u8> {
        let maximum = maximum.min(crate::MAX_STREAM_INGRESS_FRAGMENT);
        let Some(chunks) = self.stream_chunks.as_mut() else {
            return Vec::new();
        };
        let mut result = Vec::with_capacity(maximum);
        while result.len() < maximum {
            let Some((bytes, offset)) = chunks.front_mut() else {
                break;
            };
            let take = (maximum - result.len()).min(bytes.len() - *offset);
            result.extend_from_slice(&bytes[*offset..*offset + take]);
            *offset += take;
            if *offset == bytes.len() {
                chunks.pop_front();
            }
        }
        result
    }
    pub(crate) fn stream_input_bytes(&self) -> usize {
        self.stream_chunks
            .as_ref()
            .map_or(self.read_buf.len() - self.read_offset, |chunks| {
                chunks.iter().map(|(b, o)| b.len() - o).sum()
            })
    }
    pub(crate) fn stream_has_input(&self) -> bool {
        self.stream_chunks
            .as_ref()
            .map_or(self.read_offset < self.read_buf.len(), |q| !q.is_empty())
    }
    pub(crate) fn finish_stream_input(&mut self) -> Result<(), &'static str> {
        let Some(mut chunks) = self.stream_chunks.take() else {
            return Ok(());
        };
        let Some((mut buffer, offset)) = chunks.pop_front() else {
            return Ok(());
        };
        // Compact once, at the stream-to-contiguous boundary, reusing the inherited
        // allocation rather than holding two potentially32MiB buffers.
        buffer.drain(..offset);
        let total = buffer.len() + chunks.iter().map(|(b, o)| b.len() - o).sum::<usize>();
        if buffer.capacity() < total {
            // Before one exact reserve, consume/drop enough existing small
            // segments to keep old+new allocations within the original charge.
            while buffer.capacity()
                + total
                + chunks.iter().map(|(b, _)| b.capacity()).sum::<usize>()
                > Self::STREAM_INPUT_CAPACITY
            {
                let Some((bytes, offset)) = chunks.pop_front() else {
                    return Err("stream terminal input capacity exceeded bound");
                };
                if buffer.len() + bytes.len() - offset > buffer.capacity() {
                    return Err("stream terminal input requires uncharged allocation");
                }
                buffer.extend_from_slice(&bytes[offset..]);
            }
            buffer.reserve_exact(total - buffer.len());
        }
        if buffer.capacity() + chunks.iter().map(|(b, _)| b.capacity()).sum::<usize>()
            > Self::STREAM_INPUT_CAPACITY
        {
            return Err("stream terminal input capacity exceeded bound");
        }
        for (bytes, offset) in chunks {
            buffer.extend_from_slice(&bytes[offset..]);
        }
        self.read_buf = buffer;
        self.read_offset = 0;
        Ok(())
    }

    /// Encrypt and send an HTTP/1.1 response.
    ///
    /// Returns the raw TLS output bytes to send to the peer.  For large
    /// responses the TLS layer may produce multiple records; this method
    /// flushes incrementally so the internal rustls buffer never fills up.
    pub fn send_http_response(
        &mut self,
        status: u16,
        body: &[u8],
        close: bool,
    ) -> Result<TlsOutput, &'static str> {
        self.send_http_response_with_headers(status, "application/json", &[], body, close)
    }
    /// Same original response with an explicit content type.
    pub fn send_http_response_typed(
        &mut self,
        status: u16,
        content_type: &str,
        body: &[u8],
        close: bool,
    ) -> Result<TlsOutput, &'static str> {
        self.send_http_response_with_headers(status, content_type, &[], body, close)
    }
    /// Header and body enter the original TLS writer without a whole-response copy.
    pub fn send_http_response_with_headers(
        &mut self,
        status: u16,
        content_type: &str,
        extra_headers: &[(String, String)],
        body: &[u8],
        close: bool,
    ) -> Result<TlsOutput, &'static str> {
        self.require_current_configuration()?;
        let length = protocol::response_head_encoded_len(
            status,
            content_type,
            extra_headers,
            body.len(),
            close,
        )
        .ok_or("HTTP header length overflow")?;
        let head = TlsOutput::encoded(length, || {
            protocol::format_http_response_head_bounded(
                status,
                content_type,
                extra_headers,
                body.len(),
                close,
                length,
            )
        })?;
        let mut output = TlsOutput::default();
        self.write_plaintext_chunked(&head, &mut output)?;
        self.write_plaintext_chunked(body, &mut output)?;
        output.append(&self.collect_tls_output()?)?;
        Ok(output)
    }

    pub fn has_pending_response(&self) -> bool {
        self.response.is_some()
    }

    /// Keep an unconsumed body available for its owner to drop outside STATE.
    pub(crate) fn queue_http_response_owned(
        &mut self,
        status: u16,
        content_type: &str,
        extra_headers: &[(String, String)],
        body: impl Into<crate::HttpResponsePayload>,
        close: bool,
        shutdown: bool,
    ) -> std::ops::ControlFlow<(&'static str, crate::HttpResponsePayload)> {
        let body = body.into();
        #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
        let pool = match crate::local_allocation_pool() {
            Some(pool) => Some(pool),
            None => return std::ops::ControlFlow::Break(("SDK heap unavailable", body)),
        };
        #[cfg(not(any(target_env = "sgx", target_vendor = "teaclave")))]
        let pool = None;
        self.queue_http_response_admitted(
            status,
            content_type,
            extra_headers,
            body,
            (close, shutdown),
            pool.as_ref(),
        )
    }
    // Native owning fixtures supply a real pool here. Production always supplies
    // the existing SDK pool through queue_http_response_owned above.
    fn queue_http_response_admitted(
        &mut self,
        status: u16,
        content_type: &str,
        extra_headers: &[(String, String)],
        body: crate::HttpResponsePayload,
        completion: (bool, bool),
        pool: Option<&std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>>,
    ) -> std::ops::ControlFlow<(&'static str, crate::HttpResponsePayload)> {
        let (close, shutdown) = completion;
        if let Err(error) = self.require_current_configuration() {
            return std::ops::ControlFlow::Break((error, body));
        }
        if self.response.is_some() {
            return std::ops::ControlFlow::Break(("response already pending", body));
        }
        let Some(head_bytes) = protocol::response_head_encoded_len(
            status,
            content_type,
            extra_headers,
            body.len(),
            close,
        )
        .filter(|n| *n <= MAX_RESPONSE_HEADER_BYTES) else {
            return std::ops::ControlFlow::Break(("response headers too large", body));
        };
        let allocation = match pool {
            Some(pool) => match pool.reserve_unpublished(head_bytes) {
                Some(credit) => Some(credit),
                None => {
                    return std::ops::ControlFlow::Break((
                        "response header admission exhausted",
                        body,
                    ))
                }
            },
            None => None,
        };
        let head = match protocol::format_http_response_head_bounded(
            status,
            content_type,
            extra_headers,
            body.len(),
            close,
            head_bytes,
        ) {
            Ok(head) => head,
            Err(error) => return std::ops::ControlFlow::Break((error, body)),
        };
        if let Some(credit) = &allocation {
            credit.activate_release_notification();
        }
        self.response = Some(PendingResponse {
            #[cfg(feature = "diagnostic-transfer-profile")]
            cost: (body.len() >= 1024 * 1024).then(|| ResponseCost {
                started: std::time::Instant::now(),
                encryption_ns: 0,
                control_at_open: control_cost(),
                steps: 0,
                tls_bytes: 0,
            }),
            head,
            _header_allocation: allocation,
            body,
            offset: 0,
            close,
            shutdown,
        });
        std::ops::ControlFlow::Continue(())
    }

    /// Caller reserves 64 KiB of socket credit before each step. Configuration
    /// revocation is checked even while a previously admitted body is draining.
    pub fn progress_http_response(&mut self) -> Result<(TlsOutput, bool, bool), &'static str> {
        self.require_current_configuration()?;
        let mut response = self.response.take().ok_or("no pending response")?;
        #[cfg(feature = "diagnostic-transfer-profile")]
        let step_started = response.cost.as_ref().map(|_| std::time::Instant::now());
        let mut output = TlsOutput::bounded(TLS_RESPONSE_STEP_BYTES);
        // Admit this much new plaintext; actual pending/framing bytes still
        // pass the independent ciphertext limit on every append.
        let mut remaining = TLS_RESPONSE_PLAINTEXT_STEP_BYTES;
        if !response.head.is_empty() {
            self.write_plaintext_chunked(&response.head, &mut output)?;
            remaining -= response.head.len();
            response.head.clear();
        }
        let end = response
            .body
            .len()
            .min(response.offset.saturating_add(remaining));
        while response.offset < end {
            let part = response
                .body
                .part(response.offset, end - response.offset)
                .filter(|part| !part.is_empty())
                .ok_or("invalid segmented response")?;
            self.write_plaintext_chunked(part, &mut output)?;
            response.offset += part.len();
        }
        output.append(&self.collect_tls_output()?)?;
        if output.len() > TLS_RESPONSE_STEP_BYTES {
            return Err("bounded TLS response exceeded credit");
        }
        #[cfg(feature = "diagnostic-transfer-profile")]
        if let (Some(cost), Some(started)) = (&mut response.cost, step_started) {
            cost.encryption_ns += started.elapsed().as_nanos();
            cost.steps += 1;
            cost.tls_bytes += output.len();
        }
        if response.offset == response.body.len() {
            #[cfg(feature = "diagnostic-transfer-profile")]
            if let Some(cost) = response.cost {
                let control = control_cost();
                let message = format!(
                    "MINI-BOUNDED-COST body_bytes={} tls_bytes={} steps={} encrypt_ns={} span_ns={} control_ns={} control_calls={} suite={:?} clock=UNTRUSTED-DIAGNOSTIC",
                    response.body.len(), cost.tls_bytes, cost.steps, cost.encryption_ns,
                    cost.started.elapsed().as_nanos(),
                    control.0.saturating_sub(cost.control_at_open.0),
                    control.1.saturating_sub(cost.control_at_open.1), self.tls_conn.negotiated_cipher_suite().map(|suite| suite.suite())
                );
                #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
                enclave_os_common::enclave_log_info!("{}", message);
                #[cfg(not(any(target_env = "sgx", target_vendor = "teaclave")))]
                eprintln!("{}", message);
            }
            Ok((output, response.close, response.shutdown))
        } else {
            self.response = Some(response);
            Ok((output, false, false))
        }
    }

    const PLAINTEXT_READ_CHUNK_BYTES: usize = 16 * 1024;
    const MAX_PENDING_HTTP_BYTES: usize =
        protocol::MAX_BODY_SIZE + crate::MAX_STREAM_INGRESS_FRAGMENT;
    fn append_plaintext_admitted(
        &mut self,
        input: &[u8],
        pool: Option<&std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>>,
    ) -> Result<(), &'static str> {
        let required = self
            .read_buf
            .len()
            .checked_add(input.len())
            .ok_or("pending HTTP input overflow")?;
        if required > Self::MAX_PENDING_HTTP_BYTES {
            return Err("pending HTTP input exceeded bound");
        }
        if required > self.read_buf.capacity() {
            let maximum = Self::MAX_PENDING_HTTP_BYTES
                .checked_next_power_of_two()
                .ok_or("HTTP capacity overflow")?;
            let capacity = enclave_os_common::allocation::bounded_vec_capacity(required, maximum)
                .ok_or("HTTP capacity overflow")?;
            // The stream owner already prepaid this old/new parser overlap.
            // Ordinary sessions reserve new backing while the old lease lives.
            let covered = self.stream_allocation.is_some();
            if covered
                && self
                    .read_buf
                    .capacity()
                    .checked_add(capacity)
                    .is_none_or(|n| n > Self::STREAM_INPUT_CAPACITY)
            {
                return Err("stream parser replacement exceeds admission");
            }
            let allocation = if covered {
                None
            } else {
                match pool {
                    Some(pool) => Some(
                        pool.reserve_unpublished(capacity)
                            .ok_or("HTTP input admission exhausted")?,
                    ),
                    None => None,
                }
            };
            self.read_buf
                .try_reserve_exact(capacity - self.read_buf.len())
                .map_err(|_| "HTTP input allocation failed")?;
            if self.read_buf.capacity() != capacity {
                // Refusal must not retain new backing after its temporary
                // reservation refunds. The caller closes this failed stream.
                drop(core::mem::take(&mut self.read_buf));
                drop(self.read_allocation.take());
                self.read_offset = 0;
                return Err("HTTP input capacity exceeds admission");
            }
            if !covered {
                // Successful realloc freed the old backing before this credit.
                let old = core::mem::replace(&mut self.read_allocation, allocation);
                drop(old);
                if let Some(credit) = &self.read_allocation {
                    credit.activate_release_notification();
                }
            }
        }
        self.read_buf.extend_from_slice(input);
        Ok(())
    }

    /// Drain all available decrypted plaintext from the TLS reader into
    /// the internal accumulation buffer.
    fn drain_plaintext(&mut self) -> Result<(), &'static str> {
        // Fixed reader scratch uses the existing thread stack, not a hidden Vec.
        let mut buf = [0u8; Self::PLAINTEXT_READ_CHUNK_BYTES];
        #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
        let pool = Some(crate::local_allocation_pool().ok_or("SDK heap unavailable")?);
        #[cfg(not(any(target_env = "sgx", target_vendor = "teaclave")))]
        let pool = None;
        loop {
            let mut reader = self.tls_conn.reader();
            use std::io::Read;
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Some(chunks) = self.stream_chunks.as_mut() {
                        let unread: usize = chunks.iter().map(|(v, o)| v.len() - o).sum();
                        if unread.saturating_add(n)
                            > protocol::MAX_BODY_SIZE + crate::MAX_STREAM_INGRESS_FRAGMENT
                        {
                            return Err("stream unread input exceeded bound");
                        }
                        let capacity: usize = chunks.iter().map(|(v, _)| v.capacity()).sum();
                        if chunks.back().is_none_or(|(v, _)| v.len() == v.capacity()) {
                            if capacity + crate::MAX_STREAM_INGRESS_FRAGMENT
                                > Self::STREAM_INPUT_CAPACITY
                            {
                                return Err("stream input capacity exceeded bound");
                            }
                            if chunks.len() == Self::STREAM_CHUNK_SLOTS {
                                return Err("stream queue full");
                            }
                            chunks.push_back((
                                Vec::with_capacity(crate::MAX_STREAM_INGRESS_FRAGMENT),
                                0,
                            ));
                        }
                        let mut input = &buf[..n];
                        while !input.is_empty() {
                            let (last, _) = chunks.back_mut().unwrap();
                            let take = input.len().min(last.capacity() - last.len());
                            last.extend_from_slice(&input[..take]);
                            input = &input[take..];
                            if !input.is_empty() {
                                let capacity: usize =
                                    chunks.iter().map(|(v, _)| v.capacity()).sum();
                                if capacity + crate::MAX_STREAM_INGRESS_FRAGMENT
                                    > Self::STREAM_INPUT_CAPACITY
                                {
                                    return Err("stream input capacity exceeded bound");
                                }
                                if chunks.len() == Self::STREAM_CHUNK_SLOTS {
                                    return Err("stream queue full");
                                }
                                chunks.push_back((
                                    Vec::with_capacity(crate::MAX_STREAM_INGRESS_FRAGMENT),
                                    0,
                                ));
                            }
                        }
                        continue;
                    }
                    // Compact only after consuming at least the remaining
                    // suffix, or to maintain the unchanged physical buffer cap.
                    // Every byte moves amortized once, never per64KiB fragment.
                    if self.read_offset > 0
                        && (self.read_offset >= self.read_buf.len() - self.read_offset
                            || self.read_buf.len().saturating_add(n)
                                > protocol::MAX_BODY_SIZE + crate::MAX_STREAM_INGRESS_FRAGMENT)
                    {
                        self.read_buf.drain(..self.read_offset);
                        self.read_offset = 0;
                    }
                    self.append_plaintext_admitted(&buf[..n], pool.as_ref())?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    enclave_log_error!("reader.read error: kind={:?} msg={}", e.kind(), e);
                    return Err("TLS read failed");
                }
            }
        }
        Ok(())
    }

    // ================================================================
    //  Application data: write (encrypt)
    // ================================================================

    /// Write plaintext into the TLS writer in chunks, flushing TLS
    /// output records into `output` whenever the internal buffer fills.
    ///
    /// This prevents the ~64 KB rustls internal buffer from truncating
    /// large responses.
    fn write_plaintext_chunked(
        &mut self,
        data: &[u8],
        output: &mut TlsOutput,
    ) -> Result<(), &'static str> {
        self.require_current_configuration()?;
        use std::io::Write;
        let mut offset = 0;
        while offset < data.len() {
            let n = {
                let mut writer = self.tls_conn.writer();
                writer.write(&data[offset..]).map_err(|e| {
                    enclave_log_error!(
                        "writer.write failed ({}B remaining): kind={:?} msg={}",
                        data.len() - offset,
                        e.kind(),
                        e
                    );
                    "TLS write failed"
                })?
            };
            if n == 0 {
                // rustls internal buffer full — flush encrypted records
                // to make room, then continue writing.
                let flushed = self.collect_tls_output()?;
                if flushed.is_empty() {
                    // No progress possible — should not happen but avoid
                    // an infinite loop.
                    enclave_log_error!(
                        "write_plaintext_chunked: no progress at offset {}/{}",
                        offset,
                        data.len()
                    );
                    return Err("TLS write stalled: no progress");
                }
                output.append(&flushed)?;
            } else {
                offset += n;
            }
        }
        Ok(())
    }

    // ================================================================
    //  Peer certificate access
    // ================================================================

    /// Return the DER-encoded leaf certificate presented by the TLS client.
    ///
    /// Returns `Some(der)` when the client presented a certificate during
    /// the handshake (mutual RA-TLS), or `None` for unauthenticated
    /// clients (e.g. browsers).
    pub fn peer_cert_der(&self) -> Option<Vec<u8>> {
        self.peer_cert_der_ref().map(<[u8]>::to_vec)
    }
    pub(crate) fn peer_cert_der_ref(&self) -> Option<&[u8]> {
        self.tls_conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|cert| cert.as_ref())
    }

    /// Attestation tag of this connection ("none", "deterministic", "challenge").
    pub fn attestation(&self) -> &'static str {
        self.attestation
    }

    /// Borrow the immutable served leaf for identity comparisons. This is data,
    /// not a currentness grant; dispatch/exporter checks retain their authority.
    pub(crate) fn local_cert_der_ref(&self) -> &[u8] {
        self.local_cert_der.bytes()
    }

    /// Exact DER leaf served by this session.
    pub fn local_cert_der(&self) -> Option<Vec<u8>> {
        Some(self.local_cert_der.bytes().to_vec())
    }

    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    pub fn attested_endpoint(
        &self,
    ) -> Option<enclave_os_common::modules::AttestedEndpointIdentity> {
        self.attested_endpoint
    }

    /// Record what the client asked for after the handshake.
    pub fn set_attestation(&mut self, tag: &'static str) {
        self.attestation = tag;
    }

    /// Start a new proof exchange without retaining a previous client's admission.
    pub fn begin_attestation(&mut self) {
        self.attestation = "none";
        self.client_context = None;
        self.peer_evidence = None;
        self.local_evidence = None;
    }

    pub fn fail_attestation(&mut self) {
        self.begin_attestation();
        self.attestation_failed = true;
    }

    pub fn attestation_failed(&self) -> bool {
        self.attestation_failed
    }

    pub fn local_evidence(&self) -> Option<&enclave_os_common::modules::PeerEvidence> {
        self.configuration.is_current().then_some(())?;
        self.local_evidence
            .as_ref()
            .map(retained_evidence::RetainedEvidence::evidence)
    }

    pub(crate) fn set_local_evidence(&mut self, value: retained_evidence::RetainedEvidence) {
        self.local_evidence = Some(value);
    }

    /// Retain evidence whose key/exporter binding was checked. Its quote
    /// signature and admission policy still require application appraisal.
    pub(crate) fn set_peer_evidence(&mut self, value: retained_evidence::RetainedEvidence) {
        self.peer_evidence = Some(value);
    }

    /// Requested child allocation lengths of the actual fresh_context copies.
    /// RequestContext itself moves inline in Work; its container is a separate
    /// owner. Fixed endpoint fields are Copy; oidc_claims is None on this path.
    pub(crate) fn context_allocation_bound(&self) -> Option<usize> {
        fn evidence(value: &enclave_os_common::modules::PeerEvidence) -> Option<usize> {
            value
                .tee
                .len()
                .checked_add(value.quote.len())?
                .checked_add(value.quote_time.len())?
                .checked_add(value.gpu_evidence.as_ref().map_or(0, Vec::len))
        }
        let mut bytes = Self::CHANNEL_BINDER_BYTES
            .checked_add(self.attestation().len())?
            .checked_add(self.local_cert_der.bytes().len())?
            .checked_add(self.server_name.as_ref().map_or(0, String::len))?
            .checked_add(
                self.tls_conn
                    .peer_certificates()
                    .and_then(|certs| certs.first())
                    .map_or(0, |cert| cert.as_ref().len()),
            )?;
        for value in [&self.local_evidence, &self.peer_evidence]
            .into_iter()
            .flatten()
        {
            bytes = bytes.checked_add(evidence(value.evidence())?)?;
        }
        Some(bytes)
    }

    pub(crate) fn request_context(
        &self,
        connection_id: u32,
        ingress_class: enclave_os_common::modules::IngressClass,
    ) -> Result<PaidRequestContext, &'static str> {
        #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
        let pool = Some(crate::local_allocation_pool().ok_or("SDK heap unavailable")?);
        #[cfg(not(any(target_env = "sgx", target_vendor = "teaclave")))]
        let pool = None;
        self.request_context_with_pool(connection_id, ingress_class, pool.as_ref())
    }
    fn request_context_with_pool(
        &self,
        connection_id: u32,
        ingress_class: enclave_os_common::modules::IngressClass,
        pool: Option<&std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>>,
    ) -> Result<PaidRequestContext, &'static str> {
        if !self.configuration.is_current() || self.attestation_failed() {
            return Err("TLS context is not current");
        }
        let bytes = self
            .context_allocation_bound()
            .ok_or("context size overflow")?;
        let allocation = match pool {
            Some(pool) => Some(
                pool.reserve_unpublished(bytes)
                    .ok_or("context admission exhausted")?,
            ),
            None => None,
        };
        let context = enclave_os_common::modules::RequestContext {
            ingress_class,
            connection_id,
            server_name: self.server_name().map(str::to_owned),
            attested_endpoint: self.attested_endpoint(),
            local_cert_der: self.local_cert_der(),
            local_evidence: self.local_evidence().cloned(),
            channel_binder: self.channel_binder(),
            peer_cert_der: self.peer_cert_der(),
            peer_evidence: self.peer_evidence().cloned(),
            attestation: self.attestation().to_string(),
            oidc_claims: None,
        };
        if let Some(credit) = &allocation {
            credit.activate_release_notification();
        }
        Ok(PaidRequestContext {
            context,
            _allocation: allocation,
        })
    }

    /// Owned context child; actual callers reserve the copied-context quote.
    pub fn channel_binder(&self) -> Option<Vec<u8>> {
        self.channel_binder_bytes().map(|value| value.to_vec())
    }

    /// Fixed exporter output for comparisons. Only a successful connection
    /// exporter is cached; every use rechecks the original configuration lease.
    pub(crate) fn channel_binder_bytes(&self) -> Option<[u8; Self::CHANNEL_BINDER_BYTES]> {
        self.configuration.is_current().then_some(())?;
        if let Some(value) = self.channel_binder_cache.get() {
            return Some(*value);
        }
        let value = self
            .tls_conn
            .export_keying_material(
                [0u8; Self::CHANNEL_BINDER_BYTES],
                b"EXPORTER-honest-peer-channel-v2",
                Some(&[]),
            )
            .ok()?;
        Some(*self.channel_binder_cache.get_or_init(|| value))
    }

    /// Remember the client context issued with an attest response that
    /// requires client evidence.
    pub fn set_client_context(&mut self, ctx: [u8; 32]) {
        self.client_context = Some(ctx);
    }

    /// Take the pending client context (one present per response).
    pub fn take_client_context(&mut self) -> Option<[u8; 32]> {
        self.client_context.take()
    }

    /// The peer's evidence accepted at present time, if any.
    pub fn peer_evidence(&self) -> Option<&enclave_os_common::modules::PeerEvidence> {
        self.configuration.is_current().then_some(())?;
        self.peer_evidence
            .as_ref()
            .map(retained_evidence::RetainedEvidence::evidence)
    }

    /// Existing exporter protocol width, shared by its allocation consumers.
    pub const CHANNEL_BINDER_BYTES: usize = 32;

    /// The 32-byte RFC 8446 exporter value of this connection for `label` and
    /// `context`, keyed by exporter_master_secret (RA-TLS v2 binding).
    pub fn export_hctx(
        &self,
        label: &[u8],
        context: &[u8],
    ) -> Result<[u8; Self::CHANNEL_BINDER_BYTES], String> {
        if !self.configuration.is_current() {
            return Err("certificate configuration changed; reconnect required".into());
        }
        self.tls_conn
            .export_keying_material([0u8; Self::CHANNEL_BINDER_BYTES], label, Some(context))
            .map_err(|e| format!("exporter: {e}"))
    }

    /// Return the FIDO2 identity for this session, if authenticated.
    pub fn fido2_identity(&self) -> Option<&FidoIdentity> {
        self.fido2_identity.as_ref()
    }

    /// Mark this session as FIDO2-authenticated.
    pub fn set_fido2_identity(&mut self, identity: FidoIdentity) {
        self.fido2_identity = Some(identity);
    }

    // ================================================================
    //  Lifecycle
    // ================================================================

    /// Produce a TLS close_notify alert.
    ///
    /// Returns the raw TLS bytes to send to the peer. The caller should
    /// send these via the data channel, then close the connection.
    pub fn close_notify(&mut self) -> TlsOutput {
        self.tls_conn.send_close_notify();
        self.collect_tls_output().unwrap_or_default()
    }
    /// Check at ingress and before each decoded request/response. Buffered
    /// requests must not cross a workload replacement within one TLS flight.
    pub(crate) fn require_current_configuration(&mut self) -> Result<(), &'static str> {
        if !self.configuration.is_current() {
            self.fail_attestation();
            self.fido2_identity = None;
            self.read_buf.clear();
            self.read_offset = 0;
            self.stream_chunks = None;
            self.response = None;
            return Err("certificate configuration changed; reconnect required");
        }
        Ok(())
    }
}
