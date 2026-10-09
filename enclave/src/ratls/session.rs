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
            && session.channel_binder().is_some()
    })
}

pub(crate) fn response_credit(
    payload: &[u8],
    window: Option<&mut enclave_os_common::channel::TcpWriteWindow>,
    established: Option<&RaTlsSession>,
) -> (bool, bool) {
    let Some(written) = enclave_os_common::channel::decode_tcp_write_credit(payload) else { return (false, false); };
    let Some(window) = window else { return (false, false); };
    let before = window.available();
    let valid = window.acknowledge(written);
    (valid, valid && window.available() > before
        && established.is_some_and(RaTlsSession::has_pending_response))
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;

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
    tls_conn: rustls::ServerConnection,
    /// Accumulation buffer for incomplete application-level frames.
    read_buf: Vec<u8>,
    read_offset:usize,
    stream_chunks:Option<std::collections::VecDeque<(Vec<u8>,usize)>>,
    response: Option<PendingResponse>,
    /// Exact v2 leaf served on this connection (evidence is exchanged separately).
    local_cert_der: Vec<u8>,
    /// SNI and endpoint identity selected with the served leaf.
    server_name: Option<String>,
    attested_endpoint: Option<enclave_os_common::modules::AttestedEndpointIdentity>,
    /// Attestation tag of this connection: "none" until the client asks for
    /// evidence after the handshake, then "deterministic" or "challenge".
    attestation: &'static str,
    /// Client context issued in the last attest response that required
    /// client evidence (mutual leg), consumed by the present message.
    client_context: Option<[u8; 32]>,
    /// The peer's evidence accepted at present time (binding verified).
    peer_evidence: Option<enclave_os_common::modules::PeerEvidence>,
    local_evidence: Option<enclave_os_common::modules::PeerEvidence>,
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
struct PendingResponse {
    #[cfg(feature = "diagnostic-transfer-profile")]
    cost: Option<ResponseCost>,
    head: Vec<u8>,
    body: crate::HttpResponsePayload,
    offset: usize,
    close: bool,
    shutdown: bool,
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
    /// Create a session from a `ServerConnection`.
    ///
    /// The caller (IngressServer) is responsible for creating the
    /// ServerConnection from the Acceptor flow.
    ///
    pub fn new(
        tls_conn: rustls::ServerConnection,
        local_cert_der: Vec<u8>,
        server_name: Option<String>,
        attested_endpoint: Option<enclave_os_common::modules::AttestedEndpointIdentity>,
        configuration: ConfigurationLease,
    ) -> Self {
        Self {
            tls_conn,
            read_buf: Vec::new(),read_offset:0,stream_chunks:None,
            response: None,
            local_cert_der,
            server_name,
            attested_endpoint,
            attestation: "none",
            client_context: None,
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
    pub fn collect_tls_output(&mut self) -> Result<Vec<u8>, &'static str> {
        let mut output = Vec::new();
        let mut buf = vec![0u8; 16384];
        loop {
            let mut cursor = std::io::Cursor::new(&mut buf[..]);
            match self.tls_conn.write_tls(&mut cursor) {
                Ok(0) => break,
                Ok(n) => output.extend_from_slice(&buf[..n]),
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
    pub fn recv_http_request(&mut self) -> Result<Option<protocol::HttpRequest>, &'static str> {
        self.require_current_configuration()?;
        // Drain any available decrypted plaintext into read_buf
        self.drain_plaintext()?;

        match protocol::parse_http_request(&self.read_buf[self.read_offset..]) {
            Ok((request, consumed)) => {
                self.read_offset+=consumed;
                Ok(Some(request))
            }
            Err(protocol::HttpParseError::Incomplete) => Ok(None),
            Err(protocol::HttpParseError::TooManyHeaders) => Err("HTTP: too many headers"),
            Err(protocol::HttpParseError::BodyTooLarge) => Err("HTTP body too large"),
            Err(_) => Err("malformed HTTP request"),
        }
    }

    pub(crate) fn stream_head(&mut self)->Result<Option<(protocol::HttpRequest,usize,usize)>,&'static str> {
        self.require_current_configuration()?;
        match protocol::peek_http_stream_request_head(&self.read_buf[self.read_offset..]) {
            Ok(value)=>Ok(Some(value)),
            Err(protocol::HttpParseError::Incomplete)=>Ok(None),
            Err(_)=>Err("malformed streaming HTTP header"),
        }
    }
    pub(crate) fn validate_stream_head(&self)->bool {protocol::parse_http_stream_request_head(&self.read_buf[self.read_offset..]).is_ok()}
    // Reuse the old parser Vec plus full-body copy allowance. This is a
    // physical capacity bound; unread bytes keep the original separate cap.
    pub(crate) const STREAM_INPUT_CAPACITY:usize=(protocol::MAX_BODY_SIZE+64*1024).next_power_of_two()+protocol::MAX_BODY_SIZE;
    pub(crate) fn consume_stream_head(&mut self,bytes:usize)->Result<(),&'static str> {
        let offset=self.read_offset.checked_add(bytes).ok_or("stream header overflow")?;
        if offset>self.read_buf.len() || self.read_buf.capacity()>(protocol::MAX_BODY_SIZE+64*1024).next_power_of_two(){return Err("stream inherited input capacity exceeded bound");}
        let bytes=std::mem::take(&mut self.read_buf);self.read_offset=0;
        let mut chunks=std::collections::VecDeque::new();
        if bytes.len()>offset {chunks.push_back((bytes,offset));}
        self.stream_chunks=Some(chunks);Ok(())
    }
    pub(crate) fn stream_fragment(&mut self,maximum:usize)->Vec<u8> {
        let maximum=maximum.min(crate::MAX_STREAM_INGRESS_FRAGMENT);
        let Some(chunks)=self.stream_chunks.as_mut() else{return Vec::new();};
        let mut result=Vec::with_capacity(maximum);
        while result.len()<maximum {
            let Some((bytes,offset))=chunks.front_mut() else{break;};
            let take=(maximum-result.len()).min(bytes.len()-*offset);
            result.extend_from_slice(&bytes[*offset..*offset+take]);*offset+=take;
            if *offset==bytes.len(){chunks.pop_front();}
        }
        result
    }
    pub(crate) fn stream_input_bytes(&self)->usize {
        self.stream_chunks.as_ref().map_or(self.read_buf.len()-self.read_offset,|chunks|chunks.iter().map(|(b,o)|b.len()-o).sum())
    }
    pub(crate) fn stream_has_input(&self)->bool {
        self.stream_chunks.as_ref().map_or(self.read_offset<self.read_buf.len(),|q|!q.is_empty())
    }
    pub(crate) fn finish_stream_input(&mut self)->Result<(),&'static str> {
        let Some(mut chunks)=self.stream_chunks.take() else{return Ok(());};
        let Some((mut buffer,offset))=chunks.pop_front() else{return Ok(());};
        // Compact once, at the stream-to-legacy boundary, reusing the inherited
        // allocation rather than holding two potentially32MiB buffers.
        buffer.drain(..offset);
        let total=buffer.len()+chunks.iter().map(|(b,o)|b.len()-o).sum::<usize>();
        if buffer.capacity()<total {
            // Before one exact reserve, consume/drop enough existing small
            // segments to keep old+new allocations within the original charge.
            while buffer.capacity()+total+chunks.iter().map(|(b,_)|b.capacity()).sum::<usize>()>Self::STREAM_INPUT_CAPACITY {
                let Some((bytes,offset))=chunks.pop_front() else{return Err("stream terminal input capacity exceeded bound");};
                if buffer.len()+bytes.len()-offset>buffer.capacity(){return Err("stream terminal input requires uncharged allocation");}
                buffer.extend_from_slice(&bytes[offset..]);
            }
            buffer.reserve_exact(total-buffer.len());
        }
        if buffer.capacity()+chunks.iter().map(|(b,_)|b.capacity()).sum::<usize>()>Self::STREAM_INPUT_CAPACITY{return Err("stream terminal input capacity exceeded bound");}
        for (bytes,offset) in chunks {buffer.extend_from_slice(&bytes[offset..]);}
        self.read_buf=buffer;self.read_offset=0;Ok(())
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
    ) -> Result<Vec<u8>, &'static str> {
        let response = protocol::format_http_response(status, body, close);
        let mut all_output = Vec::new();
        self.write_plaintext_chunked(&response, &mut all_output)?;
        let final_output = self.collect_tls_output()?;
        all_output.extend_from_slice(&final_output);
        Ok(all_output)
    }

    /// Like [`send_http_response`] but lets the caller pick the
    /// `Content-Type` (e.g. `application/privasys-sealed+cbor`).
    pub fn send_http_response_typed(
        &mut self,
        status: u16,
        content_type: &str,
        body: &[u8],
        close: bool,
    ) -> Result<Vec<u8>, &'static str> {
        self.send_http_response_with_headers(status, content_type, &[], body, close)
    }

    /// Like [`Self::send_http_response_typed`] but with extra response
    /// headers (e.g. the session-relay `X-Privasys-EncAuth-Reject`
    /// diagnostic).
    pub fn send_http_response_with_headers(
        &mut self,
        status: u16,
        content_type: &str,
        extra_headers: &[(String, String)],
        body: &[u8],
        close: bool,
    ) -> Result<Vec<u8>, &'static str> {
        let response = protocol::format_http_response_with_headers(
            status,
            content_type,
            extra_headers,
            body,
            close,
        );
        let mut all_output = Vec::new();
        self.write_plaintext_chunked(&response, &mut all_output)?;
        let final_output = self.collect_tls_output()?;
        all_output.extend_from_slice(&final_output);
        Ok(all_output)
    }

    pub fn has_pending_response(&self) -> bool {
        self.response.is_some()
    }

    pub fn queue_http_response(
        &mut self,
        status: u16,
        content_type: &str,
        extra_headers: &[(String, String)],
        body: impl Into<crate::HttpResponsePayload>,
        close: bool,
        shutdown: bool,
    ) -> Result<(), &'static str> {
        self.queue_http_response_owned(status, content_type, extra_headers, body, close, shutdown)
            .map_err(|(error, _body)| error)
    }

    /// Keep an unconsumed body available for its owner to drop outside STATE.
    pub(crate) fn queue_http_response_owned(
        &mut self, status: u16, content_type: &str, extra_headers: &[(String, String)],
        body: impl Into<crate::HttpResponsePayload>, close: bool, shutdown: bool,
    ) -> Result<(), (&'static str, crate::HttpResponsePayload)> {
        let body = body.into();
        if let Err(error) = self.require_current_configuration() { return Err((error, body)); }
        if self.response.is_some() { return Err(("response already pending", body)); }
        let head = protocol::format_http_response_head(status, content_type, extra_headers, body.len(), close);
        if head.len() > 32 * 1024 { return Err(("response headers too large", body)); }
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
            body,
            offset: 0,
            close,
            shutdown,
        });
        Ok(())
    }

    /// Caller reserves 64 KiB of socket credit before each step. Configuration
    /// revocation is checked even while a previously admitted body is draining.
    pub fn progress_http_response(&mut self) -> Result<(Vec<u8>, bool, bool), &'static str> {
        self.require_current_configuration()?;
        let mut response = self.response.take().ok_or("no pending response")?;
        #[cfg(feature = "diagnostic-transfer-profile")]
        let step_started = response.cost.as_ref().map(|_| std::time::Instant::now());
        let mut output = Vec::new();
        // Keep 4 KiB of the admitted 64 KiB socket step for TLS framing.
        let mut remaining = 60 * 1024;
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
            let part = response.body.part(response.offset, end - response.offset)
                .filter(|part| !part.is_empty()).ok_or("invalid segmented response")?;
            self.write_plaintext_chunked(part, &mut output)?;
            response.offset += part.len();
        }
        output.extend_from_slice(&self.collect_tls_output()?);
        if output.len() > 64 * 1024 {
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
                #[cfg(target_env = "sgx")]
                enclave_os_common::enclave_log_info!("{}", message);
                #[cfg(not(target_env = "sgx"))]
                eprintln!("{}", message);
            }
            Ok((output, response.close, response.shutdown))
        } else {
            self.response = Some(response);
            Ok((output, false, false))
        }
    }

    /// Drain all available decrypted plaintext from the TLS reader into
    /// the internal accumulation buffer.
    fn drain_plaintext(&mut self) -> Result<(), &'static str> {
        let mut buf = vec![0u8; 16384];
        loop {
            let mut reader = self.tls_conn.reader();
            use std::io::Read;
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Some(chunks)=self.stream_chunks.as_mut() {
                        let unread:usize=chunks.iter().map(|(v,o)|v.len()-o).sum();
                        if unread.saturating_add(n)>protocol::MAX_BODY_SIZE+64*1024 {return Err("stream unread input exceeded bound");}
                        let capacity:usize=chunks.iter().map(|(v,_)|v.capacity()).sum();
                        if chunks.back().is_none_or(|(v,_)|v.len()==v.capacity()) {
                            if capacity+crate::MAX_STREAM_INGRESS_FRAGMENT>Self::STREAM_INPUT_CAPACITY {return Err("stream input capacity exceeded bound");}
                            chunks.push_back((Vec::with_capacity(crate::MAX_STREAM_INGRESS_FRAGMENT),0));
                        }
                        let mut input=&buf[..n];
                        while !input.is_empty(){
                            let (last,_)=chunks.back_mut().unwrap();let take=input.len().min(last.capacity()-last.len());last.extend_from_slice(&input[..take]);input=&input[take..];
                            if !input.is_empty(){
                                let capacity:usize=chunks.iter().map(|(v,_)|v.capacity()).sum();
                                if capacity+crate::MAX_STREAM_INGRESS_FRAGMENT>Self::STREAM_INPUT_CAPACITY {return Err("stream input capacity exceeded bound");}
                                chunks.push_back((Vec::with_capacity(crate::MAX_STREAM_INGRESS_FRAGMENT),0));
                            }
                        }
                        continue;
                    }
                    // Compact only after consuming at least the remaining
                    // suffix, or to maintain the unchanged physical buffer cap.
                    // Every byte moves amortized once, never per64KiB fragment.
                    if self.read_offset>0 && (self.read_offset>=self.read_buf.len()-self.read_offset
                        || self.read_buf.len().saturating_add(n)>protocol::MAX_BODY_SIZE+64*1024) {
                        self.read_buf.drain(..self.read_offset);self.read_offset=0;
                    }
                    if self.read_buf.len().saturating_add(n) > protocol::MAX_BODY_SIZE + 64 * 1024 {
                        return Err("pending HTTP input exceeded bound");
                    }
                    self.read_buf.extend_from_slice(&buf[..n]);
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
        output: &mut Vec<u8>,
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
                output.extend_from_slice(&flushed);
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
        self.tls_conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|cert| cert.as_ref().to_vec())
    }

    /// Attestation tag of this connection ("none", "deterministic", "challenge").
    pub fn attestation(&self) -> &'static str {
        self.attestation
    }

    /// Exact DER leaf served by this session.
    pub fn local_cert_der(&self) -> Option<Vec<u8>> {
        Some(self.local_cert_der.clone())
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
        self.local_evidence.as_ref()
    }

    pub fn set_local_evidence(&mut self, evidence: enclave_os_common::modules::PeerEvidence) {
        self.local_evidence = Some(evidence);
    }

    /// Conservative capacities of every dynamically cloned context field.
    pub(crate) fn context_allocation_bound(&self) -> Option<usize> {
        fn evidence(value: &enclave_os_common::modules::PeerEvidence) -> Option<usize> {
            value.tee.capacity().checked_add(value.quote.capacity())?
                .checked_add(value.quote_time.capacity())?
                .checked_add(value.gpu_evidence.as_ref().map_or(0, Vec::capacity))
        }
        let mut bytes = 1024usize.checked_add(self.local_cert_der.capacity())?
            .checked_add(self.server_name.as_ref().map_or(0, String::capacity))?
            .checked_add(self.tls_conn.peer_certificates().and_then(|certs| certs.first()).map_or(0, |cert| cert.as_ref().len()))?;
        for value in [&self.local_evidence, &self.peer_evidence].into_iter().flatten() {
            bytes = bytes.checked_add(evidence(value)?)?;
        }
        Some(bytes)
    }

    pub fn channel_binder(&self) -> Option<Vec<u8>> {
        self.export_hctx(b"EXPORTER-honest-peer-channel-v2", &[])
            .ok()
            .map(|value| value.to_vec())
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
        self.peer_evidence.as_ref()
    }

    /// Retain evidence whose key/exporter binding was checked. Its quote
    /// signature and admission policy still require application appraisal.
    pub fn set_peer_evidence(&mut self, ev: enclave_os_common::modules::PeerEvidence) {
        self.peer_evidence = Some(ev);
    }

    /// The 32-byte RFC 8446 exporter value of this connection for `label` and
    /// `context`, keyed by exporter_master_secret (RA-TLS v2 binding).
    pub fn export_hctx(&self, label: &[u8], context: &[u8]) -> Result<[u8; 32], String> {
        if !self.configuration.is_current() {
            return Err("certificate configuration changed; reconnect required".into());
        }
        self.tls_conn
            .export_keying_material([0u8; 32], label, Some(context))
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
    pub fn close_notify(&mut self) -> Vec<u8> {
        self.tls_conn.send_close_notify();
        self.collect_tls_output().unwrap_or_default()
    }
    /// Check at ingress and before each decoded request/response. Buffered
    /// requests must not cross a workload replacement within one TLS flight.
    pub(crate) fn require_current_configuration(&mut self) -> Result<(), &'static str> {
        if !self.configuration.is_current() {
            self.fail_attestation();
            self.fido2_identity = None;
            self.read_buf.clear();self.read_offset=0;self.stream_chunks=None;
            self.response = None;
            return Err("certificate configuration changed; reconnect required");
        }
        Ok(())
    }
}
