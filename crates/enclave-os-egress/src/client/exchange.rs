// Copyright (c) 2026 Florian Guitton. All rights reserved.
// Portions copyright (c) Privasys.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

//! Bounded RA-TLS v2 exchange shared by blocking and incremental transports.
//! This module makes no socket calls and performs no remote quote appraisal.

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::ClientConnection;
use x509_parser::prelude::*;

use super::{IdentityClientAuth, RaTlsPolicy, ReportDataBinding, CLIENT_CERT_SIGNER};
use crate::attest::{self, AttestationMode, Evidence};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    ServerEvidence,
    ClientAcknowledgement,
    Complete,
    Failed,
}

pub(super) struct AttestationExchange {
    phase: Phase,
    mode: AttestationMode,
    context: Option<[u8; 32]>,
    hctx: Option<[u8; 32]>,
    response: Vec<u8>,
    peer: Option<Evidence>,
    local: Option<Evidence>,
}

impl AttestationExchange {
    pub(super) fn start(tls: &mut ClientConnection, policy: &RaTlsPolicy) -> Result<Self, String> {
        if tls.is_handshaking() {
            return Err("RA-TLS: TLS handshake incomplete".into());
        }
        let leaf = tls
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or("RA-TLS: peer leaf missing")?;
        super::verify_ratls_leaf(leaf.as_ref(), policy)?;
        let (_, cert) =
            X509Certificate::from_der(leaf.as_ref()).map_err(|_| "RA-TLS: malformed peer leaf")?;
        let spki = super::validated_spki(&cert)?;
        let (mode, context, hctx) = match &policy.report_data {
            ReportDataBinding::Deterministic => (AttestationMode::Deterministic, None, None),
            ReportDataBinding::ChallengeResponse { nonce } => {
                let context: [u8; 32] = nonce
                    .as_slice()
                    .try_into()
                    .map_err(|_| "RA-TLS: context must be exactly 32 bytes")?;
                let hctx = tls
                    .export_keying_material(
                        [0u8; 32],
                        attest::EXPORTER_LABEL_SERVER,
                        Some(&context),
                    )
                    .map_err(|_| "RA-TLS: server exporter unavailable")?;
                (AttestationMode::Challenge, Some(context), Some(hctx))
            }
        };
        let request = attest::AttestRequest {
            v: attest::PROTOCOL_VERSION,
            mode: mode.as_str().into(),
            leaf: attest::leaf_id(&spki),
            context: context.map(|value| attest::b64_encode(&value)),
            tee: None,
            quote: None,
            gpu_evidence: None,
            quote_time: None,
        };
        write_request(tls, &request)?;
        Ok(Self {
            phase: Phase::ServerEvidence,
            mode,
            context,
            hctx,
            response: Vec::new(),
            peer: None,
            local: None,
        })
    }

    /// Perform at most one response transition. Every error permanently closes
    /// the exchange; subsequent fragments cannot turn a failed proof into readiness.
    pub(super) fn advance(
        &mut self,
        tls: &mut ClientConnection,
        policy: &RaTlsPolicy,
        identity: Option<&Arc<IdentityClientAuth>>,
    ) -> Result<(), String> {
        let result = self.advance_inner(tls, policy, identity);
        if result.is_err() {
            self.phase = Phase::Failed;
            tls.send_close_notify();
        }
        result
    }

    fn advance_inner(
        &mut self,
        tls: &mut ClientConnection,
        policy: &RaTlsPolicy,
        identity: Option<&Arc<IdentityClientAuth>>,
    ) -> Result<(), String> {
        match self.phase {
            Phase::Failed => return Err("RA-TLS: evidence exchange previously failed".into()),
            Phase::Complete => return Ok(()),
            _ => {}
        }
        let mut bytes = [0u8; 16384];
        loop {
            match tls.reader().read(&mut bytes) {
                Ok(0) => return Err("RA-TLS: peer closed during evidence exchange".into()),
                Ok(n) => {
                    if self.response.len().saturating_add(n) > attest::MAX_MESSAGE + MAX_HEADERS {
                        return Err("RA-TLS: evidence response exceeds profile bound".into());
                    }
                    self.response.extend_from_slice(&bytes[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => return Err("RA-TLS: evidence plaintext read failed".into()),
            }
        }
        let Some((status, body)) = response_frame(&self.response)? else {
            return Ok(());
        };
        if self.phase == Phase::ClientAcknowledgement {
            if !matches!(status, 200 | 204) || !body.is_empty() {
                return Err("RA-TLS: client evidence acknowledgement rejected".into());
            }
            self.response.clear();
            self.phase = Phase::Complete;
            return Ok(());
        }
        if status != 200 {
            return Err(format!("RA-TLS: evidence endpoint returned {status}"));
        }
        let (evidence, client_context) = attest::parse_response(
            body,
            self.mode,
            self.context,
            self.hctx,
            super::now_unix() as i64,
        )?;
        let leaf = tls
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or("RA-TLS: peer leaf missing")?;
        let (_, cert) =
            X509Certificate::from_der(leaf.as_ref()).map_err(|_| "RA-TLS: malformed peer leaf")?;
        let spki = super::validated_spki(&cert)?;
        super::verify_evidence_locally(&cert, &spki, &evidence, policy)?;
        if policy.client_identity.is_some() && client_context.is_none() {
            return Err("RA-TLS: mutual evidence was required by the client policy".into());
        }
        self.peer = Some(evidence);
        self.response.clear();
        if let Some(context) = client_context {
            let identity = identity.ok_or("RA-TLS: server requires a client identity")?;
            let local = client_evidence(tls, identity, context)?;
            let request = attest::AttestRequest {
                v: attest::PROTOCOL_VERSION,
                mode: "present".into(),
                leaf: String::new(),
                context: Some(attest::b64_encode(&context)),
                tee: Some(local.tee.clone()),
                quote: Some(attest::b64_encode(&local.quote)),
                gpu_evidence: None,
                quote_time: Some(local.quote_time.clone()),
            };
            write_request(tls, &request)?;
            self.local = Some(local);
            self.phase = Phase::ClientAcknowledgement;
        } else {
            self.phase = Phase::Complete;
        }
        Ok(())
    }

    pub(super) fn is_complete(&self) -> bool {
        self.phase == Phase::Complete
    }
    pub(super) fn peer_evidence(&self) -> Option<&Evidence> {
        if self.is_complete() {
            self.peer.as_ref()
        } else {
            None
        }
    }
    pub(super) fn local_evidence(&self) -> Option<&Evidence> {
        if self.is_complete() {
            self.local.as_ref()
        } else {
            None
        }
    }
}

fn client_evidence(
    tls: &ClientConnection,
    identity: &IdentityClientAuth,
    context: [u8; 32],
) -> Result<Evidence, String> {
    let signer = *CLIENT_CERT_SIGNER
        .get()
        .ok_or("RA-TLS: client signer unavailable")?;
    let leaf = identity
        .presented_leaf()
        .ok_or("RA-TLS: no client leaf was presented")?;
    let (_, cert) =
        X509Certificate::from_der(&leaf).map_err(|_| "RA-TLS: malformed client leaf")?;
    let spki = super::validated_spki(&cert)?;
    let hctx = tls
        .export_keying_material([0u8; 32], attest::EXPORTER_LABEL_CLIENT, Some(&context))
        .map_err(|_| "RA-TLS: client exporter unavailable")?;
    let report_data = attest::client_report_data(&spki, &context, &hctx, None);
    let quote = signer
        .evidence(&report_data)
        .ok_or("RA-TLS: client evidence declined")?;
    if quote.is_empty() || quote.len() > attest::MAX_MESSAGE {
        return Err("RA-TLS: client quote exceeds profile bound".into());
    }
    Ok(Evidence {
        mode: AttestationMode::Challenge,
        tee: "sgx".into(),
        quote,
        gpu_evidence: None,
        quote_time: attest::format_quote_time(super::now_unix() as i64),
        context: Some(context),
        hctx: Some(hctx),
    })
}

fn write_request(
    tls: &mut ClientConnection,
    request: &attest::AttestRequest,
) -> Result<(), String> {
    let body = serde_json::to_vec(request).map_err(|_| "RA-TLS: evidence encoding failed")?;
    if body.len() > attest::MAX_MESSAGE {
        return Err("RA-TLS: evidence request too large".into());
    }
    let mut encoded = format!("POST {} HTTP/1.1\r\nHost: enclave\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        attest::ATTEST_PATH, body.len()).into_bytes();
    encoded.extend_from_slice(&body);
    tls.writer()
        .write_all(&encoded)
        .map_err(|_| "RA-TLS: evidence write failed".into())
}

const MAX_HEADERS: usize = 4096;

#[cfg(test)]
mod tests;

pub(super) fn run_blocking(
    io: &mut dyn super::InterruptibleBlockingNetIo,
    fd: i32,
    tls: &mut ClientConnection,
    policy: &RaTlsPolicy,
    identity: Option<&Arc<IdentityClientAuth>>,
) -> Result<(), String> {
    let mut exchange = AttestationExchange::start(tls, policy)?;
    loop {
        super::request::flush_tls(io, fd, tls).map_err(|_| "RA-TLS: evidence flush failed")?;
        exchange.advance(tls, policy, identity)?;
        if exchange.is_complete() {
            return super::appraise_evidence(
                exchange.peer_evidence().ok_or("RA-TLS: evidence missing")?,
                policy,
            );
        }
        // A transition may have queued the mutual evidence request.
        super::request::flush_tls(io, fd, tls).map_err(|_| "RA-TLS: evidence flush failed")?;
        let mut bytes = [0u8; 16384];
        let n = io
            .recv(fd, &mut bytes)
            .map_err(|_| "RA-TLS: evidence receive failed")?;
        if n == 0 || n > bytes.len() {
            return Err("RA-TLS: evidence connection closed".into());
        }
        let mut cursor = std::io::Cursor::new(&bytes[..n]);
        while (cursor.position() as usize) < n {
            let count = tls
                .read_tls(&mut cursor)
                .map_err(|_| "RA-TLS: evidence TLS read failed")?;
            if count == 0 {
                return Err("RA-TLS: evidence TLS read stalled".into());
            }
            tls.process_new_packets()
                .map_err(|_| "RA-TLS: evidence TLS record rejected")?;
            exchange.advance(tls, policy, identity)?;
        }
    }
}

/// The runtime's reserved endpoint uses one length-delimited HTTP response.
/// Reject ambiguous lengths, transfer encodings and unsolicited trailing data.
fn response_frame(data: &[u8]) -> Result<Option<(u16, &[u8])>, String> {
    let Some(end) = data.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
        if data.len() > MAX_HEADERS {
            return Err("RA-TLS: response headers too large".into());
        }
        return Ok(None);
    };
    if end + 4 > MAX_HEADERS {
        return Err("RA-TLS: response headers too large".into());
    }
    let header =
        std::str::from_utf8(&data[..end]).map_err(|_| "RA-TLS: invalid response headers")?;
    let mut lines = header.split("\r\n");
    let mut status_line = lines.next().unwrap_or_default().splitn(3, ' ');
    if status_line.next() != Some("HTTP/1.1") {
        return Err("RA-TLS: invalid HTTP version".into());
    }
    let status = status_line
        .next()
        .filter(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("RA-TLS: invalid HTTP status")?;
    let mut length = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or("RA-TLS: malformed response header")?;
        if name.is_empty()
            || name
                .bytes()
                .any(|b| !b.is_ascii_alphanumeric() && b != b'-')
        {
            return Err("RA-TLS: invalid response header name".into());
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("RA-TLS: transfer encoding is not allowed".into());
        }
        if name.eq_ignore_ascii_case("content-length") {
            let value = value.trim();
            if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err("RA-TLS: ambiguous response length".into());
            }
            length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| "RA-TLS: invalid response length")?,
            );
        }
    }
    let length = match (length, status) {
        (Some(length), _) => length,
        (None, 204) => 0,
        _ => return Err("RA-TLS: response length missing".into()),
    };
    if length > attest::MAX_MESSAGE || (status == 204 && length != 0) {
        return Err("RA-TLS: invalid response body length".into());
    }
    let total = end + 4 + length;
    if data.len() < total {
        return Ok(None);
    }
    if data.len() != total {
        return Err("RA-TLS: unsolicited trailing plaintext".into());
    }
    Ok(Some((status, &data[end + 4..total])))
}
