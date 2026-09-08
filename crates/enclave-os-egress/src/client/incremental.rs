// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Socket-free incremental TLS state for a control-loop multiplexer.

use std::io::{Read, Write};

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, RootCertStore};

use super::{
    build_attested_client_config, build_client_config, exchange::AttestationExchange,
    IdentityClientAuth, RaTlsPolicy,
};

/// Incrementally advanced TLS client for the control-TCS raw multiplexer.
///
/// It performs no socket calls and no internal waits. The caller feeds
/// ciphertext received from the host-owned connection ID, drains ciphertext
/// to the data channel, and schedules at most one bounded method call per
/// control-loop opportunity.
pub struct IncrementalTlsClient {
    tls_conn: ClientConnection,
    ratls: Option<RaTlsPolicy>,
    channel_verified: bool,
    plaintext: Vec<u8>,
    identity: Option<std::sync::Arc<IdentityClientAuth>>,
    exchange: Option<AttestationExchange>,
    appraisal_pending: bool,
    failed: bool,
}

impl IncrementalTlsClient {
    /// Construct a fresh TLS client and queue its ClientHello.
    ///
    /// Remote appraisal URLs are rejected here because the ordinary
    /// verifier calls them synchronously. Incremental users instead extract
    /// locally verified quote evidence and appraise it over a second,
    /// incrementally pumped HTTPS connection.
    pub fn new(
        server_name: &str,
        root_store: &RootCertStore,
        ratls: Option<RaTlsPolicy>,
    ) -> Result<Self, String> {
        if ratls
            .as_ref()
            .is_some_and(|policy| !policy.attestation_servers.is_empty())
        {
            return Err("incremental TLS requires separately pumped quote appraisal".to_string());
        }
        let (config, identity) =
            build_client_config(root_store, ratls.as_ref()).map_err(str::to_string)?;
        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|_| "invalid incremental TLS server name".to_string())?;
        let mut tls_conn = ClientConnection::new(config, server_name)
            .map_err(|error| format!("incremental TLS init failed: {error}"))?;
        // Rustls's smaller default plaintext buffer would otherwise undercut
        // the explicit request bound below. Keep the queue finite and aligned
        // with the public incremental-client contract.
        tls_conn.set_buffer_limit(Some(MAX_INCREMENTAL_REQUEST));
        Ok(Self {
            tls_conn,
            ratls,
            channel_verified: false,
            plaintext: Vec::new(),
            identity,
            exchange: None,
            failed: false,
            appraisal_pending: false,
        })
    }

    /// Construct a TLS 1.3 client for an enclave-owned CA, authenticating the
    /// leaf through appraised, measurement-pinned, channel-bound RA-TLS.
    pub fn new_attested(server_name: &str, policy: RaTlsPolicy) -> Result<Self, String> {
        let (config, identity) = build_attested_client_config(&policy).map_err(str::to_string)?;
        let appraisal_pending = !policy.attestation_servers.is_empty();
        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|_| "invalid incremental TLS server name".to_string())?;
        let mut tls_conn = ClientConnection::new(config, server_name)
            .map_err(|error| format!("incremental TLS init failed: {error}"))?;
        tls_conn.set_buffer_limit(Some(MAX_INCREMENTAL_REQUEST));
        Ok(Self {
            tls_conn,
            ratls: Some(policy),
            channel_verified: false,
            plaintext: Vec::new(),
            identity,
            exchange: None,
            failed: false,
            appraisal_pending,
        })
    }

    /// Feed one bounded ciphertext fragment and drain newly decrypted bytes.
    pub fn feed_tls_bytes(&mut self, bytes: &[u8]) -> Result<(), String> {
        if self.failed {
            return Err("incremental TLS previously failed".into());
        }
        let result = self.feed_tls_bytes_inner(bytes);
        if result.is_err() {
            self.failed = true;
            self.tls_conn.send_close_notify();
        }
        result
    }

    fn feed_tls_bytes_inner(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() > MAX_INCREMENTAL_TLS_FRAGMENT {
            return Err("incremental TLS fragment exceeds profile bound".to_string());
        }
        let mut cursor = std::io::Cursor::new(bytes);
        while (cursor.position() as usize) < bytes.len() {
            let read = self
                .tls_conn
                .read_tls(&mut cursor)
                .map_err(|error| format!("incremental TLS read failed: {error}"))?;
            if read == 0 {
                break;
            }
            self.tls_conn
                .process_new_packets()
                .map_err(|error| format!("incremental TLS packet rejected: {error}"))?;
            self.advance_attestation()?;
        }
        self.advance_attestation()?;
        Ok(())
    }

    /// Drain all currently queued TLS ciphertext without touching a socket.
    pub fn collect_tls_output(&mut self) -> Result<Vec<u8>, String> {
        let mut output = Vec::new();
        while self.tls_conn.wants_write() {
            let written = self
                .tls_conn
                .write_tls(&mut output)
                .map_err(|error| format!("incremental TLS write failed: {error}"))?;
            if written == 0 {
                break;
            }
            if output.len() > MAX_INCREMENTAL_TLS_OUTPUT {
                return Err("incremental TLS output exceeds profile bound".to_string());
            }
        }
        Ok(output)
    }

    /// Queue one bounded application request after local handshake validation.
    pub fn write_plaintext(&mut self, bytes: &[u8]) -> Result<(), String> {
        if !self.is_ready() {
            return Err("incremental TLS handshake is not ready".to_string());
        }
        if bytes.len() > MAX_INCREMENTAL_REQUEST {
            return Err("incremental TLS request exceeds profile bound".to_string());
        }
        self.tls_conn
            .writer()
            .write_all(bytes)
            .map_err(|error| format!("incremental TLS plaintext write failed: {error}"))
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        !self.failed
            && !self.appraisal_pending
            && !self.tls_conn.is_handshaking()
            && self.channel_verified
    }

    #[must_use]
    pub fn peer_cert_der(&self) -> Option<Vec<u8>> {
        self.tls_conn
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .map(|certificate| certificate.as_ref().to_vec())
    }

    /// Exact client leaf emitted for this TLS session, when mutual RA-TLS was
    /// requested and the peer asked for a certificate.
    #[must_use]
    pub fn local_cert_der(&self) -> Option<Vec<u8>> {
        self.identity
            .as_ref()
            .and_then(|identity| identity.presented_leaf())
    }

    /// Server-issued context bound into the client's v2 quote.
    pub fn peer_challenge_nonce(&self) -> Option<Vec<u8>> {
        self.local_evidence()
            .and_then(|evidence| evidence.context.map(|value| value.to_vec()))
    }

    /// Shared application channel binding. Quote proofs use their separate
    /// role-specific exporters retained in `peer_evidence` and `local_evidence`.
    pub fn channel_binder(&self) -> Option<Vec<u8>> {
        self.tls_conn
            .export_keying_material([0u8; 32], b"EXPORTER-honest-peer-channel-v2", Some(&[]))
            .ok()
            .map(|value| value.to_vec())
    }

    pub fn peer_evidence(&self) -> Option<&crate::attest::Evidence> {
        if self.failed {
            return None;
        }
        self.exchange
            .as_ref()
            .and_then(|exchange| exchange.peer_evidence())
    }

    pub fn local_evidence(&self) -> Option<&crate::attest::Evidence> {
        if self.failed {
            return None;
        }
        self.exchange
            .as_ref()
            .and_then(|exchange| exchange.local_evidence())
    }

    /// The identity proof is ready for the explicitly configured remote service.
    pub fn needs_remote_appraisal(&self) -> bool {
        !self.failed && self.channel_verified && self.appraisal_pending
    }

    /// Blocking operator-client adapter. Never call from a control TCS: peers
    /// use `new` with separately pumped quote appraisal instead. Application
    /// writes remain blocked until every required appraiser accepts.
    pub fn appraise_pending_evidence(&mut self) -> Result<(), String> {
        if !self.needs_remote_appraisal() {
            return Err("no pending remote appraisal".into());
        }
        let evidence = self.peer_evidence().ok_or("RA-TLS evidence missing")?;
        let policy = self.ratls.as_ref().ok_or("RA-TLS policy missing")?;
        let result = super::appraise_evidence(evidence, policy);
        if result.is_ok() {
            self.appraisal_pending = false;
        } else {
            self.failed = true;
            self.tls_conn.send_close_notify();
        }
        result
    }

    /// Begin a fresh challenge exchange on this TLS connection. The HTTP
    /// owner must first finish its in-flight request/response and pause new
    /// application traffic; raw protocols must reconnect instead. This method
    /// performs no socket I/O and does not schedule its own renewal interval.
    ///
    /// Both old proofs disappear immediately. Callers doing asynchronous
    /// appraisal must retire their previous admission and appraise the new
    /// proof identities before granting application authority again.
    pub fn re_attest(&mut self) -> Result<[u8; 32], String> {
        if !self.is_ready() {
            return Err("RA-TLS renewal requires a ready connection".into());
        }
        if self.tls_conn.wants_write() || !self.plaintext.is_empty() {
            return Err("RA-TLS renewal requires drained application buffers".into());
        }
        let policy = self
            .ratls
            .as_mut()
            .ok_or("RA-TLS renewal requires a policy")?;
        if !matches!(
            policy.report_data,
            super::ReportDataBinding::ChallengeResponse { .. }
        ) {
            return Err("RA-TLS renewal requires challenge mode".into());
        }
        self.channel_verified = false;
        self.appraisal_pending = !policy.attestation_servers.is_empty();
        self.exchange = None;
        let mut nonce = [0u8; 32];
        if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce).is_err() {
            self.close();
            return Err("RA-TLS renewal entropy unavailable".into());
        }
        policy.report_data = super::ReportDataBinding::ChallengeResponse {
            nonce: nonce.to_vec(),
        };
        let result = self.advance_attestation();
        if result.is_err() {
            self.close();
        }
        result.map(|()| nonce)
    }

    fn advance_attestation(&mut self) -> Result<(), String> {
        if self.tls_conn.is_handshaking() {
            return Ok(());
        }
        if let Some(policy) = self.ratls.as_ref() {
            if self.exchange.is_none() {
                self.exchange = Some(AttestationExchange::start(&mut self.tls_conn, policy)?);
            }
            let exchange = self.exchange.as_mut().ok_or("RA-TLS exchange missing")?;
            exchange.advance(&mut self.tls_conn, policy, self.identity.as_ref())?;
            self.channel_verified = exchange.is_complete();
        } else {
            self.channel_verified = true;
        }
        if self.is_ready() {
            self.drain_plaintext()?;
        }
        Ok(())
    }

    /// Take all plaintext accumulated so far.
    pub fn take_plaintext(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.plaintext)
    }

    pub fn close(&mut self) {
        self.failed = true;
        self.tls_conn.send_close_notify();
    }

    fn drain_plaintext(&mut self) -> Result<(), String> {
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            match self.tls_conn.reader().read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(read) => {
                    if self.plaintext.len().saturating_add(read) > MAX_INCREMENTAL_PLAINTEXT {
                        return Err("incremental TLS plaintext exceeds profile bound".to_string());
                    }
                    self.plaintext.extend_from_slice(&buffer[..read]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => {
                    return Err(format!("incremental TLS plaintext read failed: {error}"));
                }
            }
        }
    }
}

const MAX_INCREMENTAL_TLS_FRAGMENT: usize = 1024 * 1024;
const MAX_INCREMENTAL_TLS_OUTPUT: usize = 1024 * 1024;
const MAX_INCREMENTAL_REQUEST: usize = 512 * 1024;
const MAX_INCREMENTAL_PLAINTEXT: usize = 2 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use std::io::Write;

    use rustls::RootCertStore;

    use super::{IncrementalTlsClient, MAX_INCREMENTAL_REQUEST};
    use crate::client::{RaTlsPolicy, ReportDataBinding, TeeType};

    #[test]
    fn rustls_buffer_does_not_undercut_the_declared_request_bound() {
        let roots = RootCertStore::empty();
        let mut client =
            IncrementalTlsClient::new("bounded.invalid", &roots, None).expect("incremental client");
        client
            .tls_conn
            .writer()
            .write_all(&vec![0xa5; MAX_INCREMENTAL_REQUEST])
            .expect("the declared request bound must fit the TLS plaintext buffer");
    }

    #[cfg(all(not(feature = "mock"), not(feature = "sgx-sim-attestation")))]
    #[test]
    fn attested_only_client_requires_measurement_and_remote_appraisal() {
        let policy = RaTlsPolicy {
            tee: TeeType::Sgx,
            mr_enclave: Some([7; 32]),
            mr_signer: None,
            mr_td: None,
            report_data: ReportDataBinding::ChallengeResponse { nonce: vec![9; 32] },
            expected_oids: Vec::new(),
            attestation_servers: Vec::new(),
            acceptable_tcb_statuses: None,
            client_identity: None,
            dependencies: None,
        };
        assert_eq!(
            IncrementalTlsClient::new_attested("local-control.invalid", policy)
                .err()
                .as_deref(),
            Some("attested-only TLS requires a quote-appraisal service")
        );
    }

    #[cfg(feature = "sgx-sim-attestation")]
    #[test]
    fn simulation_client_accepts_local_typed_appraisal_without_remote_service() {
        let policy = RaTlsPolicy {
            tee: TeeType::Sgx,
            mr_enclave: Some([7; 32]),
            mr_signer: None,
            mr_td: None,
            report_data: ReportDataBinding::ChallengeResponse { nonce: vec![9; 32] },
            expected_oids: Vec::new(),
            attestation_servers: Vec::new(),
            acceptable_tcb_statuses: None,
            client_identity: None,
            dependencies: None,
        };
        assert!(IncrementalTlsClient::new_attested("local-control.invalid", policy).is_ok());
    }
}
