//! Socket-free incremental TLS state for a control-loop multiplexer.

use std::io::{Read, Write};

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, RootCertStore};

use super::{build_client_config, verify_channel_binding, RaTlsPolicy};

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
        let config = build_client_config(root_store, ratls.as_ref()).map_err(str::to_string)?;
        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|_| "invalid incremental TLS server name".to_string())?;
        let tls_conn = ClientConnection::new(config, server_name)
            .map_err(|error| format!("incremental TLS init failed: {error}"))?;
        Ok(Self {
            tls_conn,
            ratls,
            channel_verified: false,
            plaintext: Vec::new(),
        })
    }

    /// Feed one bounded ciphertext fragment and drain newly decrypted bytes.
    pub fn feed_tls_bytes(&mut self, bytes: &[u8]) -> Result<(), String> {
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
            self.drain_plaintext()?;
        }
        if !self.tls_conn.is_handshaking() && !self.channel_verified {
            if let Some(policy) = self.ratls.as_ref() {
                verify_channel_binding(&self.tls_conn, policy)?;
            }
            self.channel_verified = true;
        }
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
        !self.tls_conn.is_handshaking() && self.channel_verified
    }

    #[must_use]
    pub fn peer_cert_der(&self) -> Option<Vec<u8>> {
        self.tls_conn
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .map(|certificate| certificate.as_ref().to_vec())
    }

    #[must_use]
    pub fn channel_binder(&self) -> Option<Vec<u8>> {
        self.tls_conn
            .ratls_channel_binder()
            .map(|binder| binder.to_vec())
    }

    /// Take all plaintext accumulated so far.
    pub fn take_plaintext(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.plaintext)
    }

    pub fn close(&mut self) {
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
