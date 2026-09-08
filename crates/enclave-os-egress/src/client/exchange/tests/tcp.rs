// Copyright (c) 2026 Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

//! Loopback TCP carries actual rustls ciphertext. Quote bodies remain fixtures;
//! this lane covers transport fragmentation, renewal and loss, not DCAP or SGX.

use super::*;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Duration;

struct TcpPair {
    client: IncrementalTlsClient,
    server: ServerConnection,
    client_wire: TcpStream,
    server_wire: TcpStream,
}

impl TcpPair {
    fn new(identity: &Identity) -> Self {
        let (client, server) = pair(identity, Some(mutual_identity()));
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client_wire = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server_wire, _) = listener.accept().unwrap();
        assert_ne!(
            client_wire.local_addr().unwrap(),
            server_wire.local_addr().unwrap()
        );
        assert_eq!(
            client_wire.peer_addr().unwrap(),
            server_wire.local_addr().unwrap()
        );
        for stream in [&client_wire, &server_wire] {
            stream.set_nodelay(true).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
        }
        Self {
            client,
            server,
            client_wire,
            server_wire,
        }
    }

    fn client_to_server(&mut self) {
        let output = self.client.collect_tls_output().unwrap();
        self.client_wire.write_all(&output).unwrap();
        // Tiny reads deliberately split TLS records, independent of kernel
        // coalescing and of the attestation HTTP message boundaries.
        let mut buffer = [0; 13];
        let mut remaining = output.len();
        while remaining > 0 {
            let n = remaining.min(buffer.len());
            self.server_wire.read_exact(&mut buffer[..n]).unwrap();
            self.server
                .read_tls(&mut std::io::Cursor::new(&buffer[..n]))
                .unwrap();
            self.server.process_new_packets().unwrap();
            remaining -= n;
        }
    }

    fn server_to_client(&mut self) -> Result<(), String> {
        let mut output = Vec::new();
        while self.server.wants_write() {
            self.server.write_tls(&mut output).unwrap();
        }
        self.server_wire.write_all(&output).unwrap();
        let mut buffer = [0; 7];
        let mut remaining = output.len();
        while remaining > 0 {
            let n = remaining.min(buffer.len());
            self.client_wire.read_exact(&mut buffer[..n]).unwrap();
            self.client.feed_tls_bytes(&buffer[..n])?;
            remaining -= n;
        }
        Ok(())
    }

    fn request(&mut self) -> attest::AttestRequest {
        let mut plain = Vec::new();
        for _ in 0..32 {
            self.client_to_server();
            self.server_to_client().unwrap();
            let mut buffer = [0; 4096];
            loop {
                match self.server.reader().read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => plain.extend_from_slice(&buffer[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("TCP server plaintext: {e}"),
                }
            }
            if let Ok((parsed, used)) = enclave_os_common::protocol::parse_http_request(&plain) {
                assert_eq!(used, plain.len());
                assert_eq!(parsed.path, attest::ATTEST_PATH);
                return serde_json::from_slice(&parsed.body).unwrap();
            }
        }
        panic!("bounded TCP exchange did not produce an attestation request")
    }

    fn send(&mut self, status: u16, body: &[u8]) -> Result<(), String> {
        let encoded = enclave_os_common::protocol::format_http_response(status, body, false);
        self.server.writer().write_all(&encoded).unwrap();
        self.server_to_client()
    }

    fn present(&mut self, evidence: &attest::AttestResponse) {
        self.send(200, &serde_json::to_vec(evidence).unwrap())
            .unwrap();
        assert!(!self.client.is_ready());
        assert!(self.client.write_plaintext(b"protected request").is_err());
        let present = self.request();
        assert_eq!(present.mode, "present");
        assert_eq!(present.context, evidence.client_context);
        let context = attest::b64_decode(present.context.as_ref().unwrap()).unwrap();
        let hctx = self
            .server
            .export_keying_material([0; 32], attest::EXPORTER_LABEL_CLIENT, Some(&context))
            .unwrap();
        let expected = attest::client_report_data(&mutual_identity().spki, &context, &hctx, None);
        assert_eq!(
            attest::b64_decode(present.quote.as_ref().unwrap()).unwrap(),
            quote(&expected)
        );
        assert!(!self.client.is_ready());
        assert!(self.client.local_evidence().is_none());
    }
}

fn assert_closed(client: &mut IncrementalTlsClient) {
    assert!(!client.is_ready());
    assert!(client.peer_evidence().is_none());
    assert!(client.local_evidence().is_none());
    assert!(client.write_plaintext(b"protected request").is_err());
    assert!(client.re_attest().is_err());
    assert!(client.feed_tls_bytes(&[]).is_err());
}

#[test]
fn tcp_mutual_renewal_preserves_channel_but_rejects_old_and_cross_connection_proofs() {
    let identity = Identity::new();
    let mut wire = TcpPair::new(&identity);
    let req = wire.request();
    let original = response(&identity, &wire.server, &req, true);
    wire.present(&original);
    wire.send(204, &[]).unwrap();
    assert!(wire.client.is_ready());
    let old_peer = wire.client.peer_evidence().unwrap().quote.clone();
    let old_local = wire.client.local_evidence().unwrap().quote.clone();
    let binder = wire.client.channel_binder().unwrap();

    let application = b"GET /data HTTP/1.1\r\nHost: v2.test\r\n\r\n";
    wire.client.write_plaintext(application).unwrap();
    wire.client_to_server();
    let mut received = vec![0; application.len()];
    wire.server.reader().read_exact(&mut received).unwrap();
    assert_eq!(received, application);
    wire.send(200, b"before renewal").unwrap();
    assert!(wire.client.re_attest().is_err());
    assert_eq!(
        wire.client.take_plaintext(),
        enclave_os_common::protocol::format_http_response(200, b"before renewal", false)
    );

    wire.client.re_attest().unwrap();
    assert!(wire.client.peer_evidence().is_none());
    assert!(wire.client.local_evidence().is_none());
    let req = wire.request();
    let mut renewed = response(&identity, &wire.server, &req, true);
    renewed.client_context = Some(attest::b64_encode(&[4; 32]));
    wire.present(&renewed);
    wire.send(204, &[]).unwrap();
    assert!(wire.client.is_ready());
    assert_ne!(wire.client.peer_evidence().unwrap().quote, old_peer);
    assert_ne!(wire.client.local_evidence().unwrap().quote, old_local);
    assert_eq!(wire.client.channel_binder().unwrap(), binder);

    wire.client.re_attest().unwrap();
    wire.request();
    assert!(wire
        .send(200, &serde_json::to_vec(&renewed).unwrap())
        .is_err());
    assert_closed(&mut wire.client);

    // The same certificate and original nonce are used on another real TCP/TLS
    // connection. Only the exporter differs; copying evidence cannot admit it.
    let mut replay = TcpPair::new(&identity);
    let req = replay.request();
    assert_eq!(req.context, Some(attest::b64_encode(&[9; 32])));
    assert!(replay
        .send(200, &serde_json::to_vec(&original).unwrap())
        .is_err());
    assert_closed(&mut replay.client);
}

#[test]
fn tcp_loss_before_mutual_ack_cannot_retain_authority_and_fresh_reconnect_succeeds() {
    let identity = Identity::new();
    let mut wire = TcpPair::new(&identity);
    let req = wire.request();
    let evidence = response(&identity, &wire.server, &req, true);
    wire.present(&evidence);
    wire.server_wire.shutdown(Shutdown::Both).unwrap();
    assert_eq!(wire.client_wire.read(&mut [0; 1]).unwrap(), 0);
    // The socket owner reports EOF to the incremental state, just as a host
    // channel close retires a peer. No synthetic timeout or sleep drives this.
    wire.client.close();
    assert_closed(&mut wire.client);

    let mut fresh = TcpPair::new(&identity);
    let req = fresh.request();
    let evidence = response(&identity, &fresh.server, &req, true);
    fresh.present(&evidence);
    fresh.send(204, &[]).unwrap();
    assert!(fresh.client.is_ready());
    fresh
        .client
        .write_plaintext(b"fresh connection request")
        .unwrap();
}
