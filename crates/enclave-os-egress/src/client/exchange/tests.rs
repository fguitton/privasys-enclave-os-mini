// Copyright (c) 2026 Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

//! Real TLS endpoints with fabricated quote bodies. These verify local proof
//! binding and protocol ordering only; they establish no hardware appraisal.

use super::*;
use crate::client::{
    ClientCertIdentity, EnclaveClientCertSigner, IncrementalTlsClient, RootCertStore, TeeType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};

#[cfg(feature = "native-sgx-types")]
mod tcp;

struct Identity {
    cert: Vec<u8>,
    key: Vec<u8>,
    spki: Vec<u8>,
}

impl Identity {
    fn new() -> Self {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            enclave_os_common::ocall::register(enclave_os_common::ocall::OcallVtable {
                net_tcp_listen: |_, _| panic!("incremental exchange attempted socket I/O"),
                net_tcp_accept: |_| panic!("incremental exchange attempted socket I/O"),
                net_tcp_connect: |_, _| panic!("incremental exchange attempted socket I/O"),
                net_send: |_, _| panic!("incremental exchange attempted socket I/O"),
                net_recv: |_, _| panic!("incremental exchange attempted socket I/O"),
                net_close: |_| panic!("incremental exchange attempted socket I/O"),
                kv_store_put: |_, _, _| panic!("unexpected storage I/O"),
                kv_store_get: |_, _| panic!("unexpected storage I/O"),
                kv_store_delete: |_, _| panic!("unexpected storage I/O"),
                kv_store_list_keys: |_, _| panic!("unexpected storage I/O"),
                kv_store_write_batch: |_, _| panic!("unexpected storage I/O"),
                kv_store_multi_get: |_, _| panic!("unexpected storage I/O"),
                kv_store_scan: |_, _, _, _| panic!("unexpected storage I/O"),
                get_current_time: || Ok(1_788_811_200),
                log: |_, _| {},
                cert_store_register: |_| panic!("unexpected certificate registration"),
                cert_store_unregister: |_| panic!("unexpected certificate registration"),
            })
        });
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["v2.test".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        Self {
            cert: cert.der().to_vec(),
            key: key.serialize_der(),
            spki: key.public_key_der(),
        }
    }
    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(self.cert.clone())).unwrap();
        roots
    }
}

impl EnclaveClientCertSigner for Identity {
    fn identity(&self, _: &ClientCertIdentity, _: u64) -> Option<(Vec<Vec<u8>>, Vec<u8>)> {
        Some((vec![self.cert.clone()], self.key.clone()))
    }
    fn evidence(&self, data: &[u8; 64]) -> Option<Vec<u8>> {
        Some(quote(data))
    }
}

fn mutual_identity() -> &'static Identity {
    static CLIENT: std::sync::OnceLock<Identity> = std::sync::OnceLock::new();
    let identity = CLIENT.get_or_init(Identity::new);
    crate::client::register_enclave_client_cert_signer(identity);
    identity
}

fn quote(data: &[u8; 64]) -> Vec<u8> {
    #[cfg(feature = "sgx-sim-attestation")]
    {
        let mut bytes = enclave_os_common::quote::SGX_SIM_REPORT_PREFIX.to_vec();
        bytes.extend_from_slice(&[7; 32]);
        bytes.extend_from_slice(data);
        bytes
    }
    #[cfg(not(feature = "sgx-sim-attestation"))]
    {
        use enclave_os_common::quote::*;
        let mut bytes = vec![0u8; std::mem::size_of::<sgx_types::types::Quote3>()];
        bytes[..2].copy_from_slice(&3u16.to_le_bytes());
        bytes[SGX_MRENCLAVE_OFFSET..SGX_MRENCLAVE_OFFSET + 32].fill(7);
        bytes[SGX_REPORT_DATA_OFFSET..SGX_REPORT_DATA_OFFSET + 64].copy_from_slice(data);
        bytes
    }
}

fn pair(
    identity: &Identity,
    client_identity: Option<&Identity>,
) -> (IncrementalTlsClient, ServerConnection) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap();
    let builder = if let Some(client) = client_identity {
        builder.with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(client.roots()),
                provider,
            )
            .build()
            .unwrap(),
        )
    } else {
        builder.with_no_client_auth()
    };
    let server = builder
        .with_single_cert(
            vec![CertificateDer::from(identity.cert.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key.clone())),
        )
        .unwrap();
    let policy = RaTlsPolicy {
        tee: TeeType::Sgx,
        mr_enclave: Some([7; 32]),
        mr_signer: None,
        mr_td: None,
        report_data: ReportDataBinding::ChallengeResponse { nonce: vec![9; 32] },
        expected_oids: vec![],
        attestation_servers: vec![],
        acceptable_tcb_statuses: None,
        client_identity: client_identity.map(|_| ClientCertIdentity {
            code_hash: vec![1; 32],
            app_id: None,
        }),
        dependencies: None,
    };
    (
        IncrementalTlsClient::new("v2.test", &identity.roots(), Some(policy)).unwrap(),
        ServerConnection::new(Arc::new(server)).unwrap(),
    )
}

fn request(
    client: &mut IncrementalTlsClient,
    server: &mut ServerConnection,
) -> attest::AttestRequest {
    let mut plain = Vec::new();
    for _ in 0..32 {
        let output = client.collect_tls_output().unwrap();
        if !output.is_empty() {
            server.read_tls(&mut std::io::Cursor::new(output)).unwrap();
            server.process_new_packets().unwrap();
        }
        let mut output = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut output).unwrap();
        }
        if !output.is_empty() {
            client.feed_tls_bytes(&output).unwrap();
        }
        let mut buffer = [0; 16384];
        loop {
            match server.reader().read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => plain.extend_from_slice(&buffer[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("server plaintext: {e}"),
            }
        }
        if let Ok((parsed, used)) = enclave_os_common::protocol::parse_http_request(&plain) {
            assert_eq!(used, plain.len());
            assert_eq!(parsed.path, attest::ATTEST_PATH);
            return serde_json::from_slice(&parsed.body).unwrap();
        }
    }
    panic!("bounded TLS exchange did not produce an attestation request")
}

fn response(
    identity: &Identity,
    server: &ServerConnection,
    request: &attest::AttestRequest,
    mutual: bool,
) -> attest::AttestResponse {
    let context = attest::b64_decode(request.context.as_ref().unwrap()).unwrap();
    let hctx = server
        .export_keying_material([0u8; 32], attest::EXPORTER_LABEL_SERVER, Some(&context))
        .unwrap();
    let data = attest::challenge_report_data(&identity.spki, &context, &hctx, None);
    attest::AttestResponse {
        v: attest::PROTOCOL_VERSION,
        mode: "challenge".into(),
        tee: "sgx".into(),
        quote: attest::b64_encode(&quote(&data)),
        gpu_evidence: None,
        quote_time: attest::format_quote_time(super::super::now_unix() as i64),
        client_evidence: if mutual { "required" } else { "none" }.into(),
        client_context: mutual.then(|| attest::b64_encode(&[3; 32])),
        error: None,
    }
}

fn send(
    client: &mut IncrementalTlsClient,
    server: &mut ServerConnection,
    status: u16,
    body: &[u8],
) -> Result<(), String> {
    let encoded = enclave_os_common::protocol::format_http_response(status, body, false);
    server.writer().write_all(&encoded).unwrap();
    let mut output = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut output).unwrap();
    }
    for fragment in output.chunks(7) {
        client.feed_tls_bytes(fragment)?;
    }
    Ok(())
}

#[test]
fn evidence_http_framing_rejects_ambiguous_and_unbounded_responses() {
    let valid = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
    for end in 0..valid.len() {
        assert!(response_frame(&valid[..end]).unwrap().is_none());
    }
    assert_eq!(
        response_frame(valid).unwrap(),
        Some((200, b"{}".as_slice()))
    );
    for bad in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n\r\n",
        b"HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\nx",
        b"HTTP/1.1 204 No Content\r\n\r\nextra",
    ] {
        assert!(response_frame(bad).is_err(), "accepted ambiguous response");
    }
    assert!(response_frame(&vec![b'a'; MAX_HEADERS + 1]).is_err());
}

#[test]
fn live_exporter_binds_evidence_and_replay_cannot_open_application_writes() {
    let identity = Identity::new();
    let (mut client, mut server) = pair(&identity, None);
    let req = request(&mut client, &mut server);
    assert!(!client.is_ready());
    assert!(client.write_plaintext(b"protected request").is_err());
    let body = serde_json::to_vec(&response(&identity, &server, &req, false)).unwrap();
    send(&mut client, &mut server, 200, &body).unwrap();
    assert!(client.is_ready());
    let evidence = client.peer_evidence().unwrap();
    assert_eq!(
        crate::client::locally_verify_sgx_peer_certificate(&identity.cert, [7; 32], evidence)
            .unwrap()
            .mr_enclave,
        [7; 32]
    );
    assert!(
        crate::client::locally_verify_sgx_peer_certificate(&identity.cert, [8; 32], evidence)
            .is_err()
    );
    client.write_plaintext(b"protected request").unwrap();

    // Same leaf and challenge, different real TLS key schedule. Replaying the
    // accepted response must fail, including after an attempted retry.
    let (mut replay, mut other_server) = pair(&identity, None);
    request(&mut replay, &mut other_server);
    assert!(send(&mut replay, &mut other_server, 200, &body).is_err());
    assert!(!replay.is_ready());
    assert!(replay.peer_evidence().is_none());
    assert!(replay.write_plaintext(b"protected request").is_err());
    assert!(replay.feed_tls_bytes(&[]).is_err());
}

#[test]
fn mutual_evidence_uses_client_exporter_and_waits_for_acknowledgement() {
    let client_identity = mutual_identity();
    let identity = Identity::new();
    let (mut client, mut server) = pair(&identity, Some(client_identity));
    let req = request(&mut client, &mut server);
    let body = serde_json::to_vec(&response(&identity, &server, &req, true)).unwrap();
    send(&mut client, &mut server, 200, &body).unwrap();
    assert!(!client.is_ready());
    let present = request(&mut client, &mut server);
    assert_eq!(present.mode, "present");
    let context = attest::b64_decode(present.context.as_ref().unwrap()).unwrap();
    let hctx = server
        .export_keying_material([0u8; 32], attest::EXPORTER_LABEL_CLIENT, Some(&context))
        .unwrap();
    let expected = attest::client_report_data(&client_identity.spki, &context, &hctx, None);
    assert_eq!(
        attest::b64_decode(present.quote.as_ref().unwrap()).unwrap(),
        quote(&expected)
    );
    assert!(client.write_plaintext(b"protected request").is_err());
    send(&mut client, &mut server, 204, &[]).unwrap();
    assert!(client.is_ready());
    assert_eq!(client.local_evidence().unwrap().hctx, Some(hctx));
    assert_eq!(client.local_cert_der().unwrap(), client_identity.cert);

    // Renewal retires both proof legs and repeats the mutual acknowledgement
    // gate on the same TLS connection, with fresh role-specific contexts.
    let previous_peer = client.peer_evidence().unwrap().quote.clone();
    let previous_local = client.local_evidence().unwrap().quote.clone();
    let previous_binder = client.channel_binder().unwrap();
    client.re_attest().unwrap();
    assert!(!client.is_ready());
    assert!(client.peer_evidence().is_none());
    assert!(client.local_evidence().is_none());
    assert!(client.write_plaintext(b"protected request").is_err());
    let fresh_req = request(&mut client, &mut server);
    assert_ne!(fresh_req.context, req.context);
    let mut fresh_response = response(&identity, &server, &fresh_req, true);
    fresh_response.client_context = Some(attest::b64_encode(&[4; 32]));
    send(
        &mut client,
        &mut server,
        200,
        &serde_json::to_vec(&fresh_response).unwrap(),
    )
    .unwrap();
    let present = request(&mut client, &mut server);
    assert_eq!(present.mode, "present");
    assert_eq!(present.context, fresh_response.client_context);
    assert!(!client.is_ready());
    assert!(client.local_evidence().is_none());
    send(&mut client, &mut server, 204, &[]).unwrap();
    assert!(client.is_ready());
    assert_ne!(client.peer_evidence().unwrap().quote, previous_peer);
    assert_ne!(client.local_evidence().unwrap().quote, previous_local);
    assert_eq!(client.channel_binder().unwrap(), previous_binder);
    client.write_plaintext(b"protected request").unwrap();
}

#[test]
fn renewal_rejects_old_proofs_on_the_same_connection_and_busy_buffers() {
    let identity = Identity::new();
    let (mut client, mut server) = pair(&identity, None);
    assert!(client.re_attest().is_err());
    let req = request(&mut client, &mut server);
    let body = serde_json::to_vec(&response(&identity, &server, &req, false)).unwrap();
    send(&mut client, &mut server, 200, &body).unwrap();
    assert!(client.is_ready());
    client
        .write_plaintext(b"GET /data HTTP/1.1\r\nHost: v2.test\r\n\r\n")
        .unwrap();
    assert!(client.re_attest().is_err());
    let application = client.collect_tls_output().unwrap();
    server
        .read_tls(&mut std::io::Cursor::new(application))
        .unwrap();
    server.process_new_packets().unwrap();
    let mut consumed = [0; 256];
    assert!(server.reader().read(&mut consumed).unwrap() > 0);
    send(&mut client, &mut server, 200, b"application response").unwrap();
    assert!(client.re_attest().is_err());
    assert!(!client.take_plaintext().is_empty());
    client.re_attest().unwrap();
    let fresh_req = request(&mut client, &mut server);
    assert_ne!(fresh_req.context, req.context);
    assert!(send(&mut client, &mut server, 200, &body).is_err());
    assert!(!client.is_ready());
    assert!(client.peer_evidence().is_none());
    assert!(client.write_plaintext(b"protected request").is_err());
    assert!(client.re_attest().is_err());
}
