// Copyright (c) 2026 Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

//! Real TLS sessions and the production certificate store. No hardware or
//! quote-verification claim: these exercise configuration revocation boundaries.

use super::super::cert_store::CertStore;
use super::{FidoIdentity, RaTlsSession};
use enclave_os_common::modules::{AppIdentity, PeerEvidence};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use std::io::{Cursor, Write};
use std::sync::Arc;

fn register(store: &CertStore, name: &str) {
    store.register(AppIdentity {
        hostname: name.into(),
        config: vec![],
        attested_endpoint: None,
    });
}

fn pair(store: &CertStore, name: &str) -> (ClientConnection, RaTlsSession) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![name.into()])
        .unwrap()
        .self_signed(&key)
        .unwrap()
        .der()
        .to_vec();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert.clone())).unwrap();
    let client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let (app, lease) = store.snapshot(Some(name)).unwrap();
    (
        ClientConnection::new(
            Arc::new(client),
            ServerName::try_from(name.to_owned()).unwrap(),
        )
        .unwrap(),
        RaTlsSession::new(
            ServerConnection::new(Arc::new(server)).unwrap(),
            cert,
            Some(name.into()),
            app.and_then(|app| app.attested_endpoint),
            lease,
        ),
    )
}

fn flight(client: &mut ClientConnection) -> Vec<u8> {
    let mut output = vec![];
    while client.wants_write() {
        client.write_tls(&mut output).unwrap();
    }
    output
}

fn handshake(client: &mut ClientConnection, session: &mut RaTlsSession) {
    for _ in 0..16 {
        session.feed_tls_bytes(&flight(client)).unwrap();
        let output = session.collect_tls_output().unwrap();
        if !output.is_empty() {
            client.read_tls(&mut Cursor::new(output)).unwrap();
            client.process_new_packets().unwrap();
        }
        if !client.is_handshaking() && !session.is_handshaking() {
            return;
        }
    }
    panic!("TLS handshake did not complete within the fixture bound");
}

fn write_requests(client: &mut ClientConnection, session: &mut RaTlsSession, requests: &[u8]) {
    client.writer().write_all(requests).unwrap();
    session.feed_tls_bytes(&flight(client)).unwrap();
}

#[test]
fn replacement_during_handshake_requires_a_new_connection() {
    let store = CertStore::new();
    register(&store, "a.test");
    let (mut client, mut session) = pair(&store, "a.test");
    session.feed_tls_bytes(&flight(&mut client)).unwrap();
    assert!(session.is_handshaking());
    register(&store, "a.test");
    assert!(session.feed_tls_bytes(&[]).is_err());
    assert!(session.attestation_failed());
    let (mut client, mut session) = pair(&store, "a.test");
    handshake(&mut client, &mut session);
    assert!(session.export_hctx(b"test", &[1; 32]).is_ok());
}

#[test]
fn replacement_rejects_buffered_requests_and_re_attestation() {
    let store = CertStore::new();
    register(&store, "a.test");
    let (mut client, mut session) = pair(&store, "a.test");
    handshake(&mut client, &mut session);
    write_requests(
        &mut client,
        &mut session,
        b"GET /first HTTP/1.1\r\nHost: a.test\r\n\r\nGET /second HTTP/1.1\r\nHost: a.test\r\n\r\n",
    );
    assert_eq!(session.recv_http_request().unwrap().unwrap().path, "/first");
    let evidence = PeerEvidence {
        tee: "sgx".into(),
        quote: vec![1],
        gpu_evidence: None,
        quote_time: "2026-09-08T10:00Z".into(),
        context: Some([1; 32]),
        hctx: Some([2; 32]),
    };
    session.set_peer_evidence(evidence.clone());
    session.set_local_evidence(evidence);
    session.set_fido2_identity(FidoIdentity {
        user_handle: "holder".into(),
        credential_id: "id".into(),
        authenticated_at: 0,
    });
    assert!(session.peer_evidence().is_some());
    assert!(session.local_evidence().is_some());
    register(&store, "a.test");
    assert!(session.peer_evidence().is_none());
    assert!(session.local_evidence().is_none());
    assert!(session.recv_http_request().is_err());
    assert!(session.fido2_identity().is_none());
    session.begin_attestation();
    assert!(session.export_hctx(b"test", &[3; 32]).is_err());
    assert!(session.send_http_response(200, b"stale", false).is_err());
    assert!(session.feed_tls_bytes(&[]).is_err());
    assert!(session.collect_tls_output().unwrap().is_empty());
}

#[test]
fn revocation_prevents_response_after_dispatch_but_preserves_other_workloads() {
    let store = CertStore::new();
    register(&store, "a.test");
    register(&store, "b.test");
    let (mut a_client, mut a) = pair(&store, "a.test");
    let (mut b_client, mut b) = pair(&store, "b.test");
    handshake(&mut a_client, &mut a);
    handshake(&mut b_client, &mut b);
    write_requests(
        &mut a_client,
        &mut a,
        b"GET /data HTTP/1.1\r\nHost: a.test\r\n\r\n",
    );
    assert!(a.recv_http_request().unwrap().is_some());
    // A synchronous request handler unloads A before returning its response.
    assert!(store.unregister("a.test"));
    assert!(a
        .send_http_response(200, b"old configuration", false)
        .is_err());
    assert!(a.collect_tls_output().unwrap().is_empty());
    write_requests(
        &mut b_client,
        &mut b,
        b"GET /data HTTP/1.1\r\nHost: b.test\r\n\r\n",
    );
    assert!(b.recv_http_request().unwrap().is_some());
    assert!(!b
        .send_http_response(200, b"current", false)
        .unwrap()
        .is_empty());
}
