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

struct BodyOwner(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl Drop for BodyOwner {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}
fn owned_body(
    bytes: Vec<u8>,
    drops: &Arc<std::sync::atomic::AtomicUsize>,
) -> crate::HttpResponseBody {
    crate::HttpResponseBody::with_owner(bytes, Arc::new(BodyOwner(Arc::clone(drops))))
}

#[test]
fn revocation_prevents_response_after_dispatch_but_preserves_other_workloads() {
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let owner_drop_count = || drops.load(std::sync::atomic::Ordering::SeqCst);
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
    // Drain a body larger than both old transport caps, without making a
    // whole-response TLS buffer. Check every byte against an independent
    // HTTP oracle while the receiver accepts only bounded flights.
    let body: Vec<u8> = (0..5 * 1024 * 1024).map(|n| (n % 251) as u8).collect();
    let expected = enclave_os_common::protocol::format_http_response(200, &body, false);
    b.queue_http_response(
        200,
        "application/json",
        &[],
        owned_body(body, &drops),
        false,
        false,
    )
    .unwrap();
    assert!(b
        .queue_http_response(
            200,
            "application/json",
            &[],
            owned_body(vec![], &drops),
            false,
            false
        )
        .is_err());
    assert_eq!(
        owner_drop_count(),
        1,
        "failed queue drops only its own body admission"
    );
    let mut received = Vec::new();
    let mut window = enclave_os_common::channel::TcpWriteWindow::default();
    assert_eq!(super::response_credit(&[0; 7], Some(&mut window), Some(&b)), (false, false));
    assert_eq!(super::response_credit(&0u64.to_le_bytes(), None, Some(&b)), (false, false), "absent/foreign window cannot classify as cheap");
    assert!(window.send(17));
    assert_eq!(super::response_credit(&17u64.to_le_bytes(), Some(&mut window), None), (true, false), "absent/handshaking session stays full");
    let mut sent = 17u64;
    while b.has_pending_response() {
        let (flight, close, shutdown) = b.progress_http_response().unwrap();
        assert!(flight.len() <= 64 * 1024);
        assert!(!close && !shutdown);
        assert!(window.send(flight.len() as u64));
        sent += flight.len() as u64;
        let pending = b.has_pending_response();
        assert_eq!(super::response_credit(&sent.to_le_bytes(), Some(&mut window), Some(&b)), (true, pending), "actual advancing credit is cheap only while this response drains");
        assert_eq!(super::response_credit(&sent.to_le_bytes(), Some(&mut window), Some(&b)), (true, false), "duplicate credit never creates progress");
        assert_eq!(super::response_credit(&(sent - 1).to_le_bytes(), Some(&mut window), Some(&b)), (false, false));
        assert_eq!(super::response_credit(&(sent + 1).to_le_bytes(), Some(&mut window), Some(&b)), (false, false));
        let mut input = Cursor::new(flight);
        while input.position() < input.get_ref().len() as u64 {
            b_client.read_tls(&mut input).unwrap();
            b_client.process_new_packets().unwrap();
            let mut chunk = [0; 8192];
            loop {
                match std::io::Read::read(&mut b_client.reader(), &mut chunk) {
                    Ok(0) => break,
                    Ok(count) => received.extend_from_slice(&chunk[..count]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("read response: {error}"),
                }
            }
        }
    }
    assert_eq!(received, expected);
    assert!(!b.has_pending_response());
    assert!(window.send(1));
    assert_eq!(super::response_credit(&(sent + 1).to_le_bytes(), Some(&mut window), Some(&b)), (true, false), "finished response remains full");
    assert_eq!(
        owner_drop_count(),
        2,
        "successful complete drain releases the body admission"
    );
    b.queue_http_response(
        200,
        "application/octet-stream",
        &[],
        owned_body(vec![9; 1024 * 1024], &drops),
        false,
        false,
    )
    .unwrap();
    assert!(!b.progress_http_response().unwrap().0.is_empty());
    assert!(b.has_pending_response());
    assert_eq!(
        owner_drop_count(),
        2,
        "partial TLS drain retains the body admission"
    );
    assert!(store.unregister("b.test"));
    assert!(b.progress_http_response().is_err());
    assert!(!b.has_pending_response());
    assert_eq!(
        owner_drop_count(),
        3,
        "configuration revocation drops the retained body"
    );
    assert!(b.collect_tls_output().unwrap().is_empty());

    // A bounded control reply fits in its dispatch turn. A configuration
    // transition at the next hook cannot truncate that already written reply,
    // while subsequent traffic on the old lease is still rejected.
    register(&store, "control.test");
    let (mut client, mut control) = pair(&store, "control.test");
    handshake(&mut client, &mut control);
    let body = b"{\"runtime_active\":true}";
    control
        .queue_http_response(200, "application/json", &[], body.to_vec(), false, false)
        .unwrap();
    let (flight, close, shutdown) = control.progress_http_response().unwrap();
    assert!(!control.has_pending_response());
    assert!(!close && !shutdown);
    client.read_tls(&mut Cursor::new(flight)).unwrap();
    client.process_new_packets().unwrap();
    let mut received = [0; 1024];
    let count = std::io::Read::read(&mut client.reader(), &mut received).unwrap();
    assert_eq!(
        &received[..count],
        &enclave_os_common::protocol::format_http_response(200, body, false)
    );
    register(&store, "control.test");
    assert!(control
        .queue_http_response(
            200,
            "application/json",
            &[],
            owned_body(vec![1], &drops),
            false,
            false
        )
        .is_err());
    assert!(control.collect_tls_output().unwrap().is_empty());
    assert_eq!(
        owner_drop_count(),
        4,
        "revoked configuration rejects and drops new admission"
    );
    register(&store, "teardown.test");
    let (mut teardown_client, mut teardown) = pair(&store, "teardown.test");
    handshake(&mut teardown_client, &mut teardown);
    teardown
        .queue_http_response(
            200,
            "application/json",
            &[],
            owned_body(vec![7; 1024 * 1024], &drops),
            false,
            false,
        )
        .unwrap();
    assert_eq!(owner_drop_count(), 4);
    drop(teardown);
    assert_eq!(
        owner_drop_count(),
        5,
        "session teardown releases an undrained body"
    );
}
