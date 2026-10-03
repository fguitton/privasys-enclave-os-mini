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
    bulk_header_and_lifetime_boundaries();
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
    bulk_revocation_timeout_and_final_currentness();
}

#[test]
fn revocation_prevents_response_after_dispatch_but_preserves_other_workloads() {
    bulk_streaming_and_pipeline();
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
    b.queue_http_response(200, "application/json", &[], body, false, false)
        .unwrap();
    assert!(b
        .queue_http_response(200, "application/json", &[], vec![], false, false)
        .is_err());
    let mut received = Vec::new();
    while b.has_pending_response() {
        let (flight, close, shutdown) = b.progress_http_response().unwrap();
        assert!(flight.len() <= 64 * 1024);
        assert!(!close && !shutdown);
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
    b.queue_http_response(
        200,
        "application/octet-stream",
        &[],
        vec![9; 1024 * 1024],
        false,
        false,
    )
    .unwrap();
    assert!(!b.progress_http_response().unwrap().0.is_empty());
    assert!(b.has_pending_response());
    assert!(store.unregister("b.test"));
    assert!(b.progress_http_response().is_err());
    assert!(!b.has_pending_response());
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
        .queue_http_response(200, "application/json", &[], vec![1], false, false)
        .is_err());
    assert!(control.collect_tls_output().unwrap().is_empty());
}

// The same real TLS session and production configuration lease exercise the
// optional incremental receiver. This fixture's staged marker is not an
// application V2 frame-verification or appraisal claim.
use super::super::bulk_ingress::{
    AdmittedBulkIngress, BulkIngressContext, BulkIngressReceiver, BulkIngressResponse,
};
use enclave_os_common::ingress::{CapacityCharge, ChargedBytes};
use std::sync::atomic::{AtomicUsize, Ordering};

struct BulkLedger {
    capacity: AtomicUsize,
    peak: AtomicUsize,
    commits: AtomicUsize,
    receives: AtomicUsize,
    received_bytes: AtomicUsize,
    acquired: AtomicUsize,
    epoch: AtomicUsize,
    limit: usize,
}
impl BulkLedger {
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            commits: AtomicUsize::new(0),
            receives: AtomicUsize::new(0),
            received_bytes: AtomicUsize::new(0),
            acquired: AtomicUsize::new(0),
            epoch: AtomicUsize::new(1),
            limit,
        })
    }
}
thread_local! {
    static BULK_LEDGER: std::cell::RefCell<Option<Arc<BulkLedger>>> = const { std::cell::RefCell::new(None) };
}
struct BulkCharge {
    ledger: Arc<BulkLedger>,
    capacity: usize,
}
impl CapacityCharge for BulkCharge {
    fn reserve(&mut self, capacity: usize) -> Result<(), &'static str> {
        if capacity > self.ledger.limit {
            return Err("fixture budget exhausted");
        }
        let old = self.capacity;
        assert!(capacity >= old);
        let total = self
            .ledger
            .capacity
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(capacity - old)
                    .filter(|total| *total <= self.ledger.limit + 2)
            })
            .map_err(|_| "fixture aggregate budget exhausted")?
            + capacity
            - old;
        self.capacity = capacity;
        self.ledger.peak.fetch_max(total, Ordering::SeqCst);
        Ok(())
    }
}
impl Drop for BulkCharge {
    fn drop(&mut self) {
        self.ledger
            .capacity
            .fetch_sub(self.capacity, Ordering::SeqCst);
    }
}
struct BulkReceiver {
    bytes: ChargedBytes,
    ledger: Arc<BulkLedger>,
    binder: Vec<u8>,
    epoch: usize,
    endpoint: Option<enclave_os_common::modules::AttestedEndpointIdentity>,
    leaf: Option<Vec<u8>>,
}
impl BulkIngressReceiver for BulkReceiver {
    fn charged_capacity(&self) -> usize {
        self.bytes.reserved_capacity()
    }
    fn receive(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        assert!(bytes.len() <= super::BULK_PLAINTEXT_PIECE_BYTES);
        self.ledger.receives.fetch_add(1, Ordering::SeqCst);
        self.ledger
            .received_bytes
            .fetch_add(bytes.len(), Ordering::SeqCst);
        self.bytes.try_extend_from_slice(bytes)
    }
    fn finish(
        self: Box<Self>,
        head: &enclave_os_common::protocol::HttpRequestHead,
        context: &BulkIngressContext,
    ) -> Result<BulkIngressResponse, &'static str> {
        if context.request.channel_binder.as_ref() != Some(&self.binder)
            || self.ledger.epoch.load(Ordering::SeqCst) != self.epoch
            || context.request.attested_endpoint != self.endpoint
            || context.request.local_cert_der != self.leaf
            || self.bytes.len() != head.body_bytes()
            || self.bytes.as_slice().last() != Some(&0xfe)
        {
            return Err("fixture final authority or body rejected");
        }
        let mut response = ChargedBytes::try_new(
            2,
            2,
            Box::new(BulkCharge {
                ledger: self.ledger.clone(),
                capacity: 0,
            }),
        )?;
        response.try_extend_from_slice(b"ok")?;
        self.ledger.commits.fetch_add(1, Ordering::SeqCst);
        Ok(BulkIngressResponse {
            status: 200,
            content_type: "application/octet-stream",
            body: response,
        })
    }
}
fn bulk_hook(
    head: &enclave_os_common::protocol::HttpRequestHead,
    context: &BulkIngressContext,
) -> Result<Option<AdmittedBulkIngress>, &'static str> {
    if head.request().path != "/bulk" {
        return Ok(None);
    }
    if context.request.server_name.as_deref() != Some("a.test")
        || context.request.attestation != "challenge"
    {
        return Err("fixture unappraised session");
    }
    let ledger = BULK_LEDGER.with(|current| current.borrow().as_ref().unwrap().clone());
    ledger.acquired.fetch_add(1, Ordering::SeqCst);
    let bytes = ChargedBytes::try_new(
        head.body_bytes(),
        ledger.limit,
        Box::new(BulkCharge {
            ledger: ledger.clone(),
            capacity: 0,
        }),
    )?;
    let epoch = ledger.epoch.load(Ordering::SeqCst);
    Ok(Some(AdmittedBulkIngress {
        receiver: Box::new(BulkReceiver {
            bytes,
            ledger,
            binder: context.request.channel_binder.clone().unwrap(),
            epoch,
            endpoint: context.request.attested_endpoint,
            leaf: context.request.local_cert_der.clone(),
        }),
        max_body_bytes: 20 * 1024 * 1024,
        max_staged_capacity: 20 * 1024 * 1024,
        max_response_capacity: 2,
        resource_timeout: std::time::Duration::from_secs(60),
    }))
}
fn bulk_pair(limit: usize) -> (CertStore, ClientConnection, RaTlsSession, Arc<BulkLedger>) {
    let store = CertStore::new();
    register(&store, "a.test");
    let (mut client, mut session) = pair(&store, "a.test");
    handshake(&mut client, &mut session);
    session.set_attestation("challenge");
    session.set_bulk_ingress(
        7,
        enclave_os_common::modules::IngressClass::ExternalNetwork,
        Some(bulk_hook),
    );
    let ledger = BulkLedger::new(limit);
    BULK_LEDGER.with(|current| *current.borrow_mut() = Some(ledger.clone()));
    (store, client, session, ledger)
}
fn bulk_header_and_lifetime_boundaries() {
    for header in [
        "Content-Length: 1\r\nContent-Length: 1\r\n",
        "Content-Length: 2\r\nContent-Length: 1\r\n",
        "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
        "Content-Length: 18446744073709551615\r\n",
    ] {
        let (_, mut client, mut session, ledger) = bulk_pair(32);
        client
            .writer()
            .write_all(format!("POST /bulk HTTP/1.1\r\n{header}\r\n").as_bytes())
            .unwrap();
        assert!(session.feed_tls_bytes(&flight(&mut client)).is_err());
        assert_eq!(ledger.capacity.load(Ordering::SeqCst), 0);
        assert_eq!(ledger.receives.load(Ordering::SeqCst), 0);
    }
    let (_, mut client, mut session, ledger) = bulk_pair(32);
    session.set_attestation("none");
    client
        .writer()
        .write_all(b"POST /bulk HTTP/1.1\r\nContent-Length: 17000000\r\n\r\n")
        .unwrap();
    assert!(session.feed_tls_bytes(&flight(&mut client)).is_err());
    assert_eq!(ledger.acquired.load(Ordering::SeqCst), 0);
    assert_eq!(ledger.capacity.load(Ordering::SeqCst), 0);
    assert_eq!(session.read_buf.capacity(), 0);
    let (_, mut client, mut session, ledger) = bulk_pair(2);
    client
        .writer()
        .write_all(b"POST /bulk HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc")
        .unwrap();
    assert!(session.feed_tls_bytes(&flight(&mut client)).is_err());
    assert_eq!(ledger.capacity.load(Ordering::SeqCst), 0);
    // Authenticated header alone cannot reserve a larger body than its credit.
    let length = 20 * 1024 * 1024;
    let (_, mut client, mut session, ledger) = bulk_pair(1024 * 1024);
    client
        .writer()
        .write_all(format!("POST /bulk HTTP/1.1\r\nContent-Length: {length}\r\n\r\n").as_bytes())
        .unwrap();
    assert!(session.feed_tls_bytes(&flight(&mut client)).is_err());
    assert_eq!(ledger.acquired.load(Ordering::SeqCst), 1);
    assert_eq!(ledger.received_bytes.load(Ordering::SeqCst), 0);
    assert_eq!(ledger.commits.load(Ordering::SeqCst), 0);
    assert_eq!(ledger.capacity.load(Ordering::SeqCst), 0);
    assert_eq!(session.read_buf.capacity(), 0);
    assert!(session.recv_ingress_request().is_err());
    // The same geometry remains rejected over real TLS with no optional hook.
    let store = CertStore::new();
    register(&store, "a.test");
    let (mut client, mut session) = pair(&store, "a.test");
    handshake(&mut client, &mut session);
    write_requests(
        &mut client,
        &mut session,
        format!("POST /bulk HTTP/1.1\r\nContent-Length: {length}\r\n\r\n").as_bytes(),
    );
    assert!(session.recv_http_request().is_err());
    assert!(session.read_buf.capacity() <= super::MAX_BULK_LOOKAHEAD_BYTES);
    // Installing a hook that selects ordinary None does not expand that cap.
    let (_, mut client, mut session, ledger) = bulk_pair(length);
    client
        .writer()
        .write_all(
            format!("POST /ordinary HTTP/1.1\r\nContent-Length: {length}\r\n\r\n").as_bytes(),
        )
        .unwrap();
    assert!(session.feed_tls_bytes(&flight(&mut client)).is_err());
    assert_eq!(ledger.acquired.load(Ordering::SeqCst), 0);
    assert_eq!(ledger.received_bytes.load(Ordering::SeqCst), 0);
    assert_eq!(ledger.capacity.load(Ordering::SeqCst), 0);
    // Disconnect drops a partial body's allocation and unique permit.
    let (_, mut client, mut session, ledger) = bulk_pair(32);
    write_requests(
        &mut client,
        &mut session,
        b"POST /bulk HTTP/1.1\r\nContent-Length: 3\r\n\r\na",
    );
    assert!(ledger.capacity.load(Ordering::SeqCst) > 0);
    drop(session);
    assert_eq!(ledger.capacity.load(Ordering::SeqCst), 0);
}
fn bulk_revocation_timeout_and_final_currentness() {
    let (store, mut client, mut session, ledger) = bulk_pair(32);
    write_requests(
        &mut client,
        &mut session,
        b"POST /bulk HTTP/1.1\r\nContent-Length: 3\r\n\r\na",
    );
    register(&store, "a.test");
    // No new TCP input: the same bounded idle resource seam must retire it.
    assert!(session
        .check_bulk_deadline(std::time::Instant::now())
        .is_err());
    assert!(session.feed_tls_bytes(&[]).is_err());
    assert_eq!(ledger.capacity.load(Ordering::SeqCst), 0);
    assert_eq!(session.read_buf.capacity(), 0);
    let (_, mut client, mut session, ledger) = bulk_pair(32);
    write_requests(
        &mut client,
        &mut session,
        b"POST /bulk HTTP/1.1\r\nContent-Length: 3\r\n\r\na",
    );
    let deadline = session.bulk.as_ref().unwrap().deadline;
    write_requests(&mut client, &mut session, b"b");
    assert_eq!(session.bulk.as_ref().unwrap().deadline, deadline);
    assert!(session.check_bulk_deadline(deadline).is_err()); // exact idle seam
    assert_eq!(ledger.capacity.load(Ordering::SeqCst), 0);
    for changed_binding in 0..4 {
        let (_, mut client, mut session, ledger) = bulk_pair(32);
        write_requests(
            &mut client,
            &mut session,
            b"POST /bulk HTTP/1.1\r\nContent-Length: 2\r\n\r\na\xfe",
        );
        if changed_binding == 1 {
            let (_, mut other_client, mut other, _) = bulk_pair(32);
            handshake(&mut other_client, &mut other);
            session.tls_conn = other.tls_conn;
        } else if changed_binding == 2 {
            session.attested_endpoint =
                Some(enclave_os_common::modules::AttestedEndpointIdentity {
                    endpoint_manifest_id: [1; 16],
                    endpoint_manifest_digest: [2; 32],
                    endpoint_id: [3; 16],
                    operation_id: [4; 16],
                    workflow_generation_id: [5; 16],
                    entry_stage_id: 6,
                    workflow_id: [7; 16],
                    workflow_manifest_digest: [8; 32],
                    route_digest: [9; 32],
                    activation_epoch: 10,
                });
        } else if changed_binding == 3 {
            session.local_cert_der = vec![0];
        } else {
            ledger.epoch.fetch_add(1, Ordering::SeqCst);
        }
        assert!(session.recv_ingress_request().is_err());
        assert_eq!(ledger.commits.load(Ordering::SeqCst), 0);
        assert_eq!(ledger.capacity.load(Ordering::SeqCst), 0);
    }
    let (_, mut client, mut session, ledger) = bulk_pair(32);
    write_requests(
        &mut client,
        &mut session,
        b"POST /bulk HTTP/1.1\r\nContent-Length: 2\r\n\r\nax",
    );
    assert!(session.recv_ingress_request().is_err());
    assert_eq!(ledger.commits.load(Ordering::SeqCst), 0);
    assert_eq!(ledger.capacity.load(Ordering::SeqCst), 0);
}
fn bulk_streaming_and_pipeline() {
    let length = 20 * 1024 * 1024;
    assert!(length > enclave_os_common::protocol::MAX_BODY_SIZE);
    let (_, mut client, mut session, ledger) = bulk_pair(length);
    write_requests(
        &mut client,
        &mut session,
        b"POST /bulk HTTP/1.1\r\nContent-Len",
    );
    assert_eq!(ledger.acquired.load(Ordering::SeqCst), 0);
    write_requests(
        &mut client,
        &mut session,
        format!("gth: {length}\r\n\r\n").as_bytes(),
    );
    assert_eq!(ledger.acquired.load(Ordering::SeqCst), 1);
    let piece = [0x21; 8192];
    let mut remaining = length - 1;
    while remaining != 0 {
        let count = remaining.min(piece.len());
        write_requests(&mut client, &mut session, &piece[..count]);
        assert!(session.read_buf.capacity() <= super::MAX_BULK_LOOKAHEAD_BYTES);
        remaining -= count;
    }
    write_requests(
        &mut client,
        &mut session,
        b"\xfeGET /healthz HTTP/1.1\r\n\r\n",
    );
    assert!(session.read_buf.capacity() <= super::MAX_BULK_LOOKAHEAD_BYTES);
    assert_eq!(ledger.commits.load(Ordering::SeqCst), 0);
    assert_eq!(ledger.received_bytes.load(Ordering::SeqCst), length);
    let super::IngressRequest::Bulk(response, close) =
        session.recv_ingress_request().unwrap().unwrap()
    else {
        panic!("bulk response missing");
    };
    assert!(!close);
    assert_eq!(response.body.as_slice(), b"ok");
    assert_eq!(ledger.commits.load(Ordering::SeqCst), 1);
    assert_eq!(
        ledger.capacity.load(Ordering::SeqCst),
        response.body.capacity()
    );
    session.queue_bulk_response(response, false).unwrap();
    assert!(ledger.capacity.load(Ordering::SeqCst) > 0);
    while session.has_pending_response() {
        session.progress_http_response().unwrap();
    }
    assert_eq!(ledger.capacity.load(Ordering::SeqCst), 0);
    let super::IngressRequest::Ordinary(request) = session.recv_ingress_request().unwrap().unwrap()
    else {
        panic!("pipeline successor missing");
    };
    assert_eq!(request.path, "/healthz");
    assert_eq!(ledger.acquired.load(Ordering::SeqCst), 1);
    assert!(ledger.peak.load(Ordering::SeqCst) >= length);
    assert!(ledger.peak.load(Ordering::SeqCst) <= length + 2);
    // The successor's body is already in bounded lookahead and exceeds one
    // TLS scratch piece. Admission must split it and charge fresh callback
    // work rather than forwarding it as one oversized receiver call.
    let next_len = 32 * 1024 + 1;
    let (_, mut client, mut session, ledger) = bulk_pair(next_len);
    let mut pipelined = b"POST /bulk HTTP/1.1\r\nContent-Length: 1\r\n\r\n\xfe".to_vec();
    pipelined.extend_from_slice(
        format!("POST /bulk HTTP/1.1\r\nContent-Length: {next_len}\r\n\r\n").as_bytes(),
    );
    pipelined.extend_from_slice(&vec![0x21; next_len - 1]);
    pipelined.push(0xfe);
    write_requests(&mut client, &mut session, &pipelined);
    let super::IngressRequest::Bulk(first, _) = session.recv_ingress_request().unwrap().unwrap()
    else {
        panic!("first pipeline request missing");
    };
    drop(first);
    let super::IngressRequest::Bulk(second, _) = session.recv_ingress_request().unwrap().unwrap()
    else {
        panic!("second pipeline request missing");
    };
    drop(second);
    assert_eq!(ledger.acquired.load(Ordering::SeqCst), 2);
    assert_eq!(ledger.commits.load(Ordering::SeqCst), 2);
    assert!(ledger.receives.load(Ordering::SeqCst) >= 4);
    assert_eq!(ledger.capacity.load(Ordering::SeqCst), 0);
}
