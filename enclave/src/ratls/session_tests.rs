// Copyright (c) 2026 Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

//! Real TLS sessions and the production certificate store. No hardware or
//! quote-verification claim: these exercise configuration revocation boundaries.

use super::super::cert_store::CertStore;
use super::{FidoIdentity, RaTlsSession, TlsOutput};
use enclave_os_common::modules::{AppIdentity, PeerEvidence};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
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
    let (client, session, pool) = pair_with_certificate(store, name);
    assert!(pool.used() > 0);
    (client, session)
}

fn pair_with_certificate(
    store: &CertStore,
    name: &str,
) -> (
    ClientConnection,
    RaTlsSession,
    Arc<enclave_os_common::allocation::AllocationPoolV1>,
) {
    let (client, session, certificate, _) = pair_with_all_pools(store, name, 0);
    (client, session, certificate)
}

fn pair_with_all_pools(
    store: &CertStore,
    name: &str,
    extra_config_bytes: usize,
) -> (
    ClientConnection,
    RaTlsSession,
    Arc<enclave_os_common::allocation::AllocationPoolV1>,
    Arc<enclave_os_common::allocation::AllocationPoolV1>,
) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![name.into()])
        .unwrap()
        .self_signed(&key)
        .unwrap()
        .der()
        .to_vec();
    super::ca_context::check_runtime_ca_ownership(&cert, &key.serialize_der());
    use super::retained_tls_config::RetainedTlsConfig;
    let authentication = super::retained_tls_config::ClientAuthentication::Anonymous;
    let config_bytes = RetainedTlsConfig::required_bytes(authentication).unwrap();
    let config_short =
        enclave_os_common::allocation::AllocationPoolV1::new(config_bytes - 1).unwrap();
    assert!(RetainedTlsConfig::reserve(&config_short, authentication).is_none());
    assert_eq!(config_short.used(), 0);
    let config_pool = enclave_os_common::allocation::AllocationPoolV1::new(
        config_bytes.checked_add(extra_config_bytes).unwrap(),
    )
    .unwrap();
    #[cfg(feature = "fallible-allocation-v1")]
    super::retained_tls_config::check_provider_allocation_refusals();
    let reservation = RetainedTlsConfig::reserve(&config_pool, authentication).unwrap();
    let retained_config = reservation
        .configure(
            vec![CertificateDer::from(cert.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert.clone())).unwrap();
    let client =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    let (app, lease) = store.snapshot(Some(name)).unwrap();
    assert_eq!(config_pool.used(), config_bytes);
    let config_alias = retained_config.clone();
    let server = retained_config.connect().unwrap();
    assert_eq!(config_pool.used(), config_bytes);
    drop(config_alias);

    let endpoint = app.and_then(|app| app.attested_endpoint);
    use super::retained_certificate::RetainedCertificate;
    use enclave_os_common::allocation::{AllocationPoolV1, SharedAllocationV1};
    let required = SharedAllocationV1::<Vec<u8>>::required_bytes(cert.len()).unwrap();
    let short = AllocationPoolV1::new(required - 1).unwrap();
    assert!(RetainedCertificate::copy_from(&short, &cert).is_none());
    assert_eq!(short.used(), 0);
    let pool = AllocationPoolV1::new(required).unwrap();
    let retained = RetainedCertificate::copy_from(&pool, &cert).unwrap();
    assert_eq!(retained.bytes(), cert);
    assert_eq!(pool.used(), required);
    let session = RaTlsSession::new(server, retained, Some(name.into()), endpoint, lease);
    (
        ClientConnection::new(
            Arc::new(client),
            ServerName::try_from(name.to_owned()).unwrap(),
        )
        .unwrap(),
        session,
        pool,
        config_pool,
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
    streamed_request_preserves_tls_and_following_request();
    checked_plaintext_backing();
    checked_tls_output_backing();
    let step = u64::try_from(super::TLS_RESPONSE_STEP_BYTES).unwrap();
    assert!(!super::response_socket_credit_ready(step - 1));
    assert!(super::response_socket_credit_ready(step));
    assert!(super::response_socket_credit_ready(step + 1));

    checked_http_request_admission();
    checked_stream_header_admission();
    crate::deferred_ingress::check_context_physical_for_native();
    checked_ordinary_context_admission();
    super::channel_output::check();
    checked_pending_client_hello();
    super::ordered_map::check();
    super::retained_name::check();
    super::leaf_key::check();
    checked_session_table_refusal();
    checked_connection_metadata_tables();
    checked_fixed_channel_binder();
    checked_retained_certificate();
    checked_retained_tls_config();
    checked_retained_evidence();
    checked_paid_quote_time();
    super::attest_response::check();
    super::decoded_attest::check();
    let store = CertStore::new();
    register(&store, "a.test");
    let (mut client, mut session) = pair(&store, "a.test");
    handshake(&mut client, &mut session);
    assert_eq!(
        session.local_cert_der_ref(),
        session.local_cert_der().unwrap()
    );
    {
        use x509_parser::prelude::*;
        let (_, served) = X509Certificate::from_der(session.local_cert_der_ref()).unwrap();
        let point = served.public_key().subject_public_key.as_ref();
        let encoded = enclave_os_common::quote::build_p256_spki_der(point);
        assert_eq!(
            enclave_os_common::quote::p256_spki_sha256(point)
                .unwrap()
                .as_ref(),
            ring::digest::digest(&ring::digest::SHA256, &encoded).as_ref()
        );
    }
    write_requests(
        &mut client,
        &mut session,
        b"GET /first HTTP/1.1\r\nHost: a.test\r\n\r\nGET /second HTTP/1.1\r\nHost: a.test\r\n\r\n",
    );
    assert_eq!(session.recv_http_request().unwrap().unwrap().path, "/first");
    use super::retained_evidence::{EvidenceRef, RetainedEvidence};
    use enclave_os_common::allocation::{AllocationPoolV1, SharedAllocationV1};
    let evidence = EvidenceRef {
        tee: "sgx",
        quote: &[1],
        gpu_evidence: None,
        quote_time: "2026-09-08T10:00Z",
        context: Some([1; 32]),
        hctx: Some([2; 32]),
    };
    let bytes =
        SharedAllocationV1::<PeerEvidence>::required_bytes(evidence.children_bytes().unwrap())
            .unwrap();
    let pool = AllocationPoolV1::new(bytes).unwrap();
    let evidence = RetainedEvidence::copy_from(&pool, &evidence).unwrap();
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
    assert_eq!(core::mem::size_of::<crate::HonestStreamIngressError>(), 0);
    contiguous_response_keeps_original_bytes();
    let allocation_pool = enclave_os_common::allocation::AllocationPoolV1::new(1).unwrap();
    let lease = allocation_pool.reserve_unpublished(1).unwrap();
    let paid_body = crate::HttpResponseBody::with_allocation(vec![7], Some(lease));
    assert_eq!(&*paid_body, &[7]);
    assert_eq!(allocation_pool.used(), 1);
    assert!(allocation_pool.reserve_unpublished(1).is_none());
    drop(paid_body);
    assert_eq!(allocation_pool.used(), 0);
    // Real pool admission remains until the last body/payload pair releases.
    // Erasure itself allocates nothing; each original Arc layout is prepaid.
    struct PairedPayload(Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for PairedPayload {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    struct PairedLease {
        lease: enclave_os_common::allocation::AllocationLeaseV1,
        dropped: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl Drop for PairedLease {
        fn drop(&mut self) {
            assert_eq!(self.dropped.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert!(self.lease.bytes() > 0);
        }
    }
    let pair_bytes = enclave_os_common::allocation::shared_allocation_bytes::<PairedPayload>()
        .unwrap()
        + enclave_os_common::allocation::shared_allocation_bytes::<PairedLease>().unwrap();
    let pair_pool = enclave_os_common::allocation::AllocationPoolV1::new(pair_bytes).unwrap();
    let lease = pair_pool.reserve_unpublished(pair_bytes).unwrap();
    let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let payload = Arc::new(PairedPayload(dropped.clone()));
    let credit = Arc::new(PairedLease {
        lease,
        dropped: dropped.clone(),
    });
    let first =
        crate::HttpResponseBody::with_paired_owner(Vec::new(), payload.clone(), credit.clone());
    let second = crate::HttpResponseBody::with_paired_owner(Vec::new(), payload, credit);
    drop(first);
    assert_eq!(pair_pool.used(), pair_bytes);
    assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 0);
    drop(second);
    assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(pair_pool.used(), 0);
    let credit_bytes = enclave_os_common::allocation::shared_allocation_bytes::<
        enclave_os_common::allocation::AllocationLeaseV1,
    >()
    .unwrap()
        + enclave_os_common::allocation::shared_allocation_bytes::<Vec<u8>>().unwrap();
    let credit_pool = enclave_os_common::allocation::AllocationPoolV1::new(credit_bytes).unwrap();
    let credit = Arc::new(credit_pool.reserve_unpublished(credit_bytes).unwrap());
    let contiguous = crate::HttpResponseBody::with_shared_credit(Vec::new(), credit.clone());
    let shared = crate::HttpResponsePayload::shared_with_credit(
        Vec::new(),
        Arc::new(Vec::<u8>::new()),
        credit,
    )
    .unwrap();
    drop(contiguous);
    assert_eq!(credit_pool.used(), credit_bytes);
    assert!(shared.is_empty());
    drop(shared);
    assert_eq!(credit_pool.used(), 0);
    segmented_response_lifecycle();
    checked_response_step_policy();
    fixed_peer_configuration_boundary();
    #[cfg(feature = "native-deferred-fixture")]
    crate::actual_control_wake::check();
    #[cfg(feature = "native-deferred-fixture")]
    crate::actual_workflow_budget::check_continuation_for_native();
    #[cfg(feature = "native-deferred-fixture")]
    crate::deferred_ingress::check_pending_for_native();
    #[cfg(feature = "native-deferred-fixture")]
    crate::actual_deferred_selector::check_selector_for_native();
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let owner_drop_count = || drops.load(std::sync::atomic::Ordering::SeqCst);
    let store = CertStore::new();
    register(&store, "a.test");
    register(&store, "b.test");
    let (mut a_client, mut a) = pair(&store, "a.test");
    let (mut b_client, mut b) = pair(&store, "b.test");
    assert!(!super::current_data_session(None));
    assert!(
        !super::current_data_session(Some(&mut a)),
        "handshake has no current data binding"
    );
    handshake(&mut a_client, &mut a);
    handshake(&mut b_client, &mut b);
    // Same original queue owner, with a real finite header pool before formatting.
    let (mut header_client, mut header_session) = pair(&store, "b.test");
    handshake(&mut header_client, &mut header_session);
    let required = enclave_os_common::protocol::response_head_encoded_len(
        200,
        "application/json",
        &[],
        0,
        false,
    )
    .unwrap();
    let short = enclave_os_common::allocation::AllocationPoolV1::new(required - 1).unwrap();
    assert!(header_session
        .queue_http_response_admitted(
            200,
            "application/json",
            &[],
            Vec::new().into(),
            (false, false),
            Some(&short)
        )
        .is_break());
    assert_eq!(short.used(), 0);
    assert!(!header_session.has_pending_response());
    for capacity in [required, required + 1] {
        let pool = enclave_os_common::allocation::AllocationPoolV1::new(capacity).unwrap();
        header_session
            .queue_http_response_admitted(
                200,
                "application/json",
                &[],
                Vec::new().into(),
                (false, false),
                Some(&pool),
            )
            .continue_value()
            .unwrap();
        assert_eq!(pool.used(), required);
        assert_eq!(
            header_session.response.as_ref().unwrap().head.capacity(),
            required
        );
        assert!(header_session
            .queue_http_response_admitted(
                200,
                "application/json",
                &[],
                Vec::new().into(),
                (false, false),
                Some(&pool)
            )
            .is_break());
        let (output, _, _) = header_session.progress_http_response().unwrap();
        assert!(!output.is_empty());
        assert_eq!(pool.used(), 0);
        assert!(!header_session.has_pending_response());
    }
    let pool = enclave_os_common::allocation::AllocationPoolV1::new(required).unwrap();
    let oversized = "x".repeat(super::MAX_RESPONSE_HEADER_BYTES + 1);
    assert!(header_session
        .queue_http_response_admitted(
            200,
            &oversized,
            &[],
            Vec::new().into(),
            (false, false),
            Some(&pool)
        )
        .is_break());
    assert_eq!(pool.used(), 0);
    header_session
        .queue_http_response_admitted(
            200,
            "application/json",
            &[],
            Vec::new().into(),
            (false, false),
            Some(&pool),
        )
        .continue_value()
        .unwrap();
    drop(header_session);
    assert_eq!(pool.used(), 0);

    assert!(super::current_data_session(Some(&mut a)));
    assert!(super::current_data_session(Some(&mut b)));
    write_requests(
        &mut a_client,
        &mut a,
        b"GET /data HTTP/1.1\r\nHost: a.test\r\n\r\n",
    );
    assert!(a.recv_http_request().unwrap().is_some());
    // A synchronous request handler unloads A before returning its response.
    assert!(store.unregister("a.test"));
    assert!(
        !super::current_data_session(Some(&mut a)),
        "revocation keeps control work on the full path"
    );
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
    b.queue_http_response_owned(
        200,
        "application/json",
        &[],
        owned_body(body, &drops),
        false,
        false,
    )
    .continue_value()
    .unwrap();
    let failed_owner = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (reason, returned) = b
        .queue_http_response_owned(
            200,
            "application/json",
            &[],
            owned_body(vec![9; 7], &failed_owner),
            false,
            false,
        )
        .break_value()
        .unwrap();
    assert_eq!(reason, "response already pending");
    assert_eq!(returned.len(), 7);
    assert_eq!(
        failed_owner.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "failed queue returns body ownership to the outside-STATE caller"
    );
    drop(returned);
    assert_eq!(failed_owner.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(b
        .queue_http_response_owned(
            200,
            "application/json",
            &[],
            owned_body(vec![], &drops),
            false,
            false
        )
        .is_break());
    assert_eq!(
        owner_drop_count(),
        1,
        "failed queue drops only its own body admission"
    );
    let mut received = Vec::new();
    let mut response_steps = 0usize;
    let mut window = enclave_os_common::channel::TcpWriteWindow::default();
    assert_eq!(
        super::response_credit(&[0; 7], Some(&mut window), Some(&b)),
        (false, false)
    );
    assert_eq!(
        super::response_credit(&0u64.to_le_bytes(), None, Some(&b)),
        (false, false),
        "absent/foreign window cannot classify as cheap"
    );
    assert!(window.send(17));
    assert_eq!(
        super::response_credit(&17u64.to_le_bytes(), Some(&mut window), None),
        (true, false),
        "absent/handshaking session stays full"
    );
    let mut sent = 17u64;
    while b.has_pending_response() {
        response_steps += 1;
        let (flight, close, shutdown) = b.progress_http_response().unwrap();
        assert!(flight.len() <= 64 * 1024);
        assert!(!close && !shutdown);
        assert!(window.send(flight.len() as u64));
        sent += flight.len() as u64;
        let pending = b.has_pending_response();
        assert_eq!(
            super::response_credit(&sent.to_le_bytes(), Some(&mut window), Some(&b)),
            (true, pending),
            "actual advancing credit is cheap only while this response drains"
        );
        assert_eq!(
            super::response_credit(&sent.to_le_bytes(), Some(&mut window), Some(&b)),
            (true, false),
            "duplicate credit never creates progress"
        );
        assert_eq!(
            super::response_credit(&(sent - 1).to_le_bytes(), Some(&mut window), Some(&b)),
            (false, false)
        );
        assert_eq!(
            super::response_credit(&(sent + 1).to_le_bytes(), Some(&mut window), Some(&b)),
            (false, false)
        );
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
    assert_eq!(
        response_steps,
        expected.len().div_ceil(60 * 1024),
        "actual admitted TLS flights use the larger bounded plaintext quantum"
    );
    assert!(response_steps < expected.len().div_ceil(32 * 1024));
    assert!(!b.has_pending_response());
    assert!(window.send(1));
    assert_eq!(
        super::response_credit(&(sent + 1).to_le_bytes(), Some(&mut window), Some(&b)),
        (true, false),
        "finished response remains full"
    );
    assert_eq!(
        owner_drop_count(),
        2,
        "successful complete drain releases the body admission"
    );
    b.queue_http_response_owned(
        200,
        "application/octet-stream",
        &[],
        owned_body(vec![9; 1024 * 1024], &drops),
        false,
        false,
    )
    .continue_value()
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
        .queue_http_response_owned(200, "application/json", &[], body.to_vec(), false, false)
        .continue_value()
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
        .queue_http_response_owned(
            200,
            "application/json",
            &[],
            owned_body(vec![1], &drops),
            false,
            false
        )
        .is_break());
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
        .queue_http_response_owned(
            200,
            "application/json",
            &[],
            owned_body(vec![7; 1024 * 1024], &drops),
            false,
            false,
        )
        .continue_value()
        .unwrap();
    assert_eq!(owner_drop_count(), 4);
    drop(teardown);
    assert_eq!(
        owner_drop_count(),
        5,
        "session teardown releases an undrained body"
    );
}

fn fixed_peer_configuration_boundary() {
    let store = CertStore::new_honest_profile();
    let name = enclave_os_common::modules::HONEST_PEER_SNI;
    let (mut client, mut session) = pair(&store, name);
    handshake(&mut client, &mut session);
    let binder = session.export_hctx(b"fixed-peer-test", &[]).unwrap();
    write_requests(
        &mut client,
        &mut session,
        b"GET /first HTTP/1.1\r\nHost: peer.s1.invalid\r\n\r\nGET /second HTTP/1.1\r\nHost: peer.s1.invalid\r\n\r\n",
    );
    assert_eq!(session.recv_http_request().unwrap().unwrap().path, "/first");
    register(&store, "workflow.test");
    assert_eq!(
        session.recv_http_request().unwrap().unwrap().path,
        "/second"
    );
    assert_eq!(
        session.export_hctx(b"fixed-peer-test", &[]).unwrap(),
        binder
    );

    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let body: Vec<_> = (0..256 * 1024).map(|n| (n % 251) as u8).collect();
    let expected = enclave_os_common::protocol::format_http_response(200, &body, false);
    session
        .queue_http_response_owned(
            200,
            "application/json",
            &[],
            owned_body(body, &drops),
            false,
            false,
        )
        .continue_value()
        .unwrap();
    let mut actual = Vec::new();
    let mut steps = 0;
    while session.has_pending_response() {
        let (bytes, close, shutdown) = session.progress_http_response().unwrap();
        assert!(!close && !shutdown && bytes.len() <= 64 * 1024);
        if !bytes.is_empty() {
            let mut input = Cursor::new(bytes);
            while input.position() < input.get_ref().len() as u64 {
                client.read_tls(&mut input).unwrap();
                client.process_new_packets().unwrap();
                let mut plaintext = [0; 16 * 1024];
                loop {
                    match std::io::Read::read(&mut client.reader(), &mut plaintext) {
                        Ok(0) => break,
                        Ok(length) => actual.extend_from_slice(&plaintext[..length]),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) => panic!("peer response read failed: {error}"),
                    }
                }
            }
        }
        if steps == 0 {
            register(&store, "workflow.test");
            assert!(store.unregister("workflow.test"));
        }
        steps += 1;
        assert!(steps < 32, "bounded peer response must complete");
    }
    assert_eq!(
        actual, expected,
        "unrelated endpoint churn preserves exact partial peer response"
    );
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);

    session
        .queue_http_response_owned(
            200,
            "application/json",
            &[],
            owned_body(vec![7; 256 * 1024], &drops),
            false,
            false,
        )
        .continue_value()
        .unwrap();
    let (bytes, _, _) = session.progress_http_response().unwrap();
    assert!(!bytes.is_empty() && session.has_pending_response());
    store.invalidate(name);
    assert!(session.progress_http_response().is_err());
    assert!(!session.has_pending_response());
    assert_eq!(
        drops.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "explicit peer revocation releases remaining body ownership once"
    );
    assert!(session.export_hctx(b"fixed-peer-test", &[]).is_err());
    assert!(session.recv_http_request().is_err());
    let (mut replacement_client, mut replacement) = pair(&store, name);
    handshake(&mut replacement_client, &mut replacement);
    assert!(replacement.export_hctx(b"fixed-peer-test", &[]).is_ok());
    assert!(
        session.export_hctx(b"fixed-peer-test", &[]).is_err(),
        "replacement cannot resurrect old peer session"
    );
}

// Actual Rustls + production session buffer/header/fragment methods. This
// proves TLS delivery and extraction, not SGX quote or BFT source authority.
fn streamed_request_preserves_tls_and_following_request() {
    crate::stream_ingress::check_slot_ownership();
    streamed_input_alternating_cap_refill();
    let store = CertStore::new();
    register(&store, "stream.test");
    let (mut client, mut session) = pair(&store, "stream.test");
    handshake(&mut client, &mut session);
    let binding = session.channel_binder().unwrap();
    let body = vec![0xa7; 128 * 1024 + 17];
    let head=format!("POST /honest/v1/proposal HTTP/1.1\r\nHost: stream.test\r\nContent-Type: application/honest-source-upload-batch-v2\r\nContent-Length: {}\r\n\r\n",body.len());
    write_requests(&mut client, &mut session, head.as_bytes());
    let (header, head_bytes, length) = session.stream_head().unwrap().unwrap();
    assert!(header.body.is_empty());
    assert_eq!(length, body.len());
    assert!(session.validate_stream_head());
    // Reparse these actual decrypted bytes with the real pool, then move that
    // exact paid header through the original Work/begin callback below.
    drop(header);
    let header_bytes = &session.read_buf[session.read_offset..];
    let header_charge =
        enclave_os_common::protocol::http_request_head_allocation_bound(header_bytes).unwrap();
    let header_pool = enclave_os_common::allocation::AllocationPoolV1::new(header_charge).unwrap();
    let (header, paid_head, paid_length) =
        super::PaidHttpRequest::parse_head(header_bytes, Some(&header_pool))
            .unwrap()
            .unwrap();
    assert_eq!((paid_head, paid_length), (head_bytes, length));
    assert_eq!(header_pool.used(), header_charge);
    let working = RaTlsSession::stream_allocation_bytes().unwrap();
    let slot_bytes = crate::stream_ingress::SlotCharge::metadata_bytes().unwrap();
    let physical =
        enclave_os_common::allocation::AllocationPoolV1::new(working + slot_bytes).unwrap();
    let insufficient = enclave_os_common::allocation::AllocationPoolV1::new(working - 1).unwrap();
    assert!(session.admit_stream_allocation(&insufficient).is_err());
    assert_eq!(insufficient.used(), 0);
    let allocation = session.admit_stream_allocation(&physical).unwrap();
    assert_eq!(physical.used(), working);
    let remaining = physical.reserve(slot_bytes).unwrap();
    assert!(physical.reserve(1).is_none());
    assert!(
        crate::stream_ingress::SlotCharge::reserve_with_allocation(allocation.clone()).is_none()
    );
    drop(remaining);
    assert_eq!(physical.used(), working);
    assert!(session.admit_stream_allocation(&insufficient).is_err());
    session.consume_stream_head(head_bytes).unwrap();
    assert_eq!(
        session.stream_chunks.as_ref().unwrap().capacity(),
        RaTlsSession::STREAM_CHUNK_SLOTS
    );
    let context = enclave_os_common::modules::RequestContext {
        ingress_class: enclave_os_common::modules::IngressClass::ExternalNetwork,
        connection_id: 7,
        server_name: Some("stream.test".into()),
        attested_endpoint: None,
        local_cert_der: session.local_cert_der(),
        local_evidence: None,
        channel_binder: Some(binding.clone()),
        peer_cert_der: None,
        peer_evidence: None,
        attestation: session.attestation().into(),
        oidc_claims: None,
    };
    let mut work = crate::stream_ingress::Work {
        lease: crate::stream_ingress::SlotCharge::reserve_with_allocation(allocation.clone())
            .unwrap(),
        connection: 7,
        nonce: 1,
        generation: 1,
        binding: binding.as_slice().try_into().unwrap(),
        context: Some(context),
        _context_charge: None,
        header: Some(header),
        receiver: None,
        bytes: vec![],
        length,
        remaining: length,
        pending: false,
    };
    assert!(crate::stream_ingress::run_work(fixture_begin, &mut work).is_none());
    assert_eq!(
        header_pool.used(),
        0,
        "original begin consumes header before metadata credit refund"
    );
    for part in body.chunks(32 * 1024) {
        write_requests(&mut client, &mut session, part);
    }
    write_requests(
        &mut client,
        &mut session,
        b"GET /next HTTP/1.1\r\nHost: stream.test\r\n\r\n",
    );
    let segments: Vec<_> = session
        .stream_chunks
        .as_ref()
        .unwrap()
        .iter()
        .map(|(b, _)| b.as_ptr())
        .collect();
    let mut alternating = 0;
    let mut actual = Vec::new();
    while actual.len() < length {
        let part = session.stream_fragment((length - actual.len()).min(64 * 1024));
        assert!(!part.is_empty() && part.len() <= 64 * 1024);
        actual.extend_from_slice(&part);
        for (bytes, _) in session.stream_chunks.as_ref().unwrap() {
            assert!(
                segments.contains(&bytes.as_ptr()),
                "existing backlog segment never moves on extraction"
            );
        }
        alternating += 1;
        work.remaining -= part.len();
        work.bytes = part;
        let result = crate::stream_ingress::run_work(fixture_begin, &mut work);
        if work.remaining == 0 {
            assert_eq!(result.unwrap().body.contiguous().unwrap(), body.as_slice());
        } else {
            assert!(result.is_none());
        }
    }
    assert_eq!(actual, body);
    assert_eq!(session.channel_binder().unwrap(), binding);
    assert!(alternating >= 3);
    session.finish_stream_input().unwrap();
    assert_eq!(session.recv_http_request().unwrap().unwrap().path, "/next");
    // Actual TLS fragment + shared production pending-accounting seam. The
    // receiver is a data-only facade; no Main ticket/custody is manufactured.
    session.consume_stream_head(0).unwrap();
    for _ in 0..2 {
        write_requests(&mut client, &mut session, &vec![0x7a; 32 * 1024]);
    }
    work.bytes = session.stream_fragment(64 * 1024);
    assert_eq!(work.bytes.len(), 64 * 1024);
    work.length = work.bytes.len();
    work.remaining = 0;
    let fragment = work.bytes.as_ptr();
    let credit = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let consumed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    work.receiver = Some(Box::new(PendingReceiver {
        binding: binding.clone(),
        credit: credit.clone(),
        consumed: consumed.clone(),
    }));
    assert!(crate::stream_ingress::run_work(fixture_begin, &mut work).is_none());
    assert!(work.pending);
    let mut slot = crate::stream_ingress::Slot {
        lease: work.lease.clone(),
        nonce: work.nonce,
        generation: work.generation,
        binding: work.binding,
        header: None,
        receiver: None,
        remaining: 64 * 1024,
        fragment: vec![],
        parked: false,
        length: 64 * 1024,
        close: false,
        started: std::time::Instant::now(),
    };
    work.nonce += 1;
    assert!(crate::stream_ingress::retain_work(&mut slot, &mut work).is_err());
    work.nonce -= 1;
    crate::stream_ingress::retain_work(&mut slot, &mut work).unwrap();
    assert!(slot.parked);
    assert_eq!(slot.remaining, 64 * 1024);
    assert_eq!(slot.fragment.as_ptr(), fragment);
    assert_eq!(consumed.load(std::sync::atomic::Ordering::Acquire), 0);
    crate::stream_ingress::notify();
    assert!(
        slot.parked,
        "input/deadline revision cannot rearm stage-credit wait"
    );
    credit.store(true, std::sync::atomic::Ordering::Release);
    crate::stream_ingress::notify_honest_stream_ingress();
    assert!(crate::stream_ingress::take_credit_ready());
    slot.credit_ready();
    session.require_current_configuration().unwrap();
    assert_eq!(session.channel_binder().unwrap(), binding);
    work.bytes = std::mem::take(&mut slot.fragment);
    work.receiver = slot.receiver.take().map(|r| r.value);
    work.remaining = 0;
    let response = crate::stream_ingress::run_work(fixture_begin, &mut work).unwrap();
    assert!(!work.pending);
    assert_eq!(response.status, 202);
    assert_eq!(
        consumed.load(std::sync::atomic::Ordering::Acquire),
        64 * 1024
    );
    assert!(work.receiver.is_none());
    assert_eq!(work.bytes.as_ptr(), fragment);
    drop(slot);
    session.finish_stream_input().unwrap();
    println!("HONEST-STREAM-PENDING exact-fragment=65536 pending-offset-unchanged=PASS actual-credit-resume=PASS consume-once-eof=PASS stale-nonce-denied=PASS");

    let (mut other_client, mut other) = pair(&store, "stream.test");
    assert!(other.channel_binder().is_none());
    handshake(&mut other_client, &mut other);
    assert_ne!(
        other.channel_binder().unwrap(),
        binding,
        "a replacement connection cannot borrow the active stream exporter"
    );
    let head =
        b"POST /honest/v1/proposal HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n";
    write_requests(&mut client, &mut session, head);
    assert!(session.stream_head().is_err());
    assert!(!session.validate_stream_head());
    assert!(store.unregister("stream.test"));
    assert!(session.stream_head().is_err());
    assert!(session.attestation_failed());
    drop(session);
    drop(allocation);
    assert_eq!(
        physical.used(),
        working + slot_bytes,
        "outside-STATE fragment/work owns allocation and slot metadata after session teardown"
    );
    drop(work);
    assert_eq!(physical.used(), 0);
}

struct FixtureReceiver {
    bytes: Vec<u8>,
    binding: Vec<u8>,
}
impl crate::HonestStreamIngressReceiver for FixtureReceiver {
    fn push(
        &mut self,
        bytes: &[u8],
        context: &enclave_os_common::modules::RequestContext,
    ) -> Result<(), crate::HonestStreamIngressError> {
        if context.channel_binder.as_ref() != Some(&self.binding) {
            return Err(crate::HonestStreamIngressError);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn finish(
        self: Box<Self>,
        context: &enclave_os_common::modules::RequestContext,
    ) -> crate::HonestIngressResponse {
        assert_eq!(context.channel_binder.as_ref(), Some(&self.binding));
        crate::HonestIngressResponse {
            status: 202,
            content_type: "application/octet-stream",
            body: self.bytes.into(),
        }
    }
}
fn fixture_begin(
    request: &enclave_os_common::protocol::HttpRequest,
    length: usize,
    context: &enclave_os_common::modules::RequestContext,
) -> std::ops::ControlFlow<crate::HonestIngressResponse, Box<dyn crate::HonestStreamIngressReceiver>>
{
    assert!(request.body.is_empty());
    assert_eq!(length, 128 * 1024 + 17);
    std::ops::ControlFlow::Continue(Box::new(FixtureReceiver {
        bytes: Vec::new(),
        binding: context.channel_binder.clone().unwrap(),
    }))
}

// Exercise actual TLS plaintext draining at the original input ceiling, then
// alternate a bounded extraction and TLS refill. Existing unread segments
// retain their allocation and content; no large suffix is compacted.
fn streamed_input_alternating_cap_refill() {
    let store = CertStore::new();
    register(&store, "stream-cap.test");
    let (mut client, mut session) = pair(&store, "stream-cap.test");
    handshake(&mut client, &mut session);
    session.consume_stream_head(0).unwrap();
    let frame = vec![0x5a; crate::MAX_STREAM_INGRESS_FRAGMENT];
    for _ in 0..enclave_os_common::protocol::MAX_BODY_SIZE / frame.len() {
        for piece in frame.chunks(32 * 1024) {
            write_requests(&mut client, &mut session, piece);
        }
    }
    for _ in 0..8 {
        let old: Vec<_> = session
            .stream_chunks
            .as_ref()
            .unwrap()
            .iter()
            .skip(1)
            .map(|(b, _)| b.as_ptr())
            .collect();
        assert_eq!(session.stream_fragment(frame.len()), frame);
        for piece in frame.chunks(32 * 1024) {
            write_requests(&mut client, &mut session, piece);
        }
        let queue = session.stream_chunks.as_ref().unwrap();
        assert_eq!(
            queue.iter().map(|(b, o)| b.len() - o).sum::<usize>(),
            enclave_os_common::protocol::MAX_BODY_SIZE
        );
        assert!(
            queue.iter().map(|(b, _)| b.capacity()).sum::<usize>()
                <= enclave_os_common::protocol::MAX_BODY_SIZE + frame.len()
        );
        assert_eq!(
            queue
                .iter()
                .take(old.len())
                .map(|(b, _)| b.as_ptr())
                .collect::<Vec<_>>(),
            old,
            "cap/refill does not move the unread suffix"
        );
    }
    // The old growable Vec can retain32MiB capacity. Reuse its already
    // reserved parser/copy allowance without pretending capacity equals len.
    session.stream_chunks = None;
    session.read_buf = Vec::with_capacity(
        (enclave_os_common::protocol::MAX_BODY_SIZE + 64 * 1024).next_power_of_two(),
    );
    session.read_buf.extend_from_slice(&frame);
    let inherited = session.read_buf.as_ptr();
    session.consume_stream_head(0).unwrap();
    assert_eq!(
        session.stream_fragment(frame.len() / 2),
        frame[..frame.len() / 2]
    );
    write_requests(&mut client, &mut session, &frame[..frame.len() / 2]);
    let chunks = session.stream_chunks.as_ref().unwrap();
    assert_eq!(chunks.front().unwrap().0.as_ptr(), inherited);
    assert!(
        chunks.iter().map(|(b, _)| b.capacity()).sum::<usize>()
            <= RaTlsSession::STREAM_INPUT_CAPACITY
    );
    assert_eq!(session.stream_fragment(frame.len()), frame);
    // Terminal reuse: a tiny consumed prefix may leave a large allocation.
    // Completing it must preserve that allocation, not allocate another32MiB.
    session.read_buf = Vec::with_capacity(
        (enclave_os_common::protocol::MAX_BODY_SIZE + 64 * 1024).next_power_of_two(),
    );
    session.read_buf.push(b'x');
    for _ in 0..enclave_os_common::protocol::MAX_BODY_SIZE / frame.len() + 1 {
        session.read_buf.extend_from_slice(&frame);
    }
    let original = session.read_buf.as_ptr();
    session.consume_stream_head(1).unwrap();
    session.finish_stream_input().unwrap();
    assert_eq!(session.read_buf.as_ptr(), original);
    assert_eq!(
        session.read_buf.len(),
        enclave_os_common::protocol::MAX_BODY_SIZE + frame.len()
    );
    session.read_buf.clear();
    session
        .read_buf
        .extend_from_slice(b"GET /tail HTTP/1.1\r\n\r\n");
    assert_eq!(session.recv_http_request().unwrap().unwrap().path, "/tail");

    println!("HONEST-STREAM-INGRESS-CAP-REFILL original-bound=16777216 fragment=65536 rounds=8");
}

struct PendingReceiver {
    binding: Vec<u8>,
    credit: Arc<std::sync::atomic::AtomicBool>,
    consumed: Arc<std::sync::atomic::AtomicUsize>,
}
impl crate::HonestStreamIngressReceiver for PendingReceiver {
    fn push(
        &mut self,
        _: &[u8],
        _: &enclave_os_common::modules::RequestContext,
    ) -> Result<(), crate::HonestStreamIngressError> {
        unreachable!()
    }
    fn push_with_backpressure(
        &mut self,
        bytes: &[u8],
        context: &enclave_os_common::modules::RequestContext,
    ) -> Result<crate::stream_ingress::HonestStreamIngressPush, crate::HonestStreamIngressError>
    {
        if context.channel_binder.as_ref() != Some(&self.binding) {
            return Err(crate::HonestStreamIngressError);
        }
        if !self.credit.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(crate::stream_ingress::HonestStreamIngressPush::Pending);
        }
        assert!(bytes.iter().all(|b| *b == 0x7a));
        self.consumed
            .fetch_add(bytes.len(), std::sync::atomic::Ordering::AcqRel);
        Ok(crate::stream_ingress::HonestStreamIngressPush::Consumed)
    }
    fn finish(
        self: Box<Self>,
        _: &enclave_os_common::modules::RequestContext,
    ) -> crate::HonestIngressResponse {
        crate::HonestIngressResponse {
            status: 202,
            content_type: "application/octet-stream",
            body: vec![].into(),
        }
    }
}

fn segmented_response_lifecycle() {
    let store = CertStore::new();
    register(&store, "segments.test");
    let (mut client, mut session) = pair(&store, "segments.test");
    handshake(&mut client, &mut session);
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let bytes = Arc::new(
        (0..5 * 1024 * 1024)
            .map(|n| (n % 251) as u8)
            .collect::<Vec<_>>(),
    );
    let prefix = vec![33; 97];
    let expected_body = [prefix.as_slice(), bytes.as_slice()].concat();
    let expected = enclave_os_common::protocol::format_http_response(200, &expected_body, false);
    let payload = || {
        crate::HttpResponsePayload::shared(
            prefix.clone(),
            bytes.clone(),
            Arc::new(BodyOwner(drops.clone())),
        )
        .unwrap()
    };
    session
        .queue_http_response_owned(200, "application/json", &[], payload(), false, false)
        .continue_value()
        .unwrap();
    let (reason, returned) = session
        .queue_http_response_owned(200, "application/json", &[], payload(), false, false)
        .break_value()
        .unwrap();
    assert_eq!(reason, "response already pending");
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
    drop(returned);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    let mut received = Vec::new();
    let mut steps = 0;
    while session.has_pending_response() {
        let (flight, close, shutdown) = session.progress_http_response().unwrap();
        assert!(flight.len() <= 64 * 1024);
        assert!(!close && !shutdown);
        steps += 1;
        let mut input = Cursor::new(flight);
        while input.position() < input.get_ref().len() as u64 {
            client.read_tls(&mut input).unwrap();
            client.process_new_packets().unwrap();
            let mut chunk = [0; 8192];
            loop {
                match std::io::Read::read(&mut client.reader(), &mut chunk) {
                    Ok(0) => break,
                    Ok(count) => received.extend_from_slice(&chunk[..count]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("segmented TLS response: {error}"),
                }
            }
        }
    }
    assert!(
        received == expected,
        "every original HTTP byte including segment boundary"
    );
    assert_eq!(steps, expected.len().div_ceil(60 * 1024));
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(Arc::strong_count(&bytes), 1);
    session
        .queue_http_response_owned(200, "application/json", &[], payload(), false, false)
        .continue_value()
        .unwrap();
    assert!(!session.progress_http_response().unwrap().0.is_empty());
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert!(store.unregister("segments.test"));
    assert!(session.progress_http_response().is_err());
    assert!(!session.has_pending_response());
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(Arc::strong_count(&bytes), 1);
}

// Original Session owner: actual pool refusal precedes growth and retains old bytes.
fn checked_plaintext_backing() {
    use enclave_os_common::allocation::AllocationPoolV1;
    let store = CertStore::new();
    register(&store, "read-budget.test");
    let (_, mut session) = pair(&store, "read-budget.test");
    let pool = AllocationPoolV1::new(12).unwrap();
    session
        .append_plaintext_admitted(&[1; 4], Some(&pool))
        .unwrap();
    assert_eq!(session.read_buf.capacity(), 4);
    assert_eq!(pool.used(), 4);
    let refusal = pool.reserve(1).unwrap();
    let old = session.read_buf.as_ptr();
    assert!(session
        .append_plaintext_admitted(&[2], Some(&pool))
        .is_err());
    assert_eq!(session.read_buf.as_ptr(), old);
    assert_eq!(session.read_buf, vec![1; 4]);
    assert_eq!(pool.used(), 5);
    drop(refusal);
    session
        .append_plaintext_admitted(&[2], Some(&pool))
        .unwrap();
    assert_eq!(session.read_buf.capacity(), 8);
    assert_eq!(
        pool.used(),
        8,
        "old4/new8 fit exactly12; old backing is retired before refund"
    );
    assert_eq!(session.read_buf, vec![1, 1, 1, 1, 2]);
    session.read_buf.clear();
    assert_eq!(pool.used(), 8, "empty buffer retains its backing credit");
    drop(session);
    assert_eq!(pool.used(), 0);
    let (_, mut refused) = pair(&store, "read-budget.test");
    let small = AllocationPoolV1::new(3).unwrap();
    assert!(refused
        .append_plaintext_admitted(&[1; 4], Some(&small))
        .is_err());
    assert_eq!(refused.read_buf.capacity(), 0);
    assert_eq!(small.used(), 0);
    let exact = AllocationPoolV1::new(4).unwrap();
    refused
        .append_plaintext_admitted(&[1; 4], Some(&exact))
        .unwrap();
    drop(refused);
    assert_eq!(exact.used(), 0);
}

fn checked_tls_output_backing() {
    use enclave_os_common::allocation::AllocationPoolV1;
    let pool = AllocationPoolV1::new(12).unwrap();
    let mut output = TlsOutput::bounded(8);
    output.append_admitted(&[1; 4], Some(&pool)).unwrap();
    assert_eq!(pool.used(), 4);
    let held = pool.reserve(1).unwrap();
    assert!(output.append_admitted(&[2], Some(&pool)).is_err());
    assert_eq!(output.as_ref(), &[1; 4]);
    drop(held);
    output.append_admitted(&[2; 4], Some(&pool)).unwrap();
    assert_eq!(pool.used(), 8);
    assert!(output.append_admitted(&[3], Some(&pool)).is_err());
    assert_eq!(output.len(), 8);
    drop(output);
    assert_eq!(pool.used(), 0);
    let short = AllocationPoolV1::new(3).unwrap();
    let mut empty = TlsOutput::default();
    assert!(empty.append_admitted(&[1; 4], Some(&short)).is_err());
    assert!(empty.is_empty());
    assert_eq!(short.used(), 0);
}

fn contiguous_response_keeps_original_bytes() {
    let store = CertStore::new();
    register(&store, "contiguous-response.test");
    let (mut client, mut session) = pair(&store, "contiguous-response.test");
    handshake(&mut client, &mut session);
    let body = vec![0x5a; 70 * 1024 + 17];
    let expected = enclave_os_common::protocol::format_http_response(200, &body, false);
    let flight = session.send_http_response(200, &body, false).unwrap();
    let mut input = Cursor::new(flight);
    let mut received = Vec::new();
    while input.position() < input.get_ref().len() as u64 {
        client.read_tls(&mut input).unwrap();
        client.process_new_packets().unwrap();
        let mut bytes = [0; 8192];
        loop {
            match std::io::Read::read(&mut client.reader(), &mut bytes) {
                Ok(0) => break,
                Ok(n) => received.extend_from_slice(&bytes[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("contiguous response: {error}"),
            }
        }
    }
    assert_eq!(received, expected);
}

fn checked_http_request_admission() {
    use enclave_os_common::{allocation::AllocationPoolV1, protocol};
    let raw = b"POST /paid HTTP/1.1\r\nHost: MiXeD.test:443\r\nContent-Type: APPLICATION/JSON\r\nContent-Length: 4\r\n\r\nbody";
    let needed = protocol::http_request_allocation_bound(raw).unwrap();
    let too_small = AllocationPoolV1::new(needed - 1).unwrap();
    assert!(super::PaidHttpRequest::parse(raw, Some(&too_small)).is_err());
    assert_eq!(too_small.used(), 0);
    for limit in [needed, needed + 1] {
        let pool = AllocationPoolV1::new(limit).unwrap();
        let (request, used) = super::PaidHttpRequest::parse(raw, Some(&pool))
            .unwrap()
            .unwrap();
        assert_eq!(used, raw.len());
        assert_eq!(request.path, "/paid");
        assert_eq!(request.host.as_deref(), Some("mixed.test"));
        assert_eq!(request.content_type.as_deref(), Some("application/json"));
        assert_eq!(request.body, b"body");
        assert_eq!(pool.used(), needed);
        drop(request);
        assert_eq!(pool.used(), 0);
        assert!(
            super::PaidHttpRequest::parse(&raw[..raw.len() - 1], Some(&pool))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            pool.used(),
            0,
            "original incomplete body frees metadata before credit"
        );
        assert!(super::PaidHttpRequest::parse(b"bad\r\n\r\n", Some(&pool)).is_err());
        assert_eq!(pool.used(), 0);
    }
}

fn checked_stream_header_admission() {
    use enclave_os_common::{allocation::AllocationPoolV1, protocol};
    let raw = b"POST /paid HTTP/1.1\r\nHost: MiXeD.test:443\r\nContent-Length: 4\r\n\r\nbody";
    let head = raw.len() - b"body".len();
    let needed = protocol::http_request_head_allocation_bound(raw).unwrap();
    assert_eq!(
        needed,
        protocol::http_request_head_allocation_bound(&raw[..head]).unwrap()
    );
    let small = AllocationPoolV1::new(needed - 1).unwrap();
    assert!(super::PaidHttpRequest::parse_head(raw, Some(&small)).is_err());
    assert_eq!(small.used(), 0);
    for limit in [needed, needed + 1] {
        let pool = AllocationPoolV1::new(limit).unwrap();
        let (header, consumed, body) = super::PaidHttpRequest::parse_head(raw, Some(&pool))
            .unwrap()
            .unwrap();
        assert_eq!((consumed, body), (head, 4));
        assert_eq!(header.host.as_deref(), Some("mixed.test"));
        assert!(header.body.is_empty());
        assert_eq!(pool.used(), needed);
        drop(header);
        assert_eq!(pool.used(), 0);
    }
    let duplicate = b"POST /paid HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n";
    let pool =
        AllocationPoolV1::new(protocol::http_request_head_allocation_bound(duplicate).unwrap())
            .unwrap();
    assert!(super::PaidHttpRequest::parse_head(duplicate, Some(&pool)).is_err());
    assert_eq!(pool.used(), 0);
    assert!(
        super::PaidHttpRequest::parse_head(&raw[..head - 1], Some(&pool))
            .unwrap()
            .is_none()
    );
    assert_eq!(pool.used(), 0);
}

fn checked_ordinary_context_admission() {
    use enclave_os_common::{allocation::AllocationPoolV1, modules::IngressClass};
    let store = CertStore::new();
    register(&store, "context.test");
    let (mut client, mut session) = pair(&store, "context.test");
    handshake(&mut client, &mut session);
    let needed = session.context_allocation_bound().unwrap();
    let small = AllocationPoolV1::new(needed - 1).unwrap();
    assert!(session
        .request_context_with_pool(7, IngressClass::ExternalNetwork, Some(&small))
        .is_err());
    assert_eq!(small.used(), 0);
    for limit in [needed, needed + 1] {
        let pool = AllocationPoolV1::new(limit).unwrap();
        let context = session
            .request_context_with_pool(7, IngressClass::ExternalNetwork, Some(&pool))
            .unwrap();
        assert_eq!(context.connection_id, 7);
        assert_eq!(context.server_name.as_deref(), Some("context.test"));
        assert_eq!(context.local_cert_der, session.local_cert_der());
        assert_eq!(context.channel_binder, session.channel_binder());
        assert!(context.oidc_claims.is_none());
        assert_eq!(pool.used(), needed);
        assert!(session
            .request_context_with_pool(8, IngressClass::ExternalNetwork, Some(&pool))
            .is_err());
        assert_eq!(pool.used(), needed);
        drop(context);
        assert_eq!(pool.used(), 0);
    }
    register(&store, "context.test");
    let pool = AllocationPoolV1::new(needed).unwrap();
    assert!(session
        .request_context_with_pool(7, IngressClass::ExternalNetwork, Some(&pool))
        .is_err());
    assert!(session.channel_binder().is_none());
    assert_eq!(pool.used(), 0);
}

fn checked_pending_client_hello() {
    super::pending_client::check();
    let store = CertStore::new();
    register(&store, "a.test");
    let (mut client, mut session) = pair(&store, "a.test");
    let hello = flight(&mut client);
    let peer = b"actual-peer";
    let maximum = super::pending_client::MAX_PENDING_CLIENTHELLO
        .checked_add(enclave_os_common::channel::MAX_CHANNEL_PAYLOAD)
        .unwrap();
    let split = hello.len() / 2;
    let first = enclave_os_common::allocation::bounded_vec_capacity(split, maximum).unwrap();
    let final_size =
        enclave_os_common::allocation::bounded_vec_capacity(hello.len(), maximum).unwrap();
    let pool =
        enclave_os_common::allocation::AllocationPoolV1::new(peer.len() + first + final_size)
            .unwrap();
    let mut pending =
        super::pending_client::PendingClientHello::admitted(peer, Some(Arc::clone(&pool))).unwrap();
    pending.append(&hello[..split]).unwrap();
    pending.append(&hello[split..]).unwrap();
    assert_eq!(pending.buffered(), hello);
    session.feed_tls_bytes(pending.buffered()).unwrap();
    drop(pending);
    assert_eq!(pool.used(), 0);
    handshake(&mut client, &mut session);
    assert!(session
        .export_hctx(b"pending-client-original", &[1; 32])
        .is_ok());
    eprintln!("PENDING-CLIENT-TLS: real fragmented client flight and original handshake PASS");
}

fn checked_session_table_refusal() {
    let store = CertStore::new();
    register(&store, "a.test");
    let (mut client, mut first) = pair(&store, "a.test");
    handshake(&mut client, &mut first);
    let (mut other_client, mut rejected) = pair(&store, "a.test");
    handshake(&mut other_client, &mut rejected);
    let bytes = core::alloc::Layout::array::<(u32, RaTlsSession)>(1)
        .unwrap()
        .size();
    let pool = enclave_os_common::allocation::AllocationPoolV1::new(bytes).unwrap();
    let mut table = super::ordered_map::OrderedMap::default();
    assert!(table.insert_for_fixture(1, first, &pool).is_ok());
    let rejected = table.insert_for_fixture(2, rejected, &pool);
    let Err((id, rejected)) = rejected else {
        panic!("unpaid session admitted");
    };
    assert_eq!(id, 2);
    drop(rejected);
    assert!(!table.contains_key(&2));
    assert!(table
        .get_mut(&1)
        .unwrap()
        .export_hctx(b"retained-session", &[1; 32])
        .is_ok());
    assert_eq!(pool.used(), bytes);
    let first = table.remove(&1).unwrap();
    assert!(
        table.insert_for_fixture(3, first, &pool).is_ok(),
        "paid empty capacity supports reuse"
    );
    assert!(table
        .get_mut(&3)
        .unwrap()
        .export_hctx(b"reused-slot", &[1; 32])
        .is_ok());
    drop(table);
    assert_eq!(pool.used(), 0);
    eprintln!("SESSION-MAP-TLS: real rejected session leaves original live authority intact and paid slot reusable PASS");
}

fn checked_connection_metadata_tables() {
    use enclave_os_common::{
        allocation::AllocationPoolV1, channel::TcpWriteWindow, modules::IngressClass,
    };
    let class_bytes = core::alloc::Layout::array::<(u32, IngressClass)>(1)
        .unwrap()
        .size();
    let window_bytes = core::alloc::Layout::array::<(u32, TcpWriteWindow)>(1)
        .unwrap()
        .size();
    let pool = AllocationPoolV1::new(class_bytes + window_bytes).unwrap();
    let mut classes = super::ordered_map::OrderedMap::default();
    let mut windows = super::ordered_map::OrderedMap::default();
    assert!(classes
        .insert_for_fixture(1, IngressClass::ExternalNetwork, &pool)
        .is_ok());
    assert!(windows
        .insert_for_fixture(1, TcpWriteWindow::default(), &pool)
        .is_ok());
    let before = windows.get(&1).unwrap().available();
    assert!(classes
        .insert_for_fixture(2, IngressClass::LocalControl, &pool)
        .is_err());
    assert_eq!(classes.get(&1), Some(&IngressClass::ExternalNetwork));
    assert_eq!(windows.get(&1).unwrap().available(), before);
    assert!(!classes.contains_key(&2));
    assert!(!windows.contains_key(&2));
    drop(classes);
    assert_eq!(pool.used(), window_bytes);
    drop(windows);
    assert_eq!(pool.used(), 0);
    eprintln!("CONNECTION-METADATA-PAID: actual class/window layout refusal preserves original retained entry PASS");
}

fn checked_fixed_channel_binder() {
    let store = CertStore::new();
    register(&store, "a.test");
    let (mut client, mut session) = pair(&store, "a.test");
    assert!(session.channel_binder_bytes().is_none());
    assert!(
        session.channel_binder_cache.get().is_none(),
        "incomplete handshake not memoized"
    );
    handshake(&mut client, &mut session);
    let expected = session
        .export_hctx(b"EXPORTER-honest-peer-channel-v2", &[])
        .unwrap();
    assert_eq!(session.channel_binder_bytes(), Some(expected));
    assert_eq!(session.channel_binder_cache.get(), Some(&expected));
    assert_eq!(session.channel_binder_bytes(), Some(expected));
    assert_eq!(session.channel_binder().unwrap(), expected);
    register(&store, "a.test");
    assert!(
        session.channel_binder_bytes().is_none(),
        "cache never bypasses currentness"
    );
    assert!(session.channel_binder().is_none());
    let (mut fresh_client, mut fresh) = pair(&store, "a.test");
    assert!(fresh.channel_binder_bytes().is_none());
    handshake(&mut fresh_client, &mut fresh);
    assert!(fresh.channel_binder_bytes().is_some());
    assert_ne!(
        fresh.channel_binder_bytes(),
        Some(expected),
        "new connection has its own exporter"
    );
    eprintln!("CHANNEL-BINDER-FIXED: genuine handshake success-only cache, original exporter equality, replacement refusal PASS");
}

// Same genuine certificate store, rustls handshake and original currentness
// boundary, with the production paid constructor and no new test identity.
fn checked_retained_certificate() {
    let store = CertStore::new();
    register(&store, "paid.test");
    let (mut client, mut session, pool) = pair_with_certificate(&store, "paid.test");
    let alias = session.local_cert_der.clone();
    let charged = pool.used();
    assert!(charged > alias.bytes().len());
    handshake(&mut client, &mut session);
    assert_eq!(session.local_cert_der_ref(), alias.bytes());
    assert!(session.export_hctx(b"paid-test", &[1; 32]).is_ok());
    assert_eq!(pool.used(), charged);
    register(&store, "paid.test");
    assert!(session.feed_tls_bytes(&[]).is_err());
    assert!(session.attestation_failed());
    assert_eq!(pool.used(), charged);
    drop(session);
    assert_eq!(pool.used(), charged);
    assert!(!alias.bytes().is_empty());
    drop(alias);
    assert_eq!(pool.used(), 0);
}

fn checked_retained_evidence() {
    use super::retained_evidence::{EvidenceRef, RetainedEvidence};
    use enclave_os_common::allocation::{AllocationPoolV1, SharedAllocationV1};
    let value = EvidenceRef {
        tee: "sgx",
        quote: b"original-evidence",
        gpu_evidence: Some(b"gpu"),
        quote_time: "2026-09-08T10:00Z",
        context: Some([1; 32]),
        hctx: Some([2; 32]),
    };
    let required =
        SharedAllocationV1::<PeerEvidence>::required_bytes(value.children_bytes().unwrap())
            .unwrap();
    let short = AllocationPoolV1::new(required - 1).unwrap();
    assert!(RetainedEvidence::copy_from(&short, &value).is_none());
    assert_eq!(short.used(), 0);
    for maximum in [required, required + 1] {
        let pool = AllocationPoolV1::new(maximum).unwrap();
        let held = RetainedEvidence::copy_from(&pool, &value).unwrap();
        assert_eq!(pool.used(), required);
        assert_eq!(held.evidence().quote, value.quote);
        assert_eq!(held.evidence().quote_time, value.quote_time);
        assert_eq!(held.evidence().tee, value.tee);
        assert_eq!(held.evidence().gpu_evidence.as_deref(), value.gpu_evidence);
        assert_eq!(held.evidence().context, value.context);
        assert_eq!(held.evidence().hctx, value.hctx);
        let store = CertStore::new();
        register(&store, "a.test");
        let (mut client, mut session) = pair(&store, "a.test");
        handshake(&mut client, &mut session);
        session.set_local_evidence(held.clone());
        session.set_peer_evidence(held.clone());
        assert_eq!(pool.used(), required);
        assert_eq!(session.local_evidence().unwrap().quote, value.quote);
        assert_eq!(session.peer_evidence().unwrap().quote, value.quote);
        register(&store, "a.test");
        assert!(session.local_evidence().is_none());
        assert!(session.peer_evidence().is_none());
        session.begin_attestation();
        drop(session);
        assert_eq!(pool.used(), required);
        drop(held);
        assert_eq!(pool.used(), 0);
    }
    let empty = EvidenceRef {
        tee: "",
        quote: &[],
        gpu_evidence: Some(&[]),
        quote_time: "",
        context: None,
        hctx: None,
    };
    let required = SharedAllocationV1::<PeerEvidence>::required_bytes(0).unwrap();
    let pool = AllocationPoolV1::new(required).unwrap();
    let held = RetainedEvidence::copy_from(&pool, &empty).unwrap();
    assert_eq!(pool.used(), required);
    assert_eq!(held.evidence().gpu_evidence.as_deref(), Some(&[][..]));
    drop(held);
    assert_eq!(pool.used(), 0);
}

fn checked_paid_quote_time() {
    use enclave_os_common::allocation::{AllocationPoolV1, SharedAllocationV1};
    for unix in [0, -1, -60, 59, 60, 1_788_523_200, 253_402_300_800] {
        let expected = enclave_os_common::attest::format_quote_time(unix);
        let required = SharedAllocationV1::<String>::required_bytes(expected.len()).unwrap();
        let short = AllocationPoolV1::new(required - 1).unwrap();
        assert!(super::quote_time::QuoteTime::new(&short, unix).is_none());
        assert_eq!(short.used(), 0);
        for maximum in [required, required + 1] {
            let pool = AllocationPoolV1::new(maximum).unwrap();
            let value = super::quote_time::QuoteTime::new(&pool, unix).unwrap();
            assert_eq!(value.text(), expected);
            assert_eq!(pool.used(), required);
            let alias = value.clone();
            drop(value);
            assert_eq!(alias.text(), expected);
            assert_eq!(pool.used(), required);
            drop(alias);
            assert_eq!(pool.used(), 0);
        }
    }
}

// A plaintext policy cannot promise that existing encrypted records will fit.
// Exercise the actual TLS writer and retain the hard output refusal.
fn checked_response_step_policy() {
    use enclave_os_common::allocation::AllocationPoolV1;
    assert_eq!(super::TLS_RESPONSE_PLAINTEXT_STEP_BYTES, 60 * 1024);
    let store = CertStore::new();
    register(&store, "step.test");
    let (mut client, mut session) = pair(&store, "step.test");
    handshake(&mut client, &mut session);
    let pending = vec![7; super::TLS_RESPONSE_STEP_HEADROOM_BYTES * 2];
    session.tls_conn.writer().write_all(&pending).unwrap();
    let encrypted = session.collect_tls_output().unwrap();
    assert!(encrypted.len() > pending.len());
    let pool = AllocationPoolV1::new(encrypted.len()).unwrap();
    let mut exact = TlsOutput::bounded(encrypted.len());
    exact.append_admitted(&encrypted, Some(&pool)).unwrap();
    assert_eq!(exact.as_ref(), encrypted.as_ref());
    assert!(exact.append_admitted(&[0], Some(&pool)).is_err());
    assert_eq!(exact.as_ref(), encrypted.as_ref());
    assert_eq!(pool.used(), encrypted.len());
    drop(exact);
    assert_eq!(pool.used(), 0);

    // Keep actual encrypted records pending alongside the next HTTP step.
    session.tls_conn.writer().write_all(&pending).unwrap();
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let body = owned_body(vec![9; super::TLS_RESPONSE_PLAINTEXT_STEP_BYTES], &drops);
    session
        .queue_http_response_owned(200, "application/json", &[], body, false, false)
        .continue_value()
        .unwrap();
    assert!(session.progress_http_response().is_err());
    assert!(!session.has_pending_response());
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
}

// The same genuine TLS fixture exercises the opaque top-level config owner.
fn checked_retained_tls_config() {
    #[cfg(feature = "fallible-allocation-v1")]
    retained_cache_checks::check();
    use super::retained_tls_config::RetainedTlsConfig;
    let authentication = super::retained_tls_config::ClientAuthentication::Anonymous;
    let needed = RetainedTlsConfig::required_bytes(authentication).unwrap();
    for extra in [-1_isize, 0, 1] {
        let pool = enclave_os_common::allocation::AllocationPoolV1::new(
            needed.checked_add_signed(extra).unwrap(),
        )
        .unwrap();
        let reserved = RetainedTlsConfig::reserve(&pool, authentication);
        assert_eq!(reserved.is_some(), extra >= 0);
        drop(reserved);
        assert_eq!(pool.used(), 0);
    }
    for extra in [0, 1] {
        let store = CertStore::new();
        register(&store, "config-paid.test");
        let (mut client, mut session, cert_pool, config_pool) =
            pair_with_all_pools(&store, "config-paid.test", extra);
        assert_eq!(config_pool.used(), needed);
        // A real Session and a cached-style alias share one original payer.
        let alias = session.tls_conn.alias();
        handshake(&mut client, &mut session);
        assert_eq!(config_pool.used(), needed);
        register(&store, "config-paid.test");
        assert!(session.feed_tls_bytes(&[]).is_err());
        drop(session);
        assert_eq!(cert_pool.used(), 0);
        assert_eq!(config_pool.used(), needed);
        drop(alias);
        assert_eq!(config_pool.used(), 0);
    }
}

#[cfg(feature = "fallible-allocation-v1")]
mod retained_cache_checks {
    use rustls::server::{ServerSessionMemoryCache, StoresServerSessions};
    use std::alloc::{AllocError, Allocator, Global, Layout};
    use std::ptr::NonNull;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    #[derive(Default)]
    struct Counts {
        live: AtomicUsize,
        calls: AtomicUsize,
        frees: AtomicUsize,
        refuse: AtomicUsize,
    }
    #[derive(Clone)]
    struct Original(Arc<Counts>);
    unsafe impl Allocator for Original {
        fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
            let call = self.0.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call == self.0.refuse.load(Ordering::SeqCst) {
                return Err(AllocError);
            }
            let block = Global.allocate(layout)?;
            self.0.live.fetch_add(layout.size(), Ordering::SeqCst);
            Ok(block)
        }
        unsafe fn deallocate(&self, pointer: NonNull<u8>, layout: Layout) {
            unsafe { Global.deallocate(pointer, layout) };
            self.0.live.fetch_sub(layout.size(), Ordering::SeqCst);
            self.0.frees.fetch_add(1, Ordering::SeqCst);
        }
    }
    pub(super) fn check() {
        memory_cache();
        compression_cache();
    }
    fn memory_cache() {
        for refusal in 1..=2 {
            let counts = Arc::new(Counts::default());
            counts.refuse.store(refusal, Ordering::SeqCst);
            let result = ServerSessionMemoryCache::try_new_in(256, Original(counts.clone()));
            assert!(result.is_err());
            assert_eq!(counts.calls.load(Ordering::SeqCst), refusal);
            assert_eq!(counts.live.load(Ordering::SeqCst), 0);
            assert_eq!(Arc::strong_count(&counts), 1);
        }
        let counts = Arc::new(Counts::default());
        let allocator = Original(counts.clone());
        let cache = ServerSessionMemoryCache::try_new_in(2, allocator.clone()).unwrap();
        let ordinary = ServerSessionMemoryCache::new(2);
        for key in 0..6 {
            assert_eq!(
                cache.put(vec![key], vec![key + 10]),
                ordinary.put(vec![key], vec![key + 10])
            );
            for seen in 0..=key {
                assert_eq!(
                    cache.get(&[seen]).as_deref(),
                    ordinary.get(&[seen]).as_deref()
                );
            }
        }
        for key in 0..6 {
            assert_eq!(
                cache.take(&[key]).as_deref(),
                ordinary.take(&[key]).as_deref()
            );
        }
        let alias = cache.clone();
        assert!(cache.put(vec![77], vec![88, 89]));
        let retained_get = cache.get(&[77]).unwrap();
        let retained_take = cache.take(&[77]).unwrap();
        assert!(
            cache.take(&[77]).is_none(),
            "take removes the only stored value"
        );
        drop(allocator);
        drop(cache);
        assert!(counts.live.load(Ordering::SeqCst) > 0);
        std::thread::spawn(move || drop(alias)).join().unwrap();
        assert_eq!(retained_get.as_slice(), &[88, 89]);
        assert_eq!(retained_take.as_slice(), &[88, 89]);
        assert_eq!(
            counts.live.load(Ordering::SeqCst),
            4,
            "only returned byte backings remain"
        );
        drop(retained_get);
        std::thread::spawn(move || drop(retained_take))
            .join()
            .unwrap();
        assert_eq!(counts.live.load(Ordering::SeqCst), 0);
        assert_eq!(Arc::strong_count(&counts), 1);
        refused_entry_bytes();
    }
    fn refused_entry_bytes() {
        for refusal in 1..=3 {
            let counts = Arc::new(Counts::default());
            let cache = ServerSessionMemoryCache::try_new_in(8, Original(counts.clone())).unwrap();
            assert!(cache.put(vec![1], vec![10]));
            let baseline = counts.live.load(Ordering::SeqCst);
            let next = counts.calls.load(Ordering::SeqCst);
            counts.refuse.store(next + refusal, Ordering::SeqCst);
            assert!(!cache.put(vec![2], vec![20]));
            assert_eq!(counts.live.load(Ordering::SeqCst), baseline);
            assert!(cache.get(&[2]).is_none());
            assert_eq!(cache.get(&[1]).unwrap().as_slice(), &[10]);
            counts
                .refuse
                .store(counts.calls.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
            assert!(
                cache.get(&[1]).is_none(),
                "copy refusal does not expose unpaid bytes"
            );
            assert_eq!(cache.take(&[1]).unwrap().as_slice(), &[10]);
            drop(cache);
            assert_eq!(counts.live.load(Ordering::SeqCst), 0);
            assert_eq!(Arc::strong_count(&counts), 1);
        }
    }
    fn compression_cache() {
        for refusal in 1..=1 {
            let counts = Arc::new(Counts::default());
            counts.refuse.store(refusal, Ordering::SeqCst);
            let result =
                rustls::compress::CompressionCache::try_new_in(4, Original(counts.clone()));
            assert!(result.is_err());
            assert_eq!(counts.calls.load(Ordering::SeqCst), refusal);
            assert_eq!(counts.live.load(Ordering::SeqCst), 0);
            assert_eq!(Arc::strong_count(&counts), 1);
        }
        let counts = Arc::new(Counts::default());
        let allocator = Original(counts.clone());
        let cache = rustls::compress::CompressionCache::try_new_in(4, allocator.clone()).unwrap();
        assert!(matches!(
            cache,
            rustls::compress::CompressionCache::Enabled(_)
        ));
        drop(allocator);
        assert!(counts.live.load(Ordering::SeqCst) > 0);
        drop(cache);
        assert_eq!(counts.live.load(Ordering::SeqCst), 0);
        assert_eq!(Arc::strong_count(&counts), 1);
    }
}
