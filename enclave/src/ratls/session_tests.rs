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
    streamed_request_preserves_tls_and_following_request();
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
    fixed_peer_configuration_boundary();
    #[cfg(feature="native-deferred-fixture")]
    crate::actual_control_wake::check();
    #[cfg(feature="native-deferred-fixture")]
    crate::actual_workflow_budget::check_continuation_for_native();
    #[cfg(feature="native-deferred-fixture")]
    crate::deferred_ingress::check_pending_for_native();
    #[cfg(feature="native-deferred-fixture")]
    crate::actual_deferred_selector::check_selector_for_native();
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let owner_drop_count = || drops.load(std::sync::atomic::Ordering::SeqCst);
    let store = CertStore::new();
    register(&store, "a.test");
    register(&store, "b.test");
    let (mut a_client, mut a) = pair(&store, "a.test");
    let (mut b_client, mut b) = pair(&store, "b.test");
    assert!(!super::current_data_session(None));
    assert!(!super::current_data_session(Some(&mut a)), "handshake has no current data binding");
    handshake(&mut a_client, &mut a);
    handshake(&mut b_client, &mut b);
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
    assert!(!super::current_data_session(Some(&mut a)), "revocation keeps control work on the full path");
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
    let failed_owner = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (reason, returned) = b.queue_http_response_owned(200, "application/json", &[],
        owned_body(vec![9; 7], &failed_owner), false, false).err().unwrap();
    assert_eq!(reason, "response already pending");
    assert_eq!(returned.len(), 7);
    assert_eq!(failed_owner.load(std::sync::atomic::Ordering::SeqCst), 0,
        "failed queue returns body ownership to the outside-STATE caller");
    drop(returned);
    assert_eq!(failed_owner.load(std::sync::atomic::Ordering::SeqCst), 1);
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
    let mut response_steps = 0usize;
    let mut window = enclave_os_common::channel::TcpWriteWindow::default();
    assert_eq!(super::response_credit(&[0; 7], Some(&mut window), Some(&b)), (false, false));
    assert_eq!(super::response_credit(&0u64.to_le_bytes(), None, Some(&b)), (false, false), "absent/foreign window cannot classify as cheap");
    assert!(window.send(17));
    assert_eq!(super::response_credit(&17u64.to_le_bytes(), Some(&mut window), None), (true, false), "absent/handshaking session stays full");
    let mut sent = 17u64;
    while b.has_pending_response() {
        response_steps += 1;
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
    assert_eq!(response_steps, expected.len().div_ceil(60 * 1024), "actual admitted TLS flights use the larger bounded plaintext quantum");
    assert!(response_steps < expected.len().div_ceil(32 * 1024));
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
    assert_eq!(session.recv_http_request().unwrap().unwrap().path, "/second");
    assert_eq!(session.export_hctx(b"fixed-peer-test", &[]).unwrap(), binder);

    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let body: Vec<_> = (0..256 * 1024).map(|n| (n % 251) as u8).collect();
    let expected = enclave_os_common::protocol::format_http_response(200, &body, false);
    session.queue_http_response(200, "application/json", &[], owned_body(body, &drops), false, false).unwrap();
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
    assert_eq!(actual, expected, "unrelated endpoint churn preserves exact partial peer response");
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);

    session.queue_http_response(200, "application/json", &[], owned_body(vec![7; 256 * 1024], &drops), false, false).unwrap();
    let (bytes, _, _) = session.progress_http_response().unwrap();
    assert!(!bytes.is_empty() && session.has_pending_response());
    store.invalidate(name);
    assert!(session.progress_http_response().is_err());
    assert!(!session.has_pending_response());
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 2, "explicit peer revocation releases remaining body ownership once");
    assert!(session.export_hctx(b"fixed-peer-test", &[]).is_err());
    assert!(session.recv_http_request().is_err());
    let (mut replacement_client, mut replacement) = pair(&store, name);
    handshake(&mut replacement_client, &mut replacement);
    assert!(replacement.export_hctx(b"fixed-peer-test", &[]).is_ok());
    assert!(session.export_hctx(b"fixed-peer-test", &[]).is_err(), "replacement cannot resurrect old peer session");
}

// Actual Rustls + production session buffer/header/fragment methods. This
// proves TLS delivery and extraction, not SGX quote or BFT source authority.
fn streamed_request_preserves_tls_and_following_request() {
    crate::stream_ingress::check_slot_ownership();
    streamed_input_alternating_cap_refill();
    let store=CertStore::new();register(&store,"stream.test");
    let(mut client,mut session)=pair(&store,"stream.test");handshake(&mut client,&mut session);
    let binding=session.channel_binder().unwrap();
    let body=vec![0xa7;128*1024+17];
    let head=format!("POST /honest/v1/proposal HTTP/1.1\r\nHost: stream.test\r\nContent-Type: application/honest-source-upload-batch-v2\r\nContent-Length: {}\r\n\r\n",body.len());
    write_requests(&mut client,&mut session,head.as_bytes());
    let(header,head_bytes,length)=session.stream_head().unwrap().unwrap();
    assert!(header.body.is_empty());assert_eq!(length,body.len());assert!(session.validate_stream_head());
    session.consume_stream_head(head_bytes).unwrap();
    let context=enclave_os_common::modules::RequestContext{
        ingress_class:enclave_os_common::modules::IngressClass::ExternalNetwork,connection_id:7,
        server_name:Some("stream.test".into()),attested_endpoint:None,
        local_cert_der:session.local_cert_der(),local_evidence:None,
        channel_binder:Some(binding.clone()),peer_cert_der:None,peer_evidence:None,
        attestation:session.attestation().into(),oidc_claims:None,
    };
    let mut work=crate::stream_ingress::Work{lease:crate::stream_ingress::SlotCharge::reserve().unwrap(),connection:7,nonce:1,generation:1,binding:binding.as_slice().try_into().unwrap(),context:Some(context),context_charge:None,header:Some(header),receiver:None,bytes:vec![],length,remaining:length,pending:false};
    assert!(crate::stream_ingress::run_work(fixture_begin,&mut work).is_none());
    for part in body.chunks(32*1024){write_requests(&mut client,&mut session,part);}
    write_requests(&mut client,&mut session,b"GET /next HTTP/1.1\r\nHost: stream.test\r\n\r\n");
    let segments:Vec<_>=session.stream_chunks.as_ref().unwrap().iter().map(|(b,_)|b.as_ptr()).collect();
    let mut alternating=0;
    let mut actual=Vec::new();
    while actual.len()<length {
        let part=session.stream_fragment((length-actual.len()).min(64*1024));
        assert!(!part.is_empty() && part.len()<=64*1024);actual.extend_from_slice(&part);
        for (bytes,_) in session.stream_chunks.as_ref().unwrap(){assert!(segments.contains(&bytes.as_ptr()),"existing backlog segment never moves on extraction");}
        alternating+=1;
        work.remaining-=part.len();work.bytes=part;
        let result=crate::stream_ingress::run_work(fixture_begin,&mut work);
        if work.remaining==0 {assert_eq!(&*result.unwrap().body,body.as_slice());}
        else {assert!(result.is_none());}
    }
    assert_eq!(actual,body);assert_eq!(session.channel_binder().unwrap(),binding);
    assert!(alternating>=3);session.finish_stream_input().unwrap();
    assert_eq!(session.recv_http_request().unwrap().unwrap().path,"/next");
    // Actual TLS fragment + shared production pending-accounting seam. The
    // receiver is a data-only facade; no Main ticket/custody is manufactured.
    session.consume_stream_head(0).unwrap();
    for _ in 0..2{write_requests(&mut client,&mut session,&vec![0x7a;32*1024]);}
    work.bytes=session.stream_fragment(64*1024);assert_eq!(work.bytes.len(),64*1024);
    work.length=work.bytes.len();work.remaining=0;
    let fragment=work.bytes.as_ptr();
    let credit=Arc::new(std::sync::atomic::AtomicBool::new(false));
    let consumed=Arc::new(std::sync::atomic::AtomicUsize::new(0));
    work.receiver=Some(Box::new(PendingReceiver{binding:binding.clone(),credit:credit.clone(),consumed:consumed.clone()}));
    assert!(crate::stream_ingress::run_work(fixture_begin,&mut work).is_none());assert!(work.pending);
    let mut slot=crate::stream_ingress::Slot{lease:work.lease.clone(),nonce:work.nonce,generation:work.generation,binding:work.binding,header:None,receiver:None,remaining:64*1024,fragment:vec![],parked:false,length:64*1024,close:false,started:std::time::Instant::now()};
    work.nonce+=1;assert!(crate::stream_ingress::retain_work(&mut slot,&mut work).is_err());work.nonce-=1;
    crate::stream_ingress::retain_work(&mut slot,&mut work).unwrap();
    assert!(slot.parked);assert_eq!(slot.remaining,64*1024);assert_eq!(slot.fragment.as_ptr(),fragment);assert_eq!(consumed.load(std::sync::atomic::Ordering::Acquire),0);
    crate::stream_ingress::notify();assert!(slot.parked,"input/deadline revision cannot rearm stage-credit wait");
    credit.store(true,std::sync::atomic::Ordering::Release);crate::stream_ingress::notify_honest_stream_ingress();
    assert!(crate::stream_ingress::take_credit_ready());slot.credit_ready();
    session.require_current_configuration().unwrap();assert_eq!(session.channel_binder().unwrap(),binding);
    work.bytes=std::mem::take(&mut slot.fragment);work.receiver=slot.receiver.take().map(|r|r.value);work.remaining=0;
    let response=crate::stream_ingress::run_work(fixture_begin,&mut work).unwrap();
    assert!(!work.pending);assert_eq!(response.status,202);assert_eq!(consumed.load(std::sync::atomic::Ordering::Acquire),64*1024);
    assert!(work.receiver.is_none());assert_eq!(work.bytes.as_ptr(),fragment);drop(slot);session.finish_stream_input().unwrap();
    println!("HONEST-STREAM-PENDING exact-fragment=65536 pending-offset-unchanged=PASS actual-credit-resume=PASS consume-once-eof=PASS stale-nonce-denied=PASS");

    let(mut other_client,mut other)=pair(&store,"stream.test");
    assert!(other.channel_binder().is_none());handshake(&mut other_client,&mut other);
    assert_ne!(other.channel_binder().unwrap(),binding,"a replacement connection cannot borrow the active stream exporter");
    let head=b"POST /honest/v1/proposal HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n";
    write_requests(&mut client,&mut session,head);
    assert!(session.stream_head().unwrap().is_some());assert!(!session.validate_stream_head());
    assert!(store.unregister("stream.test"));
    assert!(session.stream_head().is_err());assert!(session.attestation_failed());
}

struct FixtureReceiver {bytes:Vec<u8>,binding:Vec<u8>}
impl crate::HonestStreamIngressReceiver for FixtureReceiver {
    fn push(&mut self,bytes:&[u8],context:&enclave_os_common::modules::RequestContext)->Result<(),()> {
        if context.channel_binder.as_ref()!=Some(&self.binding){return Err(());}
        self.bytes.extend_from_slice(bytes);Ok(())
    }
    fn finish(self:Box<Self>,context:&enclave_os_common::modules::RequestContext)->crate::HonestIngressResponse {
        assert_eq!(context.channel_binder.as_ref(),Some(&self.binding));
        crate::HonestIngressResponse{status:202,content_type:"application/octet-stream",body:self.bytes.into()}
    }
}
fn fixture_begin(request:&enclave_os_common::protocol::HttpRequest,length:usize,context:&enclave_os_common::modules::RequestContext)->Result<Box<dyn crate::HonestStreamIngressReceiver>,crate::HonestIngressResponse> {
    assert!(request.body.is_empty());assert_eq!(length,128*1024+17);
    Ok(Box::new(FixtureReceiver{bytes:Vec::new(),binding:context.channel_binder.clone().unwrap()}))
}

// Exercise actual TLS plaintext draining at the original input ceiling, then
// alternate a bounded extraction and TLS refill. Existing unread segments
// retain their allocation and content; no large suffix is compacted.
fn streamed_input_alternating_cap_refill() {
    let store=CertStore::new();register(&store,"stream-cap.test");
    let(mut client,mut session)=pair(&store,"stream-cap.test");handshake(&mut client,&mut session);
    session.consume_stream_head(0).unwrap();
    let frame=vec![0x5a;crate::MAX_STREAM_INGRESS_FRAGMENT];
    for _ in 0..enclave_os_common::protocol::MAX_BODY_SIZE/frame.len() {
        for piece in frame.chunks(32*1024){write_requests(&mut client,&mut session,piece);}
    }
    for _ in 0..8 {
        let old:Vec<_>=session.stream_chunks.as_ref().unwrap().iter().skip(1).map(|(b,_)|b.as_ptr()).collect();
        assert_eq!(session.stream_fragment(frame.len()),frame);
        for piece in frame.chunks(32*1024){write_requests(&mut client,&mut session,piece);}
        let queue=session.stream_chunks.as_ref().unwrap();
        assert_eq!(queue.iter().map(|(b,o)|b.len()-o).sum::<usize>(),enclave_os_common::protocol::MAX_BODY_SIZE);
        assert!(queue.iter().map(|(b,_)|b.capacity()).sum::<usize>()<=enclave_os_common::protocol::MAX_BODY_SIZE+frame.len());
        assert_eq!(queue.iter().take(old.len()).map(|(b,_)|b.as_ptr()).collect::<Vec<_>>(),old,"cap/refill does not move the unread suffix");
    }
    // The old growable Vec can retain32MiB capacity. Reuse its already
    // reserved parser/copy allowance without pretending capacity equals len.
    session.stream_chunks=None;
    session.read_buf=Vec::with_capacity((enclave_os_common::protocol::MAX_BODY_SIZE+64*1024).next_power_of_two());
    session.read_buf.extend_from_slice(&frame);let inherited=session.read_buf.as_ptr();
    session.consume_stream_head(0).unwrap();
    assert_eq!(session.stream_fragment(frame.len()/2),frame[..frame.len()/2]);
    write_requests(&mut client,&mut session,&frame[..frame.len()/2]);
    let chunks=session.stream_chunks.as_ref().unwrap();
    assert_eq!(chunks.front().unwrap().0.as_ptr(),inherited);
    assert!(chunks.iter().map(|(b,_)|b.capacity()).sum::<usize>()<=RaTlsSession::STREAM_INPUT_CAPACITY);
    assert_eq!(session.stream_fragment(frame.len()),frame);
    // Terminal reuse: a tiny consumed prefix may leave a large allocation.
    // Completing it must preserve that allocation, not allocate another32MiB.
    session.read_buf=Vec::with_capacity((enclave_os_common::protocol::MAX_BODY_SIZE+64*1024).next_power_of_two());
    session.read_buf.push(b'x');
    for _ in 0..enclave_os_common::protocol::MAX_BODY_SIZE/frame.len()+1{session.read_buf.extend_from_slice(&frame);}
    let original=session.read_buf.as_ptr();session.consume_stream_head(1).unwrap();
    session.finish_stream_input().unwrap();assert_eq!(session.read_buf.as_ptr(),original);
    assert_eq!(session.read_buf.len(),enclave_os_common::protocol::MAX_BODY_SIZE+frame.len());
    session.read_buf.clear();session.read_buf.extend_from_slice(b"GET /tail HTTP/1.1\r\n\r\n");
    assert_eq!(session.recv_http_request().unwrap().unwrap().path,"/tail");

    println!("HONEST-STREAM-INGRESS-CAP-REFILL original-bound=16777216 fragment=65536 rounds=8");
}

struct PendingReceiver{binding:Vec<u8>,credit:Arc<std::sync::atomic::AtomicBool>,consumed:Arc<std::sync::atomic::AtomicUsize>}
impl crate::HonestStreamIngressReceiver for PendingReceiver{
    fn push(&mut self,_:&[u8],_:&enclave_os_common::modules::RequestContext)->Result<(),()>{unreachable!()}
    fn push_with_backpressure(&mut self,bytes:&[u8],context:&enclave_os_common::modules::RequestContext)->Result<crate::stream_ingress::HonestStreamIngressPush,()>{
        if context.channel_binder.as_ref()!=Some(&self.binding){return Err(());}
        if !self.credit.load(std::sync::atomic::Ordering::Acquire){return Ok(crate::stream_ingress::HonestStreamIngressPush::Pending);}
        assert!(bytes.iter().all(|b|*b==0x7a));self.consumed.fetch_add(bytes.len(),std::sync::atomic::Ordering::AcqRel);
        Ok(crate::stream_ingress::HonestStreamIngressPush::Consumed)
    }
    fn finish(self:Box<Self>,_:&enclave_os_common::modules::RequestContext)->crate::HonestIngressResponse{
        crate::HonestIngressResponse{status:202,content_type:"application/octet-stream",body:vec![].into()}
    }
}
