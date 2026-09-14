// Copyright (c) 2026 Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

//! Real loopback TLS checks extend the existing injected-transport test identity.
use crate::{
    https_fetch_authorized_interruptible_detailed, root_store_from_der,
    verify_webpki_server_certificate_chain_at, BoundedHttpsRequest, HttpsFetchFailurePhase,
    InterruptibleBlockingNetIo,
};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

struct Wire {
    port: u16,
    stream: Option<TcpStream>,
    closed: bool,
}
impl InterruptibleBlockingNetIo for Wire {
    fn tcp_connect(&mut self, host: &str, port: u16) -> Result<i32, i32> {
        assert_eq!(host, "authorized.test");
        assert_eq!(port, self.port);
        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).map_err(|_| -1)?;
        configure(&stream);
        self.stream = Some(stream);
        Ok(1)
    }
    fn send(&mut self, fd: i32, bytes: &[u8]) -> Result<usize, i32> {
        assert_eq!(fd, 1);
        self.stream
            .as_mut()
            .unwrap()
            .write(&bytes[..bytes.len().min(257)])
            .map_err(|_| -1)
    }
    fn recv(&mut self, fd: i32, out: &mut [u8]) -> Result<usize, i32> {
        assert_eq!(fd, 1);
        let count = out.len().min(73);
        self.stream
            .as_mut()
            .unwrap()
            .read(&mut out[..count])
            .map_err(|_| -1)
    }
    fn close(&mut self, fd: i32) {
        assert_eq!(fd, 1);
        self.stream.take();
        self.closed = true;
    }
}
fn configure(stream: &TcpStream) {
    stream.set_nodelay(true).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
}

pub(super) fn check_authorization_boundary() {
    let certified = rcgen::generate_simple_self_signed(vec!["authorized.test".into()]).unwrap();
    let cert = certified.cert.der().to_vec();
    let roots = root_store_from_der([cert.clone()]).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certified.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()).into(),
    )
    .unwrap();
    let config = Arc::new(config);
    // Valid current certificate, explicit authority denial, committed time before
    // the certificate existed, and connection loss after a real request write.
    for scenario in 0..4 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_config = Arc::clone(&config);
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            configure(&socket);
            let connection = rustls::ServerConnection::new(server_config).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            let mut request = Vec::new();
            let mut bytes = [0; 1024];
            loop {
                match stream.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(n) => request.extend_from_slice(&bytes[..n]),
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(error) => panic!("loopback TLS server: {error}"),
                }
                if request.ends_with(b"protected output") {
                    if scenario == 0 {
                        stream
                            .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
                            .unwrap();
                        stream.conn.send_close_notify();
                        stream.flush().unwrap();
                    }
                    break;
                }
            }
            request
        });
        let request = BoundedHttpsRequest::new(
            "PUT",
            format!("https://authorized.test:{port}/object"),
            vec![],
            Some(b"protected output".to_vec()),
        )
        .unwrap();
        let mut wire = Wire {
            port,
            stream: None,
            closed: false,
        };
        let mut calls = 0;
        let result = https_fetch_authorized_interruptible_detailed(
            &mut wire,
            &request,
            &roots,
            None,
            &mut |chain| {
                calls += 1;
                assert_eq!(chain.certificates_der(), std::slice::from_ref(&cert));
                if scenario == 1 {
                    return Err("private authority retired".into());
                }
                verify_webpki_server_certificate_chain_at(
                    chain.certificates_der(),
                    "authorized.test",
                    &roots,
                    if scenario == 2 { 0 } else { 1_800_000_000 },
                )
            },
        );
        let received = server.join().unwrap();
        assert!(wire.closed);
        assert_eq!(calls, 1);
        match scenario {
            0 => {
                assert_eq!(result.unwrap().status, 201);
                assert!(received.ends_with(b"protected output"));
            }
            1 | 2 => {
                let error = result.unwrap_err();
                assert_eq!(
                    error.phase,
                    HttpsFetchFailurePhase::PeerVerificationBeforeDispatch
                );
                assert!(!error.request_may_have_been_dispatched());
                assert!(received.is_empty(), "denial must precede even HTTP headers");
            }
            3 => {
                let error = result.unwrap_err();
                assert!(error.request_may_have_been_dispatched());
                assert_eq!(
                    error.tls_peer_chain().unwrap().certificates_der(),
                    std::slice::from_ref(&cert)
                );
                assert!(received.ends_with(b"protected output"));
            }
            _ => unreachable!(),
        }
    }
}
