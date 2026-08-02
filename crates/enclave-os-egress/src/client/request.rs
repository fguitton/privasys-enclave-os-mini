// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Bounded full-response HTTPS over an explicitly injected network capability.

use std::io::{Read, Write};
use std::string::String;
use std::sync::Arc;
use std::vec::Vec;

use enclave_os_common::ocall;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};

use super::{build_client_config, verify_channel_binding, RaTlsPolicy};

type ParsedHttpResponse = (u16, Vec<(String, String)>, Vec<u8>);

/// Maximum HTTP response body size (2 MiB).
pub const MAX_RESPONSE_BODY: usize = 2 * 1024 * 1024;

/// Maximum request body accepted by the injected full-response client.
pub const MAX_REQUEST_BODY: usize = 2 * 1024 * 1024;

/// Maximum caller-supplied HTTP headers accepted by the injected client.
pub const MAX_REQUEST_HEADERS: usize = 64;

/// Maximum combined caller-supplied header bytes.
pub const MAX_REQUEST_HEADER_BYTES: usize = 16 * 1024;

/// A parsed HTTP response with status code, headers, and body.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Explicit network capability injected by a role-owning composition.
///
/// The trait has no global lookup and intentionally mirrors only the bounded
/// TCP operations required by the HTTPS client. Implementations are expected
/// to make every call fence-aware and interruptible.
pub trait InterruptibleBlockingNetIo {
    fn tcp_connect(&mut self, host: &str, port: u16) -> Result<i32, i32>;
    fn send(&mut self, fd: i32, bytes: &[u8]) -> Result<usize, i32>;
    fn recv(&mut self, fd: i32, out: &mut [u8]) -> Result<usize, i32>;
    fn close(&mut self, fd: i32);
}

/// Validated, owned HTTPS request for the injected-I/O path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedHttpsRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

impl BoundedHttpsRequest {
    /// Validate and own one bounded HTTPS request.
    pub fn new(
        method: impl Into<String>,
        url: impl Into<String>,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> Result<Self, String> {
        let method = method.into();
        let url = url.into();
        validate_method(&method)?;
        parse_url(&url)?;
        if headers.len() > MAX_REQUEST_HEADERS {
            return Err("too many HTTP request headers".into());
        }
        let header_bytes = headers.iter().try_fold(0usize, |total, (name, value)| {
            if name.is_empty()
                || name
                    .bytes()
                    .any(|byte| !byte.is_ascii_graphic() || byte == b':')
                || value.contains('\r')
                || value.contains('\n')
            {
                return None;
            }
            total
                .checked_add(name.len())?
                .checked_add(value.len())?
                .checked_add(4)
        });
        if header_bytes.is_none_or(|length| length > MAX_REQUEST_HEADER_BYTES) {
            return Err("invalid or oversized HTTP request headers".into());
        }
        if body
            .as_ref()
            .is_some_and(|bytes| bytes.len() > MAX_REQUEST_BODY)
        {
            return Err("HTTP request body exceeds bound".into());
        }
        Ok(Self {
            method,
            url,
            headers,
            body,
        })
    }
}

struct GlobalOcallNetIo;

impl InterruptibleBlockingNetIo for GlobalOcallNetIo {
    fn tcp_connect(&mut self, host: &str, port: u16) -> Result<i32, i32> {
        ocall::net_tcp_connect(host, port)
    }

    fn send(&mut self, fd: i32, bytes: &[u8]) -> Result<usize, i32> {
        ocall::net_send(fd, bytes)
    }

    fn recv(&mut self, fd: i32, out: &mut [u8]) -> Result<usize, i32> {
        ocall::net_recv(fd, out)
    }

    fn close(&mut self, fd: i32) {
        ocall::net_close(fd);
    }
}

/// Compatibility wrapper using the process-global OCALL vtable.
pub fn https_fetch(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    root_store: &RootCertStore,
    ratls: Option<&RaTlsPolicy>,
) -> Result<HttpResponse, String> {
    let request =
        BoundedHttpsRequest::new(method, url, headers.to_vec(), body.map(<[u8]>::to_vec))?;
    https_fetch_interruptible(&mut GlobalOcallNetIo, &request, root_store, ratls)
}

/// Perform a bounded HTTPS request using only caller-injected network I/O.
pub fn https_fetch_interruptible(
    io: &mut dyn InterruptibleBlockingNetIo,
    request: &BoundedHttpsRequest,
    root_store: &RootCertStore,
    ratls: Option<&RaTlsPolicy>,
) -> Result<HttpResponse, String> {
    let (host, port, path) = parse_url(&request.url)?;
    let mut request_head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        request.method, path, host
    );
    for (key, value) in &request.headers {
        request_head.push_str(&format!("{}: {}\r\n", key, value));
    }
    if let Some(body) = &request.body {
        if !request
            .headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        {
            request_head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
    }
    request_head.push_str("\r\n");

    let mut request_bytes = request_head.into_bytes();
    if let Some(body) = &request.body {
        request_bytes.extend_from_slice(body);
    }
    https_request_inner(io, &host, port, &request_bytes, root_store, ratls)
}

fn https_request_inner(
    io: &mut dyn InterruptibleBlockingNetIo,
    host: &str,
    port: u16,
    request: &[u8],
    root_store: &RootCertStore,
    ratls: Option<&RaTlsPolicy>,
) -> Result<HttpResponse, String> {
    let tls_config = build_client_config(root_store, ratls, None).map_err(|e| e.to_string())?;
    let fd = io
        .tcp_connect(host, port)
        .map_err(|error| format!("TCP connect failed: {error}"))?;
    let result = https_request_connected(io, fd, host, request, tls_config, ratls);
    io.close(fd);
    result
}

fn https_request_connected(
    io: &mut dyn InterruptibleBlockingNetIo,
    fd: i32,
    host: &str,
    request: &[u8],
    tls_config: Arc<ClientConfig>,
    ratls: Option<&RaTlsPolicy>,
) -> Result<HttpResponse, String> {
    let server_name =
        ServerName::try_from(host.to_string()).map_err(|_| "invalid server name".to_string())?;
    let mut tls_conn = ClientConnection::new(tls_config, server_name.to_owned())
        .map_err(|error| format!("TLS init failed: {error}"))?;

    tls_handshake(io, fd, &mut tls_conn)
        .map_err(|error| format!("TLS handshake failed: {error}"))?;
    if let Some(policy) = ratls {
        verify_channel_binding(&tls_conn, policy)?;
    }

    for chunk in request.chunks(16 * 1024) {
        tls_conn
            .writer()
            .write_all(chunk)
            .map_err(|error| format!("write failed: {error}"))?;
        flush_tls(io, fd, &mut tls_conn).map_err(|_| "flush failed".to_string())?;
    }

    let mut response_data = Vec::new();
    let mut net_buf = vec![0u8; 16384];
    let mut app_buf = vec![0u8; 16384];
    let mut body_limit_hit = false;
    tls_conn.set_buffer_limit(None);

    'outer: loop {
        match io.recv(fd, &mut net_buf) {
            Ok(0) => break,
            Ok(received) => {
                let mut cursor = std::io::Cursor::new(&net_buf[..received]);
                while (cursor.position() as usize) < received {
                    match tls_conn.read_tls(&mut cursor) {
                        Ok(0) => break,
                        Ok(_) => {
                            tls_conn
                                .process_new_packets()
                                .map_err(|error| format!("TLS error: {error:?}"))?;
                            loop {
                                match tls_conn.reader().read(&mut app_buf) {
                                    Ok(0) => break,
                                    Ok(read) => {
                                        response_data.extend_from_slice(&app_buf[..read]);
                                        if response_data.len() > MAX_RESPONSE_BODY + 16384 {
                                            body_limit_hit = true;
                                            break;
                                        }
                                    }
                                    Err(error)
                                        if error.kind() == std::io::ErrorKind::WouldBlock =>
                                    {
                                        break
                                    }
                                    Err(error) => {
                                        return Err(format!("TLS plaintext read failed: {error}"))
                                    }
                                }
                            }
                            if body_limit_hit {
                                break 'outer;
                            }
                        }
                        Err(error) => return Err(format!("read_tls error: {error:?}")),
                    }
                }
            }
            Err(error) => return Err(format!("network read failed: {error}")),
        }
    }

    tls_conn.send_close_notify();
    let _ = flush_tls(io, fd, &mut tls_conn);
    let (status, headers, mut body) = parse_http_response(&response_data)?;
    if body.len() > MAX_RESPONSE_BODY {
        body.truncate(MAX_RESPONSE_BODY);
    }
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn tls_handshake(
    io: &mut dyn InterruptibleBlockingNetIo,
    fd: i32,
    tls_conn: &mut ClientConnection,
) -> Result<(), String> {
    loop {
        flush_tls(io, fd, tls_conn).map_err(|_| String::from("flush failed"))?;
        if !tls_conn.is_handshaking() {
            return Ok(());
        }
        let mut buffer = vec![0u8; 16384];
        match io.recv(fd, &mut buffer) {
            Ok(received) if received > 0 => {
                let mut cursor = std::io::Cursor::new(&buffer[..received]);
                while (cursor.position() as usize) < received {
                    match tls_conn.read_tls(&mut cursor) {
                        Ok(0) => break,
                        Ok(_) => {
                            tls_conn
                                .process_new_packets()
                                .map_err(|error| error.to_string())?;
                        }
                        Err(error) => return Err(format!("read_tls: {error}")),
                    }
                }
            }
            Ok(_) => return Err("server closed before handshake completed".into()),
            Err(_) => return Err("network read error".into()),
        }
    }
}

fn flush_tls(
    io: &mut dyn InterruptibleBlockingNetIo,
    fd: i32,
    tls_conn: &mut ClientConnection,
) -> Result<(), i32> {
    let mut buffer = vec![0u8; 16384];
    loop {
        let mut cursor = std::io::Cursor::new(&mut buffer[..]);
        match tls_conn.write_tls(&mut cursor) {
            Ok(0) => break,
            Ok(written) => {
                let data = &buffer[..written];
                let mut offset = 0;
                while offset < data.len() {
                    match io.send(fd, &data[offset..]) {
                        Ok(0) => return Err(-1),
                        Ok(sent) => offset += sent,
                        Err(error) => return Err(error),
                    }
                }
            }
            Err(_) => return Err(-1),
        }
    }
    Ok(())
}

fn validate_method(method: &str) -> Result<(), String> {
    match method {
        "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS" => Ok(()),
        _ => Err("unsupported HTTP method".into()),
    }
}

fn parse_url(url: &str) -> Result<(String, u16, String), String> {
    let url = url.trim();
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| "only https:// URLs are supported".to_string())?;
    let (host_port, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = match host_port.rfind(':') {
        Some(index) => {
            let port = host_port[index + 1..]
                .parse()
                .map_err(|_| "invalid port".to_string())?;
            (&host_port[..index], port)
        }
        None => (host_port, 443),
    };
    if host.is_empty() {
        return Err("empty HTTPS host".into());
    }
    Ok((host.into(), port, path.into()))
}

fn parse_http_response(data: &[u8]) -> Result<ParsedHttpResponse, String> {
    let separator = data
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("invalid HTTP response: no header terminator")?;
    let header_bytes = &data[..separator];
    let raw_body = &data[separator + 4..];
    let header_text = std::str::from_utf8(header_bytes)
        .map_err(|_| "invalid HTTP response: non-UTF-8 headers")?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or("invalid HTTP response: empty")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("invalid HTTP response: no status")?
        .parse()
        .map_err(|_| "invalid HTTP status code")?;
    let mut headers = Vec::new();
    let mut chunked = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
            headers.push((name, value));
        }
    }
    let body = if chunked {
        dechunk(raw_body)?
    } else {
        raw_body.to_vec()
    };
    Ok((status, headers, body))
}

fn dechunk(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    loop {
        let newline = data
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or("chunked: missing size CRLF")?;
        let size_field = &data[..newline];
        let size_hex = size_field
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or(size_field);
        let size = usize::from_str_radix(
            std::str::from_utf8(size_hex)
                .map_err(|_| "chunked: non-UTF-8 size")?
                .trim(),
            16,
        )
        .map_err(|_| "chunked: invalid hex size")?;
        data = &data[newline + 2..];
        if size == 0 {
            break;
        }
        if data.len() < size + 2 {
            return Err("chunked: truncated chunk".into());
        }
        output.extend_from_slice(&data[..size]);
        if &data[size..size + 2] != b"\r\n" {
            return Err("chunked: missing data CRLF".into());
        }
        data = &data[size + 2..];
        if output.len() > MAX_RESPONSE_BODY {
            output.truncate(MAX_RESPONSE_BODY);
            break;
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{
        https_fetch_interruptible, BoundedHttpsRequest, InterruptibleBlockingNetIo, RootCertStore,
        MAX_REQUEST_BODY, MAX_REQUEST_HEADERS,
    };

    #[test]
    fn bounded_request_rejects_method_url_header_and_body_violations() {
        assert!(BoundedHttpsRequest::new("TRACE", "https://example.test/", vec![], None).is_err());
        assert!(BoundedHttpsRequest::new("GET", "http://example.test/", vec![], None).is_err());
        assert!(BoundedHttpsRequest::new(
            "GET",
            "https://example.test/",
            vec![("X-Test".into(), "ok\r\nInjected: true".into())],
            None,
        )
        .is_err());
        assert!(BoundedHttpsRequest::new(
            "POST",
            "https://example.test/",
            vec![],
            Some(vec![0; MAX_REQUEST_BODY + 1]),
        )
        .is_err());
        assert!(BoundedHttpsRequest::new(
            "GET",
            "https://example.test/",
            vec![("X".into(), "Y".into()); MAX_REQUEST_HEADERS + 1],
            None,
        )
        .is_err());
    }

    #[derive(Default)]
    struct FailingInjectedIo {
        connected: bool,
        sent: usize,
        closed: bool,
    }

    impl InterruptibleBlockingNetIo for FailingInjectedIo {
        fn tcp_connect(&mut self, host: &str, port: u16) -> Result<i32, i32> {
            assert_eq!(host, "fixture.test");
            assert_eq!(port, 8443);
            self.connected = true;
            Ok(7)
        }

        fn send(&mut self, fd: i32, bytes: &[u8]) -> Result<usize, i32> {
            assert_eq!(fd, 7);
            self.sent += bytes.len();
            Ok(bytes.len())
        }

        fn recv(&mut self, fd: i32, _out: &mut [u8]) -> Result<usize, i32> {
            assert_eq!(fd, 7);
            Err(-9)
        }

        fn close(&mut self, fd: i32) {
            assert_eq!(fd, 7);
            self.closed = true;
        }
    }

    #[test]
    fn injected_transport_is_used_and_closed_on_failure() {
        let request =
            BoundedHttpsRequest::new("GET", "https://fixture.test:8443/chunk/0", vec![], None)
                .unwrap();
        let mut io = FailingInjectedIo::default();
        let error = https_fetch_interruptible(&mut io, &request, &RootCertStore::empty(), None)
            .unwrap_err();
        assert!(error.contains("network read error"));
        assert!(io.connected);
        assert!(io.sent > 0);
        assert!(io.closed);
    }
}
