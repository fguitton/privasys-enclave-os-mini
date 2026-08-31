// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Host-side TCP proxy for enclave inbound connections.
//!
//! This module replaces the old OCALL-based TCP I/O path. Instead of
//! the enclave making `net_recv`/`net_send` OCALLs (one per chunk,
//! ~24 round-trips per request), the host TCP proxy:
//!
//!   1. Accepts TCP connections on the listen port.
//!   2. Assigns a `conn_id` and sends `TcpNew` on the data channel.
//!   3. Reads raw TCP bytes → sends `TcpData` to the enclave.
//!   4. Reads enclave TLS output from the data channel → writes to socket.
//!   5. Handles close in both directions.
//!
//! All sockets are non-blocking. The proxy runs in its own thread.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use enclave_os_common::channel::{self, ChannelMsgType, TcpConnectFailure, CHANNEL_MSG_HEADER};
use enclave_os_common::queue::{SpscConsumer, SpscProducer};

use log::{debug, error, info, warn};

/// Maximum bytes to read from a TCP socket in one call.
const TCP_READ_BUF: usize = 32_768;
/// Per-connection cap for enclave-produced TLS ciphertext awaiting a writable
/// socket. Exceeding it closes only that connection.
const MAX_PENDING_WRITE: usize = 2 * 1024 * 1024;
const MAX_PENDING_TO_ENCLAVE: usize = 2 * 1024 * 1024;

/// Hard cap on simultaneously-tracked connections. Leaves headroom under
/// the conventional 1024 default `RLIMIT_NOFILE`. New `accept()` calls
/// past this cap drop the freshly-accepted socket immediately so the
/// listener never wedges with `EMFILE`.
const MAX_CONNS: usize = 800;

/// Per-connection idle timeout. Any tracked connection that has not
/// produced read/write activity for this long is force-closed and the
/// enclave is notified. Catches half-dead peers (NAT timeouts, suspended
/// laptops, slow-loris ClientHello stalls) that never trigger TCP keepalive.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// How often the proxy loop scans for idle connections.
const IDLE_SCAN_INTERVAL: Duration = Duration::from_secs(30);

/// TCP keepalive parameters applied to every accepted socket. The kernel
/// sends the first probe after `KEEPALIVE_IDLE`, then `KEEPALIVE_RETRIES`
/// further probes spaced by `KEEPALIVE_INTERVAL`. Dead peers are reaped
/// in roughly `KEEPALIVE_IDLE + retries * interval` (~3.5 min by default).
const KEEPALIVE_IDLE: Duration = Duration::from_secs(120);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const KEEPALIVE_RETRIES: u32 = 3;

/// Per-connection state tracked by the proxy.
struct ConnState {
    stream: ProxyStream,
    last_activity: Instant,
    origin: ConnectionOrigin,
    write_buffer: Vec<u8>,
    write_offset: usize,
    close_after_write: bool,
}

enum ConnectionOrigin {
    Inbound,
    LocalControl,
    OutboundConnecting { request_id: u64, endpoint: String },
    Outbound,
}

enum ProxyStream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl ProxyStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buffer),
            Self::Unix(stream) => stream.read(buffer),
        }
    }

    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buffer),
            Self::Unix(stream) => stream.write(buffer),
        }
    }

    fn tcp(&self) -> Option<&TcpStream> {
        match self {
            Self::Tcp(stream) => Some(stream),
            Self::Unix(_) => None,
        }
    }
}

/// TCP proxy for enclave inbound connections.
pub struct TcpProxy {
    /// TCP listener socket (non-blocking).
    listener: TcpListener,
    /// Optional Unix listener for ciphertext-only local control.
    local_control_listener: Option<UnixListener>,
    /// Exact socket created by this process, removed on orderly shutdown.
    local_control_path: Option<PathBuf>,
    /// Active connections: conn_id → state.
    connections: HashMap<u32, ConnState>,
    /// Next connection ID to assign.
    next_conn_id: u32,
    /// Producer for `data_host_to_enc` — sends TCP data to the enclave.
    data_tx: SpscProducer,
    /// Consumer for `data_enc_to_host` — reads enclave TLS output.
    data_rx: SpscConsumer,
    /// Shared shutdown flag.
    shutdown: Arc<AtomicBool>,
    /// True once the enclave has signalled DataReady.
    ready: bool,
    /// Last time we ran the idle-connection sweep.
    last_idle_scan: Instant,
    /// Bounded credit backlog when the enclave's SPSC queue is full.
    pending_to_enclave: VecDeque<Vec<u8>>,
    pending_to_enclave_bytes: usize,
}

impl TcpProxy {
    /// Create the shared ciphertext multiplexer with an optional Unix local
    /// control listener. Both listener classes terminate TLS in the enclave.
    pub fn new_with_local_control(
        port: u16,
        backlog: i32,
        local_control_path: Option<PathBuf>,
        data_tx: SpscProducer,
        data_rx: SpscConsumer,
        shutdown: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let addr: SocketAddr = format!("0.0.0.0:{}", port)
            .parse()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let listener = crate::net::listener::bind_tcp_listener(addr, backlog)
            .map_err(|error| io::Error::other(error.to_string()))?;
        listener.set_nonblocking(true)?;
        info!("TCP proxy listening on {} (backlog {})", addr, backlog);

        let local_control_listener = local_control_path
            .as_deref()
            .map(bind_local_control)
            .transpose()?;

        Ok(Self {
            listener,
            local_control_listener,
            local_control_path,
            connections: HashMap::new(),
            next_conn_id: 1,
            data_tx,
            data_rx,
            shutdown,
            ready: false,
            last_idle_scan: Instant::now(),
            pending_to_enclave: VecDeque::new(),
            pending_to_enclave_bytes: 0,
        })
    }

    /// Run the proxy loop. Blocks until shutdown is signalled.
    pub fn run(&mut self) {
        info!("TCP proxy thread started");
        let mut read_buf = vec![0u8; TCP_READ_BUF];

        while !self.shutdown.load(Ordering::Relaxed) {
            let mut did_work = false;

            // 3 (first). Read from enclave → write to TCP sockets / check DataReady
            did_work |= self.drain_enclave_output();
            did_work |= self.flush_pending_to_enclave();

            if !self.ready {
                // Don't accept or read until the enclave signals DataReady
                if !did_work {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                continue;
            }

            // Make at most one non-blocking write per connection this round.
            did_work |= self.flush_socket_writes();

            // Apply credit backpressure instead of spinning when the enclave
            // queue is full. Existing socket writes continue to drain.
            if self.pending_to_enclave.is_empty() {
                // 1. Accept new connections
                did_work |= self.accept_connections();
                did_work |= self.accept_local_control_connections();

                // Advance every non-blocking outbound connect without delaying
                // accepted connections or another peer's socket.
                did_work |= self.progress_outbound_connections();

                // 2. Read from TCP sockets → send to enclave
                did_work |= self.read_sockets(&mut read_buf);
            }

            // 4. Periodically reap idle connections (catches half-dead peers
            //    that never trigger TCP keepalive — e.g. stalled TLS handshakes).
            if self.last_idle_scan.elapsed() >= IDLE_SCAN_INTERVAL {
                self.reap_idle_connections();
                self.last_idle_scan = Instant::now();
            }

            // If no work was done, yield briefly to avoid busy-spinning
            if !did_work {
                std::thread::sleep(std::time::Duration::from_micros(50));
            }
        }

        // Clean up: close all connections
        for (&conn_id, _) in &self.connections {
            debug!("Closing connection conn_id={} on shutdown", conn_id);
        }
        self.connections.clear();
        self.remove_local_control_socket();
        info!("TCP proxy thread stopped");
    }

    /// Accept pending connections. Returns true if any work was done.
    fn accept_connections(&mut self) -> bool {
        let mut accepted = false;
        // Accept up to 16 connections per poll cycle
        for _ in 0..16 {
            match self.listener.accept() {
                Ok((stream, addr)) => {
                    // Hard cap to avoid wedging the listener with EMFILE.
                    // Drop the freshly-accepted socket immediately if we're
                    // already tracking too many connections — better to refuse
                    // a single connection than to leak FDs and DoS ourselves.
                    if self.connections.len() >= MAX_CONNS {
                        warn!(
                            "Connection cap reached ({}), dropping new connection from {}",
                            MAX_CONNS, addr
                        );
                        drop(stream);
                        continue;
                    }

                    let Some(conn_id) = self.allocate_conn_id() else {
                        warn!("No free connection ID; dropping connection from {}", addr);
                        drop(stream);
                        continue;
                    };

                    if let Err(e) = stream.set_nonblocking(true) {
                        warn!("set_nonblocking failed for conn_id={}: {}", conn_id, e);
                        continue;
                    }
                    // Disable Nagle's algorithm for lower latency
                    let _ = stream.set_nodelay(true);
                    // Enable TCP keepalive so the kernel reaps half-dead peers
                    // (NAT timeouts, suspended laptops, killed clients) that
                    // never sent FIN/RST. Without this the host never sees a
                    // read error and the FD leaks until process restart.
                    if let Err(e) = enable_keepalive(&stream) {
                        warn!("set keepalive failed for conn_id={}: {}", conn_id, e);
                    }

                    let peer_addr = addr.to_string();
                    info!(
                        "Accepted conn_id={} from {} (active={})",
                        conn_id,
                        peer_addr,
                        self.connections.len() + 1
                    );

                    // Send TcpNew to enclave
                    let msg = channel::encode_tcp_new(conn_id, &peer_addr);
                    self.send_to_enclave(msg);

                    self.connections.insert(
                        conn_id,
                        ConnState {
                            stream: ProxyStream::Tcp(stream),
                            last_activity: Instant::now(),
                            origin: ConnectionOrigin::Inbound,
                            write_buffer: Vec::new(),
                            write_offset: 0,
                            close_after_write: false,
                        },
                    );
                    accepted = true;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    error!("Accept error: {}", e);
                    break;
                }
            }
        }
        accepted
    }

    /// Accept Unix local-control connections into the same bounded
    /// ciphertext multiplexer. Socket ownership is defense in depth only.
    fn accept_local_control_connections(&mut self) -> bool {
        let mut accepted = false;
        for _ in 0..16 {
            let result = match self.local_control_listener.as_ref() {
                Some(listener) => listener.accept(),
                None => break,
            };
            match result {
                Ok((stream, _address)) => {
                    if self.connections.len() >= MAX_CONNS {
                        warn!("Connection cap reached, dropping local-control connection");
                        continue;
                    }
                    let Some(conn_id) = self.allocate_conn_id() else {
                        warn!("No free connection ID; dropping local-control connection");
                        continue;
                    };
                    if let Err(error) = stream.set_nonblocking(true) {
                        warn!(
                            "set_nonblocking failed for local-control conn_id={}: {}",
                            conn_id, error
                        );
                        continue;
                    }
                    self.send_to_enclave(channel::encode_local_control_new(conn_id));
                    self.connections.insert(
                        conn_id,
                        ConnState {
                            stream: ProxyStream::Unix(stream),
                            last_activity: Instant::now(),
                            origin: ConnectionOrigin::LocalControl,
                            write_buffer: Vec::new(),
                            write_offset: 0,
                            close_after_write: false,
                        },
                    );
                    accepted = true;
                }
                Err(ref error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    error!("Local-control accept error: {}", error);
                    break;
                }
            }
        }
        accepted
    }

    /// Read from all TCP sockets and forward to enclave. Returns true if
    /// any data was read.
    fn read_sockets(&mut self, buf: &mut [u8]) -> bool {
        let mut did_work = false;
        let mut to_close = Vec::new();
        let mut to_enclave = Vec::new();

        for (&conn_id, conn) in self.connections.iter_mut() {
            if matches!(conn.origin, ConnectionOrigin::OutboundConnecting { .. }) {
                continue;
            }
            match conn.stream.read(buf) {
                Ok(0) => {
                    // Peer closed connection
                    debug!("Peer closed conn_id={}", conn_id);
                    to_close.push(conn_id);
                }
                Ok(n) => {
                    to_enclave.push(channel::encode_tcp_data(conn_id, &buf[..n]));
                    conn.last_activity = Instant::now();
                    did_work = true;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // No data available — normal for non-blocking
                }
                Err(e) => {
                    warn!("Read error on conn_id={}: {}", conn_id, e);
                    to_close.push(conn_id);
                }
            }
        }

        // Close connections and notify enclave
        for conn_id in to_close {
            self.connections.remove(&conn_id);
            to_enclave.push(channel::encode_tcp_close(conn_id));
            did_work = true;
        }
        for message in to_enclave {
            self.send_to_enclave(message);
        }

        did_work
    }

    /// Force-close any connection that has been idle for longer than
    /// `IDLE_TIMEOUT`. Belt-and-braces to TCP keepalive: catches stalled
    /// TLS handshakes and slow-loris peers where the kernel still considers
    /// the connection healthy. Notifies the enclave so its rustls state
    /// is freed too.
    fn reap_idle_connections(&mut self) {
        let now = Instant::now();
        let stale: Vec<u32> = self
            .connections
            .iter()
            .filter(|(_, c)| now.duration_since(c.last_activity) >= IDLE_TIMEOUT)
            .map(|(&id, _)| id)
            .collect();
        if stale.is_empty() {
            return;
        }
        warn!(
            "Reaping {} idle connection(s) (idle ≥ {}s, active={})",
            stale.len(),
            IDLE_TIMEOUT.as_secs(),
            self.connections.len()
        );
        for conn_id in stale {
            self.connections.remove(&conn_id);
            let msg = channel::encode_tcp_close(conn_id);
            self.send_to_enclave(msg);
        }
    }

    /// Read messages from the enclave data channel and process them.
    /// Returns true if any messages were processed.
    fn drain_enclave_output(&mut self) -> bool {
        let mut did_work = false;
        // Process up to 64 messages per poll cycle
        for _ in 0..64 {
            match self.data_rx.try_recv() {
                Some(msg) => {
                    did_work = true;
                    if msg.len() < CHANNEL_MSG_HEADER {
                        warn!("Short message from enclave ({} bytes)", msg.len());
                        continue;
                    }
                    match channel::decode_channel_msg(&msg) {
                        Some((ChannelMsgType::TcpData, conn_id, payload)) => {
                            self.write_to_socket(conn_id, payload);
                        }
                        Some((ChannelMsgType::TcpClose, conn_id, _)) => {
                            debug!("Enclave closed conn_id={}", conn_id);
                            self.close_from_enclave(conn_id);
                        }
                        Some((ChannelMsgType::TcpConnect, conn_id, payload)) => {
                            if conn_id != 0 {
                                warn!(
                                    "Outbound connect request carried non-zero conn_id={}",
                                    conn_id
                                );
                            } else {
                                self.begin_outbound_connection(payload);
                            }
                        }
                        Some((
                            ChannelMsgType::TcpNew | ChannelMsgType::LocalControlNew,
                            conn_id,
                            _,
                        )) => {
                            warn!(
                                "Unexpected new-connection message from enclave for conn_id={}",
                                conn_id
                            );
                        }
                        Some((
                            ChannelMsgType::TcpConnected | ChannelMsgType::TcpConnectFailed,
                            conn_id,
                            _,
                        )) => {
                            warn!(
                                "Unexpected outbound completion from enclave for conn_id={}",
                                conn_id
                            );
                        }
                        Some((ChannelMsgType::DataReady, _, _)) => {
                            info!("Enclave data channel ready — accepting connections");
                            self.ready = true;
                        }
                        None => {
                            warn!("Failed to decode enclave message");
                        }
                    }
                }
                None => break, // no more messages
            }
        }
        did_work
    }

    /// Write data to a TCP socket. If the write fails, close the connection.
    fn write_to_socket(&mut self, conn_id: u32, data: &[u8]) {
        let mut close = false;
        if let Some(conn) = self.connections.get_mut(&conn_id) {
            if matches!(conn.origin, ConnectionOrigin::OutboundConnecting { .. }) {
                warn!(
                    "Write before outbound connect completed for conn_id={}",
                    conn_id
                );
                return;
            }
            let pending = conn.write_buffer.len().saturating_sub(conn.write_offset);
            if pending.saturating_add(data.len()) > MAX_PENDING_WRITE {
                warn!(
                    "Pending write cap exceeded for conn_id={} ({} + {} bytes)",
                    conn_id,
                    pending,
                    data.len()
                );
                close = true;
            } else {
                if conn.write_offset > 0 {
                    conn.write_buffer.drain(..conn.write_offset);
                    conn.write_offset = 0;
                }
                conn.write_buffer.extend_from_slice(data);
            }
        } else {
            debug!("Write to unknown conn_id={}, ignoring", conn_id);
        }
        if close {
            self.connections.remove(&conn_id);
            self.send_to_enclave(channel::encode_tcp_close(conn_id));
        }
    }

    fn close_from_enclave(&mut self, conn_id: u32) {
        let remove_now = self
            .connections
            .get_mut(&conn_id)
            .map(|conn| {
                conn.close_after_write = true;
                conn.write_offset == conn.write_buffer.len()
            })
            .unwrap_or(false);
        if remove_now {
            self.connections.remove(&conn_id);
        }
    }

    fn allocate_conn_id(&mut self) -> Option<u32> {
        for _ in 0..=MAX_CONNS {
            let candidate = self.next_conn_id;
            self.next_conn_id = self.next_conn_id.wrapping_add(1);
            if self.next_conn_id == 0 {
                self.next_conn_id = 1;
            }
            if candidate != 0 && !self.connections.contains_key(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    fn begin_outbound_connection(&mut self, payload: &[u8]) {
        const MAX_ENDPOINT_BYTES: usize = 128;
        let (request_id, endpoint) = match channel::decode_tcp_connect(payload) {
            Some((request_id, endpoint))
                if !endpoint.is_empty() && endpoint.len() <= MAX_ENDPOINT_BYTES =>
            {
                (request_id, endpoint.to_string())
            }
            Some((request_id, _)) => {
                warn!("Rejected malformed outbound endpoint");
                self.send_to_enclave(channel::encode_tcp_connect_failed(
                    request_id,
                    TcpConnectFailure::MalformedEndpoint,
                ));
                return;
            }
            None => {
                warn!("Rejected malformed outbound connect request");
                return;
            }
        };
        let Some(conn_id) = self.allocate_conn_id() else {
            warn!("No free connection ID for outbound endpoint {}", endpoint);
            self.send_to_enclave(channel::encode_tcp_connect_failed(
                request_id,
                TcpConnectFailure::ConnectionLimit,
            ));
            return;
        };
        if self.connections.len() >= MAX_CONNS {
            warn!(
                "Connection cap reached ({}), rejecting outbound endpoint {}",
                MAX_CONNS, endpoint
            );
            self.send_to_enclave(channel::encode_tcp_connect_failed(
                request_id,
                TcpConnectFailure::ConnectionLimit,
            ));
            return;
        }
        let address = match endpoint.parse::<SocketAddr>() {
            Ok(address) => address,
            Err(_) => {
                warn!("Rejected non-IP outbound endpoint {}", endpoint);
                self.send_to_enclave(channel::encode_tcp_connect_failed(
                    request_id,
                    TcpConnectFailure::MalformedEndpoint,
                ));
                return;
            }
        };
        match begin_nonblocking_connect(address) {
            Ok((stream, connected)) => {
                if let Err(error) = stream.set_nodelay(true) {
                    warn!(
                        "set_nodelay failed for outbound conn_id={}: {}",
                        conn_id, error
                    );
                }
                if let Err(error) = enable_keepalive(&stream) {
                    warn!(
                        "set keepalive failed for outbound conn_id={}: {}",
                        conn_id, error
                    );
                }
                let origin = if connected {
                    ConnectionOrigin::Outbound
                } else {
                    ConnectionOrigin::OutboundConnecting {
                        request_id,
                        endpoint: endpoint.clone(),
                    }
                };
                self.connections.insert(
                    conn_id,
                    ConnState {
                        stream: ProxyStream::Tcp(stream),
                        last_activity: Instant::now(),
                        origin,
                        write_buffer: Vec::new(),
                        write_offset: 0,
                        close_after_write: false,
                    },
                );
                if connected {
                    self.send_to_enclave(channel::encode_tcp_connected(request_id, conn_id));
                }
            }
            Err(error) => {
                warn!(
                    "Outbound connect setup failed conn_id={} endpoint={}: {}",
                    conn_id, endpoint, error
                );
                self.send_to_enclave(channel::encode_tcp_connect_failed(
                    request_id,
                    TcpConnectFailure::SocketFailure,
                ));
            }
        }
    }

    fn progress_outbound_connections(&mut self) -> bool {
        let mut connected = Vec::new();
        let mut failed = Vec::new();
        for (&conn_id, conn) in &self.connections {
            let ConnectionOrigin::OutboundConnecting {
                request_id,
                endpoint,
            } = &conn.origin
            else {
                continue;
            };
            let Some(stream) = conn.stream.tcp() else {
                failed.push((conn_id, *request_id, endpoint.clone()));
                continue;
            };
            match stream.take_error() {
                Ok(Some(error)) => {
                    warn!(
                        "Outbound connect failed conn_id={} endpoint={}: {}",
                        conn_id, endpoint, error
                    );
                    failed.push((conn_id, *request_id, endpoint.clone()));
                }
                Ok(None) => match stream.peer_addr() {
                    Ok(_) => connected.push((conn_id, *request_id, endpoint.clone())),
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::NotConnected | io::ErrorKind::WouldBlock
                        ) => {}
                    Err(error) => {
                        warn!(
                            "Outbound connect state failed conn_id={} endpoint={}: {}",
                            conn_id, endpoint, error
                        );
                        failed.push((conn_id, *request_id, endpoint.clone()));
                    }
                },
                Err(error) => {
                    warn!(
                        "Outbound connect status failed conn_id={} endpoint={}: {}",
                        conn_id, endpoint, error
                    );
                    failed.push((conn_id, *request_id, endpoint.clone()));
                }
            }
        }
        for (conn_id, request_id, _) in &connected {
            if let Some(conn) = self.connections.get_mut(conn_id) {
                conn.origin = ConnectionOrigin::Outbound;
                conn.last_activity = Instant::now();
            }
            self.send_to_enclave(channel::encode_tcp_connected(*request_id, *conn_id));
        }
        for (conn_id, request_id, _) in &failed {
            self.connections.remove(conn_id);
            self.send_to_enclave(channel::encode_tcp_connect_failed(
                *request_id,
                TcpConnectFailure::SocketFailure,
            ));
        }
        !connected.is_empty() || !failed.is_empty()
    }

    fn flush_socket_writes(&mut self) -> bool {
        let mut did_work = false;
        let mut to_close = Vec::new();
        for (&conn_id, conn) in &mut self.connections {
            if matches!(conn.origin, ConnectionOrigin::OutboundConnecting { .. })
                || conn.write_offset == conn.write_buffer.len()
            {
                continue;
            }
            match conn.stream.write(&conn.write_buffer[conn.write_offset..]) {
                Ok(0) => {
                    warn!("Zero-length write on conn_id={}", conn_id);
                    to_close.push((conn_id, true));
                }
                Ok(written) => {
                    conn.write_offset += written;
                    conn.last_activity = Instant::now();
                    did_work = true;
                    if conn.write_offset == conn.write_buffer.len() {
                        conn.write_buffer.clear();
                        conn.write_offset = 0;
                        if conn.close_after_write {
                            to_close.push((conn_id, false));
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    warn!("Write error on conn_id={}: {}", conn_id, error);
                    to_close.push((conn_id, true));
                }
            }
        }
        for (conn_id, notify_enclave) in to_close {
            self.connections.remove(&conn_id);
            if notify_enclave {
                self.send_to_enclave(channel::encode_tcp_close(conn_id));
            }
            did_work = true;
        }
        did_work
    }

    fn send_to_enclave(&mut self, message: Vec<u8>) {
        if self.pending_to_enclave.is_empty() && self.data_tx.try_send(&message).is_ok() {
            return;
        }
        if self.pending_to_enclave_bytes.saturating_add(message.len()) > MAX_PENDING_TO_ENCLAVE {
            error!(
                "Host-to-enclave credit backlog exceeded {} bytes; shutting down proxy",
                MAX_PENDING_TO_ENCLAVE
            );
            self.shutdown.store(true, Ordering::Release);
            return;
        }
        self.pending_to_enclave_bytes += message.len();
        self.pending_to_enclave.push_back(message);
    }

    fn flush_pending_to_enclave(&mut self) -> bool {
        let Some(message) = self.pending_to_enclave.front() else {
            return false;
        };
        if self.data_tx.try_send(message).is_err() {
            return false;
        }
        let sent = self.pending_to_enclave.pop_front().expect("front existed");
        self.pending_to_enclave_bytes -= sent.len();
        true
    }

    fn remove_local_control_socket(&mut self) {
        self.local_control_listener.take();
        if let Some(path) = self.local_control_path.take() {
            if let Err(error) = std::fs::remove_file(&path) {
                if error.kind() != io::ErrorKind::NotFound {
                    warn!(
                        "Failed to remove local-control socket {}: {}",
                        path.display(),
                        error
                    );
                }
            }
        }
    }
}

impl Drop for TcpProxy {
    fn drop(&mut self) {
        self.remove_local_control_socket();
    }
}

fn bind_local_control(path: &Path) -> io::Result<UnixListener> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local-control socket path must be absolute",
        ));
    }
    let listener = UnixListener::bind(path)?;
    listener.set_nonblocking(true)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    info!(
        "Local-control ciphertext relay listening on {}",
        path.display()
    );
    Ok(listener)
}

fn begin_nonblocking_connect(address: SocketAddr) -> io::Result<(TcpStream, bool)> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    socket.set_nonblocking(true)?;
    let connected = match socket.connect(&address.into()) {
        Ok(()) => true,
        Err(error) if connect_is_in_progress(&error) => false,
        Err(error) => return Err(error),
    };
    Ok((socket.into(), connected))
}

fn connect_is_in_progress(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock || matches!(error.raw_os_error(), Some(114 | 115))
}

/// Enable TCP keepalive on a stream with our standard parameters.
/// Uses `socket2` for portable access to `TCP_KEEPIDLE`/`TCP_KEEPINTVL`/
/// `TCP_KEEPCNT` (the std lib's `TcpKeepalive` only exposes `time`).
fn enable_keepalive(stream: &TcpStream) -> io::Result<()> {
    use socket2::{SockRef, TcpKeepalive};
    let sock = SockRef::from(stream);
    let ka = TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL)
        .with_retries(KEEPALIVE_RETRIES);
    sock.set_tcp_keepalive(&ka)
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclave_os_common::queue::SpscQueueHeader;

    struct QueueMemory {
        header: Box<SpscQueueHeader>,
        buffer: Box<[u8]>,
    }

    impl QueueMemory {
        fn new() -> Self {
            Self {
                header: Box::new(SpscQueueHeader::new(4096)),
                buffer: vec![0_u8; 4096].into_boxed_slice(),
            }
        }

        fn producer(&mut self) -> SpscProducer {
            unsafe { SpscProducer::from_raw(&*self.header, self.buffer.as_mut_ptr()) }
        }

        fn consumer(&mut self) -> SpscConsumer {
            unsafe { SpscConsumer::from_raw(&*self.header, self.buffer.as_ptr()) }
        }
    }

    #[test]
    fn enclave_close_drains_buffered_ciphertext_before_socket_close() {
        let mut host_to_enclave = QueueMemory::new();
        let mut enclave_to_host = QueueMemory::new();
        let data_tx = host_to_enclave.producer();
        let data_rx = enclave_to_host.consumer();
        let mut proxy =
            TcpProxy::new(0, 1, data_tx, data_rx, Arc::new(AtomicBool::new(false))).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        server.set_nonblocking(true).unwrap();
        proxy.connections.insert(
            7,
            ConnState {
                stream: ProxyStream::Tcp(server),
                last_activity: Instant::now(),
                origin: ConnectionOrigin::Inbound,
                write_buffer: Vec::new(),
                write_offset: 0,
                close_after_write: false,
            },
        );

        proxy.write_to_socket(7, b"encrypted response");
        proxy.close_from_enclave(7);
        assert!(proxy.connections.contains_key(&7));
        assert!(proxy.flush_socket_writes());
        assert!(!proxy.connections.contains_key(&7));

        let mut received = [0_u8; 18];
        client.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"encrypted response");
        let mut eof = [0_u8; 1];
        assert_eq!(client.read(&mut eof).unwrap(), 0);
    }
}
