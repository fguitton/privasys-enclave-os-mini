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

use enclave_os_common::channel::{
    self, ChannelMsgType, TcpConnectFailure, CHANNEL_MSG_HEADER, CONN_ID_OUTBOUND_BASE,
    CONN_ID_PEER_IN_BASE,
};
use enclave_os_common::queue::{SpscConsumer, SpscProducer};

use log::{debug, error, info, warn};

/// Maximum bytes to read from a TCP socket in one call.
const TCP_READ_BUF: usize = 32_768;
/// Per-connection cap for enclave-produced TLS ciphertext awaiting a writable
/// socket. Exceeding it closes only that connection.
const MAX_PENDING_WRITE: usize = 2 * 1024 * 1024;
const MAX_PENDING_TO_ENCLAVE: usize = 2 * 1024 * 1024;

/// Timeout for enclave-requested outbound connects.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on bytes buffered for a not-yet-connected outbound connection
/// (the enclave emits its TLS ClientHello before the connect completes).
const MAX_PENDING_CONNECT_WRITE: usize = 256 * 1024;

/// Raft tick cadence (sent to the enclave when a peer port is set).
const TICK_INTERVAL: Duration = Duration::from_millis(channel::SCHEDULING_TICK_INTERVAL_MILLIS);

/// Errno for a non-blocking connect in progress. The host only runs on
/// Linux (SGX); `WouldBlock` covers other platforms as a fallback.
#[cfg(target_os = "linux")]
const EINPROGRESS: i32 = 115;
#[cfg(not(target_os = "linux"))]
const EINPROGRESS: i32 = -1;

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

/// An enclave-requested outbound connection whose non-blocking connect
/// has not completed yet. `TcpData` from the enclave is buffered until
/// the socket is writable.
struct PendingConn {
    stream: TcpStream,
    buffered: Vec<Vec<u8>>,
    buffered_len: usize,
    started: Instant,
}

/// TCP proxy for enclave inbound and proxy-owned outbound connections.
pub struct TcpProxy {
    /// Ingress TCP listener socket (non-blocking).
    listener: TcpListener,
    /// Optional Unix listener for ciphertext-only local control.
    local_control_listener: Option<UnixListener>,
    /// Exact socket created by this process, removed on orderly shutdown.
    local_control_path: Option<PathBuf>,
    /// Optional peer-port listener (raft peer links). Inbound conns from
    /// this listener get ids from the `CONN_ID_PEER_IN_BASE` range.
    peer_listener: Option<TcpListener>,
    /// Active connections: conn_id → state.
    connections: HashMap<u32, ConnState>,
    /// Outbound connects in progress: conn_id → pending state.
    pending_connects: HashMap<u32, PendingConn>,
    /// Next ingress connection ID to assign.
    next_conn_id: u32,
    /// Next peer-port connection ID to assign.
    next_peer_conn_id: u32,
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
    /// Last raft tick sent (peer-port mode only).
    last_tick: Instant,
}

impl TcpProxy {
    /// Create a new TCP proxy bound to the given ingress port.
    pub fn new(
        port: u16,
        _backlog: i32,
        data_tx: SpscProducer,
        data_rx: SpscConsumer,
        shutdown: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        Self::new_with_local_control(port, _backlog, None, data_tx, data_rx, shutdown)
    }

    /// Create the shared ciphertext multiplexer with an optional Unix local
    /// control listener. Both listener classes terminate TLS in the enclave.
    pub fn new_with_local_control(
        port: u16,
        _backlog: i32,
        local_control_path: Option<PathBuf>,
        data_tx: SpscProducer,
        data_rx: SpscConsumer,
        shutdown: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        Self::new_with_listeners(
            port,
            _backlog,
            local_control_path,
            None,
            data_tx,
            data_rx,
            shutdown,
        )
    }

    /// Configure the independent ingress, local-control and optional peer listeners.
    pub fn new_with_listeners(
        port: u16,
        _backlog: i32,
        local_control_path: Option<PathBuf>,
        peer_port: Option<u16>,
        data_tx: SpscProducer,
        data_rx: SpscConsumer,
        shutdown: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr)?;
        listener.set_nonblocking(true)?;
        info!("TCP proxy listening on {}", addr);

        let peer_listener = match peer_port {
            Some(p) => {
                let peer_addr = format!("0.0.0.0:{}", p);
                let l = TcpListener::bind(&peer_addr)?;
                l.set_nonblocking(true)?;
                info!("TCP proxy peer listener on {}", peer_addr);
                Some(l)
            }
            None => None,
        };

        let local_control_listener = local_control_path
            .as_deref()
            .map(bind_local_control)
            .transpose()?;

        Ok(Self {
            listener,
            peer_listener,
            local_control_listener,
            local_control_path,
            connections: HashMap::new(),
            pending_connects: HashMap::new(),
            next_conn_id: 1,
            next_peer_conn_id: CONN_ID_PEER_IN_BASE,
            data_tx,
            data_rx,
            shutdown,
            ready: false,
            last_idle_scan: Instant::now(),
            pending_to_enclave: VecDeque::new(),
            pending_to_enclave_bytes: 0,
            last_tick: Instant::now(),
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
                did_work |= self.poll_pending_connects();

                // 2. Read from TCP sockets → send to enclave
                did_work |= self.read_sockets(&mut read_buf);
            }

            // 4. Periodically reap idle connections (catches half-dead peers
            //    that never trigger TCP keepalive — e.g. stalled TLS handshakes).
            if self.last_idle_scan.elapsed() >= IDLE_SCAN_INTERVAL {
                self.reap_idle_connections();
                self.last_idle_scan = Instant::now();
            }

            // 5. Scheduling ticks for the adopter and optional peer transport.
            did_work |= self.send_tick_if_due();

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
        self.pending_connects.clear();
        self.remove_local_control_socket();
        info!("TCP proxy thread stopped");
    }

    /// Offer one scheduling tick without building a backlog under backpressure.
    fn send_tick_if_due(&mut self) -> bool {
        if !self.pending_to_enclave.is_empty() || self.last_tick.elapsed() < TICK_INTERVAL {
            return false;
        }
        self.send_to_enclave(channel::encode_channel_msg(ChannelMsgType::Tick, 0, &[]));
        self.last_tick = Instant::now();
        true
    }

    /// Accept pending connections from both listeners. Returns true if
    /// any work was done.
    fn accept_connections(&mut self) -> bool {
        // Drain both listeners first (accept only borrows the listener),
        // then register the sockets.
        let mut incoming: Vec<(TcpStream, std::net::SocketAddr, bool)> = Vec::new();

        // Accept up to 16 connections per listener per poll cycle
        for _ in 0..16 {
            match self.listener.accept() {
                Ok((stream, addr)) => incoming.push((stream, addr, false)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    error!("Accept error: {}", e);
                    break;
                }
            }
        }
        if let Some(ref peer_listener) = self.peer_listener {
            for _ in 0..16 {
                match peer_listener.accept() {
                    Ok((stream, addr)) => incoming.push((stream, addr, true)),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        error!("Peer accept error: {}", e);
                        break;
                    }
                }
            }
        }

        let mut accepted = false;
        for (stream, addr, is_peer) in incoming {
            // Hard cap to avoid wedging the listener with EMFILE.
            // Drop the freshly-accepted socket immediately if we're
            // already tracking too many connections — better to refuse
            // a single connection than to leak FDs and DoS ourselves.
            if self.connections.len() + self.pending_connects.len() >= MAX_CONNS {
                warn!(
                    "Connection cap reached ({}), dropping new connection from {}",
                    MAX_CONNS, addr
                );
                drop(stream);
                continue;
            }

            let conn_id = if is_peer {
                self.allocate_peer_conn_id()
            } else {
                self.allocate_conn_id()
            };
            let Some(conn_id) = conn_id else {
                warn!("No free connection ID; dropping connection from {}", addr);
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
                "Accepted conn_id={} from {}{} (active={})",
                conn_id,
                peer_addr,
                if is_peer { " [peer port]" } else { "" },
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
                    if self.connections.len() + self.pending_connects.len() >= MAX_CONNS {
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

    /// Start an enclave-requested outbound peer connect (`PeerTcpConnect`).
    ///
    /// The connect is non-blocking; completion is polled in
    /// [`Self::poll_pending_connects`]. Failures are reported to the
    /// enclave as `TcpClose` for the conn_id.
    fn start_outbound_connect(&mut self, conn_id: u32, addr_str: &str) {
        use std::net::ToSocketAddrs;

        if !channel::conn_id_is_outbound(conn_id) {
            warn!(
                "TcpConnect with non-outbound conn_id={}, rejecting",
                conn_id
            );
            self.send_to_enclave(channel::encode_tcp_close(conn_id));
            return;
        }
        if self.connections.contains_key(&conn_id) || self.pending_connects.contains_key(&conn_id) {
            warn!("TcpConnect with duplicate conn_id={}, rejecting", conn_id);
            self.send_to_enclave(channel::encode_tcp_close(conn_id));
            return;
        }
        if self.connections.len() + self.pending_connects.len() >= MAX_CONNS {
            warn!(
                "Connection cap reached, rejecting outbound conn_id={}",
                conn_id
            );
            self.send_to_enclave(channel::encode_tcp_close(conn_id));
            return;
        }

        // Resolve. This can block briefly for DNS names; peer addresses
        // are normally numeric, in which case resolution is a parse.
        let addr = match addr_str.to_socket_addrs().ok().and_then(|mut a| a.next()) {
            Some(a) => a,
            None => {
                warn!(
                    "TcpConnect conn_id={}: cannot resolve '{}'",
                    conn_id, addr_str
                );
                self.send_to_enclave(channel::encode_tcp_close(conn_id));
                return;
            }
        };

        // Non-blocking connect via socket2 (std's TcpStream::connect blocks).
        let socket = match socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "TcpConnect conn_id={}: socket create failed: {}",
                    conn_id, e
                );
                self.send_to_enclave(channel::encode_tcp_close(conn_id));
                return;
            }
        };
        if let Err(e) = socket.set_nonblocking(true) {
            warn!(
                "TcpConnect conn_id={}: set_nonblocking failed: {}",
                conn_id, e
            );
            self.send_to_enclave(channel::encode_tcp_close(conn_id));
            return;
        }
        match socket.connect(&addr.into()) {
            Ok(()) => {}
            // In-progress is the normal non-blocking outcome
            // (EINPROGRESS on Unix, WSAEWOULDBLOCK on Windows).
            Err(ref e)
                if e.raw_os_error() == Some(EINPROGRESS)
                    || e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                warn!("TcpConnect conn_id={} to {}: {}", conn_id, addr, e);
                self.send_to_enclave(channel::encode_tcp_close(conn_id));
                return;
            }
        }

        debug!("Outbound connect started conn_id={} to {}", conn_id, addr);
        self.pending_connects.insert(
            conn_id,
            PendingConn {
                stream: socket.into(),
                buffered: Vec::new(),
                buffered_len: 0,
                started: Instant::now(),
            },
        );
    }

    /// Poll outbound connects for completion, failure, or timeout.
    /// Returns true if any connection changed state.
    fn poll_pending_connects(&mut self) -> bool {
        if self.pending_connects.is_empty() {
            return false;
        }
        let mut done: Vec<(u32, bool)> = Vec::new(); // (conn_id, success)
        for (&conn_id, pending) in self.pending_connects.iter() {
            // A socket error means the connect failed.
            match pending.stream.take_error() {
                Ok(Some(e)) => {
                    warn!("Outbound connect failed conn_id={}: {}", conn_id, e);
                    done.push((conn_id, false));
                    continue;
                }
                Err(e) => {
                    warn!("Outbound connect failed conn_id={}: {}", conn_id, e);
                    done.push((conn_id, false));
                    continue;
                }
                Ok(None) => {}
            }
            // peer_addr() succeeds once the socket is connected.
            match pending.stream.peer_addr() {
                Ok(_) => done.push((conn_id, true)),
                Err(_) => {
                    if pending.started.elapsed() >= CONNECT_TIMEOUT {
                        warn!("Outbound connect timeout conn_id={}", conn_id);
                        done.push((conn_id, false));
                    }
                }
            }
        }

        let changed = !done.is_empty();
        for (conn_id, success) in done {
            let pending = match self.pending_connects.remove(&conn_id) {
                Some(p) => p,
                None => continue,
            };
            if !success {
                self.send_to_enclave(channel::encode_tcp_close(conn_id));
                continue;
            }
            let _ = pending.stream.set_nodelay(true);
            if let Err(e) = enable_keepalive(&pending.stream) {
                warn!("set keepalive failed for conn_id={}: {}", conn_id, e);
            }
            info!(
                "Outbound connected conn_id={} to {} (active={})",
                conn_id,
                pending
                    .stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_default(),
                self.connections.len() + 1
            );
            self.connections.insert(
                conn_id,
                ConnState {
                    stream: ProxyStream::Tcp(pending.stream),
                    last_activity: Instant::now(),
                    origin: ConnectionOrigin::Outbound,
                    write_buffer: Vec::new(),
                    write_offset: 0,
                    close_after_write: false,
                },
            );
            self.send_to_enclave(channel::encode_peer_tcp_connected(conn_id));
            // Flush any TLS bytes the enclave emitted while connecting.
            for chunk in pending.buffered {
                self.write_to_socket(conn_id, &chunk);
                if !self.connections.contains_key(&conn_id) {
                    break; // write failed and closed the connection
                }
            }
        }
        changed
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
                        Some((ChannelMsgType::PeerTcpConnect, conn_id, payload)) => {
                            match core::str::from_utf8(payload) {
                                Ok(endpoint) => self.start_outbound_connect(conn_id, endpoint),
                                Err(_) => self.send_to_enclave(channel::encode_tcp_close(conn_id)),
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
                            ChannelMsgType::TcpConnected
                            | ChannelMsgType::TcpConnectFailed
                            | ChannelMsgType::PeerTcpConnected
                            | ChannelMsgType::Tick,
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
    /// Data for an outbound connection still connecting is buffered.
    fn write_to_socket(&mut self, conn_id: u32, data: &[u8]) {
        if let Some(pending) = self.pending_connects.get_mut(&conn_id) {
            if pending.buffered_len.saturating_add(data.len()) > MAX_PENDING_CONNECT_WRITE {
                warn!(
                    "Pre-connect buffer overflow on conn_id={}, dropping connection",
                    conn_id
                );
                self.pending_connects.remove(&conn_id);
                self.send_to_enclave(channel::encode_tcp_close(conn_id));
                return;
            }
            pending.buffered_len += data.len();
            pending.buffered.push(data.to_vec());
            return;
        }
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
        self.pending_connects.remove(&conn_id);
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
            if self.next_conn_id == 0 || self.next_conn_id >= CONN_ID_PEER_IN_BASE {
                self.next_conn_id = 1;
            }
            if candidate != 0
                && candidate < CONN_ID_PEER_IN_BASE
                && !self.connections.contains_key(&candidate)
                && !self.pending_connects.contains_key(&candidate)
            {
                return Some(candidate);
            }
        }
        None
    }

    fn allocate_peer_conn_id(&mut self) -> Option<u32> {
        for _ in 0..=MAX_CONNS {
            let candidate = self.next_peer_conn_id;
            self.next_peer_conn_id = self.next_peer_conn_id.wrapping_add(1);
            if !(CONN_ID_PEER_IN_BASE..CONN_ID_OUTBOUND_BASE).contains(&self.next_peer_conn_id) {
                self.next_peer_conn_id = CONN_ID_PEER_IN_BASE;
            }
            if (CONN_ID_PEER_IN_BASE..CONN_ID_OUTBOUND_BASE).contains(&candidate)
                && !self.connections.contains_key(&candidate)
                && !self.pending_connects.contains_key(&candidate)
            {
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
        if self.connections.len() + self.pending_connects.len() >= MAX_CONNS {
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

    struct TransportFixture {
        proxy: TcpProxy,
        to_host: SpscProducer,
        from_host: SpscConsumer,
        // The queue allocations outlive every raw-pointer endpoint above.
        _host_to_enclave: QueueMemory,
        _enclave_to_host: QueueMemory,
    }

    impl TransportFixture {
        fn new() -> Self {
            let mut host_to_enclave = QueueMemory::new();
            let mut enclave_to_host = QueueMemory::new();
            Self {
                proxy: TcpProxy::new_with_listeners(
                    0,
                    1,
                    None,
                    Some(0),
                    host_to_enclave.producer(),
                    enclave_to_host.consumer(),
                    Arc::new(AtomicBool::new(false)),
                )
                .unwrap(),
                to_host: enclave_to_host.producer(),
                from_host: host_to_enclave.consumer(),
                _host_to_enclave: host_to_enclave,
                _enclave_to_host: enclave_to_host,
            }
        }

        fn messages(&mut self, count: usize) -> Vec<Vec<u8>> {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut messages = Vec::new();
            while messages.len() < count {
                self.proxy.drain_enclave_output();
                self.proxy.progress_outbound_connections();
                self.proxy.poll_pending_connects();
                self.proxy.flush_socket_writes();
                self.proxy.read_sockets(&mut [0; 1024]);
                self.proxy.flush_pending_to_enclave();
                while let Some(message) = self.from_host.try_recv() {
                    messages.push(message);
                }
                assert!(Instant::now() < deadline, "TCP proxy message deadline");
                std::thread::yield_now();
            }
            assert_eq!(messages.len(), count, "unexpected extra channel message");
            messages
        }
    }

    fn accept_loopback(listener: &TcpListener) -> TcpStream {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    return stream;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "loopback accept deadline");
                    std::thread::yield_now();
                }
                Err(error) => panic!("loopback accept: {error}"),
            }
        }
    }

    #[test]
    fn scheduling_ticks_work_without_peer_listener_and_respect_queue_credit() {
        let mut fixture = TransportFixture::new();
        fixture.proxy.peer_listener = None;
        let due = Instant::now() - TICK_INTERVAL;
        fixture.proxy.last_tick = due;
        assert!(fixture.proxy.send_tick_if_due());
        let tick = channel::encode_channel_msg(ChannelMsgType::Tick, 0, &[]);
        assert_eq!(fixture.from_host.try_recv(), Some(tick.clone()));
        assert!(fixture.from_host.try_recv().is_none());

        // A future observation keeps this assertion independent of test latency.
        fixture.proxy.last_tick = Instant::now() + Duration::from_secs(60);
        assert!(!fixture.proxy.send_tick_if_due());
        assert!(fixture.from_host.try_recv().is_none());

        // Fill the actual enclave queue, then retain one close notification.
        let close = channel::encode_tcp_close(17);
        while fixture.proxy.data_tx.try_send(&close).is_ok() {}
        fixture.proxy.send_to_enclave(close.clone());
        assert_eq!(fixture.proxy.pending_to_enclave.len(), 1);
        fixture.proxy.last_tick = due;
        assert!(!fixture.proxy.send_tick_if_due());
        assert_eq!(fixture.proxy.last_tick, due);
        assert_eq!(fixture.proxy.pending_to_enclave.len(), 1);
        assert_eq!(fixture.proxy.pending_to_enclave_bytes, close.len());
        while let Some(message) = fixture.from_host.try_recv() {
            assert_eq!(message, close);
        }
        fixture.proxy.flush_pending_to_enclave();
        assert_eq!(fixture.from_host.try_recv(), Some(close));
        assert!(fixture.proxy.pending_to_enclave.is_empty());
        assert!(fixture.proxy.send_tick_if_due());
        assert_eq!(fixture.from_host.try_recv(), Some(tick));
        assert!(fixture.from_host.try_recv().is_none());
    }

    #[test]
    fn connect_protocols_preserve_correlation_and_ciphertext_over_loopback() {
        let mut fixture = TransportFixture::new();
        let honest_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let request_id = 0x1234_5678_abcd_ef01;
        let peer_id = CONN_ID_OUTBOUND_BASE + 11;
        fixture
            .to_host
            .try_send(&channel::encode_tcp_connect(
                request_id,
                &honest_listener.local_addr().unwrap().to_string(),
            ))
            .unwrap();
        fixture
            .to_host
            .try_send(&channel::encode_peer_tcp_connect(
                peer_id,
                &peer_listener.local_addr().unwrap().to_string(),
            ))
            .unwrap();
        // This peer protocol permits a ClientHello before connect completion.
        fixture
            .to_host
            .try_send(&channel::encode_tcp_data(peer_id, b"peer hello"))
            .unwrap();
        let messages = fixture.messages(2);
        let mut honest_id = None;
        let mut peer_connected = false;
        for message in messages {
            let (kind, id, payload) = channel::decode_channel_msg(&message).unwrap();
            match kind {
                ChannelMsgType::TcpConnected => {
                    assert_eq!(channel::decode_tcp_connected(payload), Some(request_id));
                    assert!(id > 0 && id < CONN_ID_PEER_IN_BASE);
                    assert!(honest_id.replace(id).is_none());
                }
                ChannelMsgType::PeerTcpConnected => {
                    assert_eq!(id, peer_id);
                    assert!(payload.is_empty());
                    assert!(!peer_connected);
                    peer_connected = true;
                }
                other => panic!("unexpected connect response: {other:?}"),
            }
        }
        let honest_id = honest_id.unwrap();
        assert!(peer_connected);
        let mut honest = accept_loopback(&honest_listener);
        let mut peer = accept_loopback(&peer_listener);
        let mut hello = [0; 10];
        peer.read_exact(&mut hello).unwrap();
        assert_eq!(&hello, b"peer hello");
        fixture
            .to_host
            .try_send(&channel::encode_tcp_data(honest_id, b"honest hello"))
            .unwrap();
        fixture.proxy.drain_enclave_output();
        fixture.proxy.flush_socket_writes();
        let mut hello = [0; 12];
        honest.read_exact(&mut hello).unwrap();
        assert_eq!(&hello, b"honest hello");

        for (id, socket, bytes) in [
            (honest_id, &mut honest, b"honest reply".as_slice()),
            (peer_id, &mut peer, b"peer reply".as_slice()),
        ] {
            socket.write_all(bytes).unwrap();
            let mut received = Vec::new();
            while received.len() < bytes.len() {
                for message in fixture.messages(1) {
                    let (kind, actual_id, payload) = channel::decode_channel_msg(&message).unwrap();
                    assert_eq!((kind, actual_id), (ChannelMsgType::TcpData, id));
                    received.extend_from_slice(payload);
                }
            }
            assert_eq!(received, bytes);
        }

        let malformed_request = request_id + 1;
        fixture
            .to_host
            .try_send(&channel::encode_tcp_connect(
                malformed_request,
                "localhost:443",
            ))
            .unwrap();
        let messages = fixture.messages(1);
        let (kind, id, payload) = channel::decode_channel_msg(&messages[0]).unwrap();
        assert_eq!((kind, id), (ChannelMsgType::TcpConnectFailed, 0));
        assert_eq!(
            channel::decode_tcp_connect_failed(payload),
            Some((malformed_request, TcpConnectFailure::MalformedEndpoint))
        );
        assert!(fixture.proxy.connections.contains_key(&honest_id));
        assert!(fixture.proxy.connections.contains_key(&peer_id));
    }

    #[test]
    fn ingress_and_peer_listener_ids_wrap_without_colliding() {
        let mut fixture = TransportFixture::new();
        fixture.proxy.next_conn_id = CONN_ID_PEER_IN_BASE - 1;
        fixture.proxy.next_peer_conn_id = CONN_ID_OUTBOUND_BASE - 1;
        let ingress_port = fixture.proxy.listener.local_addr().unwrap().port();
        let peer_port = fixture
            .proxy
            .peer_listener
            .as_ref()
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut sockets = Vec::new();
        let mut ingress_ids = Vec::new();
        let mut peer_ids = Vec::new();
        for _ in 0..3 {
            sockets
                .push(TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, ingress_port)).unwrap());
            sockets.push(TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, peer_port)).unwrap());
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut collected = 0;
            while collected < 2 {
                fixture.proxy.accept_connections();
                while let Some(message) = fixture.from_host.try_recv() {
                    let (kind, id, _) = channel::decode_channel_msg(&message).unwrap();
                    assert_eq!(kind, ChannelMsgType::TcpNew);
                    if id < CONN_ID_PEER_IN_BASE {
                        assert_ne!(id, 0);
                        ingress_ids.push(id);
                    } else {
                        assert!(id < CONN_ID_OUTBOUND_BASE);
                        peer_ids.push(id);
                    }
                    collected += 1;
                }
                assert!(Instant::now() < deadline, "listener notification deadline");
                std::thread::yield_now();
            }
            // Force the next allocation to revisit a live connection ID.
            fixture.proxy.next_conn_id = ingress_ids[0];
            fixture.proxy.next_peer_conn_id = peer_ids[0];
        }
        assert_eq!(ingress_ids, [CONN_ID_PEER_IN_BASE - 1, 1, 2]);
        assert_eq!(
            peer_ids,
            [
                CONN_ID_OUTBOUND_BASE - 1,
                CONN_ID_PEER_IN_BASE,
                CONN_ID_PEER_IN_BASE + 1
            ]
        );
        assert_eq!(fixture.proxy.connections.len(), sockets.len());
    }

    #[test]
    fn queue_credit_backlog_preserves_order_and_closes_on_overflow() {
        let mut fixture = TransportFixture::new();
        let expected: Vec<_> = (0..12)
            .map(|sequence| channel::encode_tcp_data(7, &vec![sequence; 1000]))
            .collect();
        for message in &expected {
            fixture.proxy.send_to_enclave(message.clone());
        }
        assert!(!fixture.proxy.pending_to_enclave.is_empty());
        assert!(
            !fixture.proxy.flush_pending_to_enclave(),
            "a full queue must yield"
        );
        let mut received = Vec::new();
        for _ in 0..expected.len() {
            while let Some(message) = fixture.from_host.try_recv() {
                received.push(message);
            }
            while fixture.proxy.flush_pending_to_enclave() {}
        }
        assert_eq!(received, expected);
        assert_eq!(fixture.proxy.pending_to_enclave_bytes, 0);
        assert!(!fixture.proxy.shutdown.load(Ordering::Acquire));

        // Fill using valid queue-sized messages, then cross the total backlog cap.
        let message = channel::encode_tcp_data(7, &[0; 1000]);
        for _ in 0..MAX_PENDING_TO_ENCLAVE / message.len() + 10 {
            fixture.proxy.send_to_enclave(message.clone());
            if fixture.proxy.shutdown.load(Ordering::Acquire) {
                break;
            }
        }
        assert!(fixture.proxy.shutdown.load(Ordering::Acquire));
        assert!(fixture.proxy.pending_to_enclave_bytes <= MAX_PENDING_TO_ENCLAVE);
    }

    #[test]
    fn ciphertext_buffer_limits_close_only_the_offending_socket() {
        let mut fixture = TransportFixture::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let offending = CONN_ID_OUTBOUND_BASE + 1;
        let healthy = CONN_ID_OUTBOUND_BASE + 2;
        fixture.proxy.start_outbound_connect(offending, &endpoint);
        let mut rejected = accept_loopback(&listener);
        assert!(fixture.proxy.pending_connects.contains_key(&offending));
        fixture
            .proxy
            .write_to_socket(offending, &vec![0; MAX_PENDING_CONNECT_WRITE]);
        assert!(fixture.proxy.pending_connects.contains_key(&offending));
        fixture.proxy.write_to_socket(offending, &[1]);
        assert!(!fixture.proxy.pending_connects.contains_key(&offending));
        assert_eq!(fixture.messages(1), [channel::encode_tcp_close(offending)]);
        assert_eq!(rejected.read(&mut [0; 1]).unwrap(), 0);

        fixture.proxy.start_outbound_connect(offending, &endpoint);
        let mut rejected = accept_loopback(&listener);
        fixture.proxy.start_outbound_connect(healthy, &endpoint);
        let mut retained = accept_loopback(&listener);
        let mut connected = fixture.messages(2);
        connected.sort();
        let mut expected = vec![
            channel::encode_peer_tcp_connected(offending),
            channel::encode_peer_tcp_connected(healthy),
        ];
        expected.sort();
        assert_eq!(connected, expected);
        fixture
            .proxy
            .write_to_socket(offending, &vec![0; MAX_PENDING_WRITE]);
        fixture.proxy.write_to_socket(healthy, b"still live");
        assert!(fixture.proxy.connections.contains_key(&offending));
        fixture.proxy.write_to_socket(offending, &[1]);
        assert!(!fixture.proxy.connections.contains_key(&offending));
        assert!(fixture.proxy.connections.contains_key(&healthy));
        assert_eq!(fixture.messages(1), [channel::encode_tcp_close(offending)]);
        assert_eq!(rejected.read(&mut [0; 1]).unwrap(), 0);
        let mut received = [0; 10];
        retained.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"still live");
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
