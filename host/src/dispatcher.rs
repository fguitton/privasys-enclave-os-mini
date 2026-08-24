// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Host-side RPC dispatcher.
//!
//! Reads requests from the `enc_to_host` SPSC queue, dispatches them to
//! the appropriate handler (network, KV store, utility), and writes
//! responses back into the `host_to_enc` queue.
//!
//! This replaces ALL of the old individual OCALLs with a single message loop.
//!
//! # Threading model
//!
//! The dispatcher runs on a dedicated host thread (or the main thread).
//! It spin-polls the `enc_to_host` queue with exponential backoff.
//! When the enclave calls `ocall_notify()`, the host can optionally
//! wake immediately, but spinning is fine for high-throughput workloads.

use log::{debug, error, info, trace, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use enclave_os_common::queue::{SpscConsumer, SpscProducer};
use enclave_os_common::rpc::{self, HonestRpcIdentity, RpcMethod, RpcRole};

use crate::kvstore;
use crate::net;

fn legacy_role_allows_method(role: RpcRole, method: RpcMethod) -> bool {
    method != RpcMethod::PersistRaftReadyBatch || role == RpcRole::Control
}

const fn role_name(role: RpcRole) -> &'static str {
    match role {
        RpcRole::Control => "control",
        RpcRole::Execution => "execution",
    }
}

fn network_error_status(error: &anyhow::Error) -> i32 {
    error.downcast_ref::<std::io::Error>().map_or(-1, |error| {
        if error.kind() == std::io::ErrorKind::WouldBlock
            || matches!(error.raw_os_error(), Some(11) | Some(115))
        {
            -11
        } else {
            -1
        }
    })
}

/// RPC dispatcher that bridges enclave requests to host services.
pub struct RpcDispatcher {
    /// Stable physical role of this dispatcher and its queue pair.
    role: RpcRole,
    /// Reads requests from the enclave.
    request_rx: SpscConsumer,
    /// Writes responses back to the enclave.
    response_tx: SpscProducer,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
}

impl RpcDispatcher {
    /// Create a new dispatcher from the raw queue endpoints.
    ///
    /// # Safety
    /// The producers/consumers must be correctly paired to the shared-memory
    /// queues allocated for the enclave channel.
    pub fn new(
        role: RpcRole,
        request_rx: SpscConsumer,
        response_tx: SpscProducer,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            role,
            request_rx,
            response_tx,
            shutdown,
        }
    }

    /// Run the dispatcher loop. Blocks until shutdown is signalled.
    pub fn run(&self) {
        info!("{} RPC dispatcher started", role_name(self.role));

        let mut backoff = Backoff::new();

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                info!(
                    "{} RPC dispatcher: shutdown requested",
                    role_name(self.role)
                );
                break;
            }

            match self.request_rx.try_recv() {
                Some(msg) => {
                    backoff.reset();
                    self.dispatch(&msg);
                }
                None => {
                    backoff.spin();
                }
            }
        }

        info!("{} RPC dispatcher stopped", role_name(self.role));
    }

    /// Dispatch a single RPC request message.
    fn dispatch(&self, raw_msg: &[u8]) {
        if rpc::has_honest_rpc_magic(raw_msg) {
            self.dispatch_honest(raw_msg);
        } else {
            self.dispatch_legacy(raw_msg);
        }
    }

    fn dispatch_honest(&self, raw_msg: &[u8]) {
        let request = match rpc::decode_honest_request(raw_msg) {
            Ok(request) => request,
            Err(error) => {
                error!(
                    "{} Honest RPC dispatcher rejected frame: {:?}",
                    role_name(self.role),
                    error
                );
                return;
            }
        };
        let identity = request.identity;
        trace!(
            "Honest RPC dispatch: role={:?} node={}/{} operation={} method={:?} payload_len={}",
            identity.role,
            identity.node_id,
            identity.node_generation,
            identity.operation_id,
            identity.method,
            request.payload.len()
        );
        let (status, payload) = if identity.role != self.role
            || !rpc::honest_role_allows_method(self.role, identity.method)
        {
            warn!(
                "{} Honest RPC dispatcher denied role={:?} method={:?}",
                role_name(self.role),
                identity.role,
                identity.method
            );
            (-13, Vec::new())
        } else {
            self.dispatch_method(identity.method, request.payload)
        };
        self.try_send_honest_response(identity, status, &payload);
    }

    fn try_send_honest_response(&self, identity: HonestRpcIdentity, status: i32, payload: &[u8]) {
        let response = match rpc::encode_honest_response(identity, status, payload) {
            Ok(response) => response,
            Err(error) => {
                error!(
                    "{} Honest RPC response rejected: {:?}",
                    role_name(self.role),
                    error
                );
                return;
            }
        };
        if self.response_tx.try_send(&response).is_err() {
            error!(
                "{} Honest RPC response queue saturated for operation {}",
                role_name(self.role),
                identity.operation_id
            );
        }
    }

    fn dispatch_legacy(&self, raw_msg: &[u8]) {
        let (req_id, method, payload) = match rpc::decode_request(raw_msg) {
            Some(r) => r,
            None => {
                error!(
                    "{} RPC dispatcher: malformed request ({} bytes)",
                    role_name(self.role),
                    raw_msg.len()
                );
                return;
            }
        };

        trace!(
            "RPC dispatch: req_id={} method={:?} payload_len={}",
            req_id,
            method,
            payload.len()
        );

        if !legacy_role_allows_method(self.role, method) {
            warn!(
                "{} RPC dispatcher denied method {:?} owned by another role",
                role_name(self.role),
                method
            );
            let response = rpc::encode_response(req_id, -13, &[]);
            self.response_tx.send(&response);
            return;
        }

        let (status, response_payload) = self.dispatch_method(method, payload);

        // Send response back to legacy Mini callers.
        let resp = rpc::encode_response(req_id, status, &response_payload);
        self.response_tx.send(&resp);
    }

    fn dispatch_method(&self, method: RpcMethod, payload: &[u8]) -> (i32, Vec<u8>) {
        match method {
            // ---- Network ----
            RpcMethod::NetTcpListen => self.handle_net_tcp_listen(payload),
            RpcMethod::NetTcpAccept => self.handle_net_tcp_accept(payload),
            RpcMethod::NetTcpConnect => self.handle_net_tcp_connect(payload),
            RpcMethod::NetSend => self.handle_net_send(payload),
            RpcMethod::NetRecv => self.handle_net_recv(payload),
            RpcMethod::NetClose => self.handle_net_close(payload),

            // ---- KV Store ----
            RpcMethod::KvPut => self.handle_kv_put(payload),
            RpcMethod::KvGet => self.handle_kv_get(payload),
            RpcMethod::KvDelete => self.handle_kv_delete(payload),
            RpcMethod::KvListKeys => self.handle_kv_list_keys(payload),
            RpcMethod::PersistRaftReadyBatch => self.handle_persist_raft_ready_batch(payload),

            // ---- Utility ----
            RpcMethod::GetCurrentTime => self.handle_get_current_time(),
            RpcMethod::Log => self.handle_log(payload),

            // ---- Attestation (DCAP quoting) ----
            RpcMethod::QeGetTargetInfo => self.handle_qe_get_target_info(),
            RpcMethod::QeGetQuote => self.handle_qe_get_quote(payload),

            // ---- Lifecycle ----
            RpcMethod::Shutdown => {
                info!("RPC: Shutdown requested by enclave");
                self.shutdown.store(true, Ordering::Relaxed);
                (0, Vec::new())
            }
        }
    }

    // ====================================================================
    //  Network handlers
    // ====================================================================

    fn handle_net_tcp_listen(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (port, backlog) = match rpc::decode_net_tcp_listen_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        debug!("RPC: NetTcpListen(port={}, backlog={})", port, backlog);
        match net::tcp_listen(port, backlog) {
            Ok(fd) => (0, rpc::encode_fd(fd)),
            Err(e) => {
                error!("NetTcpListen failed: {}", e);
                (-1, Vec::new())
            }
        }
    }

    fn handle_net_tcp_accept(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let listener_fd = match rpc::decode_net_tcp_accept_req(payload) {
            Some(fd) => fd,
            None => return (-1, Vec::new()),
        };
        match net::tcp_accept(listener_fd) {
            Ok((client_fd, addr)) => {
                trace!("RPC: NetTcpAccept -> fd={} peer={}", client_fd, addr);
                (0, rpc::encode_net_tcp_accept_resp(client_fd, &addr))
            }
            Err(_) => {
                // EWOULDBLOCK is normal
                (-11, Vec::new()) // EAGAIN
            }
        }
    }

    fn handle_net_tcp_connect(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (host, port) = match rpc::decode_net_tcp_connect_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        debug!("RPC: NetTcpConnect(host={}, port={})", host, port);
        match net::tcp_connect(&host, port) {
            Ok(fd) => (0, rpc::encode_fd(fd)),
            Err(e) => {
                error!("NetTcpConnect failed: {}", e);
                (network_error_status(&e), Vec::new())
            }
        }
    }

    fn handle_net_send(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (fd, data) = match rpc::decode_net_send_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        match net::tcp_send(fd, data) {
            Ok(n) => (0, rpc::encode_i32(n as i32)),
            Err(e) => {
                error!("NetSend failed: {}", e);
                (network_error_status(&e), Vec::new())
            }
        }
    }

    fn handle_net_recv(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (fd, max_len) = match rpc::decode_net_recv_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        let mut buf = vec![0u8; max_len as usize];
        match net::tcp_recv(fd, &mut buf) {
            Ok(n) => {
                buf.truncate(n);
                (0, buf)
            }
            Err(error) => (network_error_status(&error), Vec::new()),
        }
    }

    fn handle_net_close(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        if let Some(fd) = rpc::decode_net_close_req(payload) {
            debug!("RPC: NetClose(fd={})", fd);
            net::tcp_close(fd);
        }
        (0, Vec::new())
    }

    // ====================================================================
    //  KV store handlers
    // ====================================================================

    fn handle_kv_put(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (table, key, value) = match rpc::decode_kv_put_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        let table_str = core::str::from_utf8(table).unwrap_or("default");
        match kvstore::put(table_str, key, value) {
            Ok(()) => (0, Vec::new()),
            Err(e) => {
                error!("KvPut failed: {}", e);
                (-1, Vec::new())
            }
        }
    }

    fn handle_kv_get(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (table, key) = match rpc::decode_kv_get_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        let table_str = core::str::from_utf8(table).unwrap_or("default");
        match kvstore::get(table_str, key) {
            Ok(Some(val)) => (0, val),
            Ok(None) => (1, Vec::new()), // not found
            Err(e) => {
                error!("KvGet failed: {}", e);
                (-1, Vec::new())
            }
        }
    }

    fn handle_kv_delete(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (table, key) = match rpc::decode_kv_delete_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        let table_str = core::str::from_utf8(table).unwrap_or("default");
        match kvstore::delete(table_str, key) {
            Ok(true) => (0, Vec::new()),
            Ok(false) => (1, Vec::new()), // not found
            Err(e) => {
                error!("KvDelete failed: {}", e);
                (-1, Vec::new())
            }
        }
    }

    fn handle_kv_list_keys(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (table, prefix) = match rpc::decode_kv_list_keys_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        let table_str = core::str::from_utf8(table).unwrap_or("default");
        match kvstore::list_keys(table_str, prefix, 10_000) {
            Ok(keys) => {
                let refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
                (0, rpc::encode_kv_list_keys_resp(&refs))
            }
            Err(e) => {
                error!("KvListKeys failed: {}", e);
                (-1, Vec::new())
            }
        }
    }

    fn handle_persist_raft_ready_batch(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let request = match rpc::decode_persist_raft_ready_batch(payload) {
            Ok(request) => request,
            Err(error) => {
                warn!(
                    "PersistRaftReadyBatch rejected malformed payload: {:?}",
                    error
                );
                return (-1, Vec::new());
            }
        };
        match kvstore::persist_raft_ready_batch(&request) {
            Ok(kvstore::RaftReadyPersistenceResult::Persisted {
                batch_id,
                durable_id,
            }) => (
                0,
                rpc::encode_persisted_raft_ready_batch(rpc::PersistedRaftReadyBatch {
                    batch_id,
                    durable_id,
                }),
            ),
            Ok(kvstore::RaftReadyPersistenceResult::Conflict) => (1, Vec::new()),
            Err(error) => {
                error!("PersistRaftReadyBatch failed: {}", error);
                (-1, Vec::new())
            }
        }
    }

    // ====================================================================
    //  Utility handlers
    // ====================================================================

    fn handle_get_current_time(&self) -> (i32, Vec<u8>) {
        use std::time::{SystemTime, UNIX_EPOCH};
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => (0, rpc::encode_u64(d.as_secs())),
            Err(_) => (-1, Vec::new()),
        }
    }

    fn handle_log(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        if let Some((level, msg)) = rpc::decode_log_req(payload) {
            match level {
                0 => trace!("[enclave] {}", msg),
                1 => debug!("[enclave] {}", msg),
                2 => info!("[enclave] {}", msg),
                3 => warn!("[enclave] {}", msg),
                _ => error!("[enclave] {}", msg),
            }
        }
        // Log is fire-and-forget; no meaningful response needed.
        (0, Vec::new())
    }

    // ====================================================================
    //  DCAP attestation handlers
    // ====================================================================

    #[cfg(all(target_os = "linux", not(sgx_mode_sim)))]
    fn handle_qe_get_target_info(&self) -> (i32, Vec<u8>) {
        debug!("RPC: QeGetTargetInfo");
        match crate::dcap::qe_get_target_info() {
            Ok(target_info) => (0, target_info),
            Err(e) => {
                error!("QeGetTargetInfo failed: {}", e);
                (-1, Vec::new())
            }
        }
    }

    #[cfg(any(not(target_os = "linux"), sgx_mode_sim))]
    fn handle_qe_get_target_info(&self) -> (i32, Vec<u8>) {
        error!("QeGetTargetInfo: not supported on this platform");
        (-1, Vec::new())
    }

    #[cfg(all(target_os = "linux", not(sgx_mode_sim)))]
    fn handle_qe_get_quote(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        debug!("RPC: QeGetQuote ({} bytes)", payload.len());
        match crate::dcap::qe_get_quote(payload) {
            Ok(quote) => {
                info!("QeGetQuote: generated {} byte DCAP quote", quote.len());
                (0, quote)
            }
            Err(e) => {
                error!("QeGetQuote failed: {}", e);
                (-1, Vec::new())
            }
        }
    }

    #[cfg(any(not(target_os = "linux"), sgx_mode_sim))]
    fn handle_qe_get_quote(&self, _payload: &[u8]) -> (i32, Vec<u8>) {
        error!("QeGetQuote: not supported on this platform");
        (-1, Vec::new())
    }
}

// ---------------------------------------------------------------------------
//  Exponential backoff spinner
// ---------------------------------------------------------------------------

/// Simple exponential backoff for the polling loop.
struct Backoff {
    spin_count: u32,
}

impl Backoff {
    fn new() -> Self {
        Self { spin_count: 0 }
    }

    fn reset(&mut self) {
        self.spin_count = 0;
    }

    fn spin(&mut self) {
        if self.spin_count < 6 {
            // Hot spin with CPU hint (1-64 iterations)
            for _ in 0..(1 << self.spin_count) {
                core::hint::spin_loop();
            }
            self.spin_count += 1;
        } else if self.spin_count < 10 {
            // Yield to OS scheduler
            std::thread::yield_now();
            self.spin_count += 1;
        } else {
            // Sleep briefly (1ms) — the enclave will call ocall_notify to wake us
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    use super::{legacy_role_allows_method, RpcDispatcher};
    use enclave_os_common::queue::{SpscConsumer, SpscProducer, SpscQueueHeader};
    use enclave_os_common::rpc::{
        self, honest_role_allows_method, HonestRpcIdentity, RpcMethod, RpcRole,
    };

    fn queue() -> (SpscProducer, SpscConsumer) {
        let capacity = 8_192_u64;
        let header = Box::into_raw(Box::new(SpscQueueHeader::new(capacity)));
        let buffer = vec![0_u8; capacity as usize];
        let buffer = Box::into_raw(buffer.into_boxed_slice()).cast::<u8>();
        // SAFETY: test-owned header and backing allocation remain live for
        // the process and each endpoint retains its sole SPSC role.
        unsafe {
            (
                SpscProducer::from_raw(header, buffer),
                SpscConsumer::from_raw(header, buffer),
            )
        }
    }

    #[test]
    fn ready_persistence_is_control_role_only() {
        assert!(legacy_role_allows_method(
            RpcRole::Control,
            RpcMethod::PersistRaftReadyBatch
        ));
        assert!(!legacy_role_allows_method(
            RpcRole::Execution,
            RpcMethod::PersistRaftReadyBatch
        ));
        assert!(legacy_role_allows_method(
            RpcRole::Execution,
            RpcMethod::NetRecv
        ));
        assert!(!honest_role_allows_method(
            RpcRole::Control,
            RpcMethod::NetRecv
        ));
        assert!(honest_role_allows_method(
            RpcRole::Execution,
            RpcMethod::NetRecv
        ));
    }

    #[test]
    fn honest_dispatcher_echoes_identity_and_denies_wrong_physical_role() {
        let (_unused_request_tx, request_rx) = queue();
        let (response_tx, response_rx) = queue();
        let dispatcher = RpcDispatcher::new(
            RpcRole::Execution,
            request_rx,
            response_tx,
            Arc::new(AtomicBool::new(false)),
        );
        let identity = HonestRpcIdentity {
            role: RpcRole::Execution,
            node_id: 3,
            node_generation: 8,
            operation_id: 13,
            method: RpcMethod::NetClose,
        };
        dispatcher.dispatch(&rpc::encode_honest_request(identity, &123_i32.to_le_bytes()).unwrap());
        let encoded_response = response_rx.try_recv().expect("framed response");
        let response =
            rpc::decode_honest_response_for(&encoded_response, identity).expect("exact identity");
        assert_eq!(response.status, 0);

        let wrong_role = HonestRpcIdentity {
            role: RpcRole::Control,
            operation_id: 14,
            ..identity
        };
        dispatcher
            .dispatch(&rpc::encode_honest_request(wrong_role, &123_i32.to_le_bytes()).unwrap());
        let encoded_response = response_rx.try_recv().expect("denial response");
        let response = rpc::decode_honest_response_for(&encoded_response, wrong_role)
            .expect("denial still echoes submitted identity");
        assert_eq!(response.status, -13);
    }
}
