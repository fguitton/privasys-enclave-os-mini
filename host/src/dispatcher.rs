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
//! It drains the `enc_to_host` queue, then waits on a retained wake signal.
//! Queue publication and shutdown notify both independent dispatchers.

use log::{debug, error, info, trace, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use enclave_os_common::queue::{SpscConsumer, SpscProducer};
use enclave_os_common::rpc::{self, HonestRpcIdentity, RpcMethod, RpcRole};

use crate::dispatcher_wake::DispatcherWake;
use crate::kvstore;
use crate::net;
#[path = "response_publication.rs"]
mod response_publication;

fn legacy_role_allows_method(role: RpcRole, method: RpcMethod) -> bool {
    method != RpcMethod::WorkerStorage
        && (!matches!(method, RpcMethod::KvPutDurable) || role == RpcRole::Control)
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

fn execution_network_error_status(error: &anyhow::Error) -> i32 {
    if error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.raw_os_error() == Some(125))
    {
        -125
    } else {
        network_error_status(error)
    }
}

fn worker_data_target(table: &[u8], key: &[u8], operation: rpc::WorkerStorageOperation) -> bool {
    const DATA: &[u8] = b"honest/retained-data/v1/";
    let table_allowed = table == b"honest.accepted-artifact-chunks-v1"
        || (table == b"honest.retained-output-chunks-v1"
            && matches!(operation, rpc::WorkerStorageOperation::Put | rpc::WorkerStorageOperation::PutBatch));
    table_allowed && key.starts_with(DATA) && key.len()>DATA.len()+32 && key.len()<=512
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
    wake: Arc<DispatcherWake>,
    #[cfg(feature="diagnostic-worker-storage-rpc")]
    storage_profile:std::sync::Mutex<crate::storage_rpc_profile::Profile>,
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
        wake: Arc<DispatcherWake>,
    ) -> Self {
        Self {
            #[cfg(feature="diagnostic-worker-storage-rpc")]
            storage_profile:std::sync::Mutex::new(crate::storage_rpc_profile::Profile::new()),
            role,
            request_rx,
            response_tx,
            shutdown,
            wake,
        }
    }

    /// Run the dispatcher loop. Blocks until shutdown is signalled.
    pub fn run(&self) {
        info!("{} RPC dispatcher started", role_name(self.role));

        loop {
            if self.shutdown.load(Ordering::Acquire) {
                info!(
                    "{} RPC dispatcher: shutdown requested",
                    role_name(self.role)
                );
                break;
            }

            match self.request_rx.try_recv() {
                Some(msg) => {
                    self.dispatch(&msg);
                }
                None => {
                    self.wake.wait(self.role, &self.shutdown);
                }
            }
        }

        #[cfg(feature="diagnostic-worker-storage-rpc")]
        if self.role==RpcRole::Execution {
            let (_,tail)=self.response_tx.diagnostic_positions();
            let mut profile=self.storage_profile.lock().unwrap_or_else(|x|x.into_inner());
            profile.observe(tail,"shutdown");profile.report();
        }
        info!("{} RPC dispatcher stopped", role_name(self.role));
    }

    /// Dispatch a single RPC request message.
    fn dispatch(&self, raw_msg: &[u8]) {
        #[cfg(feature="diagnostic-worker-storage-rpc")]
        if self.role==RpcRole::Execution {
            let (_,tail)=self.response_tx.diagnostic_positions();
            self.storage_profile.lock().unwrap_or_else(|x|x.into_inner()).observe(tail,"next-request");
        }
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
        #[cfg(feature="diagnostic-worker-storage-rpc")]
        let diagnostic=(identity.role==RpcRole::Execution && self.role==RpcRole::Execution && identity.method==RpcMethod::WorkerStorage)
            .then(||self.storage_profile.lock().unwrap_or_else(|x|x.into_inner()).start());
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
            if identity.method == RpcMethod::WorkerStorage {
                self.handle_worker_storage(request.payload)
            } else {
                self.dispatch_method(identity.method, request.payload)
            }
        };
        #[cfg(feature="diagnostic-worker-storage-rpc")]
        let handler=diagnostic.map(|start|self.storage_profile.lock().unwrap_or_else(|x|x.into_inner()).handler_done(start));
        #[cfg(feature="diagnostic-worker-storage-rpc")]
        let publish=handler.map(|_|std::time::Instant::now());
        let published=self.try_send_honest_response(identity, status, &payload);
        #[cfg(not(feature="diagnostic-worker-storage-rpc"))]
        let _=published;
        #[cfg(feature="diagnostic-worker-storage-rpc")]
        if let (Some(handler),Some(publish))=(handler,publish) {
            let (end,tail)=self.response_tx.diagnostic_positions();
            self.storage_profile.lock().unwrap_or_else(|x|x.into_inner()).record(crate::storage_rpc_profile::Sample{identity,kind:request.payload.first().copied().unwrap_or(255),request:raw_msg.len(),response:payload.len(),status,handler,publish,end,tail,ok:published});
        }
    }

    fn try_send_honest_response(&self, identity: HonestRpcIdentity, status: i32, payload: &[u8]) -> bool {
        if let Err(error) = response_publication::publish(
            self.role,
            &self.response_tx,
            &self.wake,
            identity,
            status,
            payload,
        ) {
            error!(
                "{} Honest RPC response publication failed for operation {}: {}",
                role_name(self.role),
                identity.operation_id,
                error
            );
            false
        } else {true}
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
            RpcMethod::KvPutDurable => self.handle_kv_put_durable(payload),
            RpcMethod::KvGet => self.handle_kv_get(payload),
            RpcMethod::KvDelete => self.handle_kv_delete(payload),
            RpcMethod::KvListKeys => self.handle_kv_list_keys(payload),
            RpcMethod::KvWriteBatch => self.handle_kv_write_batch(payload),
            RpcMethod::KvMultiGet => self.handle_kv_multi_get(payload),
            RpcMethod::KvScan => self.handle_kv_scan(payload),
            RpcMethod::WorkerStorage => (-13, Vec::new()),

            // ---- Utility ----
            RpcMethod::GetCurrentTime => self.handle_get_current_time(),
            RpcMethod::Log => self.handle_log(payload),

            // ---- Attestation (DCAP quoting) ----
            RpcMethod::QeGetTargetInfo => self.handle_qe_get_target_info(),
            RpcMethod::QeGetQuote => self.handle_qe_get_quote(payload),

            // ---- Lifecycle ----
            RpcMethod::Shutdown => {
                info!("RPC: Shutdown requested by enclave");
                self.wake.shutdown(&self.shutdown);
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
        let result = if self.role == RpcRole::Execution {
            net::execution_send(fd, data, &self.wake)
        } else {
            net::tcp_send(fd, data)
        };
        match result {
            Ok(n) => (0, rpc::encode_i32(n as i32)),
            Err(e) => {
                error!("NetSend failed: {}", e);
                (
                    if self.role == RpcRole::Execution {
                        execution_network_error_status(&e)
                    } else {
                        network_error_status(&e)
                    },
                    Vec::new(),
                )
            }
        }
    }

    fn handle_net_recv(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (fd, max_len) = match rpc::decode_net_recv_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        let mut buf = vec![0u8; max_len as usize];
        let result = if self.role == RpcRole::Execution {
            net::execution_receive(fd, &mut buf, &self.wake)
        } else {
            net::tcp_recv(fd, &mut buf)
        };
        match result {
            Ok(n) => {
                buf.truncate(n);
                (0, buf)
            }
            Err(error) => (
                if self.role == RpcRole::Execution {
                    execution_network_error_status(&error)
                } else {
                    network_error_status(&error)
                },
                Vec::new(),
            ),
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

    fn handle_worker_storage(&self, bytes: &[u8]) -> (i32, Vec<u8>) {
        use rpc::WorkerStorageOperation as Operation;
        let Some((operation, payload)) = rpc::decode_worker_storage_request(bytes) else {
            return (-22, Vec::new());
        };
        if operation == Operation::PutBatch {
            let Some((table, records)) = rpc::decode_worker_storage_put_batch(payload) else { return (-22, Vec::new()); };
            if records.iter().any(|(key,_)| !worker_data_target(table,key,operation)) { return (-13, Vec::new()); }
            let operations=records.iter().map(|(key,value)| (*key,Some(*value))).collect::<Vec<_>>();
            let table = match table {
                b"honest.accepted-artifact-chunks-v1" => "honest.accepted-artifact-chunks-v1",
                b"honest.retained-output-chunks-v1" => "honest.retained-output-chunks-v1",
                _ => return (-13, Vec::new()),
            };
            return match kvstore::write_batch(table, &operations) {
                Ok(()) => (0,Vec::new()), Err(_) => (-1,Vec::new()),
            };
        }
        let target = match operation {
            Operation::Get | Operation::Delete => {
                rpc::decode_kv_get_req(payload)
            }
            Operation::Put => rpc::decode_kv_put_req(payload).map(|(table, key, _)| (table, key)),
            Operation::DurablePut => {
                rpc::decode_durable_kv_put_req(payload).map(|(table, key, _)| (table, key))
            }
            Operation::PutBatch => unreachable!("handled before scalar decode"),
        };
        let Some((table, key)) = target else {
            return (-13, Vec::new());
        };
        if !worker_data_target(table,key,operation) { return (-13,Vec::new()); }
        match operation {
            Operation::Get => self.handle_kv_get(payload),
            Operation::Put => self.handle_kv_put(payload),
            Operation::DurablePut => self.handle_kv_put_durable(payload),
            Operation::Delete => self.handle_kv_delete(payload),
            Operation::PutBatch => unreachable!("handled before scalar decode"),
        }
    }

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

    fn handle_kv_put_durable(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Some((table, key, value)) = rpc::decode_durable_kv_put_req(payload) else {
            return (-22, Vec::new());
        };
        let Ok(table) = core::str::from_utf8(table) else {
            return (-22, Vec::new());
        };
        match kvstore::put_durable(table, key, value) {
            Ok(()) => (0, Vec::new()),
            Err(error) => {
                error!("KvPutDurable failed: {}", error);
                (-1, Vec::new())
            }
        }
    }

    fn handle_kv_write_batch(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (table, ops) = match rpc::decode_kv_write_batch_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        let table_str = core::str::from_utf8(table).unwrap_or("default");
        let tuples: Vec<(&[u8], Option<&[u8]>)> = ops
            .iter()
            .map(|op| match op {
                rpc::KvBatchOp::Put { key, value } => (key.as_slice(), Some(value.as_slice())),
                rpc::KvBatchOp::Delete { key } => (key.as_slice(), None),
            })
            .collect();
        match kvstore::write_batch(table_str, &tuples) {
            Ok(()) => (0, Vec::new()),
            Err(e) => {
                error!("KvWriteBatch failed: {}", e);
                (-1, Vec::new())
            }
        }
    }

    fn handle_kv_multi_get(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (table, keys) = match rpc::decode_kv_multi_get_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        let table_str = core::str::from_utf8(table).unwrap_or("default");
        match kvstore::multi_get(table_str, &keys) {
            Ok(values) => (0, rpc::encode_kv_multi_get_resp(&values)),
            Err(e) => {
                error!("KvMultiGet failed: {}", e);
                (-1, Vec::new())
            }
        }
    }

    fn handle_kv_scan(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (table, start, end, limit) = match rpc::decode_kv_scan_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        let table_str = core::str::from_utf8(table).unwrap_or("default");
        match kvstore::scan(table_str, start, end, limit as usize) {
            Ok(entries) => (0, rpc::encode_kv_scan_resp(&entries)),
            Err(e) => {
                error!("KvScan failed: {}", e);
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

    #[cfg(all(target_os = "linux", not(sgx_mode_sim), not(feature = "mock")))]
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

    #[cfg(any(not(target_os = "linux"), sgx_mode_sim, feature = "mock"))]
    fn handle_qe_get_target_info(&self) -> (i32, Vec<u8>) {
        error!("QeGetTargetInfo: not supported on this platform");
        (-1, Vec::new())
    }

    #[cfg(all(target_os = "linux", not(sgx_mode_sim), not(feature = "mock")))]
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

    #[cfg(any(not(target_os = "linux"), sgx_mode_sim, feature = "mock"))]
    fn handle_qe_get_quote(&self, _payload: &[u8]) -> (i32, Vec<u8>) {
        error!("QeGetQuote: not supported on this platform");
        (-1, Vec::new())
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
    fn durable_persistence_is_control_role_only() {
        for role in [RpcRole::Control, RpcRole::Execution] {
            assert_eq!(
                legacy_role_allows_method(role, RpcMethod::KvPutDurable),
                role == RpcRole::Control
            );
            assert_eq!(
                honest_role_allows_method(role, RpcMethod::KvPutDurable),
                role == RpcRole::Control
            );
        }
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
        check_worker_storage_namespace();
        #[cfg(unix)]
        check_encoded_execution_cancel();
        #[cfg(unix)]
        crate::net::check_execution_readiness();
        let (_unused_request_tx, request_rx) = queue();
        let (response_tx, response_rx) = queue();
        let dispatcher = RpcDispatcher::new(
            RpcRole::Execution,
            request_rx,
            response_tx,
            Arc::new(AtomicBool::new(false)),
            Arc::new(crate::dispatcher_wake::DispatcherWake::new()),
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
        for submitted in [identity, wrong_role] {
            let submitted = HonestRpcIdentity {
                method: RpcMethod::KvPutDurable,
                ..submitted
            };
            let payload = rpc::encode_durable_kv_put_req(b"test", b"k", b"v").unwrap();
            dispatcher.dispatch(&rpc::encode_honest_request(submitted, &payload).unwrap());
            let response = response_rx.try_recv().expect("durable write denial");
            assert_eq!(
                rpc::decode_honest_response_for(&response, submitted)
                    .unwrap()
                    .status,
                -13
            );
        }
        dispatcher.dispatch(&rpc::encode_request(15, RpcMethod::KvPutDurable, &[]));
        let response = response_rx.try_recv().expect("legacy durable write denial");
        assert_eq!(rpc::decode_response(&response).unwrap().1, -13);
    }
    #[cfg(unix)]
    fn check_encoded_execution_cancel() {
        use std::net::{Ipv4Addr, TcpListener, TcpStream};
        use std::time::{Duration, Instant};
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let _peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        stream.set_nonblocking(true).unwrap();
        let fd = crate::net::listener::install_for_readiness_test(stream);
        let (_, request_rx) = queue();
        let (response_tx, response_rx) = queue();
        let wake = Arc::new(crate::dispatcher_wake::DispatcherWake::new());
        let identity = HonestRpcIdentity {
            role: RpcRole::Execution,
            node_id: 3,
            node_generation: 8,
            operation_id: 27,
            method: RpcMethod::NetRecv,
        };
        let payload = rpc::encode_net_recv_req(fd, 1);
        let request = rpc::encode_honest_request(identity, &payload).unwrap();
        let worker = {
            let wake = wake.clone();
            std::thread::spawn(move || {
                let dispatcher = RpcDispatcher::new(
                    RpcRole::Execution,
                    request_rx,
                    response_tx,
                    Arc::new(AtomicBool::new(false)),
                    wake,
                );
                dispatcher.dispatch(&request);
            })
        };
        let deadline = Instant::now() + Duration::from_secs(1);
        while wake.execution_waits() == 0 {
            assert!(
                Instant::now() < deadline,
                "dispatcher never entered readiness"
            );
            std::thread::yield_now();
        }
        wake.notify_execution_cancel();
        worker.join().unwrap();
        let bytes = response_rx
            .try_recv()
            .expect("actual cancellation response frame");
        let response = rpc::decode_honest_response_for(&bytes, identity).unwrap();
        assert_eq!(
            response.status, -125,
            "execution cancellation must reach trusted fence check"
        );
        assert!(response.payload.is_empty());
        assert_eq!(
            super::network_error_status(&std::io::Error::from_raw_os_error(125).into()),
            -1,
            "ordinary control error mapping stays unchanged"
        );
        crate::net::tcp_close(fd);
        println!("EXECUTION-SOCKET-CANCEL-FRAME: actual dispatcher exactidentity status=-125 emptybody PASS");
    }
    fn check_worker_storage_namespace() {
        let (_, request_rx) = queue();
        let (response_tx, response_rx) = queue();
        let dispatcher = RpcDispatcher::new(
            RpcRole::Execution,
            request_rx,
            response_tx,
            Arc::new(AtomicBool::new(false)),
            Arc::new(crate::dispatcher_wake::DispatcherWake::new()),
        );
        let identity = HonestRpcIdentity {
            role: RpcRole::Execution,
            node_id: 3,
            node_generation: 8,
            operation_id: 51,
            method: RpcMethod::WorkerStorage,
        };
        for table in [
            b"honest.bft-runtime".as_slice(),
            b"honest.guest-writer-scratch-v1".as_slice(),
            b"honest.accepted-artifact-chunks-v1".as_slice(),
        ] {
            // The last table is valid, but its catalogue key remains control-owned.
            let payload = rpc::encode_worker_storage_request(
                rpc::WorkerStorageOperation::Get,
                &rpc::encode_kv_get_req(table, b"honest/retained-scope/v1/catalog"),
            )
            .unwrap();
            dispatcher.dispatch(&rpc::encode_honest_request(identity, &payload).unwrap());
            let bytes = response_rx.try_recv().unwrap();
            assert_eq!(
                rpc::decode_honest_response_for(&bytes, identity)
                    .unwrap()
                    .status,
                -13
            );
        }
        let directory = tempfile::tempdir().unwrap();
        crate::kvstore::init(directory.path().to_str().unwrap()).unwrap();
        let table = b"honest.accepted-artifact-chunks-v1";
        let key = [b"honest/retained-data/v1/".as_slice(), &[7; 32], b"/leaf"].concat();
        let other=[b"honest/retained-data/v1/".as_slice(), &[7;32], b"/node"].concat();
        let batch=rpc::encode_worker_storage_put_batch(table,&[(&key,b"batch leaf"),(&other,b"batch node")]).unwrap();
        let payload=rpc::encode_worker_storage_request(rpc::WorkerStorageOperation::PutBatch,&batch).unwrap();
        dispatcher.dispatch(&rpc::encode_honest_request(identity,&payload).unwrap());
        let response=response_rx.try_recv().unwrap();
        assert_eq!(rpc::decode_honest_response_for(&response,identity).unwrap().status,0);
        assert_eq!(crate::kvstore::get("honest.accepted-artifact-chunks-v1",&other).unwrap().unwrap(),b"batch node");
        let forbidden=rpc::encode_worker_storage_put_batch(table,&[(&key,b"replacement"),(b"honest/retained-scope/v1/catalog",b"denied")]).unwrap();
        let payload=rpc::encode_worker_storage_request(rpc::WorkerStorageOperation::PutBatch,&forbidden).unwrap();
        dispatcher.dispatch(&rpc::encode_honest_request(identity,&payload).unwrap());
        let response=response_rx.try_recv().unwrap();assert_eq!(rpc::decode_honest_response_for(&response,identity).unwrap().status,-13);
        assert_eq!(crate::kvstore::get("honest.accepted-artifact-chunks-v1",&key).unwrap().unwrap(),b"batch leaf","entire namespace group validated before mutation");
        // The output bridge stages ciphertext only. Actual dispatcher writes
        // the selected dedicated table; roots/catalog/reads remain control-only.
        let output_table=b"honest.retained-output-chunks-v1";
        let put=rpc::encode_worker_storage_request(rpc::WorkerStorageOperation::Put,
            &rpc::encode_kv_put_req(output_table,&key,b"output scalar")).unwrap();
        dispatcher.dispatch(&rpc::encode_honest_request(identity,&put).unwrap());
        let response=response_rx.try_recv().unwrap();
        assert_eq!(rpc::decode_honest_response_for(&response,identity).unwrap().status,0);
        let output_batch=rpc::encode_worker_storage_put_batch(output_table,
            &[(&key,b"output leaf"),(&other,b"output node")]).unwrap();
        let payload=rpc::encode_worker_storage_request(rpc::WorkerStorageOperation::PutBatch,&output_batch).unwrap();
        dispatcher.dispatch(&rpc::encode_honest_request(identity,&payload).unwrap());
        let response=response_rx.try_recv().unwrap();
        assert_eq!(rpc::decode_honest_response_for(&response,identity).unwrap().status,0);
        assert_eq!(crate::kvstore::get("honest.retained-output-chunks-v1",&key).unwrap().unwrap(),b"output leaf");
        assert_eq!(crate::kvstore::get("honest.retained-output-chunks-v1",&other).unwrap().unwrap(),b"output node");
        assert_eq!(crate::kvstore::get("honest.accepted-artifact-chunks-v1",&key).unwrap().unwrap(),b"batch leaf");
        for (operation,payload) in [
            (rpc::WorkerStorageOperation::Get,rpc::encode_kv_get_req(output_table,&key)),
            (rpc::WorkerStorageOperation::Delete,rpc::encode_kv_get_req(output_table,&key)),
            (rpc::WorkerStorageOperation::DurablePut,rpc::encode_durable_kv_put_req(output_table,&key,b"forbidden root").unwrap()),
        ] {
            let request=rpc::encode_worker_storage_request(operation,&payload).unwrap();
            dispatcher.dispatch(&rpc::encode_honest_request(identity,&request).unwrap());
            let response=response_rx.try_recv().unwrap();
            assert_eq!(rpc::decode_honest_response_for(&response,identity).unwrap().status,-13);
        }
        let output_bad=rpc::encode_worker_storage_put_batch(output_table,
            &[(&key,b"must not replace"),(b"honest/retained-scope/v1/catalog",b"denied")]).unwrap();
        let request=rpc::encode_worker_storage_request(rpc::WorkerStorageOperation::PutBatch,&output_bad).unwrap();
        dispatcher.dispatch(&rpc::encode_honest_request(identity,&request).unwrap());
        let response=response_rx.try_recv().unwrap();
        assert_eq!(rpc::decode_honest_response_for(&response,identity).unwrap().status,-13);
        assert_eq!(crate::kvstore::get("honest.retained-output-chunks-v1",&key).unwrap().unwrap(),b"output leaf");
        println!("OUTPUT-WORKER-STAGED-TABLE: actual dispatch Put/PutBatch isolated; output read/durable/delete/catalog denied PASS");
        for cut in 0..batch.len() {assert!(rpc::decode_worker_storage_put_batch(&batch[..cut]).is_none());}
        let mut trailing=batch.clone();trailing.push(0);assert!(rpc::decode_worker_storage_put_batch(&trailing).is_none());
        assert!(rpc::encode_worker_storage_put_batch(table,&[(key.as_slice(),[1u8;1].as_slice());65]).is_none());
        assert!(rpc::encode_worker_storage_put_batch(table,&[(&key,&vec![1;rpc::MAX_WORKER_STORAGE_BATCH_BYTES])]).is_none());

        for (operation, payload, expected) in [
            (
                rpc::WorkerStorageOperation::Put,
                rpc::encode_kv_put_req(table, &key, b"sealed bytes"),
                Vec::new(),
            ),
            (
                rpc::WorkerStorageOperation::DurablePut,
                rpc::encode_durable_kv_put_req(table, &key, b"sealed bytes").unwrap(),
                Vec::new(),
            ),
            (
                rpc::WorkerStorageOperation::Get,
                rpc::encode_kv_get_req(table, &key),
                b"sealed bytes".to_vec(),
            ),
        ] {
            let payload = rpc::encode_worker_storage_request(operation, &payload).unwrap();
            dispatcher.dispatch(&rpc::encode_honest_request(identity, &payload).unwrap());
            let bytes = response_rx.try_recv().unwrap();
            let response = rpc::decode_honest_response_for(&bytes, identity).unwrap();
            assert_eq!(response.status, 0);
            assert_eq!(response.payload, expected);
        }
        assert!(!legacy_role_allows_method(
            RpcRole::Execution,
            RpcMethod::WorkerStorage
        ));
        assert!(!rpc::honest_role_allows_method(
            RpcRole::Execution,
            RpcMethod::KvPutDurable
        ));
        assert!(rpc::honest_role_allows_method(
            RpcRole::Control,
            RpcMethod::KvPutDurable
        ));
        println!("WORKER-STORAGE-HOST: actual framed accepted-data put/durable/get; BFT/scratch/catalogue refusals; control-only durable policy PASS");
            #[cfg(feature="diagnostic-worker-storage-rpc")]
        {let (_,tail)=dispatcher.response_tx.diagnostic_positions();let mut profile=dispatcher.storage_profile.lock().unwrap();profile.observe(tail,"next-request");profile.check();}
}
}
