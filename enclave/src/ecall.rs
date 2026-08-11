// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! ECall entry points – functions called by the host into the enclave.
//!
//! With the SPSC queue architecture, the ECALL surface is:
//! - `ecall_init_control_channel`: receive control RPC queue pointers
//! - `ecall_init_execution_channel`: receive execution RPC queue pointers
//! - `ecall_init_data_channel`: receive ingress data queue pointers
//! - `ecall_run`: main enclave entry – init subsystems, run event loop
//! - `ecall_execution_worker`: long-lived worker entry on the second TCS
//! - `ecall_shutdown`: pre-run/future spare-TCS shutdown only
//!
//! ## Composition
//!
//! When the `default-ecall` feature is enabled (the default), this module
//! provides an `ecall_run` that registers modules based on Cargo features:
//!
//! | Feature | Module | Implies |
//! |---------|--------|---------|
//! | `egress` | EgressModule | — |
//! | `kvstore` | KvStoreModule | — |
//! | `vault` | VaultModule | `kvstore`, `egress` |
//! | `wasm` | WasmModule | `kvstore`, `egress` |
//!
//! With no module features enabled, only HelloWorld is registered.
//! Features compose freely: `--features vault,wasm` registers all four.
//!
//! The CMake build system maps `-DENABLE_VAULT=ON` etc. to the
//! corresponding Cargo features.
//!
//! For fully custom registration logic, disable `default-ecall`:
//! 1. Depend on `enclave-os-enclave` with `default-features = false`
//!    and `features = ["sgx"]`.
//! 2. Provide your own `#[no_mangle] pub extern "C" fn ecall_run(…)`.
//! 3. Call [`init_enclave()`] to get the parsed config and sealed state.
//! 4. Construct modules and [`register_module()`](crate::modules::register_module) them.
//! 5. Call [`finalize_and_run()`] to build the Merkle tree, start the
//!    RA-TLS server, and enter the event loop.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::ratls::attestation::CaContext;
use crate::ratls::server::IngressServer;
use crate::rpc_client::RpcClient;
use crate::sealed_config::SealedConfig;
use crate::{enclave_log_error, enclave_log_info, ShutdownOriginV1};
use enclave_os_common::channel;
use enclave_os_common::hex::{hex_decode, hex_encode};
use enclave_os_common::queue::{SpscConsumer, SpscProducer, SpscQueueHeader};
use enclave_os_common::types::AEAD_KEY_SIZE;

// ==========================================================================
//  Channel initialisation
// ==========================================================================

const MAX_SHARED_QUEUE_CAPACITY: u64 = 16 * 1024 * 1024;
const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;
const QUEUE_BUFFER_ALIGNMENT: usize = 64;

#[derive(Clone, Copy)]
struct HostSpan {
    start: usize,
    end: usize,
}

impl HostSpan {
    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

fn checked_host_span(ptr: *const u8, len: usize, alignment: usize) -> Option<HostSpan> {
    if ptr.is_null() || len == 0 || (ptr as usize) % alignment != 0 {
        return None;
    }
    let end = (ptr as usize).checked_add(len)?;
    if !sgx_trts::trts::is_within_host(ptr, len) {
        return None;
    }
    Some(HostSpan {
        start: ptr as usize,
        end,
    })
}

fn validate_channel_description(
    enc_to_host_header: *mut u8,
    enc_to_host_buf: *mut u8,
    host_to_enc_header: *mut u8,
    host_to_enc_buf: *mut u8,
    capacity: u64,
) -> Result<(), i32> {
    if !capacity.is_power_of_two() || capacity < 4096 || capacity > MAX_SHARED_QUEUE_CAPACITY {
        return Err(-1);
    }
    let capacity = usize::try_from(capacity).map_err(|_| -1)?;
    let header_len = core::mem::size_of::<SpscQueueHeader>();
    let header_alignment = core::mem::align_of::<SpscQueueHeader>();
    let spans = [
        checked_host_span(enc_to_host_header, header_len, header_alignment).ok_or(-1)?,
        checked_host_span(enc_to_host_buf, capacity, QUEUE_BUFFER_ALIGNMENT).ok_or(-1)?,
        checked_host_span(host_to_enc_header, header_len, header_alignment).ok_or(-1)?,
        checked_host_span(host_to_enc_buf, capacity, QUEUE_BUFFER_ALIGNMENT).ok_or(-1)?,
    ];
    for left in 0..spans.len() {
        for right in (left + 1)..spans.len() {
            if spans[left].overlaps(spans[right]) {
                return Err(-1);
            }
        }
    }

    // The untrusted header is checked before construction. The queue handles
    // snapshot this validated capacity, so later host mutation cannot expand
    // an enclave-side buffer view.
    let described_capacity = capacity as u64;
    let first_capacity = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(
            (*(enc_to_host_header as *const SpscQueueHeader)).capacity
        ))
    };
    let second_capacity = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(
            (*(host_to_enc_header as *const SpscQueueHeader)).capacity
        ))
    };
    if first_capacity != described_capacity || second_capacity != described_capacity {
        return Err(-1);
    }
    Ok(())
}

fn initialise_rpc_channel(
    enc_to_host_header: *mut u8,
    enc_to_host_buf: *mut u8,
    host_to_enc_header: *mut u8,
    host_to_enc_buf: *mut u8,
    capacity: u64,
    install: fn(RpcClient) -> Result<(), i32>,
) -> i32 {
    if validate_channel_description(
        enc_to_host_header,
        enc_to_host_buf,
        host_to_enc_header,
        host_to_enc_buf,
        capacity,
    )
    .is_err()
    {
        return -1;
    }
    // The enclave is the **producer** for enc_to_host and the **consumer**
    // for host_to_enc.
    let request_tx = unsafe {
        SpscProducer::from_raw(
            enc_to_host_header as *const SpscQueueHeader,
            enc_to_host_buf,
        )
    };
    let response_rx = unsafe {
        SpscConsumer::from_raw(
            host_to_enc_header as *const SpscQueueHeader,
            host_to_enc_buf as *const u8,
        )
    };

    let client = RpcClient::new(request_tx, response_rx);
    install(client).map(|()| 0).unwrap_or(-1)
}

/// Initialise the control-plane RPC channel.
#[no_mangle]
pub extern "C" fn ecall_init_control_channel(
    enc_to_host_header: *mut u8,
    enc_to_host_buf: *mut u8,
    host_to_enc_header: *mut u8,
    host_to_enc_buf: *mut u8,
    capacity: u64,
) -> i32 {
    initialise_rpc_channel(
        enc_to_host_header,
        enc_to_host_buf,
        host_to_enc_header,
        host_to_enc_buf,
        capacity,
        crate::set_control_rpc_client,
    )
}

/// Initialise the execution-plane RPC channel.
#[no_mangle]
pub extern "C" fn ecall_init_execution_channel(
    enc_to_host_header: *mut u8,
    enc_to_host_buf: *mut u8,
    host_to_enc_header: *mut u8,
    host_to_enc_buf: *mut u8,
    capacity: u64,
) -> i32 {
    initialise_rpc_channel(
        enc_to_host_header,
        enc_to_host_buf,
        host_to_enc_header,
        host_to_enc_buf,
        capacity,
        crate::set_execution_rpc_client,
    )
}

// ==========================================================================
//  ecall_init_data_channel – set up the data channel for TCP proxy
// ==========================================================================

/// Called by the host to pass the second pair of SPSC queue pointers for
/// the data channel (TCP proxy ↔ enclave).
///
/// # Parameters
/// - `enc_to_host_header`/`enc_to_host_buf`: enclave → host (TLS output)
/// - `host_to_enc_header`/`host_to_enc_buf`: host → enclave (raw TCP data)
/// - `capacity`: ring buffer size
#[no_mangle]
pub extern "C" fn ecall_init_data_channel(
    enc_to_host_header: *mut u8,
    enc_to_host_buf: *mut u8,
    host_to_enc_header: *mut u8,
    host_to_enc_buf: *mut u8,
    capacity: u64,
) -> i32 {
    if validate_channel_description(
        enc_to_host_header,
        enc_to_host_buf,
        host_to_enc_header,
        host_to_enc_buf,
        capacity,
    )
    .is_err()
    {
        return -1;
    }

    // The enclave is the **producer** for enc_to_host (TLS output to proxy)
    // and the **consumer** for host_to_enc (raw TCP data from proxy).
    let data_tx = unsafe {
        SpscProducer::from_raw(
            enc_to_host_header as *const SpscQueueHeader,
            enc_to_host_buf,
        )
    };
    let data_rx = unsafe {
        SpscConsumer::from_raw(
            host_to_enc_header as *const SpscQueueHeader,
            host_to_enc_buf as *const u8,
        )
    };

    match crate::set_data_channel(data_tx, data_rx) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

// ==========================================================================
//  init_enclave – parse config, CPUID, crypto self-tests, sealed config
// ==========================================================================

/// Initialise the enclave core: parse configuration, set up CPUID caching,
/// run cryptographic self-tests, and resolve the sealed configuration.
///
/// Returns the parsed [`EnclaveConfig`] and a mutable [`SealedConfig`].
/// The caller (either the default `ecall_run` or an adopter's custom one)
/// is responsible for registering modules and calling [`finalize_and_run()`].
pub fn init_enclave(
    config_json: *const u8,
    config_len: u64,
) -> Result<(EnclaveConfig, SealedConfig), i32> {
    // Parse config
    let config_bytes = if config_len == 0 {
        b"{}" as &[u8]
    } else {
        let config_len = usize::try_from(config_len).map_err(|_| -2)?;
        if config_len > MAX_CONFIG_BYTES || checked_host_span(config_json, config_len, 1).is_none()
        {
            enclave_log_error!("Config pointer description rejected");
            return Err(-2);
        }
        unsafe { core::slice::from_raw_parts(config_json, config_len) }
    };

    let config: EnclaveConfig = match serde_json::from_slice(config_bytes) {
        Ok(c) => c,
        Err(e) => {
            enclave_log_error!("Config parse failed: {}", e);
            return Err(-2);
        }
    };

    // ── CPUID cache: must be initialised BEFORE any crypto ──────────
    // ring / rustls use CPUID for feature detection (SHA-NI, AES-NI, …).
    // Inside SGX, CPUID triggers #UD. We fetch results via OCALL once
    // at init and register a VEH to serve cached values thereafter.
    crate::cpuid_cache::init();

    // Crypto self-tests
    {
        let mut buf = [0u8; 32];
        if let Err(e) = getrandom::getrandom(&mut buf) {
            enclave_log_error!("getrandom FAILED: {}", e);
            return Err(-10);
        }
        use ring::rand::{SecureRandom, SystemRandom};
        if SystemRandom::new().fill(&mut buf).is_err() {
            enclave_log_error!("ring::rand FAILED");
            return Err(-11);
        }
        use ring::digest;
        let _ = digest::digest(&digest::SHA256, b"self-test");
    }
    enclave_log_info!("Crypto self-tests passed");

    // ── Resolve unified sealed config ──────────────────────────────
    let sealed_cfg = match resolve_sealed_config(&config) {
        Ok(cfg) => cfg,
        Err(e) => {
            enclave_log_error!("Sealed config resolution failed: {}", e);
            return Err(-12);
        }
    };
    enclave_log_info!("Sealed config resolved");

    // Register the OS RA-TLS client-certificate signer so outbound mutually-
    // attested connections (e.g. fetching a vault-backed KEK) can present a
    // measurement-bound client cert. The enclave CA never leaves the OS; egress
    // only ever asks the signer to mint for an OS-built identity.
    //
    // Both registrations target egress, so they are skipped on the base flavor
    // (no egress, no vault-key path).
    #[cfg(feature = "egress")]
    {
        crate::vaultkey::register_client_cert_signer(
            sealed_cfg.ca_cert_der.clone(),
            sealed_cfg.ca_key_pkcs8.clone(),
        );
        // Attestation provider: challenge-bound quotes (to authenticate this enclave
        // to the management-service vault directory over plain TLS) + self-MRENCLAVE
        // (so the wasm crate can pin the running runtime when self-authoring a vault
        // key policy). Reached from the wasm crate only via egress registration.
        crate::vaultkey::register_attestation_provider();
    }

    Ok((config, sealed_cfg))
}

// ==========================================================================
//  Reusable runtime initialisation and control loop
// ==========================================================================

/// Build the config Merkle tree and start the RA-TLS ingress runtime.
///
/// Call this after all modules have been registered and the sealed config
/// has been updated with any module-generated data.
pub fn initialise_runtime_and_ingress(
    _config: &EnclaveConfig,
    sealed_cfg: &SealedConfig,
) -> Result<(), i32> {
    let _initialisation_guard = crate::CoreInitialisationGuard::new();

    // Persist the (possibly updated) sealed config
    if let Err(e) = sealed_cfg.seal_to_disk() {
        enclave_log_error!("Failed to seal config: {}", e);
        return Err(-12);
    }
    enclave_log_info!("Sealed config persisted to disk");

    // ── Config Merkle tree ─────────────────────────────────────────
    // Core leaves + module-contributed leaves → auditable root hash.
    let merkle_root = {
        let mut tree = crate::config_merkle::ConfigMerkleTree::new();

        // Core leaf (fixed order — append-only, never reorder)
        tree.push("core.ca_cert", Some(sealed_cfg.ca_cert_der.as_slice()));

        // Core leaf: attestation servers (canonical URL list)
        let as_canonical = enclave_os_common::attestation_servers::canonical_form();
        tree.push("core.attestation_servers", as_canonical.as_deref());

        // Module leaves (collected from all registered modules)
        for leaf in crate::modules::collect_module_config_leaves() {
            tree.push(leaf.name, leaf.data.as_deref());
        }

        tree.finalize()
    };
    enclave_log_info!("Config Merkle root: {}", hex_encode(&merkle_root));

    // Log the full manifest for auditability
    if let Some(manifest) = crate::config_merkle::config_manifest() {
        for (i, entry) in manifest.entries().iter().enumerate() {
            enclave_log_info!("  leaf[{}] {} = {}", i, entry.name, hex_encode(&entry.hash));
        }
    }

    // Initialise enclave state
    if let Err(code) = crate::init_state() {
        enclave_log_error!("init_state failed ({})", code);
        return Err(code);
    }
    enclave_log_info!("Enclave state initialised");

    // Build CA context from sealed config
    let ca = match CaContext::from_parts(
        sealed_cfg.ca_cert_der.clone(),
        sealed_cfg.ca_key_pkcs8.clone(),
    ) {
        Ok(ca) => Arc::new(ca),
        Err(e) => {
            enclave_log_error!("CA validation failed: {}", e);
            return Err(-20);
        }
    };

    // ── Per-app certificate store ──────────────────────────────────
    // Initialise the global CertStore and register initial app
    // identities collected from all modules. Modules that load apps
    // dynamically (e.g. WASM) will call cert_store().register()
    // at runtime.
    {
        let store = crate::ratls::cert_store::CertStore::new(ca.clone());
        let identities = crate::modules::collect_app_identities();
        let count = identities.len();
        for identity in identities {
            enclave_log_info!("Registering app identity: {}", identity.hostname);
            store.register(identity);
        }
        crate::ratls::cert_store::init_cert_store(store);
        if count > 0 {
            enclave_log_info!("CertStore initialised with {} app identities", count);
        } else {
            enclave_log_info!("CertStore initialised (no initial app identities)");
        }
    }

    let server = IngressServer::new(ca, crate::data_tx());
    {
        let mut st = match crate::state().lock() {
            Ok(st) => st,
            Err(_) => return Err(-22),
        };
        st.ingress_server = Some(server);
    }
    enclave_log_info!("RA-TLS ingress server initialised (data channel mode)");

    // Signal the host TCP proxy that the data channel consumer is ready.
    // The proxy blocks new connections until it receives this message.
    {
        let ready_msg = channel::encode_channel_msg(channel::ChannelMsgType::DataReady, 0, &[]);
        if crate::data_tx().try_send(&ready_msg).is_err() {
            enclave_log_error!("DataReady could not acquire data-channel credit");
            return Err(-23);
        }
        enclave_log_info!("DataReady sent to host TCP proxy");
    }

    if let Err(phase) = crate::publish_core_running() {
        enclave_log_error!("Cannot publish Running from phase {:?}", phase);
        return Err(-23);
    }
    enclave_log_info!("CorePhase Running published");
    Ok(())
}

/// A bounded opportunity offered by Mini's reusable control loop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlLoopOpportunity {
    DataChannelProgress,
    Idle,
    Shutdown,
}

/// Action returned by an adopter-owned control hook.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlLoopAction {
    Continue,
    Shutdown,
}

/// Non-blocking adopter hook invoked by the control TCS.
///
/// Implementations must perform bounded work and return without waiting for a
/// worker, host RPC response, socket or persistence operation.
pub trait ControlLoopHook {
    /// Offer one decoded data-channel message to adopter-owned outbound I/O.
    ///
    /// Return `true` only for a message belonging to an adopter connection.
    /// Implementations must remain bounded and must not wait for network or
    /// host progress.
    fn on_data_channel_message(
        &mut self,
        _msg_type: channel::ChannelMsgType,
        _conn_id: u32,
        _payload: &[u8],
    ) -> bool {
        false
    }

    fn on_opportunity(&mut self, opportunity: ControlLoopOpportunity) -> ControlLoopAction;
}

struct NoopControlLoopHook;

impl ControlLoopHook for NoopControlLoopHook {
    fn on_opportunity(&mut self, _opportunity: ControlLoopOpportunity) -> ControlLoopAction {
        ControlLoopAction::Continue
    }
}

fn apply_control_action(action: ControlLoopAction) {
    if action == ControlLoopAction::Shutdown {
        enclave_log_error!("MINI-CONTROL-SHUTDOWN: reason=AdopterHook");
        crate::signal_shutdown_with_origin(ShutdownOriginV1::AdopterHook);
    }
}

/// Run the control event loop after [`initialise_runtime_and_ingress`].
pub fn run_control_loop(hook: &mut dyn ControlLoopHook) -> i32 {
    if crate::core_phase() != enclave_os_common::core_phase::CorePhase::Running {
        return -24;
    }

    // Main event loop: read from data channel, dispatch to IngressServer
    let data_rx = crate::data_rx();
    while !crate::is_shutdown() {
        if let Ok(mut st) = crate::state().lock() {
            if let Some(ref mut srv) = st.ingress_server {
                let _ = srv.progress_output();
                if let Some(reason) = srv.shutdown_reason() {
                    enclave_log_error!("MINI-CONTROL-SHUTDOWN: reason=Ingress({:?})", reason);
                    let origin = match reason {
                        crate::ratls::server::IngressShutdownReasonV1::ExplicitHttpRequest => {
                            ShutdownOriginV1::IngressExplicitHttpRequest
                        }
                        crate::ratls::server::IngressShutdownReasonV1::OutputCreditBacklog => {
                            ShutdownOriginV1::IngressOutputCreditBacklog
                        }
                    };
                    crate::signal_shutdown_with_origin(origin);
                }
            }
        } else {
            enclave_log_error!("MINI-CONTROL-SHUTDOWN: reason=StateLockUnavailable");
            crate::signal_shutdown_with_origin(ShutdownOriginV1::StateLockUnavailable);
            break;
        }

        // Try to receive a data channel message
        match data_rx.try_recv() {
            Some(msg) => {
                // Decode the channel message
                match channel::decode_channel_msg(&msg) {
                    Some((msg_type, conn_id, payload)) => {
                        if !hook.on_data_channel_message(msg_type, conn_id, payload) {
                            let mut st = match crate::state().lock() {
                                Ok(st) => st,
                                Err(_) => {
                                    enclave_log_error!(
                                        "MINI-CONTROL-SHUTDOWN: reason=StateLockUnavailable"
                                    );
                                    crate::signal_shutdown_with_origin(
                                        ShutdownOriginV1::StateLockUnavailable,
                                    );
                                    break;
                                }
                            };
                            if let Some(ref mut srv) = st.ingress_server {
                                srv.handle_message(msg_type, conn_id, payload);
                                if let Some(reason) = srv.shutdown_reason() {
                                    enclave_log_error!(
                                        "MINI-CONTROL-SHUTDOWN: reason=Ingress({:?})",
                                        reason
                                    );
                                    let origin = match reason {
                                        crate::ratls::server::IngressShutdownReasonV1::ExplicitHttpRequest => {
                                            ShutdownOriginV1::IngressExplicitHttpRequest
                                        }
                                        crate::ratls::server::IngressShutdownReasonV1::OutputCreditBacklog => {
                                            ShutdownOriginV1::IngressOutputCreditBacklog
                                        }
                                    };
                                    crate::signal_shutdown_with_origin(origin);
                                }
                            }
                            drop(st);
                        }
                        apply_control_action(
                            hook.on_opportunity(ControlLoopOpportunity::DataChannelProgress),
                        );
                    }
                    None => {
                        enclave_log_error!(
                            "Failed to decode data channel message ({} bytes)",
                            msg.len()
                        );
                    }
                }
            }
            None => {
                apply_control_action(hook.on_opportunity(ControlLoopOpportunity::Idle));
                core::hint::spin_loop();
            }
        }
    }

    let _ = hook.on_opportunity(ControlLoopOpportunity::Shutdown);
    crate::signal_shutdown();
    if let Some(state) = crate::try_state() {
        if let Ok(mut st) = state.lock() {
            st.ingress_server = None;
        }
    }
    enclave_log_info!("Event loop exited");
    crate::shutdown_return_code()
}

/// Compatibility wrapper used by Mini's default composition.
///
/// This function blocks until shutdown. Honest compositions call
/// [`initialise_runtime_and_ingress`] and [`run_control_loop`] separately so
/// they can install their bounded control hook without copying bootstrap code.
pub fn finalize_and_run(config: &EnclaveConfig, sealed_cfg: &SealedConfig) -> i32 {
    if let Err(code) = initialise_runtime_and_ingress(config, sealed_cfg) {
        return code;
    }
    run_control_loop(&mut NoopControlLoopHook)
}

// ==========================================================================
//  ecall_execution_worker – long-lived execution TCS
// ==========================================================================

#[no_mangle]
pub extern "C" fn ecall_execution_worker(worker_id: u32) -> i32 {
    crate::run_execution_worker(worker_id)
}

// ==========================================================================
//  ecall_run – default implementation (feature-gated)
// ==========================================================================

/// Register Mini's single shared OCall vtable.
///
/// Custom compositions call this helper instead of copying the host-service
/// bindings. Role-specific Honest RPC façades are layered above the explicit
/// control/execution clients and do not replace this bootstrap registration.
pub fn register_ocall_vtable() {
    enclave_os_common::ocall::register(enclave_os_common::ocall::OcallVtable {
        net_tcp_listen: crate::ocall::net_tcp_listen,
        net_tcp_accept: crate::ocall::net_tcp_accept,
        net_tcp_connect: crate::ocall::net_tcp_connect,
        net_send: crate::ocall::net_send,
        net_recv: crate::ocall::net_recv,
        net_close: crate::ocall::net_close,
        kv_store_put: crate::ocall::kv_store_put,
        kv_store_get: |table, key| crate::ocall::kv_store_get(table, key, 0),
        kv_store_delete: crate::ocall::kv_store_delete,
        kv_store_list_keys: crate::ocall::kv_store_list_keys,
        get_current_time: crate::ocall::get_current_time,
        log: |level, msg| {
            let ll = match level {
                0 => enclave_os_common::types::LogLevel::Trace,
                1 => enclave_os_common::types::LogLevel::Debug,
                2 => enclave_os_common::types::LogLevel::Info,
                3 => enclave_os_common::types::LogLevel::Warn,
                _ => enclave_os_common::types::LogLevel::Error,
            };
            crate::ocall::log(ll, msg);
        },
        cert_store_register: |identity| {
            crate::ratls::cert_store::cert_store().register(identity);
        },
        cert_store_unregister: |hostname| {
            crate::ratls::cert_store::cert_store().unregister(hostname)
        },
    });
}

/// Apply Mini-owned OIDC and attestation-server configuration.
pub fn configure_core(config: &EnclaveConfig) {
    if let Some(ref oidc) = config.oidc {
        enclave_log_info!(
            "OIDC enabled: issuer={}, audience={}",
            oidc.issuer,
            oidc.audience
        );
        crate::set_oidc_config(oidc.clone());
        enclave_os_common::oidc::set_global_oidc_config(oidc.clone());
    } else {
        enclave_log_info!("OIDC not configured — auth layer disabled");
    }

    use enclave_os_common::protocol::AttestationServer;
    let servers: Vec<AttestationServer> = config
        .extra
        .get("attestation_servers")
        .map(|value| serde_json::from_value(value.clone()).unwrap_or_default())
        .unwrap_or_default();
    let (count, hash) = enclave_os_common::attestation_servers::init(servers);
    if count > 0 {
        let hash_hex = hash.map(|value| hex_encode(&value)).unwrap_or_default();
        enclave_log_info!(
            "Attestation servers: {} configured, hash={}",
            count,
            hash_hex,
        );
    }
}

/// Default `ecall_run` that registers modules based on enabled Cargo features.
///
/// With no module features: registers only HelloWorld (smoke test).
/// With `--features vault`: registers Egress + KvStore + Vault.
/// With `--features wasm`: registers Egress + KvStore + Wasm.
/// Mix and match freely — `--features vault,wasm` registers all four.
///
/// For fully custom module registration, disable this feature
/// (`default-features = false`) and provide your own `ecall_run` in an
/// external composition crate.
#[cfg(feature = "default-ecall")]
#[no_mangle]
pub extern "C" fn ecall_run(config_json: *const u8, config_len: u64) -> i32 {
    let _initialisation_guard = crate::CoreInitialisationGuard::new();

    register_ocall_vtable();

    let (config, sealed_cfg) = match init_enclave(config_json, config_len) {
        Ok(pair) => pair,
        Err(code) => return code,
    };

    configure_core(&config);

    let mut _module_count: u32 = 0;

    // ── Egress module (outbound HTTPS) ───────────────────────────────
    #[cfg(feature = "egress")]
    {
        let egress_pem = config
            .extra
            .get("egress_ca_bundle_hex")
            .and_then(|v| v.as_str())
            .and_then(|hex| hex_decode(hex));

        let (egress, cert_count) = match enclave_os_egress::EgressModule::new(egress_pem) {
            Ok(pair) => pair,
            Err(e) => {
                enclave_log_error!("EgressModule init failed: {}", e);
                return -30;
            }
        };
        enclave_log_info!("EgressModule: {} CA certs loaded", cert_count);
        crate::modules::register_module(Box::new(egress));
        _module_count += 1;
    }

    // ── KvStore module (sealed storage, MRENCLAVE-bound AES-256-GCM) ─
    #[cfg(feature = "kvstore")]
    {
        let kvstore = match enclave_os_kvstore::KvStoreModule::new(sealed_cfg.master_key()) {
            Ok(m) => m,
            Err(e) => {
                enclave_log_error!("KvStoreModule init failed: {}", e);
                return -31;
            }
        };
        crate::modules::register_module(Box::new(kvstore));
        _module_count += 1;
    }

    // ── Vault module (policy-gated secrets, JWT + mRA-TLS) ───────────
    #[cfg(feature = "vault")]
    {
        let vault = enclave_os_vault::VaultModule::new();
        crate::modules::register_module(Box::new(vault));
        _module_count += 1;
    }

    // ── WASM module (Component Model runtime) ────────────────────────
    #[cfg(feature = "wasm")]
    {
        let wasm = match enclave_os_wasm::WasmModule::new() {
            Ok(m) => m,
            Err(e) => {
                enclave_log_error!("WasmModule init failed: {}", e);
                return -34;
            }
        };
        // Leak to obtain a `'static` reference and install it as the
        // global handle so SDK host functions (e.g.
        // `set-attestation-extension`) can call back into the
        // module. The leaked allocation lives for the process
        // lifetime, which matches the module's intended scope.
        let wasm_static: &'static enclave_os_wasm::WasmModule = Box::leak(Box::new(wasm));
        enclave_os_wasm::install_global(wasm_static);
        crate::modules::register_module(Box::new(enclave_os_wasm::WasmModuleHandle(wasm_static)));
        _module_count += 1;
    }

    // ── FIDO2 module (WebAuthn authenticator ceremonies) ─────────────
    #[cfg(feature = "fido2")]
    {
        let rp_id = config
            .extra
            .get("fido2_rp_id")
            .and_then(|v| v.as_str())
            .unwrap_or("privasys.org")
            .to_string();
        let rp_name = config
            .extra
            .get("fido2_rp_name")
            .and_then(|v| v.as_str())
            .unwrap_or("Privasys")
            .to_string();
        // Optional explicit AAGUID allowlist from config.
        // Default: Privasys Wallet only. Use ["*"] for open mode.
        let aaguid_allowlist: Option<Vec<String>> = config
            .extra
            .get("fido2_aaguid_allowlist")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        let aaguid_ref = aaguid_allowlist.as_deref();
        let fido2 = enclave_os_fido2::Fido2Module::new(rp_id, rp_name, aaguid_ref);
        crate::modules::register_module(Box::new(fido2));
        _module_count += 1;
    }

    // ── Fallback: HelloWorld only (no module features enabled) ───────
    #[cfg(not(any(
        feature = "egress",
        feature = "kvstore",
        feature = "vault",
        feature = "wasm",
        feature = "fido2"
    )))]
    {
        crate::modules::register_module(Box::new(crate::modules::helloworld::HelloWorldModule));
        _module_count += 1;
    }

    enclave_log_info!("All modules registered ({} module(s))", _module_count);

    finalize_and_run(&config, &sealed_cfg)
}

// ==========================================================================
//  ecall_shutdown – graceful stop
// ==========================================================================

#[no_mangle]
pub extern "C" fn ecall_shutdown() -> i32 {
    enclave_log_info!("Pre-run/spare-TCS shutdown requested");
    crate::signal_shutdown_with_origin(ShutdownOriginV1::ExternalEcall);
    0
}

// ==========================================================================
//  Public types & helpers
// ==========================================================================

/// Enclave configuration parsed from JSON.
///
/// Core fields are deserialized into named fields. Module-specific config
/// is captured in [`extra`](Self::extra) via `#[serde(flatten)]`, so
/// adopters can read their module config with e.g.
/// `config.extra["egress_ca_bundle_hex"]`.
#[derive(serde::Deserialize)]
pub struct EnclaveConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_backlog")]
    pub backlog: i32,
    /// Hex-encoded DER of the intermediary CA certificate.
    pub ca_cert_hex: Option<String>,
    /// Hex-encoded PKCS#8 of the intermediary CA private key.
    pub ca_key_hex: Option<String>,
    /// OIDC provider configuration.  When present, all operations except
    /// `Healthz` require a valid bearer token in the JSON `"auth"` field.
    pub oidc: Option<enclave_os_common::oidc::OidcConfig>,
    /// Module-specific configuration (catch-all for unknown JSON fields).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn default_port() -> u16 {
    443
}
fn default_backlog() -> i32 {
    128
}

// ==========================================================================
//  Unified sealed config resolution
// ==========================================================================

/// Resolve the unified sealed configuration.
///
/// 1. Try to unseal an existing `SealedConfig` from disk.
/// 2. Override CA material if provided in the current config.
/// 3. Preserve any existing `module_data` from the sealed blob.
/// 4. Re-seal after modules have had a chance to update it
///    (done in [`finalize_and_run()`]).
///
/// This ensures that:
/// - First run requires `--ca-cert` + `--ca-key`.
/// - Subsequent restarts unseal everything automatically.
/// - Passing new config params on restart updates the sealed blob.
fn resolve_sealed_config(config: &EnclaveConfig) -> Result<SealedConfig, String> {
    // Try to unseal existing config from disk
    let existing = SealedConfig::unseal_from_disk().ok();
    let is_fresh = existing.is_none();

    // ── CA material: config params override sealed state ─────────────
    let (ca_cert_der, ca_key_pkcs8) = if let (Some(cert_hex), Some(key_hex)) =
        (&config.ca_cert_hex, &config.ca_key_hex)
    {
        let cert =
            hex_decode(cert_hex).ok_or_else(|| String::from("ca_cert_hex is not valid hex"))?;
        let key = hex_decode(key_hex).ok_or_else(|| String::from("ca_key_hex is not valid hex"))?;
        // Validate the key material early
        CaContext::from_parts(cert.clone(), key.clone())?;
        enclave_log_info!(
            "CA loaded from config (cert={} B, key={} B)",
            cert.len(),
            key.len()
        );
        (cert, key)
    } else if let Some(ref ex) = existing {
        enclave_log_info!("CA loaded from sealed config");
        (ex.ca_cert_der.clone(), ex.ca_key_pkcs8.clone())
    } else {
        return Err("No CA material found on disk and none provided in config. \
             Pass --ca-cert + --ca-key on first run."
            .into());
    };

    // ── Module data: preserve from existing sealed config ────────────
    let module_data = if let Some(ref ex) = existing {
        enclave_log_info!(
            "Loaded {} module data entries from sealed config",
            ex.module_data.len()
        );
        ex.module_data.clone()
    } else {
        BTreeMap::new()
    };

    //  Master encryption key: reuse existing or generate fresh
    let master_key: [u8; AEAD_KEY_SIZE] = if let Some(ref ex) = existing {
        enclave_log_info!("Master key loaded from sealed config");
        ex.master_key
    } else {
        let rng = ring::rand::SystemRandom::new();
        let mut key = [0u8; AEAD_KEY_SIZE];
        ring::rand::SecureRandom::fill(&rng, &mut key)
            .map_err(|_| String::from("Failed to generate master key"))?;
        enclave_log_info!("Generated fresh master encryption key");
        key
    };

    let cfg = SealedConfig {
        master_key,
        ca_cert_der,
        ca_key_pkcs8,
        module_data,
    };

    if is_fresh {
        enclave_log_info!("First run: sealed config created");
    } else {
        enclave_log_info!("Sealed config loaded from disk");
    }

    Ok(cfg)
}
