// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! enclave-os-enclave: trusted core running inside the SGX enclave.
//!
//! This crate provides the core infrastructure for SGX enclave applications:
//! - RA-TLS ingress TCP server with per-session attestation
//! - Pluggable module architecture ([`modules::EnclaveModule`] trait)
//! - Sealed (encrypted) configuration bound to MRENCLAVE
//! - Config Merkle tree for auditable attestation
//! - Cryptographic primitives (AEAD, sealing)
//! - OCALL wrappers for host communication
//!
//! Business logic modules (egress, KV store, WASM, etc.) live in
//! separate crates and register themselves via
//! [`modules::register_module()`].
//!
//! ## Composition
//!
//! Module registration is controlled by Cargo features.  The `default-ecall`
//! feature provides an `ecall_run` that registers whichever modules are
//! enabled:
//!
//! | Feature | Module |
//! |---------|--------|
//! | `egress` | EgressModule (outbound HTTPS + attestation URLs) |
//! | `kvstore` | KvStoreModule (sealed AES-256-GCM storage) |
//! | `vault` | VaultModule (implies kvstore + egress) |
//! | `wasm` | WasmModule (implies kvstore + egress) |
//!
//! CMake maps `-DENABLE_VAULT=ON` etc. to Cargo features automatically.
//!
//! For fully custom registration, disable `default-ecall` and provide
//! your own `ecall_run` in an external composition crate:
//! 1. Depends on `enclave-os-enclave` with `default-features = false`
//!    and `features = ["sgx"]` (disabling `default-ecall`).
//! 2. Provides its own `#[no_mangle] pub extern "C" fn ecall_run(…)`.
//! 3. Calls Mini's reusable OCall/core/bootstrap helpers, registers only its
//!    admitted modules, then calls [`ecall::initialise_runtime_and_ingress()`]
//!    and [`ecall::run_control_loop()`].
//!
//! **Build mode**: sysroot replacement.
//! `sgx_tstd` is compiled as `std` in a custom sysroot, so all crates
//! (including third-party deps like rustls) resolve `std` to `sgx_tstd`.
//! No `#![no_std]` or `extern crate sgx_tstd as std` is needed.

// sgx_types is provided by the sysroot (as a dependency of std/sgx_tstd).
// We access it via `extern crate` rather than a Cargo.toml dep to avoid
// having two copies of the same crate (sysroot vs. git).
extern crate sgx_trts;
extern crate sgx_types;

pub mod config_merkle;
pub mod cpuid_cache;
pub mod crypto;
pub mod ecall;
pub mod encauth;
pub mod modules;
pub mod ocall;
pub mod ratls;
pub mod rpc_client;
pub mod sealed_config;
pub mod sessionrelay;
// vaultkey registers the RA-TLS client-cert signer + attestation provider into
// egress, so it only compiles when egress is linked (vault/wasm/egress flavors).
// The base flavor has no egress, hence no vault-key path.
#[cfg(feature = "egress")]
pub mod vaultkey;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use std::sync::Mutex;

use crate::ratls::server::IngressServer;
use crate::rpc_client::RpcClient;

use enclave_os_common::core_phase::{CorePhase, CorePhaseCell};
use enclave_os_common::queue::{SpscConsumer, SpscProducer};

// ---------------------------------------------------------------------------
//  Global state
// ---------------------------------------------------------------------------

/// Control-plane RPC client (set by `ecall_init_control_channel`).
static CONTROL_RPC_CLIENT: OnceLock<RpcClient> = OnceLock::new();

/// Execution-plane RPC client (set by `ecall_init_execution_channel`).
static EXECUTION_RPC_CLIENT: OnceLock<RpcClient> = OnceLock::new();

/// Enclave-owned lifecycle barrier shared by the control and worker TCS.
static CORE_PHASE: CorePhaseCell = CorePhaseCell::new();

/// Optional adopter-owned execution worker.
pub type ExecutionWorkerHook = fn(worker_id: u32) -> i32;
static EXECUTION_WORKER_HOOK: OnceLock<ExecutionWorkerHook> = OnceLock::new();

/// Shutdown flag – set when `ecall_shutdown` is called.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Data channel: enclave → host TCP proxy (set by `ecall_init_data_channel`).
static DATA_TX: OnceLock<SpscProducer> = OnceLock::new();

/// Data channel: host TCP proxy → enclave (set by `ecall_init_data_channel`).
static DATA_RX: OnceLock<SpscConsumer> = OnceLock::new();

/// Configuration Merkle root – delegates to the [`config_merkle`] manifest.
///
/// Returns `None` before the tree is finalized during init.
pub fn config_merkle_root() -> Option<&'static [u8; 32]> {
    config_merkle::config_manifest().map(|m| m.root())
}

/// Global enclave application state, initialised by `ecall_run`.
pub struct EnclaveState {
    pub ingress_server: Option<IngressServer>,
}

static ENCLAVE_STATE: OnceLock<Mutex<EnclaveState>> = OnceLock::new();

/// Global OIDC configuration (set by `ecall_run` if `oidc` is in config).
static OIDC_CONFIG: OnceLock<enclave_os_common::oidc::OidcConfig> = OnceLock::new();

/// Set the global OIDC configuration.
pub fn set_oidc_config(config: enclave_os_common::oidc::OidcConfig) {
    let _ = OIDC_CONFIG.set(config);
}

/// Get the global OIDC configuration, if configured.
pub fn oidc_config() -> Option<&'static enclave_os_common::oidc::OidcConfig> {
    OIDC_CONFIG.get()
}

/// Get a reference to the global enclave state.
pub fn state() -> &'static Mutex<EnclaveState> {
    ENCLAVE_STATE.get().expect("Enclave not initialised")
}

/// Get the enclave state only after control initialisation reaches that step.
pub fn try_state() -> Option<&'static Mutex<EnclaveState>> {
    ENCLAVE_STATE.get()
}

/// Compatibility accessor for Mini modules, which always use control RPC.
pub fn rpc_client_ref() -> &'static RpcClient {
    control_rpc_client_ref()
}

/// Get the control-plane RPC client.
pub fn control_rpc_client_ref() -> &'static RpcClient {
    CONTROL_RPC_CLIENT
        .get()
        .expect("Control RPC channel not initialised")
}

/// Get the execution-plane RPC client.
pub fn execution_rpc_client_ref() -> &'static RpcClient {
    EXECUTION_RPC_CLIENT
        .get()
        .expect("Execution RPC channel not initialised")
}

/// Get a reference to the data channel producer (enclave → host).
pub fn data_tx() -> &'static SpscProducer {
    DATA_TX.get().expect("Data channel not initialised")
}

/// Get a reference to the data channel consumer (host → enclave).
pub fn data_rx() -> &'static SpscConsumer {
    DATA_RX.get().expect("Data channel not initialised")
}

/// Check if shutdown has been requested.
pub fn is_shutdown() -> bool {
    SHUTDOWN.load(Ordering::Acquire)
}

/// Initialise the enclave state.
pub fn init_state() -> Result<(), i32> {
    let st = EnclaveState {
        ingress_server: None,
    };
    ENCLAVE_STATE.set(Mutex::new(st)).map_err(|_| -1)?;
    Ok(())
}

/// Store the control-plane RPC client.
pub fn set_control_rpc_client(client: RpcClient) -> Result<(), i32> {
    CONTROL_RPC_CLIENT.set(client).map_err(|_| -1)
}

/// Store the execution-plane RPC client.
pub fn set_execution_rpc_client(client: RpcClient) -> Result<(), i32> {
    EXECUTION_RPC_CLIENT.set(client).map_err(|_| -1)
}

/// Store the data channel endpoints. Called once from `ecall_init_data_channel`.
pub fn set_data_channel(tx: SpscProducer, rx: SpscConsumer) -> Result<(), i32> {
    DATA_TX.set(tx).map_err(|_| -1)?;
    DATA_RX.set(rx).map_err(|_| -1)?;
    Ok(())
}

/// Signal shutdown.
pub fn signal_shutdown() {
    SHUTDOWN.store(true, Ordering::Release);
    CORE_PHASE.request_shutdown();
}

/// Return the current enclave lifecycle phase.
pub fn core_phase() -> CorePhase {
    CORE_PHASE.load()
}

/// Publish successful control-plane initialisation.
pub fn publish_core_running() -> Result<(), CorePhase> {
    CORE_PHASE.publish_running()
}

/// Publish failed control-plane initialisation.
pub fn publish_core_failed() {
    let _ = CORE_PHASE.publish_failed();
}

/// Guards an initialisation path so an early return releases a waiting
/// execution TCS as [`CorePhase::Failed`].
pub struct CoreInitialisationGuard;

impl CoreInitialisationGuard {
    pub fn new() -> Self {
        Self
    }
}

impl Drop for CoreInitialisationGuard {
    fn drop(&mut self) {
        if CORE_PHASE.load() == CorePhase::Initialising {
            let _ = CORE_PHASE.publish_failed();
        }
    }
}

/// Register the sole adopter-owned execution worker.
pub fn register_execution_worker_hook(hook: ExecutionWorkerHook) -> Result<(), i32> {
    EXECUTION_WORKER_HOOK.set(hook).map_err(|_| -1)
}

/// Run worker zero on the execution TCS.
pub fn run_execution_worker(worker_id: u32) -> i32 {
    if worker_id != 0 {
        return -61;
    }

    loop {
        match CORE_PHASE.load() {
            CorePhase::Initialising => core::hint::spin_loop(),
            CorePhase::Failed => return -62,
            CorePhase::ShuttingDown => {
                let _ = CORE_PHASE.publish_stopped();
                return 0;
            }
            CorePhase::Stopped => return 0,
            CorePhase::Running => break,
        }
    }

    if let Some(hook) = EXECUTION_WORKER_HOOK.get() {
        let result = hook(worker_id);
        if CORE_PHASE.load() == CorePhase::Running {
            signal_shutdown();
        }
        if CORE_PHASE.load() == CorePhase::ShuttingDown {
            let _ = CORE_PHASE.publish_stopped();
        }
        return result;
    }

    // Mini itself has no execution work. An adopter installs the hook above;
    // the default worker occupies the second TCS and observes lifecycle.
    loop {
        match CORE_PHASE.load() {
            CorePhase::Running => core::hint::spin_loop(),
            CorePhase::ShuttingDown => {
                let _ = CORE_PHASE.publish_stopped();
                return 0;
            }
            CorePhase::Stopped => return 0,
            CorePhase::Failed => return -62,
            CorePhase::Initialising => core::hint::spin_loop(),
        }
    }
}
