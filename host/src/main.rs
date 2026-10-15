// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! enclave-os-host: the untrusted host application.
//!
//! Responsibilities:
//! - Load and manage the SGX enclave
//! - Allocate shared-memory SPSC queues for RPC
//! - Run the RPC dispatcher (reads enclave requests, dispatches to handlers)
//! - Implement the single OCALL: `ocall_notify()`
//! - Provide the CLI entry point

mod build_contract;
#[cfg(all(target_os = "linux", not(sgx_mode_sim), not(feature = "mock")))]
mod dcap;
mod dispatcher;
mod dispatcher_wake;
mod enclave;
mod kvstore;
mod net;
#[cfg(target_os = "linux")]
mod ocall_alignment;
mod ocall_impl;
#[cfg(feature = "diagnostic-worker-storage-rpc")]
mod storage_rpc_profile;
mod tcp_proxy;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use log::{error, info};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

use enclave::SharedChannel;
use enclave_os_common::queue::DEFAULT_QUEUE_CAPACITY;
use enclave_os_common::rpc::RpcRole;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum EcallStartOrder {
    WorkerFirst,
    ControlFirst,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum EnclaveTestSelection {
    All,
    Empty,
    Failure,
    Panic,
    Invalid,
}

const EXPECTED_SIGNED_ENCLAVE_TESTS: u8 = 5;

impl EnclaveTestSelection {
    const fn code(self) -> u32 {
        match self {
            Self::All => 0,
            Self::Empty => 1,
            Self::Failure => 2,
            Self::Panic => 3,
            Self::Invalid => u32::MAX,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Empty => "empty",
            Self::Failure => "failure",
            Self::Panic => "panic",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "enclave-os-host",
    about = "Host for enclave-os-mini SGX application"
)]
struct Cli {
    /// Print compiled capabilities without loading an enclave or opening stores.
    #[arg(long)]
    build_contract: bool,

    /// Path to the signed enclave binary (.signed.so)
    #[arg(short, long, default_value = "enclave.signed.so")]
    enclave_path: String,

    /// Port for the RA-TLS ingress server
    #[arg(short, long, default_value_t = 443)]
    port: u16,

    /// Public literal IP advertised by a cluster after explicit --init.
    /// This is a transport assertion only; membership authority remains in
    /// the enclave. If omitted, local status remains available but cluster
    /// initialization is rejected.
    #[arg(long)]
    peer_advertise_ip: Option<IpAddr>,

    /// TCP listen backlog
    #[arg(short, long, default_value_t = 128)]
    backlog: i32,

    /// Internal Unix socket carrying TLS ciphertext for local control.
    /// The enclave, not this host process, terminates the TLS session.
    #[arg(long)]
    local_control_socket: Option<PathBuf>,
    /// Optional second listen port for cluster peer links.
    /// Inbound connections on this port are routed to the enclave's
    /// peer-link layer instead of the HTTPS ingress.
    #[arg(long)]
    peer_port: Option<u16>,

    /// Path for the KV store data directory
    #[arg(short, long, default_value = "./kvdata")]
    kv_path: String,

    /// Path to a PEM bundle of trusted root CAs for HTTPS egress.
    /// e.g. /etc/ssl/certs/ca-certificates.crt or a custom bundle.
    /// If omitted, the enclave cannot make outbound HTTPS requests.
    #[arg(long)]
    egress_ca_bundle: Option<String>,

    /// Comma-separated list of attestation server URLs for remote quote
    /// verification.  e.g. "https://as.privasys.org/verify,https://as.customer.com/verify"
    /// The list is hashed into the config Merkle tree (leaf: egress.attestation_servers)
    /// and embedded as X.509 OID 1.3.6.1.4.1.65230.2.3.
    #[arg(long, value_delimiter = ',')]
    attestation_servers: Option<Vec<String>>,

    /// Path to a file holding an OIDC bearer token for the attestation
    /// server(s). Applied to every URL in --attestation-servers, so the
    /// enclave can authenticate its own quote-verification calls to servers
    /// that require it (e.g. as.privasys.org, which 401s without a bearer).
    /// The token is a runtime secret: it is NOT hashed into the config
    /// Merkle tree (only the URL list is — see common/attestation_servers).
    #[arg(long)]
    attestation_token_file: Option<String>,

    /// OIDC issuer URL (e.g. https://privasys.id).
    /// When set (together with --oidc-audience), enables OIDC-based RBAC.
    #[arg(long)]
    oidc_issuer: Option<String>,

    /// OIDC audience claim (e.g. `privasys-platform`).
    /// Required when --oidc-issuer is set.
    #[arg(long)]
    oidc_audience: Option<String>,

    /// Extra enclave config as a JSON object, merged into the config
    /// passed to ecall_run.
    #[arg(long)]
    extra: Option<String>,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,

    /// Long-ECALL entry order. Both orders are supported by the enclave-owned
    /// CorePhase barrier.
    #[arg(long, value_enum, default_value_t = EcallStartOrder::WorkerFirst)]
    ecall_start_order: EcallStartOrder,

    /// Run the release-disabled signed-enclave regression registry and exit.
    /// Negative selections exist only to prove fail-closed gate propagation.
    #[arg(long, value_enum)]
    enclave_test_selection: Option<EnclaveTestSelection>,
}

fn spawn_control_ecall(enclave_id: u64, config_bytes: Vec<u8>) -> Result<thread::JoinHandle<i32>> {
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
    let handle = thread::Builder::new()
        .name("enclave-control".into())
        .spawn(move || {
            let _ = entered_tx.send(());
            let result = enclave::call_ecall_run(enclave_id, &config_bytes);
            if result == 0 {
                info!("Control ECALL returned: code=0");
            } else {
                error!("Control ECALL returned: code={result}");
            }
            result
        })?;
    entered_rx
        .recv()
        .map_err(|_| anyhow::anyhow!("Control ECALL thread failed before entry"))?;
    Ok(handle)
}

fn spawn_execution_ecall(enclave_id: u64) -> Result<thread::JoinHandle<i32>> {
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
    let handle = thread::Builder::new()
        .name("enclave-execution-worker".into())
        .spawn(move || {
            let _ = entered_tx.send(());
            let result = enclave::call_ecall_execution_worker(enclave_id, 0);
            if result == 0 {
                info!("Execution worker ECALL returned: code=0");
            } else {
                error!("Execution worker ECALL returned: code={result}");
            }
            result
        })?;
    entered_rx
        .recv()
        .map_err(|_| anyhow::anyhow!("Execution ECALL thread failed before entry"))?;
    Ok(handle)
}

fn run_enclave_tests(enclave_path: &str, selection: EnclaveTestSelection) -> Result<()> {
    // This single-use CLI exits after the suite. Mini retains the enclave in a
    // process-lifetime OnceLock; its destroy helper does not drop that owner.
    // Retain this bounded real channel for the same lifetime, including errors.
    // No proxy or network worker is started for the fixture.
    let data_channel = Box::leak(Box::new(SharedChannel::new(DEFAULT_QUEUE_CAPACITY)));
    let enclave_id = enclave::create_enclave(enclave_path)?;
    let ret = enclave::call_ecall_init_data_channel(
        enclave_id,
        data_channel.enc_to_host_header as *mut u8,
        data_channel.enc_to_host_buf,
        data_channel.host_to_enc_header as *mut u8,
        data_channel.host_to_enc_buf,
        data_channel.capacity,
    );
    if ret != 0 {
        enclave::destroy_enclave(enclave_id);
        anyhow::bail!("Failed to initialise enclave test data channel: {ret}");
    }
    let result = enclave::call_ecall_enclave_tests(enclave_id, selection.code());
    enclave::destroy_enclave(enclave_id);
    let packed = result?;

    let code = u8::try_from(packed >> 24).expect("packed result code is one byte");
    let collected = u8::try_from((packed >> 16) & 0xff).expect("packed collection is one byte");
    let executed = u8::try_from((packed >> 8) & 0xff).expect("packed execution is one byte");
    let failed = u8::try_from(packed & 0xff).expect("packed failure count is one byte");
    println!(
        "TEACLAVE-SIM-HOST: selection={} collected={} executed={} failed={} code={}",
        selection.label(),
        collected,
        executed,
        failed,
        code
    );

    if code != 0 {
        anyhow::bail!(
            "signed-enclave registry rejected selection {} with code {}",
            selection.label(),
            code
        );
    }
    if selection != EnclaveTestSelection::All
        || collected != EXPECTED_SIGNED_ENCLAVE_TESTS
        || executed != EXPECTED_SIGNED_ENCLAVE_TESTS
        || failed != 0
    {
        anyhow::bail!(
            "signed-enclave registry returned an invalid successful result: selection={} collected={} executed={} failed={}",
            selection.label(),
            collected,
            executed,
            failed
        );
    }
    Ok(())
}

fn validate_long_lived_ecall_results(control: i32, execution: i32) -> Result<()> {
    if control != 0 || execution != 0 {
        anyhow::bail!(
            "enclave ECALL failure: control={} execution={}",
            control,
            execution
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.build_contract {
        println!("{}", build_contract::compiled());
        return Ok(());
    }

    // Initialise logging
    let log_level = if cli.debug { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    info!("enclave-os-host starting");
    info!("Enclave path : {}", cli.enclave_path);
    info!("RA-TLS port  : {}", cli.port);
    info!("KV store path: {}", cli.kv_path);

    if let Some(selection) = cli.enclave_test_selection {
        return run_enclave_tests(&cli.enclave_path, selection);
    }

    // Initialise the KV store backend
    kvstore::init(&cli.kv_path)?;

    // Create the SGX enclave
    let enclave_id = enclave::create_enclave(&cli.enclave_path)?;
    info!("Enclave created, id = {}", enclave_id);

    // Allocate physically distinct shared-memory RPC pairs. Their endpoints
    // have disjoint SPSC owners for the lifetime of the enclave.
    let control_channel = SharedChannel::new(DEFAULT_QUEUE_CAPACITY);
    info!(
        "Control RPC channel allocated (capacity = {} bytes per queue)",
        DEFAULT_QUEUE_CAPACITY
    );

    let execution_channel = SharedChannel::new(DEFAULT_QUEUE_CAPACITY);
    info!(
        "Execution RPC channel allocated (capacity = {} bytes per queue)",
        DEFAULT_QUEUE_CAPACITY
    );

    // Allocate shared-memory SPSC queues for data channel (TCP proxy ↔ enclave)
    let data_channel = SharedChannel::new(DEFAULT_QUEUE_CAPACITY);
    info!(
        "Data channel allocated (capacity = {} bytes per queue)",
        DEFAULT_QUEUE_CAPACITY
    );

    // Initialise every channel before either long-lived ECALL may enter.
    let ret = enclave::call_ecall_init_control_channel(
        enclave_id,
        control_channel.enc_to_host_header as *mut u8,
        control_channel.enc_to_host_buf,
        control_channel.host_to_enc_header as *mut u8,
        control_channel.host_to_enc_buf,
        control_channel.capacity,
    );
    if ret != 0 {
        error!("ecall_init_control_channel failed: {}", ret);
        enclave::destroy_enclave(enclave_id);
        anyhow::bail!("Failed to initialise enclave control RPC channel");
    }
    info!("Enclave control RPC channel initialised");

    let ret = enclave::call_ecall_init_execution_channel(
        enclave_id,
        execution_channel.enc_to_host_header as *mut u8,
        execution_channel.enc_to_host_buf,
        execution_channel.host_to_enc_header as *mut u8,
        execution_channel.host_to_enc_buf,
        execution_channel.capacity,
    );
    if ret != 0 {
        error!("ecall_init_execution_channel failed: {}", ret);
        enclave::destroy_enclave(enclave_id);
        anyhow::bail!("Failed to initialise enclave execution RPC channel");
    }
    info!("Enclave execution RPC channel initialised");

    // Pass data channel queue pointers to the enclave
    let ret = enclave::call_ecall_init_data_channel(
        enclave_id,
        data_channel.enc_to_host_header as *mut u8,
        data_channel.enc_to_host_buf,
        data_channel.host_to_enc_header as *mut u8,
        data_channel.host_to_enc_buf,
        data_channel.capacity,
    );
    if ret != 0 {
        error!("ecall_init_data_channel failed: {}", ret);
        enclave::destroy_enclave(enclave_id);
        anyhow::bail!("Failed to initialise enclave data channel");
    }
    info!("Enclave data channel initialised");

    // Create host-side queue endpoints (consumer for requests, producer for responses)
    let (control_request_rx, control_response_tx) = unsafe { control_channel.host_endpoints() };
    let (execution_request_rx, execution_response_tx) =
        unsafe { execution_channel.host_endpoints() };

    // Create host-side data channel endpoints
    // For data channel: host writes to host_to_enc (raw TCP → enclave),
    // host reads from enc_to_host (TLS output from enclave)
    let (data_from_enc_rx, data_to_enc_tx) = unsafe { data_channel.host_endpoints() };

    // Set up shared shutdown flag
    let shutdown = Arc::new(AtomicBool::new(false));

    // Install retained notifications before either dispatcher or ECALL starts.
    let dispatcher_wake = Arc::new(dispatcher_wake::DispatcherWake::new());
    ocall_impl::set_dispatcher_wake(dispatcher_wake.clone());

    // Spawn one named dispatcher per RPC pair.
    let shutdown_clone = shutdown.clone();
    let wake = dispatcher_wake.clone();
    let control_dispatcher_handle = thread::Builder::new()
        .name("control-rpc-dispatcher".into())
        .spawn(move || {
            let dispatcher = dispatcher::RpcDispatcher::new(
                RpcRole::Control,
                control_request_rx,
                control_response_tx,
                shutdown_clone,
                wake,
            );
            dispatcher.run();
        })?;
    info!("Control RPC dispatcher thread started");

    let shutdown_clone = shutdown.clone();
    let wake = dispatcher_wake.clone();
    let execution_dispatcher_handle = thread::Builder::new()
        .name("execution-rpc-dispatcher".into())
        .spawn(move || {
            let dispatcher = dispatcher::RpcDispatcher::new(
                RpcRole::Execution,
                execution_request_rx,
                execution_response_tx,
                shutdown_clone,
                wake,
            );
            dispatcher.run();
        })?;
    info!("Execution RPC dispatcher thread started");

    // Spawn the TCP proxy thread
    let proxy_port = cli.port;
    let proxy_backlog = cli.backlog;
    let local_control_socket = cli.local_control_socket.clone();
    let proxy_peer_port = cli.peer_port;
    let shutdown_clone = shutdown.clone();
    let proxy_handle = thread::Builder::new()
        .name("tcp-proxy".into())
        .spawn(move || {
            match tcp_proxy::TcpProxy::new_with_listeners(
                proxy_port,
                proxy_backlog,
                local_control_socket,
                proxy_peer_port,
                data_to_enc_tx,
                data_from_enc_rx,
                shutdown_clone,
            ) {
                Ok(mut proxy) => proxy.run(),
                Err(e) => {
                    error!("TCP proxy failed to start: {}", e);
                }
            }
        })?;
    info!("TCP proxy thread started on port {}", cli.port);

    // Build config JSON for the enclave
    let mut config = serde_json::json!({
        "port": cli.port,
        "backlog": cli.backlog,
    });
    if let Some(address) = cli.peer_advertise_ip {
        config["cluster_control_peer_ip"] = serde_json::Value::String(address.to_string());
    }

    // If an egress CA bundle is provided, read it and hex-encode for the enclave
    if let Some(ref bundle_path) = cli.egress_ca_bundle {
        let pem_bytes = std::fs::read(bundle_path).map_err(|e| {
            anyhow::anyhow!("Failed to read egress CA bundle '{}': {}", bundle_path, e)
        })?;
        info!(
            "Egress CA bundle: {} bytes from {}",
            pem_bytes.len(),
            bundle_path
        );
        config["egress_ca_bundle_hex"] = serde_json::Value::String(hex::encode(&pem_bytes));
    }

    // If attestation server URLs are provided, build AttestationServer objects.
    if let Some(ref servers) = cli.attestation_servers {
        info!("Attestation servers: {:?}", servers);

        // Optional bearer token shared by all configured servers. Read from
        // a file so it never appears in the process args / launch command.
        let token: Option<String> = match cli.attestation_token_file {
            Some(ref path) => {
                let t = std::fs::read_to_string(path)
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to read attestation token file '{}': {}", path, e)
                    })?
                    .trim()
                    .to_string();
                if t.is_empty() {
                    anyhow::bail!("attestation token file '{}' is empty", path);
                }
                info!("Attestation bearer token: {} chars from {}", t.len(), path);
                Some(t)
            }
            None => None,
        };

        let server_objects: Vec<serde_json::Value> = servers
            .iter()
            .map(|url| match token {
                Some(ref t) => serde_json::json!({ "url": url, "token": t }),
                None => serde_json::json!({ "url": url }),
            })
            .collect();

        config["attestation_servers"] = serde_json::to_value(&server_objects)
            .map_err(|e| anyhow::anyhow!("Failed to serialise attestation servers: {}", e))?;
    }

    // OIDC configuration
    if let Some(ref issuer) = cli.oidc_issuer {
        let audience = cli.oidc_audience.as_deref().ok_or_else(|| {
            anyhow::anyhow!("--oidc-audience is required when --oidc-issuer is set")
        })?;
        info!("OIDC enabled: issuer={}, audience={}", issuer, audience);
        config["oidc"] = serde_json::json!({
            "issuer": issuer,
            "audience": audience,
        });
    } else if cli.oidc_audience.is_some() {
        anyhow::bail!("--oidc-issuer is required when --oidc-audience is set");
    }

    // Merge --extra JSON object into the enclave config.
    if let Some(ref extra) = cli.extra {
        match serde_json::from_str::<serde_json::Value>(extra) {
            Ok(serde_json::Value::Object(map)) => {
                for (k, v) in map {
                    if config.get(&k).is_some()
                        || k.starts_with("c3_")
                        || k.starts_with("s1_")
                        || k.starts_with("s1_2_")
                        || k.starts_with("s2_")
                    {
                        anyhow::bail!("--extra cannot override reserved configuration key: {}", k);
                    }
                    config[k] = v;
                }
            }
            _ => anyhow::bail!("--extra must be a JSON object"),
        }
    }

    let config_bytes = serde_json::to_vec(&config)?;

    let (control_handle, execution_handle) = match cli.ecall_start_order {
        EcallStartOrder::WorkerFirst => {
            let execution = spawn_execution_ecall(enclave_id)?;
            info!("Execution worker ECALL entered first");
            let control = spawn_control_ecall(enclave_id, config_bytes)?;
            (control, execution)
        }
        EcallStartOrder::ControlFirst => {
            let control = spawn_control_ecall(enclave_id, config_bytes)?;
            info!("Control ECALL entered first");
            let execution = spawn_execution_ecall(enclave_id)?;
            (control, execution)
        }
    };
    info!("Both long-lived ECALLs entered (in-band ingress shutdown to stop)");

    let control_ret = control_handle
        .join()
        .map_err(|_| anyhow::anyhow!("Control ECALL host thread panicked"))?;
    if control_ret != 0 {
        error!("ecall_run returned: {}", control_ret);
    }

    let execution_ret = execution_handle
        .join()
        .map_err(|_| anyhow::anyhow!("Execution ECALL host thread panicked"))?;
    if execution_ret != 0 {
        error!("ecall_execution_worker returned: {}", execution_ret);
    }
    let ecall_result = validate_long_lived_ecall_results(control_ret, execution_ret);

    // Signal dispatcher and proxy to stop
    dispatcher_wake.shutdown(&shutdown);

    // Both long-lived ECALLs have returned through the in-band lifecycle.
    info!("Waiting for control dispatcher thread...");
    let _ = control_dispatcher_handle.join();
    info!("Waiting for execution dispatcher thread...");
    let _ = execution_dispatcher_handle.join();
    info!("Waiting for TCP proxy thread...");
    let _ = proxy_handle.join();
    enclave::destroy_enclave(enclave_id);
    info!("Enclave destroyed. Goodbye.");

    // Keep channels alive until after enclave is destroyed
    drop(control_channel);
    drop(execution_channel);
    drop(data_channel);

    ecall_result
}

#[cfg(test)]
mod tests {
    use super::validate_long_lived_ecall_results;

    #[test]
    fn long_lived_ecall_success_requires_both_zero_results() {
        assert!(validate_long_lived_ecall_results(0, 0).is_ok());
        assert!(validate_long_lived_ecall_results(-83, 0).is_err());
        assert!(validate_long_lived_ecall_results(0, -79).is_err());
        assert!(validate_long_lived_ecall_results(-83, -79).is_err());
    }
}
