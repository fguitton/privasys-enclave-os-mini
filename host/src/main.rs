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

#[cfg(target_os = "linux")]
mod dcap;
mod dispatcher;
mod enclave;
mod kvstore;
mod net;
mod ocall_impl;
mod tcp_proxy;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use log::{error, info};
use std::sync::atomic::{AtomicBool, Ordering};
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

#[derive(Parser, Debug)]
#[command(
    name = "enclave-os-host",
    about = "Host for enclave-os-mini SGX application"
)]
struct Cli {
    /// Path to the signed enclave binary (.signed.so)
    #[arg(short, long, default_value = "enclave.signed.so")]
    enclave_path: String,

    /// Port for the RA-TLS ingress server
    #[arg(short, long, default_value_t = 443)]
    port: u16,

    /// TCP listen backlog
    #[arg(short, long, default_value_t = 128)]
    backlog: i32,

    /// Path for the KV store data directory
    #[arg(short, long, default_value = "./kvdata")]
    kv_path: String,

    /// Path to intermediary CA certificate (DER or PEM).
    /// Required on first run; sealed to disk for subsequent restarts.
    #[arg(long)]
    ca_cert: Option<String>,

    /// Path to intermediary CA private key (PKCS#8 DER or PEM).
    /// Required on first run; sealed to disk for subsequent restarts.
    #[arg(long)]
    ca_key: Option<String>,

    /// Path to a PEM bundle of trusted root CAs for HTTPS egress.
    /// e.g. /etc/ssl/certs/ca-certificates.crt or a custom bundle.
    /// If omitted, the enclave cannot make outbound HTTPS requests.
    #[arg(long)]
    egress_ca_bundle: Option<String>,

    /// Comma-separated list of attestation server URLs for remote quote
    /// verification.  e.g. "https://as.privasys.org/verify,https://as.customer.com/verify"
    /// The list is hashed into the config Merkle tree (leaf: egress.attestation_servers)
    /// and embedded as X.509 OID 1.3.6.1.4.1.65230.2.7.
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

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,

    /// Long-ECALL entry order. Both orders are supported by the enclave-owned
    /// CorePhase barrier.
    #[arg(long, value_enum, default_value_t = EcallStartOrder::WorkerFirst)]
    ecall_start_order: EcallStartOrder,

    /// S1.2 test-only synthetic worker budget. Ignored by legacy compositions.
    #[arg(long)]
    s1_2_synthetic_work_units: Option<u64>,

    /// S2.0 test-only private executor fixture. Ignored by legacy
    /// compositions and absent unless explicitly requested.
    #[arg(long)]
    s2_0_private_fixture: bool,

    /// Test-only literal IP:port for the incremental appraised peer probe.
    #[arg(long)]
    s1_peer_probe_endpoint: Option<String>,

    /// Development-only physical-cluster node ID (1..=5).
    #[arg(long)]
    c3_development_node_id: Option<u64>,

    /// Development-only fixed network ID as 32 hexadecimal characters.
    #[arg(long)]
    c3_development_network_id: Option<String>,

    /// Five `node-id=IP:port` entries for the physical cluster.
    #[arg(long, value_delimiter = ',')]
    c3_development_peer_endpoints: Option<Vec<String>>,

    /// File containing exactly two P-256 reviewer public keys, one hex key
    /// per line. Private reviewer keys never enter the host configuration.
    #[arg(long)]
    c3_development_reviewer_keys_file: Option<String>,

    /// Optional development supplier identity as 32 hexadecimal characters.
    /// It is accepted only together with its Ed25519 public key.
    #[arg(long)]
    c3_development_component_supplier_id: Option<String>,

    /// Optional development supplier Ed25519 public key as 64 hexadecimal
    /// characters. Private supplier material remains outside the node.
    #[arg(long)]
    c3_development_component_supplier_public_key: Option<String>,

    /// Development-only fault: change this node's post-WASM receipt vector.
    /// This can only deny progress and is accepted only with the complete C3
    /// development-cluster profile.
    #[arg(long)]
    c3_development_inject_divergent_receipt: bool,
}

fn spawn_control_ecall(enclave_id: u64, config_bytes: Vec<u8>) -> Result<thread::JoinHandle<i32>> {
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
    let handle = thread::Builder::new()
        .name("enclave-control".into())
        .spawn(move || {
            let _ = entered_tx.send(());
            enclave::call_ecall_run(enclave_id, &config_bytes)
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
            enclave::call_ecall_execution_worker(enclave_id, 0)
        })?;
    entered_rx
        .recv()
        .map_err(|_| anyhow::anyhow!("Execution ECALL thread failed before entry"))?;
    Ok(handle)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialise logging
    let log_level = if cli.debug { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    info!("enclave-os-host starting");
    info!("Enclave path : {}", cli.enclave_path);
    info!("RA-TLS port  : {}", cli.port);
    info!("KV store path: {}", cli.kv_path);

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

    // Store notify flag for the OCALL handler
    ocall_impl::set_notify_flag(shutdown.clone());

    // Spawn one named dispatcher per RPC pair.
    let shutdown_clone = shutdown.clone();
    let control_dispatcher_handle = thread::Builder::new()
        .name("control-rpc-dispatcher".into())
        .spawn(move || {
            let dispatcher = dispatcher::RpcDispatcher::new(
                RpcRole::Control,
                control_request_rx,
                control_response_tx,
                shutdown_clone,
            );
            dispatcher.run();
        })?;
    info!("Control RPC dispatcher thread started");

    let shutdown_clone = shutdown.clone();
    let execution_dispatcher_handle = thread::Builder::new()
        .name("execution-rpc-dispatcher".into())
        .spawn(move || {
            let dispatcher = dispatcher::RpcDispatcher::new(
                RpcRole::Execution,
                execution_request_rx,
                execution_response_tx,
                shutdown_clone,
            );
            dispatcher.run();
        })?;
    info!("Execution RPC dispatcher thread started");

    // Spawn the TCP proxy thread
    let proxy_port = cli.port;
    let proxy_backlog = cli.backlog;
    let shutdown_clone = shutdown.clone();
    let proxy_handle = thread::Builder::new()
        .name("tcp-proxy".into())
        .spawn(move || {
            match tcp_proxy::TcpProxy::new(
                proxy_port,
                proxy_backlog,
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

    // If intermediary CA cert + key are provided, read them and add as hex
    if let (Some(cert_path), Some(key_path)) = (&cli.ca_cert, &cli.ca_key) {
        let cert_der = read_pem_or_der(cert_path, "CERTIFICATE")
            .map_err(|e| anyhow::anyhow!("Failed to read CA cert '{}': {}", cert_path, e))?;
        let key_der = read_pem_or_der(key_path, "PRIVATE KEY")
            .map_err(|e| anyhow::anyhow!("Failed to read CA key '{}': {}", key_path, e))?;
        info!(
            "CA cert: {} bytes (DER), CA key: {} bytes (DER)",
            cert_der.len(),
            key_der.len()
        );
        config["ca_cert_hex"] = serde_json::Value::String(hex::encode(&cert_der));
        config["ca_key_hex"] = serde_json::Value::String(hex::encode(&key_der));
    } else if cli.ca_cert.is_some() || cli.ca_key.is_some() {
        anyhow::bail!("Both --ca-cert and --ca-key must be specified together");
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

    if let Some(work_units) = cli.s1_2_synthetic_work_units {
        config["s1_2_synthetic_work_units"] = serde_json::Value::from(work_units);
    }
    if cli.s2_0_private_fixture {
        config["s2_0_private_fixture"] = serde_json::Value::Bool(true);
    }
    if let Some(endpoint) = cli.s1_peer_probe_endpoint {
        config["s1_peer_probe_endpoint"] = serde_json::Value::String(endpoint);
    }

    let c3_arguments = [
        cli.c3_development_node_id.is_some(),
        cli.c3_development_network_id.is_some(),
        cli.c3_development_peer_endpoints.is_some(),
        cli.c3_development_reviewer_keys_file.is_some(),
    ];
    if c3_arguments.iter().any(|present| *present) && !c3_arguments.iter().all(|present| *present) {
        anyhow::bail!("all C3 development-cluster arguments are required together");
    }
    if cli.c3_development_inject_divergent_receipt && !c3_arguments.iter().all(|present| *present) {
        anyhow::bail!("C3 divergent-receipt injection requires the complete development profile");
    }
    if cli.c3_development_component_supplier_id.is_some()
        != cli.c3_development_component_supplier_public_key.is_some()
    {
        anyhow::bail!("component supplier ID and public key must be configured together");
    }
    if cli.c3_development_component_supplier_id.is_some()
        && !c3_arguments.iter().all(|present| *present)
    {
        anyhow::bail!("component supplier configuration requires the complete C3 profile");
    }
    if let Some(node_id) = cli.c3_development_node_id {
        if !(1..=5).contains(&node_id) {
            anyhow::bail!("--c3-development-node-id must be in 1..=5");
        }
        let network_id = cli.c3_development_network_id.as_deref().unwrap_or_default();
        if network_id.len() != 32 || !network_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            anyhow::bail!("--c3-development-network-id must contain 32 hexadecimal characters");
        }
        let endpoints = cli
            .c3_development_peer_endpoints
            .as_ref()
            .expect("all C3 arguments checked");
        if endpoints.len() != 5 {
            anyhow::bail!("--c3-development-peer-endpoints requires exactly five entries");
        }
        let reviewer_path = cli
            .c3_development_reviewer_keys_file
            .as_deref()
            .expect("all C3 arguments checked");
        let reviewer_keys: Vec<String> = std::fs::read_to_string(reviewer_path)
            .map_err(|error| {
                anyhow::anyhow!(
                    "Failed to read reviewer key file '{}': {}",
                    reviewer_path,
                    error
                )
            })?
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect();
        if reviewer_keys.len() != 2
            || reviewer_keys
                .iter()
                .any(|key| key.len() != 130 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            anyhow::bail!("reviewer key file must contain exactly two 130-character hex keys");
        }
        let supplier_id = cli
            .c3_development_component_supplier_id
            .as_deref()
            .map(|value| {
                if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    anyhow::bail!(
                        "--c3-development-component-supplier-id must contain 32 hexadecimal characters"
                    );
                }
                Ok(value)
            })
            .transpose()?;
        let supplier_public_key = cli
            .c3_development_component_supplier_public_key
            .as_deref()
            .map(|value| {
                if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    anyhow::bail!(
                        "--c3-development-component-supplier-public-key must contain 64 hexadecimal characters"
                    );
                }
                Ok(value)
            })
            .transpose()?;
        let mut development = serde_json::json!({
            "node_id": node_id,
            "network_id": network_id,
            "peer_endpoints": endpoints,
            "reviewer_public_keys": reviewer_keys,
            "inject_divergent_receipt": cli.c3_development_inject_divergent_receipt,
        });
        if let (Some(supplier_id), Some(supplier_public_key)) = (supplier_id, supplier_public_key) {
            development["component_supplier_id"] =
                serde_json::Value::String(supplier_id.to_string());
            development["component_supplier_public_key"] =
                serde_json::Value::String(supplier_public_key.to_string());
        }
        config["c3_development"] = development;
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

    // Signal dispatcher and proxy to stop
    shutdown.store(true, Ordering::Relaxed);

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

    Ok(())
}

// ---------------------------------------------------------------------------
//  Helpers
// ---------------------------------------------------------------------------

/// Read a file as DER. If the file contains PEM, extract the first block
/// matching `expected_label` (e.g. "CERTIFICATE" or "PRIVATE KEY").
///
/// For key files, also accepts "EC PRIVATE KEY" (SEC1 format) and wraps
/// it in PKCS#8 so the enclave always receives PKCS#8.
fn read_pem_or_der(path: &str, expected_label: &str) -> Result<Vec<u8>> {
    let data = std::fs::read(path)?;

    // Try PEM first
    if let Ok(text) = std::str::from_utf8(&data) {
        if text.contains("-----BEGIN") {
            // Try the exact label first, then fall back to "EC PRIVATE KEY"
            let labels_to_try: Vec<&str> = if expected_label == "PRIVATE KEY" {
                vec!["PRIVATE KEY", "EC PRIVATE KEY"]
            } else {
                vec![expected_label]
            };

            for label in &labels_to_try {
                let begin = format!("-----BEGIN {}-----", label);
                let end = format!("-----END {}-----", label);
                if let Some(start_idx) = text.find(&begin) {
                    let after_begin = start_idx + begin.len();
                    if let Some(end_idx) = text[after_begin..].find(&end) {
                        let b64: String = text[after_begin..after_begin + end_idx]
                            .chars()
                            .filter(|c| !c.is_whitespace())
                            .collect();
                        use base64::Engine;
                        let der = base64::engine::general_purpose::STANDARD
                            .decode(&b64)
                            .map_err(|e| anyhow::anyhow!("PEM base64 decode: {}", e))?;

                        // If SEC1 "EC PRIVATE KEY", wrap it in PKCS#8
                        if *label == "EC PRIVATE KEY" {
                            return Ok(wrap_ec_sec1_in_pkcs8(&der));
                        }
                        return Ok(der);
                    }
                }
            }
            anyhow::bail!("PEM file does not contain a '{}' block", expected_label);
        }
    }

    // Not PEM → assume raw DER
    Ok(data)
}

/// Wrap an SEC1 EC private key in a PKCS#8 envelope for P-256.
///
/// PKCS#8 structure:
/// ```asn1
/// PrivateKeyInfo ::= SEQUENCE {
///   version       INTEGER (0),
///   algorithm     AlgorithmIdentifier { SEQUENCE { OID ecPublicKey, OID prime256v1 } },
///   privateKey    OCTET STRING (containing the SEC1 key)
/// }
/// ```
fn wrap_ec_sec1_in_pkcs8(sec1_der: &[u8]) -> Vec<u8> {
    // Fixed PKCS#8 header for P-256 (ecPublicKey + prime256v1)
    //
    // SEQUENCE (outer)
    //   INTEGER version = 0
    //   SEQUENCE (AlgorithmIdentifier)
    //     OID 1.2.840.10045.2.1 (ecPublicKey)
    //     OID 1.2.840.10045.3.1.7 (prime256v1)
    //   OCTET STRING (SEC1 key)

    // The OCTET STRING wrapping the SEC1 key
    let sec1_len = sec1_der.len();
    let octet_len_bytes = der_length_bytes(sec1_len);
    let inner_len = 3 + 21 + 1 + octet_len_bytes.len() + sec1_len; // version + algid + octet tag + octet len + sec1
    let outer_len_bytes = der_length_bytes(inner_len);

    let mut out = Vec::with_capacity(1 + outer_len_bytes.len() + inner_len);
    out.push(0x30); // SEQUENCE tag
    out.extend_from_slice(&outer_len_bytes);
    out.extend_from_slice(&[0x02, 0x01, 0x00]); // version = 0
    out.extend_from_slice(&[
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ]);
    out.push(0x04); // OCTET STRING tag
    out.extend_from_slice(&octet_len_bytes);
    out.extend_from_slice(sec1_der);
    out
}

/// Encode a length in DER format.
fn der_length_bytes(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}
