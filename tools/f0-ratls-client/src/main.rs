// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use enclave_os_common::modules::AppIdentity;
use enclave_os_common::ocall::{self, OcallVtable};
use enclave_os_egress::{
    https_fetch, root_store, EgressModule, ExpectedOid, RaTlsPolicy, ReportDataBinding, TeeType,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const APP_NAME: &str = "honest-f0-opaque";
const EXPECTED_RESPONSE: &str = "honest-opaque-fixture/0.1.0";
const M0_WORKFLOW_MANIFEST_DIGEST: &str =
    "953eff6856105cf5e1ab77b94b94ceaf7c8d4c45a84f9ea590f6a506636dd3bd";
const M0_ENDPOINT_MANIFEST_DIGEST: &str =
    "bd712af1d1f77e78c165d382500c1ba0ccf9de80eb61bdc0aad1e4de841f4694";

static SOCKETS: OnceLock<Mutex<HashMap<i32, TcpStream>>> = OnceLock::new();
static SOCKET_TIMEOUT: OnceLock<Duration> = OnceLock::new();
static CONNECT_OVERRIDE: OnceLock<(String, String)> = OnceLock::new();
static NEXT_FD: AtomicI32 = AtomicI32::new(10_000);

#[derive(Debug)]
struct Args {
    cwasm: PathBuf,
    ca_cert: PathBuf,
    host: String,
    connect_host: String,
    port: u16,
    appraiser_url: String,
    mr_enclave: [u8; 32],
    timeout: Duration,
    health_attempts: usize,
    retry_delay: Duration,
    health_only: bool,
    shutdown_after_health: bool,
    endpoint_join: bool,
}

fn sockets() -> &'static Mutex<HashMap<i32, TcpStream>> {
    SOCKETS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn net_tcp_connect(host: &str, port: u16) -> Result<i32, i32> {
    let connect_host = CONNECT_OVERRIDE
        .get()
        .filter(|(server_name, _)| server_name == host)
        .map_or(host, |(_, address)| address.as_str());
    let stream = TcpStream::connect((connect_host, port)).map_err(|_| -1)?;
    let timeout = Some(*SOCKET_TIMEOUT.get().unwrap_or(&Duration::from_secs(60)));
    stream.set_read_timeout(timeout).map_err(|_| -1)?;
    stream.set_write_timeout(timeout).map_err(|_| -1)?;
    stream.set_nodelay(true).map_err(|_| -1)?;
    let fd = NEXT_FD.fetch_add(1, Ordering::Relaxed);
    sockets().lock().map_err(|_| -1)?.insert(fd, stream);
    Ok(fd)
}

fn net_send(fd: i32, data: &[u8]) -> Result<usize, i32> {
    sockets()
        .lock()
        .map_err(|_| -1)?
        .get_mut(&fd)
        .ok_or(-1)?
        .write(data)
        .map_err(|_| -1)
}

fn net_recv(fd: i32, data: &mut [u8]) -> Result<usize, i32> {
    sockets()
        .lock()
        .map_err(|_| -1)?
        .get_mut(&fd)
        .ok_or(-1)?
        .read(data)
        .map_err(|_| -1)
}

fn net_close(fd: i32) {
    if let Ok(mut open) = sockets().lock() {
        open.remove(&fd);
    }
}

fn unavailable_listen(_: u16, _: i32) -> Result<i32, i32> {
    Err(-1)
}

fn unavailable_accept(_: i32) -> Result<(i32, String), i32> {
    Err(-1)
}

fn unavailable_put(_: &[u8], _: &[u8], _: &[u8]) -> Result<(), i32> {
    Err(-1)
}

fn unavailable_get(_: &[u8], _: &[u8]) -> Result<Option<Vec<u8>>, i32> {
    Err(-1)
}

fn unavailable_delete(_: &[u8], _: &[u8]) -> Result<bool, i32> {
    Err(-1)
}

fn unavailable_list(_: &[u8], _: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
    Err(-1)
}

fn current_time() -> Result<u64, i32> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| -1)
}

fn discard_log(_: u8, _: &str) {}
fn discard_identity(_: AppIdentity) {}
fn no_identity(_: &str) -> bool {
    false
}

fn register_native_ocalls() {
    ocall::register(OcallVtable {
        net_tcp_listen: unavailable_listen,
        net_tcp_accept: unavailable_accept,
        net_tcp_connect,
        net_send,
        net_recv,
        net_close,
        kv_store_put: unavailable_put,
        kv_store_get: unavailable_get,
        kv_store_delete: unavailable_delete,
        kv_store_list_keys: unavailable_list,
        get_current_time: current_time,
        log: discard_log,
        cert_store_register: discard_identity,
        cert_store_unregister: no_identity,
    });
}

fn take_value(values: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    values
        .next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn decode_mrenclave(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("--mrenclave must be exactly 64 hexadecimal characters".into());
    }
    let mut result = [0_u8; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid --mrenclave".to_string())?;
    }
    Ok(result)
}

fn parse_args() -> Result<Args, String> {
    let mut values = env::args().skip(1);
    let mut cwasm = None;
    let mut ca_cert = None;
    let mut host = "enclave-os.invalid".to_string();
    let mut connect_host = "127.0.0.1".to_string();
    let mut port = 18_443_u16;
    let mut appraiser_url = None;
    let mut mr_enclave = None;
    let mut timeout = Duration::from_secs(60);
    let mut health_attempts = 12_usize;
    let mut retry_delay = Duration::from_secs(5);
    let mut health_only = false;
    let mut shutdown_after_health = false;
    let mut endpoint_join = false;

    while let Some(flag) = values.next() {
        match flag.as_str() {
            "--cwasm" => cwasm = Some(PathBuf::from(take_value(&mut values, &flag)?)),
            "--ca-cert" => ca_cert = Some(PathBuf::from(take_value(&mut values, &flag)?)),
            "--host" => host = take_value(&mut values, &flag)?,
            "--connect-host" => connect_host = take_value(&mut values, &flag)?,
            "--port" => {
                port = take_value(&mut values, &flag)?
                    .parse()
                    .map_err(|_| "invalid --port".to_string())?;
            }
            "--appraiser-url" => appraiser_url = Some(take_value(&mut values, &flag)?),
            "--mrenclave" => {
                mr_enclave = Some(decode_mrenclave(&take_value(&mut values, &flag)?)?);
            }
            "--timeout" => {
                timeout = Duration::from_secs(
                    take_value(&mut values, &flag)?
                        .parse()
                        .map_err(|_| "invalid --timeout".to_string())?,
                );
            }
            "--health-attempts" => {
                health_attempts = take_value(&mut values, &flag)?
                    .parse()
                    .map_err(|_| "invalid --health-attempts".to_string())?;
            }
            "--retry-delay" => {
                retry_delay = Duration::from_secs(
                    take_value(&mut values, &flag)?
                        .parse()
                        .map_err(|_| "invalid --retry-delay".to_string())?,
                );
            }
            "--health-only" => health_only = true,
            "--shutdown-after-health" => shutdown_after_health = true,
            "--endpoint-join" => endpoint_join = true,
            _ => return Err(format!("unknown argument: {flag}")),
        }
    }

    Ok(Args {
        cwasm: cwasm.ok_or_else(|| "--cwasm is required".to_string())?,
        ca_cert: ca_cert.ok_or_else(|| "--ca-cert is required".to_string())?,
        host,
        connect_host,
        port,
        appraiser_url: appraiser_url.ok_or_else(|| "--appraiser-url is required".to_string())?,
        mr_enclave: mr_enclave.ok_or_else(|| "--mrenclave is required".to_string())?,
        timeout,
        health_attempts,
        retry_delay,
        health_only,
        shutdown_after_health,
        endpoint_join,
    })
}

fn endpoint_expected_oids() -> Result<Vec<ExpectedOid>, String> {
    Ok(vec![
        ExpectedOid {
            oid: enclave_os_common::oids::HONEST_ENDPOINT_MANIFEST_ID_OID_STR.into(),
            expected_value: vec![0x41; 16],
        },
        ExpectedOid {
            oid: enclave_os_common::oids::HONEST_ENDPOINT_MANIFEST_DIGEST_OID_STR.into(),
            expected_value: decode_mrenclave(M0_ENDPOINT_MANIFEST_DIGEST)?.to_vec(),
        },
        ExpectedOid {
            oid: enclave_os_common::oids::HONEST_WORKFLOW_ID_OID_STR.into(),
            expected_value: vec![0x40; 16],
        },
        ExpectedOid {
            oid: enclave_os_common::oids::HONEST_WORKFLOW_MANIFEST_DIGEST_OID_STR.into(),
            expected_value: decode_mrenclave(M0_WORKFLOW_MANIFEST_DIGEST)?.to_vec(),
        },
        ExpectedOid {
            oid: enclave_os_common::oids::HONEST_ENDPOINT_ROUTE_DIGEST_OID_STR.into(),
            expected_value: vec![0x42; 32],
        },
        ExpectedOid {
            oid: enclave_os_common::oids::HONEST_ENDPOINT_ACTIVATION_EPOCH_OID_STR.into(),
            expected_value: 1_u64.to_be_bytes().to_vec(),
        },
    ])
}

fn request_with_status(
    args: &Args,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), String> {
    let mut nonce = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "failed to generate RA-TLS challenge".to_string())?;
    let policy = RaTlsPolicy {
        tee: TeeType::Sgx,
        mr_enclave: Some(args.mr_enclave),
        mr_signer: None,
        mr_td: None,
        report_data: ReportDataBinding::ChallengeResponse {
            nonce: nonce.to_vec(),
        },
        expected_oids: if args.endpoint_join {
            endpoint_expected_oids()?
        } else {
            Vec::new()
        },
        attestation_servers: vec![args.appraiser_url.clone()],
        client_identity: None,
        dependencies: None,
    };
    let mut headers = vec![("Accept".to_string(), "application/json".to_string())];
    if body.is_some() {
        headers.push(("Content-Type".to_string(), "application/json".to_string()));
    }
    let url = format!("https://{}:{}{}", args.host, args.port, path);
    let roots = root_store().ok_or_else(|| "RA-TLS root store is unavailable".to_string())?;
    let response = https_fetch(method, &url, &headers, body, roots, Some(&policy))?;
    Ok((response.status, response.body))
}

fn request(args: &Args, method: &str, path: &str, body: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let (status, body) = request_with_status(args, method, path, body)?;
    if status != 200 {
        return Err(format!("{method} {path} returned HTTP {status}"));
    }
    Ok(body)
}

fn parse_object(body: &[u8], operation: &str) -> Result<Value, String> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| format!("{operation} returned invalid JSON"))?;
    if !value.is_object() {
        return Err(format!("{operation} returned a non-object JSON value"));
    }
    Ok(value)
}

fn await_health(args: &Args) -> Result<(), String> {
    let mut last_error = String::new();
    for attempt in 1..=args.health_attempts {
        match request(args, "GET", "/healthz", None).and_then(|body| parse_object(&body, "healthz"))
        {
            Ok(value) if value.get("status") == Some(&Value::String("ok".into())) => {
                return Ok(());
            }
            Ok(_) => last_error = "healthz did not report ok".into(),
            Err(error) => last_error = error,
        }
        if attempt < args.health_attempts {
            thread::sleep(args.retry_delay);
        }
    }
    Err(format!(
        "healthz failed after {} attempts: {last_error}",
        args.health_attempts
    ))
}

fn await_endpoint_result(args: &Args, body: &[u8]) -> Result<Value, String> {
    let mut last_error = String::new();
    for attempt in 1..=args.health_attempts {
        match request_with_status(args, "POST", "/honest/v1/proposals", Some(body)) {
            Ok((200, response)) => return parse_object(&response, "endpoint join"),
            Ok((202, response)) => {
                let pending = parse_object(&response, "endpoint pending")?;
                if pending.get("status") != Some(&Value::String("in-wasm-pending".into())) {
                    return Err("endpoint returned an invalid pending response".into());
                }
                last_error = "in-WASM result remained pending".into();
            }
            Ok((status, _)) => last_error = format!("endpoint returned HTTP {status}"),
            Err(error) => last_error = error,
        }
        if attempt < args.health_attempts {
            thread::sleep(args.retry_delay);
        }
    }
    Err(format!(
        "endpoint result failed after {} attempts: {last_error}",
        args.health_attempts
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    SOCKET_TIMEOUT
        .set(args.timeout)
        .map_err(|_| "socket timeout was already configured".to_string())?;
    CONNECT_OVERRIDE
        .set((args.host.clone(), args.connect_host.clone()))
        .map_err(|_| "connect override was already configured".to_string())?;
    register_native_ocalls();
    let ca_pem = fs::read(&args.ca_cert)
        .map_err(|error| format!("failed to read CA certificate: {error}"))?;
    let (_egress, count) = EgressModule::new(Some(ca_pem))?;
    if count == 0 {
        return Err("CA certificate bundle was empty".into());
    }
    let cwasm = fs::read(&args.cwasm).map_err(|error| format!("failed to read cwasm: {error}"))?;

    await_health(&args)?;
    if args.endpoint_join {
        let body = serde_json::to_vec(&json!({
            "endpoint_manifest_id": "41414141414141414141414141414141",
            "endpoint_manifest_digest": M0_ENDPOINT_MANIFEST_DIGEST,
            "workflow_id": "40404040404040404040404040404040",
            "workflow_manifest_digest": M0_WORKFLOW_MANIFEST_DIGEST,
        }))
        .map_err(|error| format!("failed to encode endpoint request: {error}"))?;
        let response = await_endpoint_result(&args, &body)?;
        let ticket_evidence = response
            .get("ticket_evidence_commitment")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if response.get("status") != Some(&Value::String("in-wasm-result".into()))
            || response.get("canonical_result_hex") != Some(&Value::String("44cd091c00".into()))
            || response.get("endpoint_manifest_digest")
                != Some(&Value::String(M0_ENDPOINT_MANIFEST_DIGEST.into()))
            || ticket_evidence.len() != 64
            || !ticket_evidence.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(format!(
                "endpoint request did not preserve the committed identity join: {response}"
            ));
        }
        println!(
            "ENDPOINT-JOIN-001: PASS assurance=sgx_hardware \
             path=https/challenge-ratls/sni/committed-endpoint/ticket/in-wasm"
        );
        return Ok(());
    }
    if args.shutdown_after_health {
        let status_body = request(&args, "GET", "/status", None)?;
        let status: Value = serde_json::from_slice(&status_body)
            .map_err(|_| "status returned invalid JSON".to_string())?;
        if !status.is_array() {
            return Err("status returned a non-array JSON value".into());
        }
        let _shutdown = parse_object(
            &request(&args, "POST", "/shutdown", Some(b"{}"))?,
            "shutdown",
        )?;
    }
    if args.health_only {
        println!(
            "F0 RA-TLS HEALTH PASS: assurance=sgx_hardware \
             appraisal=intel-dcap-qvl-pccs"
        );
        return Ok(());
    }

    let load_body = serde_json::to_vec(&json!({
        "wasm_load": {
            "name": APP_NAME,
            "bytes": STANDARD.encode(&cwasm),
            "mcp_enabled": false,
        }
    }))
    .map_err(|error| format!("failed to encode wasm_load: {error}"))?;
    let load = parse_object(
        &request(&args, "POST", "/data", Some(&load_body))?,
        "wasm_load",
    )?;
    if load.get("status") != Some(&Value::String("loaded".into()))
        || load.pointer("/app/name") != Some(&Value::String(APP_NAME.into()))
    {
        return Err(format!(
            "wasm_load did not admit the expected F0 app: {load}"
        ));
    }

    let call_body = serde_json::to_vec(&json!({
        "wasm_call": {
            "app": APP_NAME,
            "function": "version",
            "params": [],
        }
    }))
    .map_err(|error| format!("failed to encode wasm_call: {error}"))?;
    let call = parse_object(
        &request(&args, "POST", "/data", Some(&call_body))?,
        "wasm_call",
    )?;
    let expected = json!({
        "status": "ok",
        "returns": [{
            "type": "string",
            "value": EXPECTED_RESPONSE,
        }],
    });
    if call != expected {
        return Err("wasm_call response failed the exact F0 oracle".into());
    }

    let cwasm_digest = Sha256::digest(&cwasm);
    let response_digest = Sha256::digest(EXPECTED_RESPONSE.as_bytes());
    println!(
        "F0 PASS: assurance=sgx_hardware path=https/challenge-ratls/upstream-wasm \
         appraisal=intel-dcap-qvl-pccs cwasm_sha256={} response_sha256={}",
        hex(&cwasm_digest),
        hex(&response_digest),
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("F0 FAIL: {error}");
        std::process::exit(1);
    }
}
