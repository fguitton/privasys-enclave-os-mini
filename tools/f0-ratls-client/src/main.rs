// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpStream;
#[cfg(test)]
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
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
const M0_ENDPOINT_MANIFEST_ID: [u8; 16] = [
    0xb9, 0x87, 0xc6, 0x95, 0xfb, 0x26, 0xa8, 0x94, 0xfe, 0x3e, 0xbc, 0x20, 0x30, 0xb0, 0xca, 0xa4,
];
const M0_ENDPOINT_MANIFEST_DIGEST: &str =
    "e8efa235f99af54f62df39e2930a89f85d57865bede204594dc6b4454917b8e3";

static SOCKETS: OnceLock<Mutex<HashMap<i32, TcpStream>>> = OnceLock::new();
static SOCKET_TIMEOUT: OnceLock<Duration> = OnceLock::new();
static CONNECT_OVERRIDE: OnceLock<(String, String)> = OnceLock::new();
static NEXT_FD: AtomicI32 = AtomicI32::new(10_000);

#[derive(Debug)]
struct Args {
    cwasm: Option<PathBuf>,
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
    endpoint_submit_only: bool,
    work_id: [u8; 16],
    raw_post_path: Option<String>,
    raw_body_file: Option<PathBuf>,
    raw_response_file: Option<PathBuf>,
    expected_status: u16,
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

fn decode_work_id(value: &str) -> Result<[u8; 16], String> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("--work-id must be exactly 32 hexadecimal characters".into());
    }
    let mut result = [0_u8; 16];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid --work-id".to_string())?;
    }
    if result.iter().all(|byte| *byte == 0) {
        return Err("--work-id cannot be zero".into());
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
    let mut endpoint_submit_only = false;
    let mut work_id = [0x4b; 16];
    let mut raw_post_path = None;
    let mut raw_body_file = None;
    let mut raw_response_file = None;
    let mut expected_status = 200_u16;

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
            "--endpoint-submit-only" => endpoint_submit_only = true,
            "--work-id" => work_id = decode_work_id(&take_value(&mut values, &flag)?)?,
            "--raw-post-path" => raw_post_path = Some(take_value(&mut values, &flag)?),
            "--raw-body-file" => {
                raw_body_file = Some(PathBuf::from(take_value(&mut values, &flag)?));
            }
            "--raw-response-file" => {
                raw_response_file = Some(PathBuf::from(take_value(&mut values, &flag)?));
            }
            "--expect-status" => {
                expected_status = take_value(&mut values, &flag)?
                    .parse()
                    .map_err(|_| "invalid --expect-status".to_string())?;
            }
            _ => return Err(format!("unknown argument: {flag}")),
        }
    }

    if endpoint_join && endpoint_submit_only {
        return Err("--endpoint-join and --endpoint-submit-only are mutually exclusive".into());
    }
    if raw_response_file.is_some() && raw_post_path.is_none() {
        return Err("--raw-response-file requires --raw-post-path".into());
    }
    Ok(Args {
        cwasm,
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
        endpoint_submit_only,
        work_id,
        raw_post_path,
        raw_body_file,
        raw_response_file,
        expected_status,
    })
}

fn endpoint_request_identity(args: &Args) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    endpoint_request_identity_from_path(args.raw_body_file.as_ref())
}

fn endpoint_request_identity_from_path(
    path: Option<&PathBuf>,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let Some(path) = path else {
        return Ok((
            M0_ENDPOINT_MANIFEST_ID.to_vec(),
            decode_mrenclave(M0_ENDPOINT_MANIFEST_DIGEST)?.to_vec(),
            decode_mrenclave(M0_WORKFLOW_MANIFEST_DIGEST)?.to_vec(),
        ));
    };
    let body: Value = serde_json::from_slice(
        &fs::read(path).map_err(|error| format!("failed to read endpoint identity: {error}"))?,
    )
    .map_err(|_| "endpoint identity file is not JSON".to_string())?;
    let fixed = |field: &str, bytes: usize| -> Result<Vec<u8>, String> {
        let value = body
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("endpoint identity omitted {field}"))?;
        if value.len() != bytes * 2 {
            return Err(format!("endpoint identity {field} has the wrong length"));
        }
        (0..bytes)
            .map(|index| {
                u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                    .map_err(|_| format!("endpoint identity {field} is not hexadecimal"))
            })
            .collect()
    };
    Ok((
        fixed("endpoint_manifest_id", 16)?,
        fixed("endpoint_manifest_digest", 32)?,
        fixed("workflow_manifest_digest", 32)?,
    ))
}

fn endpoint_expected_oids(args: &Args) -> Result<Vec<ExpectedOid>, String> {
    let (endpoint_manifest_id, endpoint_manifest_digest, workflow_manifest_digest) =
        endpoint_request_identity(args)?;
    Ok(vec![
        ExpectedOid {
            oid: enclave_os_common::oids::HONEST_ENDPOINT_MANIFEST_ID_OID_STR.into(),
            expected_value: endpoint_manifest_id,
        },
        ExpectedOid {
            oid: enclave_os_common::oids::HONEST_ENDPOINT_MANIFEST_DIGEST_OID_STR.into(),
            expected_value: endpoint_manifest_digest,
        },
        ExpectedOid {
            oid: enclave_os_common::oids::HONEST_ENDPOINT_ID_OID_STR.into(),
            expected_value: vec![0x43; 16],
        },
        ExpectedOid {
            oid: enclave_os_common::oids::HONEST_OPERATION_ID_OID_STR.into(),
            expected_value: vec![0x45; 16],
        },
        ExpectedOid {
            oid: enclave_os_common::oids::HONEST_WORKFLOW_GENERATION_ID_OID_STR.into(),
            expected_value: vec![0x46; 16],
        },
        ExpectedOid {
            oid: enclave_os_common::oids::HONEST_ENTRY_STAGE_ID_OID_STR.into(),
            expected_value: 1_u32.to_be_bytes().to_vec(),
        },
        ExpectedOid {
            oid: enclave_os_common::oids::HONEST_WORKFLOW_ID_OID_STR.into(),
            expected_value: vec![0x40; 16],
        },
        ExpectedOid {
            oid: enclave_os_common::oids::HONEST_WORKFLOW_MANIFEST_DIGEST_OID_STR.into(),
            expected_value: workflow_manifest_digest,
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
        expected_oids: if args.endpoint_join || args.endpoint_submit_only {
            endpoint_expected_oids(args)?
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
                if !matches!(
                    pending.get("status").and_then(Value::as_str),
                    Some(
                        "in-wasm-pending"
                            | "logchain-commit-pending"
                            | "execution-or-agreement-pending"
                            | "retrying-after-membership-change"
                    )
                ) {
                    return Err("endpoint returned an invalid pending response".into());
                }
                last_error = "in-WASM/logchain result remained pending".into();
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

fn persist_raw_response(path: &PathBuf, response: &[u8]) -> Result<(), String> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("failed to create raw response file: {error}"))?;
    output
        .write_all(response)
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("failed to persist raw response file: {error}"))
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
    await_health(&args)?;
    if let Some(path) = args.raw_post_path.as_deref() {
        if !path.starts_with('/') || path.contains(['\r', '\n']) {
            return Err("--raw-post-path must be one absolute HTTP path".into());
        }
        let body = args
            .raw_body_file
            .as_ref()
            .map(fs::read)
            .transpose()
            .map_err(|error| format!("failed to read raw request body: {error}"))?
            .unwrap_or_default();
        let (status, response) = request_with_status(&args, "POST", path, Some(&body))?;
        if status != args.expected_status {
            return Err(format!(
                "raw POST returned HTTP {status}, expected {}",
                args.expected_status
            ));
        }
        println!("RAW-POST-STATUS: {status}");
        if let Some(output_path) = args.raw_response_file.as_ref() {
            persist_raw_response(output_path, &response)?;
            println!("RAW-POST-BODY-FILE: {}", output_path.display());
        } else {
            println!("RAW-POST-BODY: {}", String::from_utf8_lossy(&response));
        }
        return Ok(());
    }
    if args.endpoint_join || args.endpoint_submit_only {
        let body = serde_json::to_vec(&json!({
            "schema": "honest.document-28.proposal-identity-join.v2",
            "idempotency_id": hex(&args.work_id),
            "endpoint_id": "43434343434343434343434343434343",
            "endpoint_manifest_id": hex(&M0_ENDPOINT_MANIFEST_ID),
            "endpoint_manifest_digest": M0_ENDPOINT_MANIFEST_DIGEST,
            "operation_id": "45454545454545454545454545454545",
            "workflow_generation_id": "46464646464646464646464646464646",
            "workflow_id": "40404040404040404040404040404040",
            "workflow_manifest_digest": M0_WORKFLOW_MANIFEST_DIGEST,
        }))
        .map_err(|error| format!("failed to encode endpoint request: {error}"))?;
        if args.endpoint_submit_only {
            let (status, response) =
                request_with_status(&args, "POST", "/honest/v1/proposals", Some(&body))?;
            if status != 202 {
                return Err(format!(
                    "endpoint submit returned HTTP {status}, expected 202: {}",
                    String::from_utf8_lossy(&response)
                ));
            }
            let pending = parse_object(&response, "endpoint submit")?;
            if pending.get("status").and_then(Value::as_str)
                != Some("execution-or-agreement-pending")
            {
                return Err(format!(
                    "endpoint submit returned invalid pending state: {pending}"
                ));
            }
            println!("ENDPOINT-SUBMIT-001: PASS status=202 result=uncommitted");
            return Ok(());
        }
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
             path=https/challenge-ratls/sni/committed-endpoint/ticket/in-wasm/logchain"
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

    let cwasm_path = args
        .cwasm
        .as_ref()
        .ok_or_else(|| "--cwasm is required outside health and raw POST modes".to_string())?;
    let cwasm = fs::read(cwasm_path).map_err(|error| format!("failed to read cwasm: {error}"))?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_binary_response_is_private_and_never_overwritten() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "honest-ratls-response-{}-{nonce}.bin",
            std::process::id()
        ));
        persist_raw_response(&path, b"\x00\xff\x81\x01").expect("first persistence");
        assert_eq!(fs::read(&path).expect("response read"), b"\x00\xff\x81\x01");
        assert_eq!(
            fs::symlink_metadata(&path)
                .expect("response metadata")
                .mode()
                & 0o777,
            0o600
        );
        assert!(persist_raw_response(&path, b"replacement").is_err());
        fs::remove_file(path).expect("response cleanup");
    }

    #[test]
    fn endpoint_oids_follow_the_exact_canonical_request_identity() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "honest-endpoint-identity-{}-{nonce}.json",
            std::process::id()
        ));
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "endpoint_manifest_id": "71".repeat(16),
                "endpoint_manifest_digest": "72".repeat(32),
                "workflow_manifest_digest": "73".repeat(32),
            }))
            .expect("request encoding"),
        )
        .expect("request write");
        let identity = endpoint_request_identity_from_path(Some(&path)).expect("exact identity");
        assert_eq!(identity, (vec![0x71; 16], vec![0x72; 32], vec![0x73; 32]));

        fs::write(
            &path,
            br#"{"endpoint_manifest_id":"71","endpoint_manifest_digest":"72","workflow_manifest_digest":"73"}"#,
        )
        .expect("mutated request write");
        assert!(endpoint_request_identity_from_path(Some(&path)).is_err());
        fs::remove_file(path).expect("request cleanup");
    }
}
