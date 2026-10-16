// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! SGX attestation integration for RA-TLS v2.
//!
//! The leaf certificate identifies the enclave (leaf key, chain to the
//! intermediary CA, Privasys OIDs) and carries no evidence. A leaf key lives
//! 24 hours and is kept across re-mints that only change extension values (an
//! app registered, a dependency set changed), so a deterministic quote minted
//! for the key stays valid across such a re-mint. Evidence is served after the
//! handshake by `POST /__privasys/attest` (see `server.rs`):
//!
//! ```text
//! deterministic: report_data = SHA-512( SHA-256(SPKI_DER) || quote_time )   cached 24 h per key
//! challenge:     report_data = SHA-512( SHA-256(SPKI_DER) || context || hctx )
//!                hctx = TLS-Exporter("EXPORTER-privasys-ratls-attest-v2", context, 32)
//! ```

use std::string::String;
use std::vec::Vec;
use time::OffsetDateTime;

use enclave_os_common::oids::{APP_CONFIG_MERKLE_ROOT_OID, CONFIG_MERKLE_ROOT_OID};

use crate::ratls::cert_store::AppCertData;

/// Lifetime of a serving leaf and of its key (24 hours).
pub const DETERMINISTIC_VALIDITY_SECS: u64 = 86400;

/// Validity of a minted client identity (1 hour).
pub const CLIENT_IDENTITY_VALIDITY_SECS: u64 = 3600;

// ---------------------------------------------------------------------------
//  Types
// ---------------------------------------------------------------------------

pub use super::session::ca_context::{CaContext, RetainedCaContext};

impl CaContext {
    /// Generate the current intermediary through the one paid certificate codec.
    pub fn generate(
        pool: &std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
    ) -> Result<RetainedCaContext, String> {
        let key = super::session::leaf_key::RetainedLeafKey::new(pool, 0)?;
        let certificate = super::session::certificate_wire::ca(pool, &key).map_err(String::from)?;
        RetainedCaContext::copy_from_parts(pool, certificate.as_slice(), &key.pkcs8)
            .map_err(|_| String::new())
    }
}

pub use super::session::leaf_key::{generate_keypair, new_leaf_key, LeafKey};

/// Admitted current leaf DER; the existing CA and leaf key are borrowed by the
/// final TLS factory rather than cloned into a temporary certificate graph.
pub struct CertGenerationResult {
    pub(crate) leaf: super::session::certificate_wire::PaidDer,
}
impl CertGenerationResult {
    /// Borrow the current admitted leaf without copying or transferring its owner.
    pub fn certificate_der(&self) -> &[u8] {
        self.leaf.as_slice()
    }
}

// ---------------------------------------------------------------------------
//  Public API
// ---------------------------------------------------------------------------

/// Compute the 64-byte `report_data` that goes into the SGX quote:
/// `SHA-512( SHA-256(SPKI_DER) || binding )`, with `spki_der` the full DER
/// `SubjectPublicKeyInfo` (91 bytes for P-256).
pub fn compute_report_data(spki_der: &[u8], binding: &[u8]) -> [u8; 64] {
    let rd = enclave_os_common::quote::compute_report_data_hash(spki_der, binding);
    let mut out = [0u8; 64];
    out.copy_from_slice(rd.as_ref());
    out
}

/// Generate the enclave-wide RA-TLS leaf for `key`, signed by the CA, carrying
/// the platform OIDs (config Merkle root, attestation servers hash, module
/// OIDs) and no evidence. Valid from `now` until the key's 24-hour lifetime.
pub fn generate_ratls_certificate(
    pool: &std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
    ca: &CaContext,
    key: &LeafKey,
    now: u64,
) -> Result<CertGenerationResult, String> {
    let mut extensions = super::session::certificate_wire::Extensions::new();
    if let Some(root) = crate::config_merkle_root() {
        extensions
            .push(pool, CONFIG_MERKLE_ROOT_OID, root.as_slice())
            .map_err(String::from)?;
    }
    if let Some(h) = enclave_os_common::attestation_servers::hash() {
        extensions
            .push(
                pool,
                enclave_os_common::oids::ATTESTATION_SERVERS_HASH_OID,
                &h,
            )
            .map_err(String::from)?;
    }
    crate::modules::visit_module_oids(&mut |oid, value| {
        extensions
            .push(pool, oid, value)
            .map_err(|_| enclave_os_common::modules::ModuleOidError)
    })
    .map_err(|_| String::new())?;
    let (nb, na) = leaf_validity(key, now)?;
    // These are fixed substrate routes, never host-selected or guest names.
    // Only the Honest operational profile exposes the peer/control aliases.
    let names: &[&str] = if crate::honest_ingress_profile_selected() {
        &[
            "enclave-os.invalid",
            enclave_os_common::modules::HONEST_PEER_SNI,
            "local-control.honest.invalid",
        ]
    } else {
        &["enclave-os.invalid"]
    };
    let leaf = super::session::certificate_wire::leaf(
        pool,
        key,
        (nb, na),
        ca,
        "Enclave OS RA-TLS",
        names,
        &extensions,
    )
    .map_err(String::from)?;
    Ok(CertGenerationResult { leaf })
}

/// Generate a per-app RA-TLS leaf for `key`: the app's config Merkle root
/// (OID 5.1) and its identity extensions (code digest 4.2, key source 6.1,
/// configuration hash 5.2, app id 4.1, dependency set 7.1, app-defined 5.4.*),
/// subject CN = app hostname (SNI). No evidence.
pub fn generate_app_certificate(
    pool: &std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
    ca: &CaContext,
    key: &LeafKey,
    app: &AppCertData,
    now: u64,
) -> Result<CertGenerationResult, String> {
    let mut extensions = super::session::certificate_wire::Extensions::new();
    if app.merkle_root != [0u8; 32] {
        extensions
            .push(pool, APP_CONFIG_MERKLE_ROOT_OID, &app.merkle_root)
            .map_err(String::from)?;
    }
    for (oid, value) in &app.oid_extensions {
        extensions.push(pool, *oid, value).map_err(String::from)?;
    }
    if let Some(endpoint) = app.attested_endpoint {
        extensions
            .push(
                pool,
                enclave_os_common::oids::HONEST_ENDPOINT_MANIFEST_ID_OID,
                &endpoint.endpoint_manifest_id,
            )
            .map_err(String::from)?;
        extensions
            .push(
                pool,
                enclave_os_common::oids::HONEST_ENDPOINT_MANIFEST_DIGEST_OID,
                &endpoint.endpoint_manifest_digest,
            )
            .map_err(String::from)?;
        extensions
            .push(
                pool,
                enclave_os_common::oids::HONEST_ENDPOINT_ID_OID,
                &endpoint.endpoint_id,
            )
            .map_err(String::from)?;
        extensions
            .push(
                pool,
                enclave_os_common::oids::HONEST_OPERATION_ID_OID,
                &endpoint.operation_id,
            )
            .map_err(String::from)?;
        extensions
            .push(
                pool,
                enclave_os_common::oids::HONEST_WORKFLOW_GENERATION_ID_OID,
                &endpoint.workflow_generation_id,
            )
            .map_err(String::from)?;
        extensions
            .push(
                pool,
                enclave_os_common::oids::HONEST_ENTRY_STAGE_ID_OID,
                &endpoint.entry_stage_id.to_be_bytes(),
            )
            .map_err(String::from)?;
        extensions
            .push(
                pool,
                enclave_os_common::oids::HONEST_WORKFLOW_ID_OID,
                &endpoint.workflow_id,
            )
            .map_err(String::from)?;
        extensions
            .push(
                pool,
                enclave_os_common::oids::HONEST_WORKFLOW_MANIFEST_DIGEST_OID,
                &endpoint.workflow_manifest_digest,
            )
            .map_err(String::from)?;
        extensions
            .push(
                pool,
                enclave_os_common::oids::HONEST_ENDPOINT_ROUTE_DIGEST_OID,
                &endpoint.route_digest,
            )
            .map_err(String::from)?;
        extensions
            .push(
                pool,
                enclave_os_common::oids::HONEST_ENDPOINT_ACTIVATION_EPOCH_OID,
                &endpoint.activation_epoch.to_be_bytes(),
            )
            .map_err(String::from)?;
    }

    let (nb, na) = leaf_validity(key, now)?;
    let leaf = super::session::certificate_wire::leaf(
        pool,
        key,
        (nb, na),
        ca,
        &app.hostname,
        &[&app.hostname],
        &extensions,
    )
    .map_err(String::from)?;
    Ok(CertGenerationResult { leaf })
}

fn leaf_validity(key: &LeafKey, now: u64) -> Result<(OffsetDateTime, OffsetDateTime), String> {
    let nb = OffsetDateTime::from_unix_timestamp(now.saturating_sub(60) as i64)
        .map_err(|e| format!("not_before out of range: {e}"))?;
    let na =
        OffsetDateTime::from_unix_timestamp((key.created + DETERMINISTIC_VALIDITY_SECS) as i64)
            .map_err(|e| format!("not_after out of range: {e}"))?;
    Ok((nb, na))
}

/// Mint this enclave's client identity for a mutual leg (a vault, an app-to-app
/// call): a fresh key, the app's code digest (OID 4.2) and, when present, its
/// app id (OID 4.1), signed by the CA, valid one hour, no evidence. Evidence for
/// it is minted per connection with [`sgx_quote`] over the report_data the
/// verifier predicts (`client_report_data`). Returns
/// `(cert_chain_der, pkcs8_key_der, spki_hash)`.
#[cfg(feature = "egress")]
pub fn mint_client_identity(
    pool: &std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
    ca: &CaContext,
    cwasm_code_hash: &[u8],
    app_id: Option<&[u8]>,
    now: u64,
) -> Result<enclave_os_egress::ClientCredential, enclave_os_egress::ClientCredentialError> {
    use enclave_os_egress::ClientCredentialError as Refusal;
    let certificate_error = |error| match error {
        super::session::certificate_wire::CertificateError::Allocation => Refusal::Allocation,
        _ => Refusal::Signing,
    };
    let key =
        super::session::leaf_key::RetainedLeafKey::new(pool, now).map_err(|error| match error {
            super::session::leaf_key::LeafKeyError::Allocation => Refusal::Allocation,
            _ => Refusal::Signing,
        })?;
    let mut oid_extensions = super::session::certificate_wire::Extensions::new();
    oid_extensions
        .push(
            pool,
            enclave_os_common::oids::APP_CODE_HASH_OID,
            cwasm_code_hash,
        )
        .map_err(certificate_error)?;
    if let Some(id) = app_id {
        if !id.is_empty() {
            oid_extensions
                .push(pool, enclave_os_common::oids::APP_ID_OID, id)
                .map_err(certificate_error)?;
        }
    }
    let nb = OffsetDateTime::from_unix_timestamp(now.saturating_sub(60) as i64)
        .map_err(|_| Refusal::Signing)?;
    let na = OffsetDateTime::from_unix_timestamp((now + CLIENT_IDENTITY_VALIDITY_SECS) as i64)
        .map_err(|_| Refusal::Signing)?;
    let leaf = super::session::certificate_wire::leaf(
        pool,
        &key,
        (nb, na),
        ca,
        "enclave-os client",
        &[],
        &oid_extensions,
    )
    .map_err(certificate_error)?;
    enclave_os_egress::ClientCredential::new(pool, &[leaf.as_slice(), &ca.ca_cert_der], &key.pkcs8)
}

#[cfg(all(feature = "mock", not(feature = "sgx-sim-attestation")))]
const MOCK_QUOTE_PREFIX: &[u8] = b"MOCK_QUOTE:";

/// Produce an SGX DCAP quote over `report_data` (the attest endpoint and the
/// client-evidence path).
pub fn sgx_quote(report_data: &[u8; 64]) -> Result<Vec<u8>, String> {
    generate_sgx_quote(report_data)
}

/// Paid quote construction for the live server/cache route. The client-attestation
/// provider retains an owned quote; this value grants no authority.
pub(crate) fn sgx_quote_paid(
    report_data: &[u8; 64],
) -> Result<super::session::retained_quote::RetainedQuote, String> {
    let pool = crate::local_allocation_pool().ok_or_else(String::new)?;
    generate_sgx_quote_paid(&pool, report_data)
}

#[cfg(all(not(feature = "mock"), not(feature = "sgx-sim-attestation")))]
fn generate_sgx_quote_paid(
    pool: &std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
    report_data: &[u8; 64],
) -> Result<super::session::retained_quote::RetainedQuote, String> {
    use sgx_types::types::{Report, ReportData, TargetInfo};
    let rpc = crate::rpc_client_ref();
    let target: TargetInfo = rpc
        .with_qe_target_info(pool, |bytes| {
            if bytes.len() != core::mem::size_of::<TargetInfo>() {
                return Err(-22);
            }
            // SAFETY: exact fixed-size SGX value is copied before working credit ends.
            Ok(unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<TargetInfo>()) })
        })
        .map_err(|error| format!("QeGetTargetInfo RPC failed: status={error}"))?;
    let mut data = ReportData::default();
    data.d.copy_from_slice(report_data);
    let report = <Report as sgx_tse::EnclaveReport>::for_target(&target, &data)
        .map_err(|error| format!("sgx_create_report failed: {error:?}"))?;
    // SAFETY: borrow the original initialized SGX report for its exact layout.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&report as *const Report).cast::<u8>(),
            core::mem::size_of::<Report>(),
        )
    };
    rpc.with_qe_quote(pool, bytes, |quote| {
        super::session::retained_quote::RetainedQuote::copy_from(pool, quote).ok_or(-12)
    })
    .map_err(|error| format!("QeGetQuote RPC failed: status={error}"))
}

#[cfg(any(feature = "mock", feature = "sgx-sim-attestation"))]
fn generate_sgx_quote_paid(
    pool: &std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
    report_data: &[u8; 64],
) -> Result<super::session::retained_quote::RetainedQuote, String> {
    // The original selected mock/SIM producer has a fixed codec-owned bound.
    // Retain its temporary separately from the resulting shared copy.
    #[cfg(feature = "sgx-sim-attestation")]
    let temporary = enclave_os_common::quote::SGX_SIM_REPORT_SIZE;
    #[cfg(all(feature = "mock", not(feature = "sgx-sim-attestation")))]
    let temporary = MOCK_QUOTE_PREFIX.len() + core::mem::size_of::<[u8; 64]>();
    let credit = pool.reserve(temporary).ok_or_else(String::new)?;
    let bytes = generate_sgx_quote(report_data)?;
    let retained = super::session::retained_quote::RetainedQuote::copy_from(pool, &bytes)
        .ok_or_else(String::new);
    drop(bytes);
    drop(credit);
    retained
}

// ---------------------------------------------------------------------------
//  SGX quote generation
// ---------------------------------------------------------------------------

/// Generate an SGX DCAP Quote v3 with the given 64-byte report_data.
///
/// Two-phase RPC flow:
///   1. Ask the host for the Quoting Enclave's `TargetInfo` (RPC: `QeGetTargetInfo`)
///   2. Call `sgx_create_report()` inside the enclave, targeting the QE
///   3. Send the raw report to the host (RPC: `QeGetQuote`) → host calls
///      `sgx_qe_get_quote()` → returns the full DCAP Quote v3
///
/// In mock mode this returns a deterministic dummy quote.
#[cfg(all(not(feature = "mock"), not(feature = "sgx-sim-attestation")))]
fn generate_sgx_quote(report_data: &[u8; 64]) -> Result<Vec<u8>, String> {
    use sgx_types::types::{ReportData, TargetInfo};

    let rpc = crate::rpc_client_ref();

    // Phase 1: Get QE target info from the host (via DCAP QL)
    let target_info_bytes = rpc
        .qe_get_target_info()
        .map_err(|e| format!("QeGetTargetInfo RPC failed: status={}", e))?;

    if target_info_bytes.len() != core::mem::size_of::<TargetInfo>() {
        return Err(format!(
            "QeGetTargetInfo: unexpected size {} (expected {})",
            target_info_bytes.len(),
            core::mem::size_of::<TargetInfo>()
        ));
    }

    let target_info: TargetInfo =
        unsafe { core::ptr::read_unaligned(target_info_bytes.as_ptr() as *const TargetInfo) };

    let mut rd = ReportData::default();
    rd.d.copy_from_slice(report_data);

    let report =
        <sgx_types::types::Report as sgx_tse::EnclaveReport>::for_target(&target_info, &rd)
            .map_err(|e| format!("sgx_create_report failed: {:?}", e))?;

    let report_bytes = unsafe {
        core::slice::from_raw_parts(
            &report as *const sgx_types::types::Report as *const u8,
            core::mem::size_of::<sgx_types::types::Report>(),
        )
    };

    // Phase 3: Ask the host to get a DCAP Quote v3 from the QE
    let quote = rpc
        .qe_get_quote(report_bytes)
        .map_err(|e| format!("QeGetQuote RPC failed: status={}", e))?;

    Ok(quote)
}

#[cfg(all(feature = "mock", not(feature = "sgx-sim-attestation")))]
fn generate_sgx_quote(report_data: &[u8; 64]) -> Result<Vec<u8>, String> {
    let mut quote = Vec::with_capacity(MOCK_QUOTE_PREFIX.len() + report_data.len());
    quote.extend_from_slice(MOCK_QUOTE_PREFIX);
    quote.extend_from_slice(report_data);
    Ok(quote)
}

#[cfg(feature = "sgx-sim-attestation")]
fn generate_sgx_quote(report_data: &[u8; 64]) -> Result<Vec<u8>, String> {
    use sgx_tse::{EnclaveReport, EnclaveTarget};
    use sgx_types::types::{Report, ReportData, TargetInfo};

    let target = TargetInfo::for_self()
        .map_err(|error| format!("SGX simulation target failed: {error:?}"))?;
    let mut data = ReportData::default();
    data.d.copy_from_slice(report_data);
    let report = Report::for_target(&target, &data)
        .map_err(|error| format!("SGX simulation report failed: {error:?}"))?;
    let mut evidence = Vec::with_capacity(enclave_os_common::quote::SGX_SIM_REPORT_SIZE);
    evidence.extend_from_slice(enclave_os_common::quote::SGX_SIM_REPORT_PREFIX);
    evidence.extend_from_slice(&report.body.mr_enclave.m);
    evidence.extend_from_slice(&report.body.report_data.d);
    Ok(evidence)
}

/// Produce a DCAP quote binding `nonce` into ReportData, for authenticating this
/// enclave to a non-RA-TLS verifier (the management-service vault directory). The
/// nonce is placed in the first 32 bytes of the 64-byte ReportData (the rest is
/// zero); the verifier reproduces the same binding from the challenge it issued.
pub fn quote_binding_nonce(nonce: &[u8]) -> Result<Vec<u8>, String> {
    let mut report_data = [0u8; 64];
    let n = core::cmp::min(nonce.len(), 32);
    report_data[..n].copy_from_slice(&nonce[..n]);
    generate_sgx_quote(&report_data)
}

// ---------------------------------------------------------------------------
//  Self measurement (MRENCLAVE)
// ---------------------------------------------------------------------------

/// Read this enclave's own MRENCLAVE (its code identity), for self-authoring a
/// vault key policy that pins the running runtime as the `Tee` measurement.
///
/// MRENCLAVE is independent of the report target, so a local SGX report suffices.
/// It sits at byte offset 64 of the SGX ReportBody (the first field of the
/// Report), so we read it from the report bytes rather than depend on the SDK
/// fork's struct field names — matching how the rest of this module treats
/// reports and quotes as opaque bytes.
#[cfg(all(not(feature = "mock"), not(feature = "sgx-sim-attestation")))]
pub fn self_mrenclave() -> Result<[u8; 32], String> {
    use sgx_types::types::{ReportData, TargetInfo};

    let rpc = crate::rpc_client_ref();
    let target_info_bytes = rpc
        .qe_get_target_info()
        .map_err(|e| format!("QeGetTargetInfo RPC failed: status={}", e))?;
    if target_info_bytes.len() != core::mem::size_of::<TargetInfo>() {
        return Err(format!(
            "QeGetTargetInfo: unexpected size {} (expected {})",
            target_info_bytes.len(),
            core::mem::size_of::<TargetInfo>()
        ));
    }
    let target_info: TargetInfo =
        unsafe { core::ptr::read_unaligned(target_info_bytes.as_ptr() as *const TargetInfo) };
    let rd = ReportData::default();
    let report =
        <sgx_types::types::Report as sgx_tse::EnclaveReport>::for_target(&target_info, &rd)
            .map_err(|e| format!("sgx_create_report failed: {:?}", e))?;
    let report_bytes = unsafe {
        core::slice::from_raw_parts(
            &report as *const sgx_types::types::Report as *const u8,
            core::mem::size_of::<sgx_types::types::Report>(),
        )
    };
    const MRENCLAVE_OFFSET: usize = 64;
    if report_bytes.len() < MRENCLAVE_OFFSET + 32 {
        return Err(format!(
            "self report too short: {} bytes",
            report_bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&report_bytes[MRENCLAVE_OFFSET..MRENCLAVE_OFFSET + 32]);
    Ok(out)
}

#[cfg(feature = "sgx-sim-attestation")]
pub fn self_mrenclave() -> Result<[u8; 32], String> {
    use sgx_tse::{EnclaveReport, EnclaveTarget};
    use sgx_types::types::{Report, ReportData, TargetInfo};

    let target = TargetInfo::for_self()
        .map_err(|error| format!("SGX simulation target failed: {error:?}"))?;
    let report = Report::for_target(&target, &ReportData::default())
        .map_err(|error| format!("SGX simulation self report failed: {error:?}"))?;
    Ok(report.body.mr_enclave.m)
}

#[cfg(all(feature = "mock", not(feature = "sgx-sim-attestation")))]
pub fn self_mrenclave() -> Result<[u8; 32], String> {
    Ok([0x11u8; 32])
}

// ---------------------------------------------------------------------------
//  ClientHello parser (SNI)
// ---------------------------------------------------------------------------

/// Information extracted from a TLS ClientHello message.
pub struct ClientHelloInfo {
    /// Challenge nonce from extension 0xFFBB (if present).
    pub challenge_nonce: Option<Vec<u8>>,
    /// Server Name Indication hostname (from extension 0x0000).
    pub sni: Option<String>,
}

/// Parse a raw TLS ClientHello to extract extension data.
///
/// Extracts both the challenge nonce (extension 0xFFBB) and the SNI
/// hostname (extension 0x0000) in a single pass. The `raw` bytes may
/// start at the TLS record layer or the Handshake layer.
pub fn parse_client_hello(raw: &[u8]) -> ClientHelloInfo {
    let mut info = ClientHelloInfo {
        challenge_nonce: None,
        sni: None,
    };

    if raw.len() < 44 {
        return info;
    }

    let mut pos: usize = 0;

    // --- TLS record layer (optional) ---
    if raw[0] == 0x16 {
        pos += 5;
    }

    // --- Handshake header ---
    if pos >= raw.len() || raw[pos] != 0x01 {
        return info;
    }
    pos += 1;
    if pos + 3 > raw.len() {
        return info;
    }
    pos += 3; // 3-byte handshake length

    // --- ClientHello body ---
    if pos + 2 > raw.len() {
        return info;
    }
    pos += 2; // client_version

    if pos + 32 > raw.len() {
        return info;
    }
    pos += 32; // random

    if pos >= raw.len() {
        return info;
    }
    let sid_len = raw[pos] as usize;
    pos += 1;
    if pos + sid_len > raw.len() {
        return info;
    }
    pos += sid_len;

    if pos + 2 > raw.len() {
        return info;
    }
    let cs_len = u16::from_be_bytes([raw[pos], raw[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_len > raw.len() {
        return info;
    }
    pos += cs_len;

    if pos >= raw.len() {
        return info;
    }
    let cm_len = raw[pos] as usize;
    pos += 1;
    if pos + cm_len > raw.len() {
        return info;
    }
    pos += cm_len;

    // --- Extensions ---
    if pos + 2 > raw.len() {
        return info;
    }
    let ext_total_len = u16::from_be_bytes([raw[pos], raw[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_total_len;
    if ext_end > raw.len() {
        return info;
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
        let ext_len = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > ext_end {
            break;
        }

        match ext_type {
            // Challenge nonce — Privasys RA-TLS extension
            ext if ext == enclave_os_common::types::RATLS_CLIENT_HELLO_EXTENSION_TYPE => {
                info.challenge_nonce = Some(raw[pos..pos + ext_len].to_vec());
            }
            // SNI — Server Name Indication (RFC 6066)
            0x0000 => {
                info.sni = parse_sni_extension(&raw[pos..pos + ext_len]);
            }
            _ => {}
        }

        pos += ext_len;
    }

    info
}

/// Parse the SNI extension value to extract the host_name.
///
/// Format (RFC 6066 §3):
/// ```text
/// [2 bytes: ServerNameList length]
/// [1 byte:  name_type (0x00 = host_name)]
/// [2 bytes: HostName length]
/// [N bytes: hostname (UTF-8)]
/// ```
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    // Skip list length (2 bytes)
    let name_type = data[2];
    if name_type != 0x00 {
        return None; // Only host_name type is supported
    }
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if 5 + name_len > data.len() {
        return None;
    }
    String::from_utf8(data[5..5 + name_len].to_vec()).ok()
}

// ===========================================================================
//  Unit tests (run with `--features mock` to get std)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ----- compute_report_data -------------------------------------------

    #[test]
    fn report_data_is_64_bytes() {
        let rd = compute_report_data(b"pubkey", b"binding");
        assert_eq!(rd.len(), 64);
    }

    #[test]
    fn report_data_deterministic() {
        let a = compute_report_data(b"key", b"nonce");
        let b = compute_report_data(b"key", b"nonce");
        assert_eq!(a, b);
    }

    #[test]
    fn report_data_differs_with_different_key() {
        let a = compute_report_data(b"key_a", b"nonce");
        let b = compute_report_data(b"key_b", b"nonce");
        assert_ne!(a, b);
    }

    #[test]
    fn report_data_differs_with_different_binding() {
        let a = compute_report_data(b"key", b"nonce_1");
        let b = compute_report_data(b"key", b"nonce_2");
        assert_ne!(a, b);
    }

    #[test]
    fn report_data_empty_inputs() {
        // Should not panic, should return valid 64-byte hash
        let rd = compute_report_data(b"", b"");
        assert_eq!(rd.len(), 64);
    }

    #[test]
    fn report_data_matches_manual_computation() {
        let pubkey = b"test_public_key_der";
        let binding = b"challenge_nonce";

        let pubkey_hash = ring::digest::digest(&ring::digest::SHA256, pubkey);
        let mut preimage = Vec::new();
        preimage.extend_from_slice(pubkey_hash.as_ref());
        preimage.extend_from_slice(binding);
        let expected = ring::digest::digest(&ring::digest::SHA512, &preimage);

        let actual = compute_report_data(pubkey, binding);
        assert_eq!(&actual[..], expected.as_ref());
    }

    #[test]
    fn ratls_time_format_matches_verifier() {
        // 1700000000 = 2023-11-14T22:13:20Z; minute-truncated -> 22:13.
        // This string must match byte-for-byte what the SDK verifiers
        // reconstruct from NotBefore, so pin it.
        let minute = 1700000000u64 - (1700000000u64 % 60);
        let t = OffsetDateTime::from_unix_timestamp(minute as i64).unwrap();
        assert_eq!(format_ratls_time(&t), "2023-11-14T22:13Z");
    }

    #[test]
    fn report_data_deterministic_binding_is_time_string() {
        let rd = compute_report_data(b"key", b"2023-11-14T22:13Z");
        // A different minute must give different report_data.
        let rd2 = compute_report_data(b"key", b"2023-11-14T22:14Z");
        assert_ne!(rd, rd2);
    }

    // ----- parse_client_hello (ClientHello parser) ------------------------

    /// Build a minimal TLS 1.2 ClientHello with the given extensions.
    ///
    /// Each extension is (type: u16, data: &[u8]).
    fn build_client_hello(extensions: &[(u16, &[u8])]) -> Vec<u8> {
        // --- ClientHello body ---
        let mut ch_body = Vec::new();

        // client_version = TLS 1.2
        ch_body.extend_from_slice(&[0x03, 0x03]);

        // random (32 bytes of zeros)
        ch_body.extend_from_slice(&[0u8; 32]);

        // session_id_length = 0
        ch_body.push(0);

        // cipher_suites: 2 suites (4 bytes)
        ch_body.extend_from_slice(&[0x00, 0x04]); // length
        ch_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        ch_body.extend_from_slice(&[0x13, 0x02]); // TLS_AES_256_GCM_SHA384

        // compression_methods: 1 method (null)
        ch_body.push(0x01); // length
        ch_body.push(0x00); // null

        // Extensions
        let mut ext_bytes = Vec::new();
        for &(ext_type, ext_data) in extensions {
            ext_bytes.extend_from_slice(&ext_type.to_be_bytes());
            ext_bytes.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
            ext_bytes.extend_from_slice(ext_data);
        }
        ch_body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&ext_bytes);

        // --- Handshake header ---
        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let hs_len = ch_body.len();
        hs.push(((hs_len >> 16) & 0xFF) as u8);
        hs.push(((hs_len >> 8) & 0xFF) as u8);
        hs.push((hs_len & 0xFF) as u8);
        hs.extend_from_slice(&ch_body);

        // --- TLS record layer ---
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 compat
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);

        record
    }

    #[test]
    fn parse_nonce_present() {
        let nonce = b"challenge_nonce_32_bytes_padding!";
        let ch = build_client_hello(&[(0xFFBB, nonce)]);
        let info = parse_client_hello(&ch);
        assert_eq!(info.challenge_nonce, Some(nonce.to_vec()));
        assert_eq!(info.sni, None);
    }

    #[test]
    fn parse_nonce_absent() {
        // Valid SNI extension but no 0xFFBB
        let sni = b"\x00\x0e\x00\x00\x0bexample.com";
        let ch = build_client_hello(&[(0x0000, sni)]);
        let info = parse_client_hello(&ch);
        assert_eq!(info.challenge_nonce, None);
        assert_eq!(info.sni, Some("example.com".into()));
    }

    #[test]
    fn parse_nonce_and_sni_together() {
        let nonce = b"my_nonce";
        let exts: &[(u16, &[u8])] = &[
            (0x0000, b"\x00\x0e\x00\x00\x0bexample.com"), // SNI
            (0x000D, b"\x00\x04\x04\x03\x08\x04"),        // signature_algorithms
            (0xFFBB, nonce),                              // our extension
        ];
        let ch = build_client_hello(exts);
        let info = parse_client_hello(&ch);
        assert_eq!(info.challenge_nonce, Some(nonce.to_vec()));
        assert_eq!(info.sni, Some("example.com".into()));
    }

    #[test]
    fn parse_nonce_empty_extension_data() {
        let ch = build_client_hello(&[(0xFFBB, b"")]);
        let info = parse_client_hello(&ch);
        assert_eq!(info.challenge_nonce, Some(vec![]));
    }

    #[test]
    fn parse_nonce_no_record_layer() {
        // Feed just the handshake message (no TLS record header)
        let nonce = b"nonce123";

        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]); // version
        ch_body.extend_from_slice(&[0u8; 32]); // random
        ch_body.push(0); // session_id_length
        ch_body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        ch_body.extend_from_slice(&[0x01, 0x00]); // compression

        let mut ext = Vec::new();
        ext.extend_from_slice(&0xFFBBu16.to_be_bytes());
        ext.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
        ext.extend_from_slice(nonce);
        ch_body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&ext);

        let mut hs = vec![0x01]; // ClientHello type
        let len = ch_body.len();
        hs.push(((len >> 16) & 0xFF) as u8);
        hs.push(((len >> 8) & 0xFF) as u8);
        hs.push((len & 0xFF) as u8);
        hs.extend_from_slice(&ch_body);

        let info = parse_client_hello(&hs);
        assert_eq!(info.challenge_nonce, Some(nonce.to_vec()));
    }

    #[test]
    fn parse_too_short() {
        let info = parse_client_hello(&[]);
        assert!(info.challenge_nonce.is_none() && info.sni.is_none());
        let info = parse_client_hello(&[0x16, 0x03, 0x01]);
        assert!(info.challenge_nonce.is_none());
        let info = parse_client_hello(&[0u8; 10]);
        assert!(info.challenge_nonce.is_none());
    }

    #[test]
    fn parse_not_handshake() {
        // Content type 0x17 = Application Data (not Handshake)
        let mut bad = build_client_hello(&[(0xFFBB, b"nonce")]);
        bad[0] = 0x17;
        let info = parse_client_hello(&bad);
        assert!(info.challenge_nonce.is_none());
    }

    #[test]
    fn parse_not_client_hello() {
        // Handshake type 0x02 = ServerHello (not ClientHello)
        let mut bad = build_client_hello(&[(0xFFBB, b"nonce")]);
        // Record header is 5 bytes, then handshake type is at offset 5
        bad[5] = 0x02;
        let info = parse_client_hello(&bad);
        assert!(info.challenge_nonce.is_none());
    }

    // ----- Mock-mode certificate generation (feature = "mock") -----------

    #[cfg(feature = "mock")]
    #[test]
    fn mock_generate_sgx_quote() {
        let report_data = compute_report_data(b"pubkey", b"nonce");
        let quote = super::generate_sgx_quote(&report_data).unwrap();
        assert!(quote.starts_with(b"MOCK_QUOTE:"));
        // The quote should contain the 64-byte report_data after the prefix
        assert_eq!(&quote[11..], &report_data[..]);
    }

    // ----- hex_decode (from common) ----------------------------------------

    #[test]
    fn hex_decode_basic() {
        let decoded = enclave_os_common::hex::hex_decode("48656c6c6f").unwrap();
        assert_eq!(&decoded, b"Hello");
    }

    #[test]
    fn hex_decode_empty() {
        let decoded = enclave_os_common::hex::hex_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn hex_decode_uppercase() {
        let decoded = enclave_os_common::hex::hex_decode("4F6B").unwrap();
        assert_eq!(&decoded, b"Ok");
    }

    #[test]
    fn hex_decode_odd_length() {
        assert!(enclave_os_common::hex::hex_decode("abc").is_none());
    }

    #[test]
    fn hex_decode_invalid_char() {
        assert!(enclave_os_common::hex::hex_decode("zz").is_none());
    }
}
