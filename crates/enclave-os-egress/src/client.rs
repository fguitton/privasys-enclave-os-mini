// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! HTTPS egress client – makes outbound HTTPS requests from inside the enclave.
//!
//! Uses rustls for TLS and a minimal HTTP/1.1 implementation. Network I/O
//! flows through OCALLs to the host, but the TLS termination happens inside
//! the enclave, so the host never sees plaintext.
//!
//! The single public entry point is [`https_fetch`], which returns an
//! [`HttpResponse`] (status + headers + body) and supports all HTTP methods,
//! custom headers, and optional RA-TLS verification.

use std::string::String;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use std::vec::Vec;

use core::mem;

use ring::digest;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ResolvesClientCert, WebPkiServerVerifier};
use rustls::crypto::ring::default_provider;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::sign::CertifiedKey;
#[cfg(not(feature = "sgx-sim-attestation"))]
use rustls::CertificateError;
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};

use x509_parser::prelude::*;

// sgx_types is provided by the Teaclave sysroot — gives us Quote3, Quote4,
// ReportBody, Report2Body with typed field access.
extern crate sgx_types;
#[cfg(not(feature = "sgx-sim-attestation"))]
use sgx_types::types::Quote3;
use sgx_types::types::Quote4;

use enclave_os_common::oids;

mod exchange;
mod incremental;
mod renewal;
mod request;

pub use incremental::IncrementalTlsClient;
pub use renewal::{AttestationRenewalBudget, AttestationRenewalPolicy};
pub use request::{
    https_fetch, https_fetch_interruptible, https_fetch_interruptible_detailed,
    BoundedHttpsRequest, HttpResponse, HttpsFetchError, HttpsFetchFailurePhase,
    InterruptibleBlockingNetIo, TlsPeerCertificateChain, TlsPeerCertificateEvidence,
    MAX_REQUEST_BODY, MAX_REQUEST_HEADERS, MAX_REQUEST_HEADER_BYTES, MAX_RESPONSE_BODY,
    MAX_RESPONSE_HEADERS, MAX_RESPONSE_HEADER_BYTES, MAX_TLS_PEER_CERTIFICATES,
    MAX_TLS_PEER_CERTIFICATE_BYTES, MAX_TLS_PEER_CHAIN_BYTES,
};

// Re-export shared quote primitives for callers building `RaTlsPolicy` values.
pub use enclave_os_common::quote::TeeType;

/// Re-export of `rustls::RootCertStore` so downstream callers can refer to
/// the trust-anchor type without depending on `rustls` directly.
pub use rustls::RootCertStore;

// Re-export the dotted-string OIDs for callers building `ExpectedOid` values.
pub use enclave_os_common::oids::{
    ATTESTATION_SERVERS_HASH_OID_STR as OID_ATTESTATION_SERVERS_HASH,
    COMBINED_WORKLOADS_HASH_OID_STR as OID_WASM_APPS_HASH,
    CONFIG_MERKLE_ROOT_OID_STR as OID_CONFIG_MERKLE_ROOT,
    EGRESS_CA_HASH_OID_STR as OID_EGRESS_CA_HASH,
};

// =========================================================================
//  Mozilla root CA store (for general-purpose HTTPS egress)
// =========================================================================

static MOZILLA_ROOT_STORE: OnceLock<RootCertStore> = OnceLock::new();

/// Returns a shared reference to the Mozilla root CA store.
///
/// The store is lazily initialized from `webpki-roots` on first call
/// (~150 root CAs). Subsequent calls return the cached reference.
pub fn mozilla_root_store() -> &'static RootCertStore {
    MOZILLA_ROOT_STORE.get_or_init(|| {
        let mut store = RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        store
    })
}

/// Build a fresh [`RootCertStore`] from caller-supplied DER root certificates.
///
/// Useful for callers (e.g. the WASM SDK host shim) that want to use a
/// custom set of trust anchors without depending on `rustls` directly.
/// Returns an error if any DER cannot be parsed as an X.509 certificate.
pub fn root_store_from_der<I, B>(ders: I) -> Result<RootCertStore, String>
where
    I: IntoIterator<Item = B>,
    B: Into<Vec<u8>>,
{
    let mut store = RootCertStore::empty();
    for (i, der) in ders.into_iter().enumerate() {
        store
            .add(rustls::pki_types::CertificateDer::from(der.into()))
            .map_err(|e| format!("ca-roots-der[{}]: invalid root certificate: {}", i, e))?;
    }
    Ok(store)
}

/// Re-run standard WebPKI validation over one retained DER chain.
///
/// This is intentionally side-effect free: it performs no network revocation
/// lookup and consumes only the exact caller-supplied trust store, policy,
/// server name and committed validation time. An empty OCSP input is used
/// until the transport exposes stapled OCSP/SCT material for retention. This
/// helper deliberately does not claim to reproduce RA-TLS channel binding.
pub fn verify_webpki_server_certificate_chain_at(
    certificate_chain_der: &[Vec<u8>],
    server_name: &str,
    root_store: &RootCertStore,
    verified_at_unix_seconds: u64,
) -> Result<(), String> {
    if certificate_chain_der.is_empty() || certificate_chain_der.len() > MAX_TLS_PEER_CERTIFICATES {
        return Err("TLS peer certificate count is outside the retained profile".into());
    }
    let mut chain_bytes = 0usize;
    for certificate in certificate_chain_der {
        if certificate.is_empty() || certificate.len() > MAX_TLS_PEER_CERTIFICATE_BYTES {
            return Err("TLS peer certificate is outside the retained profile".into());
        }
        chain_bytes = chain_bytes
            .checked_add(certificate.len())
            .ok_or_else(|| "TLS peer certificate chain length overflow".to_string())?;
    }
    if chain_bytes > MAX_TLS_PEER_CHAIN_BYTES {
        return Err("TLS peer certificate chain is outside the retained profile".into());
    }

    let server_name = ServerName::try_from(server_name.to_string())
        .map_err(|_| "invalid retained TLS server name".to_string())?;
    let leaf = CertificateDer::from(certificate_chain_der[0].as_slice());
    let intermediates: Vec<_> = certificate_chain_der[1..]
        .iter()
        .map(|certificate| CertificateDer::from(certificate.as_slice()))
        .collect();
    let provider = Arc::new(default_provider());
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(root_store.clone()), provider)
        .build()
        .map_err(|error| format!("WebPKI verifier build error: {error}"))?;
    let now = UnixTime::since_unix_epoch(Duration::from_secs(verified_at_unix_seconds));
    inner
        .verify_server_cert(&leaf, &intermediates, &server_name, &[], now)
        .map(|_| ())
        .map_err(|error| format!("retained TLS peer validation failed: {error}"))
}

/// Re-run standard WebPKI client-certificate validation over retained DER.
///
/// This is the certificate-role counterpart to
/// [`verify_webpki_server_certificate_chain_at`]. It performs no network
/// revocation lookup and makes no real-world identity or ownership claim; it
/// establishes only that the supplied chain is valid for client
/// authentication under the exact trust store and time.
pub fn verify_webpki_client_certificate_chain_at(
    certificate_chain_der: &[Vec<u8>],
    root_store: &RootCertStore,
    verified_at_unix_seconds: u64,
) -> Result<(), String> {
    validate_retained_certificate_chain(certificate_chain_der)?;
    let leaf = CertificateDer::from(certificate_chain_der[0].as_slice());
    let intermediates: Vec<_> = certificate_chain_der[1..]
        .iter()
        .map(|certificate| CertificateDer::from(certificate.as_slice()))
        .collect();
    let provider = Arc::new(default_provider());
    let inner = WebPkiClientVerifier::builder_with_provider(Arc::new(root_store.clone()), provider)
        .build()
        .map_err(|error| format!("WebPKI client verifier build error: {error}"))?;
    let now = UnixTime::since_unix_epoch(Duration::from_secs(verified_at_unix_seconds));
    inner
        .verify_client_cert(&leaf, &intermediates, now)
        .map(|_| ())
        .map_err(|error| format!("retained TLS client validation failed: {error}"))
}

fn validate_retained_certificate_chain(certificate_chain_der: &[Vec<u8>]) -> Result<(), String> {
    if certificate_chain_der.is_empty() || certificate_chain_der.len() > MAX_TLS_PEER_CERTIFICATES {
        return Err("TLS peer certificate count is outside the retained profile".into());
    }
    let mut chain_bytes = 0usize;
    for certificate in certificate_chain_der {
        if certificate.is_empty() || certificate.len() > MAX_TLS_PEER_CERTIFICATE_BYTES {
            return Err("TLS peer certificate is outside the retained profile".into());
        }
        chain_bytes = chain_bytes
            .checked_add(certificate.len())
            .ok_or_else(|| "TLS peer certificate chain length overflow".to_string())?;
    }
    if chain_bytes > MAX_TLS_PEER_CHAIN_BYTES {
        return Err("TLS peer certificate chain is outside the retained profile".into());
    }
    Ok(())
}

impl core::fmt::Debug for HttpResponse {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .field("headers", &"<protected>")
            .field("body", &"<protected>")
            .finish()
    }
}

// =========================================================================
//  RA-TLS verification types
// =========================================================================

/// Mock quote prefix used in development/test builds.
/// Only available when the `mock` feature is enabled.
#[cfg(feature = "mock")]
const MOCK_PREFIX: &[u8] = b"MOCK_QUOTE:";

/// How the verifier reproduces the 64-byte `ReportData` field in the quote.
///
/// Both SGX and TDX use the leaf's P-256 SPKI DER. Deterministic evidence
/// commits to its `quote_time`; challenge evidence also commits to a fresh
/// context and the role-specific TLS 1.3 exporter after the handshake.
#[derive(Debug, Clone)]
pub enum ReportDataBinding {
    /// Deterministic (RA-TLS v2 "trust the TEE" tier): the runtime's cached
    /// quote, `SHA-512(SHA-256(SPKI DER) || quote_time)` with `quote_time`
    /// carried in the attest response. No session binding.
    Deterministic,

    /// Challenge mode (RA-TLS v2, the default tier): after the handshake the
    /// client asks for a quote bound to a fresh context and this connection's
    /// RFC 8446 exporter value, `SHA-512(SHA-256(SPKI DER) || context || hctx)`.
    /// Level 3 binding.
    ChallengeResponse { nonce: Vec<u8> },
}

/// An expected X.509 extension OID and its value.
///
/// Used in [`RaTlsPolicy::expected_oids`] to verify configuration-specific
/// extensions embedded in RA-TLS certificates (e.g. config Merkle root,
/// egress CA bundle hash, WASM apps hash).
///
/// # Example
///
/// ```rust,ignore
/// use enclave_os_egress::client::{ExpectedOid, OID_CONFIG_MERKLE_ROOT};
///
/// let expected_merkle = ExpectedOid {
///     oid: OID_CONFIG_MERKLE_ROOT.into(),
///     expected_value: known_good_merkle_root.to_vec(),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ExpectedOid {
    /// Dotted-string OID (e.g. `"1.3.6.1.4.1.65230.1.1"`).
    ///
    /// Use the constants [`OID_CONFIG_MERKLE_ROOT`], [`OID_EGRESS_CA_HASH`],
    /// [`OID_WASM_APPS_HASH`], or [`OID_ATTESTATION_SERVERS_HASH`] for well-known
    /// Privasys OIDs.
    pub oid: String,
    /// Expected raw extension value. The certificate's extension value must
    /// match this exactly.
    pub expected_value: Vec<u8>,
}

/// RA-TLS verification policy.
///
/// Pass to [`https_fetch`] to verify the
/// remote server's RA-TLS certificate after standard chain validation.
///
/// ## What is verified
///
/// 1. **V2 evidence** — the peer supplies evidence after the TLS handshake.
///    Legacy certificates containing a quote are rejected.
/// 2. **Measurement registers** — MRENCLAVE / MRSIGNER (SGX) or MRTD (TDX)
///    must match the provided expected values (when set).
/// 3. **ReportData binding** — `SHA-512(SHA-256(pubkey) || binding)` is
///    verified according to the [`report_data`](Self::report_data) mode.
///    See [`ReportDataBinding`] for details.
/// 4. **Configuration OIDs** — custom X.509 extensions (config Merkle root,
///    egress CA hash, WASM apps hash, etc.) are compared against expected
///    values when provided in [`expected_oids`](Self::expected_oids).
/// 5. **Attestation server verification** — when
///    [`attestation_servers`](Self::attestation_servers) is non-empty, the
///    raw attestation quote is POSTed to each server for cryptographic
///    verification (signature chain, TCB status, platform identity).  The
///    attestation server is TEE-agnostic (SGX, TDX, SEV-SNP, etc.).
///    All servers must confirm the quote.
#[derive(Debug, Clone)]
pub struct RaTlsPolicy {
    /// Which TEE type to expect.
    pub tee: TeeType,
    /// Expected MRENCLAVE (SGX, 32 bytes). `None` = skip check.
    pub mr_enclave: Option<[u8; 32]>,
    /// Expected MRSIGNER (SGX, 32 bytes). `None` = skip check.
    pub mr_signer: Option<[u8; 32]>,
    /// Expected MRTD (TDX, 48 bytes). `None` = skip check.
    pub mr_td: Option<[u8; 48]>,
    /// How to verify the quote's 64-byte ReportData field.
    ///
    /// Defaults to [`ReportDataBinding::Deterministic`], which verifies the
    /// key and quote-time binding for both SGX and TDX. Use
    /// [`ReportDataBinding::ChallengeResponse`] with a fresh 32-byte context
    /// for evidence bound to this TLS connection.
    pub report_data: ReportDataBinding,
    /// Expected configuration OIDs to verify in the certificate.
    ///
    /// Each entry specifies an OID and its expected raw value. Common OIDs:
    ///
    /// | Constant | OID | What it proves |
    /// |----------|-----|----------------|
    /// | [`OID_CONFIG_MERKLE_ROOT`] | `1.3.6.1.4.1.65230.2.1` | All config inputs (Merkle tree root) |
    /// | [`OID_EGRESS_CA_HASH`] | `1.3.6.1.4.1.65230.2.2` | Egress CA bundle identity |
    /// | [`OID_WASM_APPS_HASH`] | `1.3.6.1.4.1.65230.2.4` | Combined workloads (WASM apps) hash |
    /// | [`OID_ATTESTATION_SERVERS_HASH`] | `1.3.6.1.4.1.65230.2.3` | Attestation server URL list identity |
    ///
    /// An empty `Vec` (the default) skips OID verification.
    pub expected_oids: Vec<ExpectedOid>,

    /// Attestation server URLs for cryptographic quote verification.
    ///
    /// When non-empty, the raw attestation quote from the server's
    /// evidence exchange is POSTed to each URL. **All** configured servers
    /// must accept it before the blocking client permits application traffic.
    ///
    /// This enables multi-party trust: the enclave operator and the secret
    /// owner can each run an independent attestation verification server.
    ///
    /// The Privasys attestation server is TEE-agnostic and supports
    /// Intel SGX, Intel TDX, AMD SEV-SNP, NVIDIA, and ARM CCA.
    ///
    /// The default is an empty `Vec` (no remote verification).  Callers
    /// who want attestation server verification can populate this from
    /// the core attestation server config via
    /// [`enclave_os_common::attestation_servers::server_urls()`].
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let servers = enclave_os_common::attestation_servers::server_urls();
    ///
    /// let policy = RaTlsPolicy {
    ///     // ... other fields ...
    ///     attestation_servers: servers,
    /// };
    /// ```
    pub attestation_servers: Vec<String>,

    /// Opt-in Intel TCB-status enforcement on the attestation servers'
    /// reported `tcbStatus`. `None` (the default) = no acceptance check
    /// beyond the always-on rejection of `"Revoked"`. `Some(set)` = the
    /// secure floor (`UpToDate`, `SWHardeningNeeded`) always passes and any
    /// other reported status must be listed in `set` (`Some(vec![])` =
    /// strict floor-only). Opt-in so existing callers keep their behaviour
    /// on fleets that report `ConfigurationAndSWHardeningNeeded`.
    pub acceptable_tcb_statuses: Option<Vec<String>>,

    /// Mutual RA-TLS: when `Some`, the connection presents a client
    /// certificate carrying this (OS-derived) app identity, minted by the
    /// registered [`EnclaveClientCertSigner`] and bound to the server's
    /// challenge. `None` (the default) presents no client certificate.
    pub client_identity: Option<ClientCertIdentity>,

    /// Attested cross-enclave dependency set (the canonical OID 6.1 encoding).
    /// Runtime-owned: injected from the calling app's sealed metadata, NOT from
    /// the app's own request, so the app cannot weaken it. When `Some` and the
    /// peer presents an app-id (OID 3.6) that this set pins, the peer MUST match
    /// the pinned identity (measurement + required OIDs) or the handshake fails
    /// closed. A peer whose app-id is not a declared dependency is unaffected
    /// (the ordinary policy above governs it). `None` (the default) disables the
    /// check.
    pub dependencies: Option<Vec<u8>>,
}

/// Locally verified SGX peer certificate evidence awaiting remote appraisal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SgxPeerCertificateEvidence {
    /// SHA-256 of the exact DER leaf certificate.
    pub certificate_digest: [u8; 32],
    /// SHA-256 of the exact SGX quote extension bytes.
    pub quote_digest: [u8; 32],
    /// MRENCLAVE extracted from the structurally valid SGX quote.
    pub mr_enclave: [u8; 32],
    /// Exact quote bytes to submit through the separately incremental
    /// appraisal-service connection.
    pub quote: Vec<u8>,
}

/// Verify a retained SGX quote and leaf using the context and role-specific
/// exporter captured by the enclave's TLS exchange. This performs no remote
/// appraisal; the caller must obtain that separately before granting authority.
pub fn locally_verify_sgx_peer_certificate(
    der: &[u8],
    expected_mr_enclave: [u8; 32],
    evidence: &crate::attest::Evidence,
) -> Result<SgxPeerCertificateEvidence, String> {
    if evidence.mode != crate::attest::AttestationMode::Challenge
        || evidence.context.is_none()
        || evidence.hctx.is_none()
    {
        return Err("RA-TLS peer: live challenge and exporter are required".into());
    }
    if evidence.tee != "sgx" || evidence.gpu_evidence.is_some() {
        return Err("RA-TLS peer: SGX evidence required".into());
    }
    let policy = RaTlsPolicy {
        tee: TeeType::Sgx,
        mr_enclave: Some(expected_mr_enclave),
        mr_signer: None,
        mr_td: None,
        report_data: ReportDataBinding::ChallengeResponse {
            nonce: evidence.context.unwrap().to_vec(),
        },
        expected_oids: Vec::new(),
        attestation_servers: Vec::new(),
        acceptable_tcb_statuses: None,
        client_identity: None,
        dependencies: None,
    };
    verify_ratls_leaf(der, &policy)?;
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|_| "RA-TLS peer: malformed certificate".to_string())?;
    let spki = validated_spki(&cert)?;
    let (measurement, _) = verify_evidence_locally(&cert, &spki, evidence, &policy)?;
    Ok(SgxPeerCertificateEvidence {
        certificate_digest: sha256_array(der),
        quote_digest: sha256_array(&evidence.quote),
        mr_enclave: measurement.ok_or("RA-TLS peer: SGX measurement unavailable")?,
        quote: evidence.quote.clone(),
    })
}

// =========================================================================
//  RA-TLS client authentication (mutual attestation)
// =========================================================================

/// The per-app measurement a client RA-TLS certificate must carry so the
/// remote enclave (e.g. an Enclave Vault) can authorise it via OID 3.2 / 3.6.
///
/// These values are **derived by the OS from real enclave state** (the loaded
/// component's code hash, the platform-assigned app id) — never supplied by an
/// untrusted caller. A connection presents a client cert iff its
/// [`RaTlsPolicy::client_identity`] is `Some`.
#[derive(Debug, Clone)]
pub struct ClientCertIdentity {
    /// App code hash (`sha256(cwasm)`), stamped at OID 3.2.
    pub code_hash: Vec<u8>,
    /// App-id, stamped at OID 3.6 (MR_APP). `None` keeps the MR_ENCLAVE shape.
    pub app_id: Option<Vec<u8>>,
}

/// Signs the enclave's RA-TLS **client** certificate for mutual attestation.
///
/// Implemented by the OS, which holds the SGX quote primitive and the enclave
/// CA signing key, and registered **once** at enclave init via
/// [`register_enclave_client_cert_signer`]. This keeps `egress` decoupled from
/// the attestation crate: egress never sees CA material, and a caller can only
/// name which app identity to present (via the policy) — the OS stamps the
/// real measurement and signs.
pub trait EnclaveClientCertSigner: Send + Sync {
    /// Mint a client identity carrying `identity` (code digest OID 4.2, app id
    /// OID 4.1), no evidence. Returns `(cert_chain_der, pkcs8_key_der)`, or
    /// `None` to decline. `now` is seconds since the epoch.
    fn identity(&self, identity: &ClientCertIdentity, now: u64) -> Option<(Vec<Vec<u8>>, Vec<u8>)>;

    /// Produce the SGX quote over `report_data` that proves the identity on one
    /// connection (the verifier predicted `report_data` from the identity key,
    /// its client context and the connection's exporter value).
    fn evidence(&self, report_data: &[u8; 64]) -> Option<Vec<u8>>;
}

static CLIENT_CERT_SIGNER: OnceLock<&'static dyn EnclaveClientCertSigner> = OnceLock::new();

/// Register the OS's client-certificate signer. Call once during enclave init,
/// after the enclave CA is available. Subsequent calls are ignored.
pub fn register_enclave_client_cert_signer(signer: &'static dyn EnclaveClientCertSigner) {
    let _ = CLIENT_CERT_SIGNER.set(signer);
}

/// Exposes the OS's attestation facts to higher crates (notably the wasm crate's
/// vault directory client and key-policy authoring), which cannot call the
/// attestation crate directly because the dep runs enclave→wasm.
///
/// Implemented by the OS (it holds the SGX quote primitive and can self-report)
/// and registered once at enclave init via [`register_enclave_attestation_provider`].
/// Mirrors [`EnclaveClientCertSigner`]: the OS — not the caller — produces the
/// real measurement; a quote travels in the request body, not the TLS layer, so
/// it authenticates the enclave to a verifier that is **not** an RA-TLS peer (in
/// particular the management-service vault directory behind a TLS-terminating LB).
pub trait EnclaveAttestationProvider: Send + Sync {
    /// Return a DCAP quote whose ReportData binds `nonce`, or `None` to decline.
    fn quote(&self, nonce: &[u8]) -> Option<Vec<u8>>;
    /// This enclave's own runtime MRENCLAVE (code identity), for self-authoring a
    /// vault key policy that pins the running runtime as the `Tee` measurement.
    fn self_mrenclave(&self) -> Option<[u8; 32]>;
}

static ATTESTATION_PROVIDER: OnceLock<&'static dyn EnclaveAttestationProvider> = OnceLock::new();

/// Register the OS's attestation provider. Call once during enclave init.
/// Subsequent calls are ignored.
pub fn register_enclave_attestation_provider(provider: &'static dyn EnclaveAttestationProvider) {
    let _ = ATTESTATION_PROVIDER.set(provider);
}

/// Produce an attestation quote binding `nonce`, via the registered
/// [`EnclaveAttestationProvider`]. `None` if none is registered (e.g. the host
/// build) or it declined.
pub fn enclave_attestation_quote(nonce: &[u8]) -> Option<Vec<u8>> {
    ATTESTATION_PROVIDER.get().and_then(|p| p.quote(nonce))
}

/// This enclave's own runtime MRENCLAVE, via the registered
/// [`EnclaveAttestationProvider`]. `None` if none is registered.
pub fn enclave_self_mrenclave() -> Option<[u8; 32]> {
    ATTESTATION_PROVIDER.get().and_then(|p| p.self_mrenclave())
}

/// Adapter that presents the enclave's client identity during the handshake,
/// minted via the registered [`EnclaveClientCertSigner`]. The identity carries
/// no evidence; evidence is presented after the handshake when the server
/// requires it (see `attest_exchange`).
#[derive(Debug)]
struct IdentityClientAuth {
    identity: ClientCertIdentity,
    provider: Arc<CryptoProvider>,
    /// DER of the leaf presented in the handshake, for the present step.
    presented: std::sync::Mutex<Option<Vec<u8>>>,
}

impl IdentityClientAuth {
    fn presented_leaf(&self) -> Option<Vec<u8>> {
        self.presented.lock().ok().and_then(|g| g.clone())
    }
}

impl ResolvesClientCert for IdentityClientAuth {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        let signer = *CLIENT_CERT_SIGNER.get()?;
        let (chain_der, pkcs8) = signer.identity(&self.identity, now_unix())?;
        if let Ok(mut g) = self.presented.lock() {
            *g = chain_der.first().cloned();
        }
        let certs: Vec<CertificateDer<'static>> =
            chain_der.into_iter().map(CertificateDer::from).collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8));
        let signing_key = self.provider.key_provider.load_private_key(key).ok()?;
        Some(Arc::new(CertifiedKey::new(certs, signing_key)))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// Build a rustls `ClientConfig` using the provided root CAs.
///
/// When `ratls` is `Some`, a custom RA-TLS verifier is installed that
/// wraps the standard WebPKI chain validation with additional RA-TLS
/// checks (quote presence, measurements, ReportData binding).
///
/// When the policy's [`RaTlsPolicy::client_identity`] is `Some`, the client
/// presents a measurement-bound certificate minted on demand by the registered
/// [`EnclaveClientCertSigner`], for mutual attestation against a server that
/// requests one (e.g. a vault).
fn build_client_config(
    root_store: &RootCertStore,
    ratls: Option<&RaTlsPolicy>,
) -> Result<(Arc<ClientConfig>, Option<Arc<IdentityClientAuth>>), &'static str> {
    let mut identity_auth: Option<Arc<IdentityClientAuth>> = None;
    let provider = Arc::new(default_provider());

    let config = if let Some(policy) = ratls {
        #[cfg(not(feature = "sgx-sim-attestation"))]
        let verifier: Arc<dyn ServerCertVerifier> = {
            // Production RA-TLS retains standard chain validation in addition
            // to quote appraisal.
            let inner = WebPkiServerVerifier::builder_with_provider(
                Arc::new(root_store.clone()),
                provider.clone(),
            )
            .build()
            .map_err(|_| "WebPKI verifier build error")?;
            Arc::new(RaTlsVerifier {
                inner,
                policy: policy.clone(),
            })
        };
        #[cfg(feature = "sgx-sim-attestation")]
        let verifier: Arc<dyn ServerCertVerifier> = Arc::new(AttestedRaTlsVerifier {
            provider: provider.clone(),
            policy: policy.clone(),
        });

        let wants_client_cert = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| "TLS config error")?
            .dangerous()
            .with_custom_certificate_verifier(verifier);
        match &policy.client_identity {
            Some(identity) => {
                let auth = Arc::new(IdentityClientAuth {
                    identity: identity.clone(),
                    provider: provider.clone(),
                    presented: std::sync::Mutex::new(None),
                });
                identity_auth = Some(auth.clone());
                wants_client_cert.with_client_cert_resolver(auth)
            }
            None => wants_client_cert.with_no_client_auth(),
        }
    } else {
        // Standard TLS — no RA-TLS verification.
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| "TLS config error")?
            .with_root_certificates(root_store.clone())
            .with_no_client_auth()
    };

    Ok((Arc::new(config), identity_auth))
}

/// Build a TLS 1.3 client config whose certificate identity is the appraised
/// RA-TLS quote instead of a host-provisioned WebPKI root.
///
/// This mode is intended for a local operator connecting to a freshly
/// initialised enclave whose CA was generated inside that enclave. It still
/// verifies the TLS CertificateVerify signature with the leaf public key and
/// requires challenge/handshake-exporter binding. Production callers must
/// provide at least one quote-appraisal service.
fn build_attested_client_config(
    policy: &RaTlsPolicy,
) -> Result<(Arc<ClientConfig>, Option<Arc<IdentityClientAuth>>), &'static str> {
    let ReportDataBinding::ChallengeResponse { nonce } = &policy.report_data else {
        return Err("attested-only TLS requires challenge-response report data");
    };
    if nonce.len() != 32 {
        return Err("attested-only TLS challenge must be exactly 32 bytes");
    }
    if policy.mr_enclave.is_none() && policy.mr_td.is_none() {
        return Err("attested-only TLS requires an expected enclave measurement");
    }
    #[cfg(all(not(feature = "mock"), not(feature = "sgx-sim-attestation")))]
    if policy.attestation_servers.is_empty() {
        return Err("attested-only TLS requires a quote-appraisal service");
    }

    let provider = Arc::new(default_provider());
    let verifier = AttestedRaTlsVerifier {
        provider: provider.clone(),
        policy: policy.clone(),
    };
    let wants_client_cert = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| "TLS config error")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier));
    let mut identity_auth = None;
    let mut config = match &policy.client_identity {
        Some(identity) => {
            let auth = Arc::new(IdentityClientAuth {
                identity: identity.clone(),
                provider,
                presented: std::sync::Mutex::new(None),
            });
            identity_auth = Some(auth.clone());
            wants_client_cert.with_client_cert_resolver(auth)
        }
        None => wants_client_cert.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"honest-local-control/1".to_vec()];
    Ok((Arc::new(config), identity_auth))
}

// =========================================================================
//  RA-TLS custom certificate verifier
// =========================================================================

/// Wraps a standard [`WebPkiServerVerifier`] with additional RA-TLS
/// attestation checks. The TLS handshake is rejected if any check fails.
#[derive(Debug)]
#[cfg(not(feature = "sgx-sim-attestation"))]
struct RaTlsVerifier {
    /// Standard WebPKI chain verifier (root CA validation).
    inner: Arc<WebPkiServerVerifier>,
    /// Caller-provided attestation expectations.
    policy: RaTlsPolicy,
}

/// RA-TLS verifier for an enclave-owned, non-WebPKI CA.
///
/// The quote authenticates the exact leaf key and expected measurement; the
/// TLS handshake proves possession of that key. No unauthenticated chain or
/// host routing label is treated as authority.
#[derive(Debug)]
struct AttestedRaTlsVerifier {
    provider: Arc<CryptoProvider>,
    policy: RaTlsPolicy,
}

impl ServerCertVerifier for AttestedRaTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if end_entity.as_ref().is_empty() {
            return Err(Error::General("RA-TLS leaf certificate is empty".into()));
        }
        verify_ratls_leaf(end_entity.as_ref(), &self.policy)
            .map(|_| ServerCertVerified::assertion())
            .map_err(Error::General)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(not(feature = "sgx-sim-attestation"))]
impl ServerCertVerifier for RaTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // 1. Standard certificate chain validation (issuer, expiry, signature).
        //    RA-TLS identity is the attestation quote, NOT the DNS/IP name: an
        //    attested peer's leaf (e.g. a vault's, dialed by IP) commonly carries
        //    no SAN, so a name mismatch is expected and ignored here. Every other
        //    chain failure still rejects the handshake.
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(_) => {}
            Err(Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => {}
            Err(e) => return Err(e),
        }

        // 2. Certificate-level RA-TLS checks: a v2 leaf (no evidence inside
        //    the certificate) and the expected configuration OIDs. The
        //    evidence itself is verified after the handshake (attest_exchange).
        verify_ratls_leaf(end_entity.as_ref(), &self.policy).map_err(Error::General)?;

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// =========================================================================
//  RA-TLS verification logic
// =========================================================================

/// Certificate-level RA-TLS checks, run inside the handshake: the leaf must be
/// a v2 leaf (no evidence inside the certificate) and carry the expected
/// configuration OIDs. Measurements, report_data, the attestation servers and
/// the dependency set are checked against the evidence after the handshake
/// ([`exchange::AttestationExchange`]).
fn verify_ratls_leaf(der: &[u8], policy: &RaTlsPolicy) -> Result<(), String> {
    if der.is_empty() || der.len() > MAX_TLS_PEER_CERTIFICATE_BYTES {
        return Err("RA-TLS: leaf certificate exceeds profile bound".into());
    }
    let (rest, cert) = X509Certificate::from_der(der)
        .map_err(|_| "RA-TLS: failed to parse leaf certificate DER".to_string())?;
    if !rest.is_empty() {
        return Err("RA-TLS: trailing certificate bytes".into());
    }
    validated_spki(&cert)?;
    if cert
        .extensions()
        .iter()
        .any(|ext| legacy_quote_oid(&ext.oid.to_id_string()))
    {
        return Err(
            "RA-TLS: v1 certificate (evidence inside the certificate) is not accepted by a v2 verifier"
                .into(),
        );
    }
    verify_expected_oids(&cert, &policy.expected_oids)
}

fn legacy_quote_oid(oid: &str) -> bool {
    oid == oids::SGX_QUOTE_OID_STR
        || oid == oids::TDX_QUOTE_OID_STR
        || oid == oids::SGX_SIM_REPORT_OID_STR
}

fn validated_spki(cert: &X509Certificate<'_>) -> Result<Vec<u8>, String> {
    let key = cert.public_key();
    let parameters = key
        .algorithm
        .parameters
        .as_ref()
        .and_then(|value| value.as_oid().ok())
        .map(|oid| oid.to_id_string());
    if key.algorithm.algorithm.to_id_string() != "1.2.840.10045.2.1"
        || parameters.as_deref() != Some("1.2.840.10045.3.1.7")
        || key.subject_public_key.unused_bits != 0
        || key.subject_public_key.as_ref().len() != 65
        || key.subject_public_key.as_ref()[0] != 4
    {
        return Err("RA-TLS: identity must use an uncompressed P-256 key".into());
    }
    Ok(enclave_os_common::quote::build_p256_spki_der(
        key.subject_public_key.as_ref(),
    ))
}

fn now_unix() -> u64 {
    enclave_os_common::ocall::get_current_time().unwrap_or(0)
}

type VerifiedMeasurements = (Option<[u8; 32]>, Option<[u8; 48]>);

/// Verify a server's evidence against the policy: evidence family, measurement
/// registers, report_data predicted from the leaf key and the evidence (never
/// taken from the peer), the attested dependency set, then the attestation
/// servers (signature chain, TCB).
fn verify_evidence_locally(
    cert: &X509Certificate<'_>,
    spki_der: &[u8],
    ev: &crate::attest::Evidence,
    policy: &RaTlsPolicy,
) -> Result<VerifiedMeasurements, String> {
    #[cfg(feature = "mock")]
    let is_mock = ev.quote.starts_with(MOCK_PREFIX);
    #[cfg(not(feature = "mock"))]
    let is_mock = false;

    match (policy.tee, ev.tee.as_str()) {
        (TeeType::Sgx, "sgx") | (TeeType::Tdx, "tdx") | (TeeType::Tdx, "tdx-gpu") => {}
        (t, got) => return Err(format!("RA-TLS: expected {t:?} evidence, got {got:?}")),
    }

    let mut peer_mrenclave: Option<[u8; 32]> = None;
    let mut peer_mrtd: Option<[u8; 48]> = None;
    if !is_mock {
        let actual: Vec<u8> = match policy.tee {
            TeeType::Sgx => {
                #[cfg(feature = "sgx-sim-attestation")]
                {
                    let (measurement, report_data) =
                        enclave_os_common::quote::parse_sgx_sim_report(&ev.quote)?;
                    if policy
                        .mr_enclave
                        .is_some_and(|expected| expected != measurement)
                    {
                        return Err("RA-TLS: simulated MRENCLAVE mismatch".into());
                    }
                    if policy.mr_signer.is_some() {
                        return Err("RA-TLS: simulation has no hardware MRSIGNER".into());
                    }
                    peer_mrenclave = Some(measurement);
                    report_data.to_vec()
                }
                #[cfg(not(feature = "sgx-sim-attestation"))]
                {
                    let q = parse_quote3(&ev.quote)?;
                    verify_sgx_measurements(&q, policy)?;
                    peer_mrenclave = Some(q.report_body.mr_enclave.m);
                    q.report_body.report_data.d.to_vec()
                }
            }
            TeeType::Tdx => {
                let q = parse_quote4(&ev.quote)?;
                verify_tdx_measurements(&q, policy)?;
                peer_mrtd = Some(q.report_body.mr_td.m);
                q.report_body.report_data.d.to_vec()
            }
        };
        let expected = crate::attest::expected_report_data(spki_der, ev)?;
        if actual != expected {
            return Err(format!(
                "RA-TLS: report_data mismatch ({} mode): the evidence does not commit to this leaf and connection",
                ev.mode.as_str()
            ));
        }
        if let Some(ref deps) = policy.dependencies {
            verify_dependencies(cert, policy.tee, peer_mrenclave, peer_mrtd, deps)?;
        }
    }

    Ok((peer_mrenclave, peer_mrtd))
}

fn appraise_evidence(ev: &crate::attest::Evidence, policy: &RaTlsPolicy) -> Result<(), String> {
    let verdicts =
        crate::attestation::verify_quote_statuses(&ev.quote, &policy.attestation_servers)?;
    for v in &verdicts {
        if !crate::attestation::tcb_status_acceptable(
            &v.tcb_status,
            policy.acceptable_tcb_statuses.as_deref(),
        ) {
            return Err(format!(
                "peer platform TCB status {:?} not acceptable under policy",
                v.tcb_status
            ));
        }
    }
    Ok(())
}

/// Verify expected configuration OIDs in the certificate.
///
/// For each [`ExpectedOid`] in the policy the function locates the
/// corresponding X.509 extension by its dotted-string OID, extracts the raw
/// value, and compares it byte-for-byte against `expected_value`.
///
/// Returns `Err` when:
/// - A required OID is missing from the certificate.
/// - The value for a present OID does not match the expected value.
fn verify_expected_oids(
    cert: &X509Certificate<'_>,
    expected: &[ExpectedOid],
) -> Result<(), String> {
    for exp in expected {
        let ext = cert
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == exp.oid)
            .ok_or_else(|| format!("RA-TLS: expected OID {} not found in certificate", exp.oid))?;

        if ext.value != exp.expected_value.as_slice() {
            return Err(format!(
                "RA-TLS: OID {} value mismatch (got {} bytes, expected {} bytes)",
                exp.oid,
                ext.value.len(),
                exp.expected_value.len(),
            ));
        }
    }

    Ok(())
}

// =========================================================================
//  Quote parsing — directly via sgx_types #[repr(C, packed)] structs
// =========================================================================

/// Parse raw bytes into an SGX DCAP v3 `Quote3` (QuoteHeader + ReportBody).
#[cfg(not(feature = "sgx-sim-attestation"))]
fn parse_quote3(data: &[u8]) -> Result<Quote3, String> {
    if data.len() < mem::size_of::<Quote3>() {
        return Err(format!(
            "RA-TLS: SGX quote too short ({} bytes, need >= {})",
            data.len(),
            mem::size_of::<Quote3>(),
        ));
    }
    // SAFETY: Quote3 is #[repr(C, packed)] (alignment 1). Length validated above.
    Ok(unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Quote3) })
}

/// Parse raw bytes into a TDX DCAP v4 `Quote4` (Quote4Header + Report2Body).
fn parse_quote4(data: &[u8]) -> Result<Quote4, String> {
    if data.len() < mem::size_of::<Quote4>() {
        return Err(format!(
            "RA-TLS: TDX quote too short ({} bytes, need >= {})",
            data.len(),
            mem::size_of::<Quote4>(),
        ));
    }
    // SAFETY: Quote4 is #[repr(C, packed)] (alignment 1). Length validated above.
    Ok(unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Quote4) })
}

// =========================================================================
//  Measurement verification — typed field access via sgx_types
// =========================================================================

/// Verify SGX measurements (MRENCLAVE, MRSIGNER) from the parsed `Quote3`.
/// Enforce the attested cross-enclave dependency set (fail closed).
///
/// The dependency set is the runtime-owned OID 6.1 encoding sealed with the
/// calling app. If the peer presents an app-id (OID 3.6) that this set pins as a
/// dependency, the peer MUST satisfy that entry: its measurement register matches
/// one of the entry's allowed measurements AND every required OID is present
/// verbatim. A peer whose app-id is not a declared dependency passes through
/// (governed only by the ordinary policy) — so an app's non-dependency egress is
/// unaffected, while a connection to a declared dependency can never land on a
/// rogue build even if the app's own policy is weak.
fn verify_dependencies(
    cert: &X509Certificate<'_>,
    tee: TeeType,
    peer_mrenclave: Option<[u8; 32]>,
    peer_mrtd: Option<[u8; 48]>,
    deps: &[u8],
) -> Result<(), String> {
    use enclave_os_common::dependencies::{decode_dependency_set, DepMeasurement};

    let set = decode_dependency_set(deps)
        .map_err(|e| format!("RA-TLS: invalid pinned dependency set: {e}"))?;
    if set.entries.is_empty() {
        return Ok(());
    }

    // The peer's app-id (raw bytes) identifies which enclave it claims to be.
    let peer_app_id = ext_value(cert, oids::APP_ID_OID_STR);
    let Some(peer_app_id) = peer_app_id else {
        // No app-id: the peer cannot be matched to a declared dependency, so the
        // ordinary policy already governed this connection.
        return Ok(());
    };

    for entry in &set.entries {
        if !entry_pins_app_id(entry, peer_app_id) {
            continue;
        }
        // This entry is about the peer's app — enforce it, fail closed.
        let measurement_ok = entry.measurements.iter().any(|m| match m {
            DepMeasurement::Sgx(h) => {
                tee == TeeType::Sgx
                    && peer_mrenclave
                        .map(|mre| enclave_os_common::hex::hex_decode(h) == Some(mre.to_vec()))
                        .unwrap_or(false)
            }
            DepMeasurement::Tdx { mrtd, .. } => {
                tee == TeeType::Tdx
                    && peer_mrtd
                        .map(|t| enclave_os_common::hex::hex_decode(mrtd) == Some(t.to_vec()))
                        .unwrap_or(false)
            }
        });
        if !measurement_ok {
            return Err(format!(
                "RA-TLS: dependency {} measurement not pinned (fail closed)",
                entry.app_id
            ));
        }
        for (oid, val) in &entry.required_oids {
            match ext_value(cert, oid) {
                Some(v) if v == val.as_slice() => {}
                _ => {
                    return Err(format!(
                        "RA-TLS: dependency {} required OID {} mismatch (fail closed)",
                        entry.app_id, oid
                    ));
                }
            }
        }
        return Ok(());
    }
    // The peer's app-id is not a declared dependency.
    Ok(())
}

/// Raw value bytes of the cert extension with the given dotted-string OID.
fn ext_value<'a>(cert: &'a X509Certificate<'_>, oid: &str) -> Option<&'a [u8]> {
    cert.extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == oid)
        .map(|e| e.value)
}

/// Whether a dependency entry pins the given peer app-id (raw bytes). Matches
/// either the entry's OID-3.6 required value or the entry's app-id parsed as a
/// dashed UUID.
fn entry_pins_app_id(
    entry: &enclave_os_common::dependencies::DependencyEntry,
    peer_app_id: &[u8],
) -> bool {
    // 1. An explicit OID 3.6 pin in required_oids (the raw app-id bytes).
    for (oid, val) in &entry.required_oids {
        if oid == oids::APP_ID_OID_STR {
            return val.as_slice() == peer_app_id;
        }
    }
    // 2. entry.app_id compared as raw bytes (matches the SDK, which compares the
    //    OID 3.6 value decoded as a string against app_id).
    if entry.app_id.as_bytes() == peer_app_id {
        return true;
    }
    // 3. entry.app_id as a dashed UUID (undashed hex → 16 bytes).
    let undashed: String = entry.app_id.chars().filter(|c| *c != '-').collect();
    matches!(enclave_os_common::hex::hex_decode(&undashed), Some(b) if b == peer_app_id)
}

#[cfg(not(feature = "sgx-sim-attestation"))]
fn verify_sgx_measurements(quote: &Quote3, policy: &RaTlsPolicy) -> Result<(), String> {
    if let Some(expected) = &policy.mr_enclave {
        if quote.report_body.mr_enclave.m != *expected {
            return Err("RA-TLS: MRENCLAVE mismatch".to_string());
        }
    }
    if let Some(expected) = &policy.mr_signer {
        if quote.report_body.mr_signer.m != *expected {
            return Err("RA-TLS: MRSIGNER mismatch".to_string());
        }
    }
    Ok(())
}

/// Verify TDX measurements (MRTD) from the parsed `Quote4`.
fn verify_tdx_measurements(quote: &Quote4, policy: &RaTlsPolicy) -> Result<(), String> {
    if let Some(expected) = &policy.mr_td {
        if quote.report_body.mr_td.m != *expected {
            return Err("RA-TLS: MRTD mismatch".to_string());
        }
    }
    Ok(())
}

// =========================================================================
//  ReportData verification — deterministic & challenge-response
// =========================================================================

fn sha256_array(bytes: &[u8]) -> [u8; 32] {
    let value = digest::digest(&digest::SHA256, bytes);
    let mut out = [0_u8; 32];
    out.copy_from_slice(value.as_ref());
    out
}

#[cfg(test)]
mod peer_appraisal_tests {
    use super::{
        legacy_quote_oid, locally_verify_sgx_peer_certificate,
        verify_webpki_client_certificate_chain_at, verify_webpki_server_certificate_chain_at,
        RootCertStore, MAX_TLS_PEER_CERTIFICATES, MAX_TLS_PEER_CERTIFICATE_BYTES,
    };

    #[test]
    fn v2_leaf_rejects_every_legacy_quote_oid() {
        for oid in [
            enclave_os_common::oids::SGX_QUOTE_OID_STR,
            enclave_os_common::oids::TDX_QUOTE_OID_STR,
            enclave_os_common::oids::SGX_SIM_REPORT_OID_STR,
        ] {
            assert!(legacy_quote_oid(oid));
        }
        assert!(!legacy_quote_oid(enclave_os_common::oids::APP_ID_OID_STR));
    }

    #[test]
    fn strict_peer_appraisal_rejects_missing_or_malformed_live_bindings_first() {
        use crate::attest::{AttestationMode, Evidence};
        let mut evidence = Evidence {
            mode: AttestationMode::Challenge,
            tee: "sgx".into(),
            quote: vec![],
            gpu_evidence: None,
            quote_time: String::new(),
            context: None,
            hctx: Some([0x42; 32]),
        };
        assert_eq!(
            locally_verify_sgx_peer_certificate(&[], [0x51; 32], &evidence).unwrap_err(),
            "RA-TLS peer: live challenge and exporter are required"
        );
        evidence.context = Some([0x41; 32]);
        evidence.hctx = None;
        assert_eq!(
            locally_verify_sgx_peer_certificate(&[], [0x51; 32], &evidence).unwrap_err(),
            "RA-TLS peer: live challenge and exporter are required"
        );
        evidence.hctx = Some([0x42; 32]);
        evidence.mode = AttestationMode::Deterministic;
        assert_eq!(
            locally_verify_sgx_peer_certificate(&[], [0x51; 32], &evidence).unwrap_err(),
            "RA-TLS peer: live challenge and exporter are required"
        );
    }

    #[test]
    fn retained_peer_chain_replay_rejects_empty_count_and_certificate_bounds_first() {
        let roots = RootCertStore::empty();
        assert!(
            verify_webpki_server_certificate_chain_at(&[], "example.test", &roots, 1)
                .unwrap_err()
                .contains("count")
        );
        assert!(verify_webpki_client_certificate_chain_at(&[], &roots, 1)
            .unwrap_err()
            .contains("count"));
        assert!(verify_webpki_server_certificate_chain_at(
            &vec![vec![1]; MAX_TLS_PEER_CERTIFICATES + 1],
            "example.test",
            &roots,
            1,
        )
        .unwrap_err()
        .contains("count"));
        assert!(verify_webpki_server_certificate_chain_at(
            &[vec![1; MAX_TLS_PEER_CERTIFICATE_BYTES + 1]],
            "example.test",
            &roots,
            1,
        )
        .unwrap_err()
        .contains("certificate"));
    }
}
