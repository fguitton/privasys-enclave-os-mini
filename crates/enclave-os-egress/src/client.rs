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
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use std::vec::Vec;

use core::mem;

use ring::digest;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ResolvesClientCert, WebPkiServerVerifier};
use rustls::crypto::ring::default_provider;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::sign::CertifiedKey;
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme,
};

use x509_parser::prelude::*;

// sgx_types is provided by the Teaclave sysroot — gives us Quote3, Quote4,
// ReportBody, Report2Body with typed field access.
extern crate sgx_types;
use sgx_types::types::{Quote3, Quote4};

use enclave_os_common::oids;

mod incremental;
mod request;

pub use incremental::IncrementalTlsClient;
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
    CONFIG_MERKLE_ROOT_OID_STR as OID_CONFIG_MERKLE_ROOT,
    EGRESS_CA_HASH_OID_STR as OID_EGRESS_CA_HASH, WASM_APPS_HASH_OID_STR as OID_WASM_APPS_HASH,
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

// =========================================================================
//  RA-TLS verification types
// =========================================================================

/// Mock quote prefix used in development/test builds.
/// Only available when the `mock` feature is enabled.
#[cfg(feature = "mock")]
const MOCK_PREFIX: &[u8] = b"MOCK_QUOTE:";

/// How the verifier reproduces the 64-byte `ReportData` field in the quote.
///
/// Both modes compute `SHA-512( SHA-256(pubkey) || binding )`, but the
/// *pubkey encoding* and the *binding* differ:
///
/// | TEE | Pubkey encoding | Deterministic binding | Challenge binding |
/// |-----|-----------------|----------------------|-------------------|
/// | SGX | Raw EC point (65 B) | *skipped* (creation_time not in cert) | Client nonce |
/// | TDX | Full SPKI DER (91 B) | `NotBefore` as `"YYYY-MM-DDTHH:MMZ"` | Client nonce |
#[derive(Debug, Clone)]
pub enum ReportDataBinding {
    /// Deterministic — reproduced from the certificate alone.
    ///
    /// * **TDX**: `SHA-512(SHA-256(SPKI DER) || NotBefore "YYYY-MM-DDTHH:MMZ")`
    /// * **SGX**: verification is **skipped** because `creation_time`
    ///   (8-byte LE epoch used as binding) is not recoverable from the
    ///   certificate's `NotBefore` (enclave-os sets it to a fixed date).
    Deterministic,

    /// Challenge-response — binding is a client-supplied nonce.
    ///
    /// * **TDX**: `SHA-512(SHA-256(SPKI DER) || nonce)`
    /// * **SGX**: `SHA-512(SHA-256(raw EC point) || nonce)`
    ///
    /// The nonce is typically sent in TLS ClientHello extension `0xFFBB`
    /// and must be **exactly** the bytes the server used as binding.
    ChallengeResponse {
        /// The nonce bytes that were included in the ClientHello.
        nonce: Vec<u8>,
    },
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
/// 1. **Quote presence** — the leaf certificate must contain an attestation
///    quote in the expected TEE-specific X.509 extension.
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
    /// Defaults to [`ReportDataBinding::Deterministic`] which reproduces the
    /// binding from the certificate's public key and `NotBefore` (TDX) or
    /// skips verification (SGX deterministic — creation_time unavailable).
    ///
    /// Set to [`ReportDataBinding::ChallengeResponse`] when the client
    /// included a nonce in TLS extension `0xFFBB`.
    pub report_data: ReportDataBinding,
    /// Expected configuration OIDs to verify in the certificate.
    ///
    /// Each entry specifies an OID and its expected raw value. Common OIDs:
    ///
    /// | Constant | OID | What it proves |
    /// |----------|-----|----------------|
    /// | [`OID_CONFIG_MERKLE_ROOT`] | `1.3.6.1.4.1.65230.1.1` | All config inputs (Merkle tree root) |
    /// | [`OID_EGRESS_CA_HASH`] | `1.3.6.1.4.1.65230.2.1` | Egress CA bundle identity |
    /// | [`OID_WASM_APPS_HASH`] | `1.3.6.1.4.1.65230.2.5` | Combined workloads (WASM apps) hash |
    /// | [`OID_ATTESTATION_SERVERS_HASH`] | `1.3.6.1.4.1.65230.2.7` | Attestation server URL list identity |
    ///
    /// An empty `Vec` (the default) skips OID verification.
    pub expected_oids: Vec<ExpectedOid>,

    /// Attestation server URLs for cryptographic quote verification.
    ///
    /// When non-empty, the raw attestation quote from the server's
    /// certificate is POSTed to each URL.  **All** servers must confirm
    /// the quote for the TLS handshake to succeed.
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

/// Verify an incoming challenge-bound SGX peer certificate locally.
///
/// This checks the exact expected MRENCLAVE, server challenge and TLS 1.3
/// binder, but deliberately does not call an appraisal service. The caller
/// must submit the returned quote through its incremental control-TCS client
/// and must not treat these facts as appraised until that service accepts.
pub fn locally_verify_sgx_peer_certificate(
    der: &[u8],
    expected_mr_enclave: [u8; 32],
    challenge: &[u8],
    channel_binder: &[u8],
) -> Result<SgxPeerCertificateEvidence, String> {
    if challenge.len() != 32 {
        return Err("RA-TLS peer: challenge must be exactly 32 bytes".into());
    }
    if channel_binder.len() != 32 {
        return Err("RA-TLS peer: channel binder must be exactly 32 bytes".into());
    }
    let policy = RaTlsPolicy {
        tee: TeeType::Sgx,
        mr_enclave: Some(expected_mr_enclave),
        mr_signer: None,
        mr_td: None,
        report_data: ReportDataBinding::ChallengeResponse {
            nonce: challenge.to_vec(),
        },
        expected_oids: Vec::new(),
        attestation_servers: Vec::new(),
        client_identity: None,
        dependencies: None,
    };
    let verified = verify_ratls_cert(der, &policy)?;
    verify_certificate_channel_binding(der, &policy, channel_binder)?;
    Ok(SgxPeerCertificateEvidence {
        certificate_digest: verified.certificate_digest,
        quote_digest: verified.quote_digest,
        mr_enclave: verified
            .peer_mrenclave
            .ok_or_else(|| "RA-TLS peer: SGX measurement unavailable".to_string())?,
        quote: verified.quote,
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
    /// Mint a client cert carrying `identity`, with the SGX quote's ReportData
    /// bound to the server's `challenge` (ext `0xFFBB`) and, when present, the
    /// session `channel_binder` (`nonce || binder`), so the quote commits to
    /// this exact TLS session. Returns `(cert_chain_der, pkcs8_key_der)`, or
    /// `None` to decline.
    fn sign(
        &self,
        challenge: &[u8],
        channel_binder: Option<&[u8]>,
        identity: &ClientCertIdentity,
    ) -> Option<(Vec<Vec<u8>>, Vec<u8>)>;
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
/// minting via the registered [`EnclaveClientCertSigner`] and binding to the
/// server's RA-TLS challenge (fork `CertificateRequest` extension `0xFFBB`).
#[derive(Debug)]
struct ChallengeBoundClientAuth {
    identity: ClientCertIdentity,
    provider: Arc<CryptoProvider>,
    capture: Option<SharedClientAuthCapture>,
}

/// Capture the server's RA-TLS challenge while deliberately declining to
/// present a client certificate. Reviewer sessions authenticate at the
/// application layer, but still bind their signatures to this TLS challenge.
#[derive(Debug)]
struct ChallengeCaptureClientAuth {
    capture: SharedClientAuthCapture,
}

impl ResolvesClientCert for ChallengeCaptureClientAuth {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
        ratls_challenge: Option<&[u8]>,
        _ratls_channel_binder: Option<&[u8]>,
    ) -> Option<Arc<CertifiedKey>> {
        if let Some(challenge) = ratls_challenge {
            if let Ok(mut capture) = self.capture.lock() {
                capture.challenge_nonce = Some(challenge.to_vec());
            }
        }
        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[derive(Debug, Default)]
pub(super) struct ClientAuthCapture {
    certificate_der: Option<Vec<u8>>,
    challenge_nonce: Option<Vec<u8>>,
}

pub(super) type SharedClientAuthCapture = Arc<Mutex<ClientAuthCapture>>;

impl ClientAuthCapture {
    pub(super) fn certificate_der(&self) -> Option<Vec<u8>> {
        self.certificate_der.clone()
    }

    pub(super) fn challenge_nonce(&self) -> Option<Vec<u8>> {
        self.challenge_nonce.clone()
    }
}

impl ResolvesClientCert for ChallengeBoundClientAuth {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
        ratls_challenge: Option<&[u8]>,
        ratls_channel_binder: Option<&[u8]>,
    ) -> Option<Arc<CertifiedKey>> {
        // Bidirectional challenge-response is mandatory: without the server's
        // nonce we cannot bind a fresh quote, so decline rather than present
        // an unbound identity. The channel binder (present on TLS 1.3) is folded
        // in too, so the client cert's quote commits to this exact session.
        let challenge = ratls_challenge?;
        let signer = *CLIENT_CERT_SIGNER.get()?;
        let (chain_der, pkcs8) = signer.sign(challenge, ratls_channel_binder, &self.identity)?;
        let leaf = chain_der.first()?.clone();
        let certs: Vec<CertificateDer<'static>> =
            chain_der.into_iter().map(CertificateDer::from).collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8));
        let signing_key = self.provider.key_provider.load_private_key(key).ok()?;
        if let Some(capture) = self.capture.as_ref() {
            let mut capture = capture.lock().ok()?;
            capture.certificate_der = Some(leaf);
            capture.challenge_nonce = Some(challenge.to_vec());
        }
        Some(Arc::new(CertifiedKey::new(certs, signing_key)))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// Build a rustls `ClientConfig` using the provided root CAs.
///
/// When `ratls` is `Some`, a custom [`RaTlsVerifier`] is installed that
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
    client_auth_capture: Option<SharedClientAuthCapture>,
) -> Result<Arc<ClientConfig>, &'static str> {
    let provider = Arc::new(default_provider());

    let config = if let Some(policy) = ratls {
        // Build a WebPkiServerVerifier for standard chain validation,
        // then wrap it with our RA-TLS verifier.
        let inner = WebPkiServerVerifier::builder_with_provider(
            Arc::new(root_store.clone()),
            provider.clone(),
        )
        .build()
        .map_err(|_| "WebPKI verifier build error")?;

        let verifier = RaTlsVerifier {
            inner,
            policy: policy.clone(),
        };

        let wants_client_cert = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| "TLS config error")?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier));
        let mut cfg = match &policy.client_identity {
            Some(identity) => {
                wants_client_cert.with_client_cert_resolver(Arc::new(ChallengeBoundClientAuth {
                    identity: identity.clone(),
                    provider: provider.clone(),
                    capture: client_auth_capture.clone(),
                }))
            }
            None => match client_auth_capture {
                Some(capture) => wants_client_cert.with_client_cert_resolver(Arc::new(
                    ChallengeCaptureClientAuth { capture },
                )),
                None => wants_client_cert.with_no_client_auth(),
            },
        };

        // When the policy uses challenge-response attestation, inject the
        // nonce into the ClientHello extension 0xFFBB so the remote server
        // can bind its attestation quote to our challenge.
        if let ReportDataBinding::ChallengeResponse { ref nonce } = policy.report_data {
            cfg.ratls_challenge = Some(nonce.clone());
        }

        cfg
    } else {
        // Standard TLS — no RA-TLS verification.
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| "TLS config error")?
            .with_root_certificates(root_store.clone())
            .with_no_client_auth()
    };

    Ok(Arc::new(config))
}

// =========================================================================
//  RA-TLS custom certificate verifier
// =========================================================================

/// Wraps a standard [`WebPkiServerVerifier`] with additional RA-TLS
/// attestation checks. The TLS handshake is rejected if any check fails.
#[derive(Debug)]
struct RaTlsVerifier {
    /// Standard WebPKI chain verifier (root CA validation).
    inner: Arc<WebPkiServerVerifier>,
    /// Caller-provided attestation expectations.
    policy: RaTlsPolicy,
}

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

        // 2. RA-TLS attestation verification (the real identity check).
        verify_ratls_cert(end_entity.as_ref(), &self.policy)
            .map(|_| ())
            .map_err(Error::General)?;

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

/// Verify the RA-TLS attestation evidence in a DER-encoded leaf certificate.
struct VerifiedRaTlsCertificate {
    certificate_digest: [u8; 32],
    quote_digest: [u8; 32],
    peer_mrenclave: Option<[u8; 32]>,
    quote: Vec<u8>,
}

fn verify_ratls_cert(der: &[u8], policy: &RaTlsPolicy) -> Result<VerifiedRaTlsCertificate, String> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|_| "RA-TLS: failed to parse leaf certificate DER".to_string())?;

    // --- Find the expected attestation extension ---
    let expected_oid = match policy.tee {
        TeeType::Sgx => oids::SGX_QUOTE_OID_STR,
        TeeType::Tdx => oids::TDX_QUOTE_OID_STR,
    };

    let quote_ext = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid.to_id_string() == expected_oid)
        .ok_or_else(|| {
            format!(
                "RA-TLS: no {} attestation quote found in certificate (expected OID {})",
                match policy.tee {
                    TeeType::Sgx => "SGX",
                    TeeType::Tdx => "TDX",
                },
                expected_oid
            )
        })?;

    let quote = quote_ext.value;

    // --- Parse quote via sgx_types and verify measurements + ReportData ---
    #[cfg(feature = "mock")]
    let is_mock = quote.starts_with(MOCK_PREFIX);
    #[cfg(not(feature = "mock"))]
    let is_mock = false;

    // Peer measurement registers, captured for the attested-dependency check.
    let mut peer_mrenclave: Option<[u8; 32]> = None;
    let mut peer_mrtd: Option<[u8; 48]> = None;

    if !is_mock {
        match policy.tee {
            TeeType::Sgx => {
                let q = parse_quote3(quote)?;
                verify_sgx_measurements(&q, policy)?;
                verify_sgx_report_data(&q, &cert, policy)?;
                peer_mrenclave = Some(q.report_body.mr_enclave.m);
            }
            TeeType::Tdx => {
                let q = parse_quote4(quote)?;
                verify_tdx_measurements(&q, policy)?;
                verify_tdx_report_data(&q, &cert, policy)?;
                peer_mrtd = Some(q.report_body.mr_td.m);
            }
        }
    }

    // --- Verify configuration OIDs ---
    verify_expected_oids(&cert, &policy.expected_oids)?;

    // --- Enforce attested cross-enclave dependencies (fail closed) ---
    // Runtime-owned: if the peer's app-id (OID 3.6) is one this app pins as a
    // dependency, the peer must match the pinned identity, regardless of the
    // app-supplied policy above. Skipped in mock mode (no real measurement).
    if !is_mock {
        if let Some(ref deps) = policy.dependencies {
            verify_dependencies(&cert, policy.tee, peer_mrenclave, peer_mrtd, deps)?;
        }
    }

    // --- Verify quote via attestation server(s) ---
    //
    // After all local checks pass, send the raw quote to each configured
    // attestation server for full cryptographic verification (signature
    // chain, TCB status, platform identity).  The attestation server is
    // TEE-agnostic and auto-detects the quote format.  This is the
    // authoritative proof that the quote was produced by genuine TEE
    // hardware and has not been tampered with.
    crate::attestation::verify_quote(quote, &policy.attestation_servers)?;

    Ok(VerifiedRaTlsCertificate {
        certificate_digest: sha256_array(der),
        quote_digest: sha256_array(quote),
        peer_mrenclave,
        quote: quote.to_vec(),
    })
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

/// Verify the SGX quote's ReportData field.
///
/// | Mode | pubkey | binding |
/// |------|--------|---------|
/// | ChallengeResponse | SPKI DER (91 B) | client nonce |
/// | Deterministic | SPKI DER (91 B) | `NotBefore` as `"YYYY-MM-DDTHH:MMZ"` |
fn verify_sgx_report_data(
    quote: &Quote3,
    cert: &X509Certificate<'_>,
    policy: &RaTlsPolicy,
) -> Result<(), String> {
    // SGX (enclave-os) uses the full SPKI DER (91 bytes for P-256), matching
    // Go's x509.MarshalPKIXPublicKey and standard X.509 certificate viewers'
    // "Public Key SHA-256" fingerprint.
    let ec_point = cert.public_key().subject_public_key.as_ref();
    let spki_der = enclave_os_common::quote::build_p256_spki_der(ec_point);

    match &policy.report_data {
        ReportDataBinding::ChallengeResponse { .. } => {
            // In challenge mode report_data folds this session's channel binder,
            // which is not available in this cert-verifier callback. The full
            // check runs post-handshake in verify_channel_binding, before any
            // application data is sent. Nothing to do here.
        }
        ReportDataBinding::Deterministic => {
            // SGX sets NotBefore to the minute-truncated creation time and binds
            // "YYYY-MM-DDTHH:MMZ", same as the container/TDX issuer, so the
            // binding is reproducible from the certificate.
            let not_before = cert.validity().not_before.to_datetime();
            let binding = format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}Z",
                not_before.year(),
                not_before.month() as u8,
                not_before.day(),
                not_before.hour(),
                not_before.minute(),
            );
            let expected = compute_report_data_hash(&spki_der, binding.as_bytes());
            if quote.report_body.report_data.d != expected.as_ref() {
                return Err("RA-TLS: SGX ReportData mismatch (deterministic)".into());
            }
        }
    }
    Ok(())
}

/// Verify the TDX quote's ReportData field.
///
/// | Mode | pubkey | binding |
/// |------|--------|---------|
/// | Deterministic | SPKI DER (91 B) | `NotBefore` as `"YYYY-MM-DDTHH:MMZ"` |
/// | ChallengeResponse | SPKI DER (91 B) | client nonce |
fn verify_tdx_report_data(
    quote: &Quote4,
    cert: &X509Certificate<'_>,
    policy: &RaTlsPolicy,
) -> Result<(), String> {
    let ec_point = cert.public_key().subject_public_key.as_ref();
    let spki_der = enclave_os_common::quote::build_p256_spki_der(ec_point);

    match &policy.report_data {
        ReportDataBinding::Deterministic => {
            let not_before = cert.validity().not_before.to_datetime();
            let binding = format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}Z",
                not_before.year(),
                not_before.month() as u8,
                not_before.day(),
                not_before.hour(),
                not_before.minute(),
            );
            let expected = compute_report_data_hash(&spki_der, binding.as_bytes());
            if quote.report_body.report_data.d != expected.as_ref() {
                return Err("RA-TLS: TDX ReportData mismatch (deterministic)".into());
            }
        }
        ReportDataBinding::ChallengeResponse { .. } => {
            // In challenge mode report_data folds this session's channel binder,
            // verified post-handshake in verify_channel_binding before any
            // application data is sent. Nothing to do here.
        }
    }
    Ok(())
}

/// Post-handshake RA-TLS channel-binding check (client verifying the server).
///
/// In challenge mode a server's quote's report_data is
/// `SHA-512(SHA-256(SPKI) || nonce || binder)`. The binder is a 32-byte value
/// derived from the shared handshake key schedule and is only available after
/// ServerHello, so it cannot be checked in the cert-verifier callback. Here —
/// after the handshake completes but before any application data is sent —
/// recompute report_data WITH the binder (obtained from our own key schedule
/// via `ratls_channel_binder`) and verify it. Binding is mandatory: a relayed,
/// co-located, or unbound quote fails, because it cannot commit to this
/// session's binder. Deterministic mode cannot channel-bind (cached quote); it
/// is fully verified in the cert-verifier callback, so this is a no-op there.
fn verify_channel_binding(tls_conn: &ClientConnection, policy: &RaTlsPolicy) -> Result<(), String> {
    let certs = tls_conn
        .peer_certificates()
        .ok_or_else(|| "RA-TLS: no peer certificate for channel-binding check".to_string())?;
    let leaf = certs
        .first()
        .ok_or_else(|| "RA-TLS: empty peer certificate chain".to_string())?;

    let binder = tls_conn
        .ratls_channel_binder()
        .ok_or_else(|| "RA-TLS: channel binder unavailable".to_string())?;

    verify_certificate_channel_binding(leaf, policy, &binder)
}

fn verify_certificate_channel_binding(
    der: &[u8],
    policy: &RaTlsPolicy,
    binder: &[u8],
) -> Result<(), String> {
    let nonce = match &policy.report_data {
        ReportDataBinding::ChallengeResponse { nonce } => nonce.clone(),
        ReportDataBinding::Deterministic => return Ok(()),
    };
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|_| "RA-TLS: failed to parse leaf for channel binding".to_string())?;

    let mut binding = nonce;
    binding.extend_from_slice(binder);

    let ec_point = cert.public_key().subject_public_key.as_ref();
    let spki_der = enclave_os_common::quote::build_p256_spki_der(ec_point);
    let expected = compute_report_data_hash(&spki_der, &binding);

    let expected_oid = match policy.tee {
        TeeType::Sgx => oids::SGX_QUOTE_OID_STR,
        TeeType::Tdx => oids::TDX_QUOTE_OID_STR,
    };
    let quote_ext = cert
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == expected_oid)
        .ok_or_else(|| "RA-TLS: no quote for channel-binding check".to_string())?;

    match policy.tee {
        TeeType::Sgx => {
            let q = parse_quote3(quote_ext.value)?;
            if q.report_body.report_data.d != expected.as_ref() {
                return Err("RA-TLS: channel-binding mismatch (SGX) — quote does not commit to this TLS session".into());
            }
        }
        TeeType::Tdx => {
            let q = parse_quote4(quote_ext.value)?;
            if q.report_body.report_data.d != expected.as_ref() {
                return Err("RA-TLS: channel-binding mismatch (TDX) — quote does not commit to this TLS session".into());
            }
        }
    }
    Ok(())
}

/// `SHA-512( SHA-256(spki_der) || binding )`
///
/// Re-exported from [`enclave_os_common::quote::compute_report_data_hash`].
fn compute_report_data_hash(pubkey_bytes: &[u8], binding: &[u8]) -> digest::Digest {
    enclave_os_common::quote::compute_report_data_hash(pubkey_bytes, binding)
}

fn sha256_array(bytes: &[u8]) -> [u8; 32] {
    let value = digest::digest(&digest::SHA256, bytes);
    let mut out = [0_u8; 32];
    out.copy_from_slice(value.as_ref());
    out
}

#[cfg(test)]
mod peer_appraisal_tests {
    use super::{
        locally_verify_sgx_peer_certificate, verify_webpki_server_certificate_chain_at,
        RootCertStore, MAX_TLS_PEER_CERTIFICATES, MAX_TLS_PEER_CERTIFICATE_BYTES,
    };

    #[test]
    fn strict_peer_appraisal_rejects_missing_or_malformed_live_bindings_first() {
        let expected = [0x51; 32];
        let challenge = [0x41; 32];
        let binder = [0x42; 32];
        assert_eq!(
            locally_verify_sgx_peer_certificate(&[], expected, &challenge[..31], &binder)
                .unwrap_err(),
            "RA-TLS peer: challenge must be exactly 32 bytes"
        );
        assert_eq!(
            locally_verify_sgx_peer_certificate(&[], expected, &challenge, &binder[..31])
                .unwrap_err(),
            "RA-TLS peer: channel binder must be exactly 32 bytes"
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
