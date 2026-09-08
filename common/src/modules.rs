// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Module trait and shared types.
//!
//! This module defines the [`EnclaveModule`] trait and its associated types.
//! Module crates implement this trait; the enclave core registers instances
//! at startup and dispatches incoming requests to them.
//!
//! These types live in `common` (rather than in the enclave crate) to
//! avoid a cyclic dependency: module crates implement the trait and
//! the enclave crate optionally pulls them in as feature-gated deps.

use crate::protocol::{HttpMethod, Request, Response};

pub const HONEST_PEER_SNI: &str = "peer.s1.invalid";
pub const HONEST_PEER_ROUTE: &str = "/honest/v1/peer";
pub const HONEST_BOOTSTRAP_ROUTE: &str = "/honest/v1/bootstrap";
pub const HONEST_PROPOSAL_ROUTE: &str = "/honest/v1/proposals";
pub const HONEST_COMPONENT_STAGING_ROUTE: &str = "/honest/v1/components/staging";
pub const HONEST_LOCAL_CONTROL_ROUTE: &str = "/honest/v1/control";

// ---------------------------------------------------------------------------
//  Config Merkle leaf
// ---------------------------------------------------------------------------

/// A named leaf for the configuration Merkle tree.
///
/// Each leaf is SHA-256 hashed and concatenated to produce the Merkle root
/// that gets embedded in every RA-TLS certificate.
pub struct ConfigLeaf {
    /// Stable, human-readable identifier (e.g. `"core.ca_cert"`).
    pub name: String,
    /// Raw bytes to hash. `None` means the input is absent (leaf = 32 zero bytes).
    pub data: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
//  Module OID
// ---------------------------------------------------------------------------

/// A custom X.509 OID extension registered by a module.
///
/// Each OID is embedded as a non-critical extension in every RA-TLS leaf
/// certificate, allowing clients to verify individual module properties
/// without computing the full config Merkle tree.
pub struct ModuleOid {
    /// OID arc sequence (e.g. `&[1, 3, 6, 1, 4, 1, 65230, 2, 1]`).
    pub oid: &'static [u64],
    /// Raw extension value bytes.
    pub value: Vec<u8>,
}

// ---------------------------------------------------------------------------
//  Per-app identity types
// ---------------------------------------------------------------------------

/// A configuration entry declared by a module or app at init time.
///
/// Each entry is SHA-256 hashed and included in the app's per-identity
/// Merkle tree. Entries flagged with an [`oid`](Self::oid) are also
/// embedded as direct X.509 extensions in the app's certificate for
/// fast-path verification.
pub struct ConfigEntry {
    /// Human-readable key (e.g. `"code_hash"`, `"policy_version"`).
    pub key: String,
    /// Raw value bytes (SHA-256 hashed into the Merkle tree).
    pub value: Vec<u8>,
    /// If `Some`, also embed this entry as a direct X.509 OID extension.
    pub oid: Option<&'static [u64]>,
}

/// S1-activated workflow endpoint identity projected into an SNI leaf.
///
/// The certificate carries this identity as evidence. It remains inert until
/// an adopter compares it with current replicated state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttestedEndpointIdentity {
    pub endpoint_manifest_id: [u8; 16],
    pub endpoint_manifest_digest: [u8; 32],
    pub endpoint_id: [u8; 16],
    pub operation_id: [u8; 16],
    pub workflow_generation_id: [u8; 16],
    pub entry_stage_id: u32,
    pub workflow_id: [u8; 16],
    pub workflow_manifest_digest: [u8; 32],
    pub route_digest: [u8; 32],
    pub activation_epoch: u64,
}

/// Identity of an app endpoint that gets its own X.509 certificate.
///
/// Each identity is served via SNI-based TLS routing.
pub struct AppIdentity {
    /// SNI hostname this app responds to (e.g. `"payments.example.com"`).
    pub hostname: String,
    /// Configuration entries for this app's Merkle tree.
    pub config: Vec<ConfigEntry>,
    /// Optional S1-activated workflow endpoint projected into this leaf.
    pub attested_endpoint: Option<AttestedEndpointIdentity>,
}

// ---------------------------------------------------------------------------
//  Request context
// ---------------------------------------------------------------------------

/// A peer's attestation evidence, accepted on the server side of a mutual leg
/// (RA-TLS v2).
#[derive(Debug, Clone)]
pub struct PeerEvidence {
    /// Evidence family: "sgx", "tdx", "tdx-gpu".
    pub tee: String,
    /// Raw DCAP quote.
    pub quote: Vec<u8>,
    /// NVIDIA CC evidence, when present.
    pub gpu_evidence: Option<Vec<u8>>,
    /// Minute the quote was minted (`YYYY-MM-DDTHH:MMZ`).
    pub quote_time: String,
    /// Context chosen by this connection's verifier, never read from the quote.
    pub context: Option<[u8; 32]>,
    /// Role-specific exporter computed by the enclave TLS terminator.
    pub hctx: Option<[u8; 32]>,
}

#[cfg(feature = "crypto")]
impl PeerEvidence {
    /// Reconstruct the proof inputs retained by the trusted TLS terminator.
    pub fn as_evidence(&self) -> crate::attest::Evidence {
        crate::attest::Evidence {
            mode: if self.context.is_some() || self.hctx.is_some() {
                crate::attest::AttestationMode::Challenge
            } else {
                crate::attest::AttestationMode::Deterministic
            },
            tee: self.tee.clone(),
            quote: self.quote.clone(),
            gpu_evidence: self.gpu_evidence.clone(),
            quote_time: self.quote_time.clone(),
            context: self.context,
            hctx: self.hctx,
        }
    }
}

/// Per-request context passed to [`EnclaveModule::handle()`].
///
/// Carries optional metadata extracted from the TLS session and OIDC auth.
pub struct RequestContext {
    /// Enclave-observed ingress class carried by the ciphertext multiplexer.
    ///
    /// This is route-selection metadata, not semantic authorization: the host
    /// can lie about it. Local-control operations must independently verify
    /// their bootstrap or governor proof inside the enclave.
    pub ingress_class: IngressClass,

    /// Host-assigned connection correlation ID.
    ///
    /// This is routing metadata only and conveys no peer identity or
    /// authority. It lets an adopter bind pending asynchronous appraisal to
    /// the exact enclave-resident TLS session.
    pub connection_id: u32,

    /// Exact SNI hostname selected by the TLS ClientHello.
    ///
    /// This is trusted transport metadata from the enclave TLS terminator,
    /// not a request header. Adopter profiles use it to keep peer and client
    /// routes non-interchangeable on a shared listener.
    pub server_name: Option<String>,

    /// Endpoint identity selected with the SNI leaf for this exact session.
    ///
    /// This is certificate evidence, not admission authority. Adopters must
    /// compare it with current replicated state before accepting a proposal.
    pub attested_endpoint: Option<AttestedEndpointIdentity>,

    /// DER-encoded leaf certificate presented by the TLS client.
    ///
    /// `Some(…)` when the client provided a certificate during the TLS
    /// handshake (mutual RA-TLS). `None` for regular browser clients.
    pub peer_cert_der: Option<Vec<u8>>,

    /// Exact DER leaf served on this TLS connection.
    pub local_cert_der: Option<Vec<u8>>,
    /// Exact local quote and its verifier context/exporter for this connection.
    pub local_evidence: Option<PeerEvidence>,
    /// Separate shared exporter used to bind Honest's application session.
    pub channel_binder: Option<Vec<u8>>,

    /// The peer's attestation evidence for this connection (RA-TLS v2 mutual
    /// leg): the quote the client presented after the handshake, whose
    /// `report_data` the ingress server verified against the peer's leaf key,
    /// the client context it issued and this connection's exporter value.
    /// `None` when the client presented no evidence. A verifier that
    /// authorises a TEE principal takes the quote from here, never from the
    /// certificate (a v2 leaf carries none), and skips the binding check
    /// (done at present time).
    pub peer_evidence: Option<PeerEvidence>,

    /// Attestation tag of the connection: "none", "deterministic" or
    /// "challenge" (what the client asked for after the handshake).
    pub attestation: String,

    /// Verified OIDC claims extracted from the `"auth"` field in the
    /// JSON envelope.  `None` when no bearer token was provided (e.g.
    /// healthz, or RA-TLS-only vault GetSecret).
    pub oidc_claims: Option<crate::oidc::OidcClaims>,
}

/// Closed ingress classes understood by the enclave TLS terminator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressClass {
    ExternalNetwork,
    LocalControl,
}

/// Closed route classes for the adopter-owned Honest ingress profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HonestIngressRoute {
    Operational,
    LocalControl,
    Peer,
    Bootstrap,
    Proposal,
    ComponentStaging,
    PeerAuthenticationRequired,
    Denied,
}

/// Classify an Honest request from enclave-derived TLS metadata only.
///
/// Peer and client routes are deliberately non-interchangeable even though
/// they share one TCP listener.
#[must_use]
pub fn classify_honest_ingress(
    method: &HttpMethod,
    path: &str,
    context: &RequestContext,
) -> HonestIngressRoute {
    if matches!(
        (method, path),
        (HttpMethod::Post, HONEST_LOCAL_CONTROL_ROUTE)
    ) {
        return if context.ingress_class == IngressClass::LocalControl {
            HonestIngressRoute::LocalControl
        } else {
            HonestIngressRoute::Denied
        };
    }
    if matches!(
        (method, path),
        (HttpMethod::Get, "/healthz")
            | (HttpMethod::Get, "/status")
            | (HttpMethod::Post, "/shutdown")
    ) {
        return HonestIngressRoute::Operational;
    }
    if matches!((method, path), (HttpMethod::Post, HONEST_PEER_ROUTE)) {
        if context.server_name.as_deref() != Some(HONEST_PEER_SNI) {
            return HonestIngressRoute::Denied;
        }
        if context.peer_cert_der.is_none()
            || context.peer_evidence.is_none()
            || context.attestation != "challenge"
        {
            return HonestIngressRoute::PeerAuthenticationRequired;
        }
        return HonestIngressRoute::Peer;
    }
    if matches!((method, path), (HttpMethod::Post, HONEST_BOOTSTRAP_ROUTE))
        && context.server_name.as_deref() != Some(HONEST_PEER_SNI)
    {
        return HonestIngressRoute::Bootstrap;
    }
    if matches!((method, path), (HttpMethod::Post, HONEST_PROPOSAL_ROUTE))
        && context.server_name.as_deref() != Some(HONEST_PEER_SNI)
    {
        return HonestIngressRoute::Proposal;
    }
    if matches!(
        (method, path),
        (HttpMethod::Post, HONEST_COMPONENT_STAGING_ROUTE)
    ) && context.server_name.as_deref() != Some(HONEST_PEER_SNI)
    {
        return HonestIngressRoute::ComponentStaging;
    }
    HonestIngressRoute::Denied
}

// ---------------------------------------------------------------------------
//  EnclaveModule trait
// ---------------------------------------------------------------------------

/// Trait for pluggable enclave business logic modules.
pub trait EnclaveModule: Send + Sync {
    /// Human-readable module name (used as config leaf prefix).
    fn name(&self) -> &str;

    /// Handle a client request. Returns `Some(response)` if handled.
    fn handle(&self, req: &Request, ctx: &RequestContext) -> Option<Response>;

    /// Config leaves to include in the configuration Merkle tree.
    ///
    /// Called once during enclave init.
    fn config_leaves(&self) -> Vec<ConfigLeaf> {
        Vec::new()
    }

    /// Custom X.509 OIDs to embed in RA-TLS certificates.
    fn custom_oids(&self) -> Vec<ModuleOid> {
        Vec::new()
    }

    /// App identities for per-app X.509 certificates.
    fn app_identities(&self) -> Vec<AppIdentity> {
        Vec::new()
    }

    /// Enrich enclave-level metrics with module-specific data.
    ///
    /// Called by the `Metrics` handler.  Modules can fill in their
    /// own fields (e.g. WASM fuel counters) and perform side-effects
    /// like snapshotting metrics to the sealed KV store.
    fn enrich_metrics(&self, _metrics: &mut crate::protocol::EnclaveMetrics) {}
}

#[cfg(test)]
mod tests {
    use super::{
        classify_honest_ingress, HonestIngressRoute, IngressClass, RequestContext,
        HONEST_BOOTSTRAP_ROUTE, HONEST_COMPONENT_STAGING_ROUTE, HONEST_LOCAL_CONTROL_ROUTE,
        HONEST_PEER_ROUTE, HONEST_PEER_SNI, HONEST_PROPOSAL_ROUTE,
    };
    use crate::protocol::HttpMethod;

    fn context(server_name: Option<&str>, mutual: bool) -> RequestContext {
        RequestContext {
            ingress_class: super::IngressClass::ExternalNetwork,
            connection_id: 0,
            server_name: server_name.map(str::to_owned),
            attested_endpoint: None,
            peer_cert_der: mutual.then(|| vec![1]),
            local_cert_der: mutual.then(|| vec![4]),
            local_evidence: None,
            channel_binder: None,
            peer_evidence: mutual.then(|| super::PeerEvidence {
                tee: "sgx".into(),
                quote: vec![2],
                gpu_evidence: None,
                quote_time: "2026-09-07T12:00Z".into(),
                context: Some([1; 32]),
                hctx: Some([2; 32]),
            }),
            attestation: if mutual { "challenge" } else { "none" }.into(),
            oidc_claims: None,
        }
    }

    #[test]
    fn peer_and_client_sni_routes_never_fall_through() {
        assert_eq!(
            classify_honest_ingress(
                &HttpMethod::Post,
                HONEST_PEER_ROUTE,
                &context(Some(HONEST_PEER_SNI), true),
            ),
            HonestIngressRoute::Peer
        );
        assert_eq!(
            classify_honest_ingress(
                &HttpMethod::Post,
                HONEST_PEER_ROUTE,
                &context(Some("client.invalid"), true),
            ),
            HonestIngressRoute::Denied
        );
        assert_eq!(
            classify_honest_ingress(
                &HttpMethod::Post,
                HONEST_COMPONENT_STAGING_ROUTE,
                &context(Some("enclave-os.invalid"), false),
            ),
            HonestIngressRoute::ComponentStaging
        );
        assert_eq!(
            classify_honest_ingress(
                &HttpMethod::Post,
                HONEST_COMPONENT_STAGING_ROUTE,
                &context(Some(HONEST_PEER_SNI), true),
            ),
            HonestIngressRoute::Denied
        );
        assert_eq!(
            classify_honest_ingress(
                &HttpMethod::Post,
                HONEST_PROPOSAL_ROUTE,
                &context(Some(HONEST_PEER_SNI), true),
            ),
            HonestIngressRoute::Denied
        );
        assert_eq!(
            classify_honest_ingress(
                &HttpMethod::Post,
                HONEST_BOOTSTRAP_ROUTE,
                &context(Some("enclave-os.invalid"), false),
            ),
            HonestIngressRoute::Bootstrap
        );
        assert_eq!(
            classify_honest_ingress(
                &HttpMethod::Post,
                HONEST_BOOTSTRAP_ROUTE,
                &context(Some(HONEST_PEER_SNI), true),
            ),
            HonestIngressRoute::Denied
        );
        assert_eq!(
            classify_honest_ingress(
                &HttpMethod::Post,
                HONEST_PEER_ROUTE,
                &context(Some(HONEST_PEER_SNI), false),
            ),
            HonestIngressRoute::PeerAuthenticationRequired
        );
    }

    #[test]
    fn local_control_route_is_not_reachable_from_the_network_class() {
        let mut local = context(None, false);
        local.ingress_class = IngressClass::LocalControl;
        assert_eq!(
            classify_honest_ingress(&HttpMethod::Post, HONEST_LOCAL_CONTROL_ROUTE, &local),
            HonestIngressRoute::LocalControl
        );
        assert_eq!(
            classify_honest_ingress(
                &HttpMethod::Post,
                HONEST_LOCAL_CONTROL_ROUTE,
                &context(None, false),
            ),
            HonestIngressRoute::Denied
        );
    }
}
