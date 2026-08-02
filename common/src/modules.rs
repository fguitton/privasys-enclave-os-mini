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

/// Per-request context passed to [`EnclaveModule::handle()`].
///
/// Carries optional metadata extracted from the TLS session and OIDC auth.
pub struct RequestContext {
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

    /// DER-encoded leaf certificate actually served by this TLS session.
    ///
    /// This is captured at the channel-binding certificate-emission seam, so
    /// it is the rebound leaf seen by the peer rather than the pre-handshake
    /// placeholder certificate.
    pub local_cert_der: Option<Vec<u8>>,

    /// Random nonce sent to the client via the TLS CertificateRequest
    /// extension `0xFFBB` for bidirectional challenge-response attestation.
    pub client_challenge_nonce: Option<Vec<u8>>,

    /// Random nonce received in the client's ClientHello and committed by the
    /// locally served challenge-mode certificate.
    pub local_challenge_nonce: Option<Vec<u8>>,

    /// 32-byte RA-TLS channel binder for this TLS session (TLS 1.3), derived
    /// from the handshake key schedule. A mutual-auth verifier folds it into the
    /// expected client-cert `report_data` so a relayed client cert from another
    /// session fails closed. `None` on non-TLS-1.3 handshakes.
    pub channel_binder: Option<Vec<u8>>,

    /// Verified OIDC claims extracted from the `"auth"` field in the
    /// JSON envelope.  `None` when no bearer token was provided (e.g.
    /// healthz, or RA-TLS-only vault GetSecret).
    pub oidc_claims: Option<crate::oidc::OidcClaims>,
}

/// Closed route classes for the adopter-owned Honest ingress profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HonestIngressRoute {
    Operational,
    Peer,
    Bootstrap,
    Proposal,
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
            || context.client_challenge_nonce.is_none()
            || context.channel_binder.is_none()
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
        classify_honest_ingress, HonestIngressRoute, RequestContext, HONEST_BOOTSTRAP_ROUTE,
        HONEST_PEER_ROUTE, HONEST_PEER_SNI, HONEST_PROPOSAL_ROUTE,
    };
    use crate::protocol::HttpMethod;

    fn context(server_name: Option<&str>, mutual: bool) -> RequestContext {
        RequestContext {
            connection_id: 0,
            server_name: server_name.map(str::to_owned),
            attested_endpoint: None,
            peer_cert_der: mutual.then(|| vec![1]),
            local_cert_der: mutual.then(|| vec![4]),
            client_challenge_nonce: mutual.then(|| vec![2]),
            local_challenge_nonce: mutual.then(|| vec![5]),
            channel_binder: mutual.then(|| vec![3]),
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
}
