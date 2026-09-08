// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Per-app certificate store with SNI-based resolution.
//!
//! Each registered app gets its own leaf X.509 certificate (signed by
//! the Enclave CA) containing:
//! - A per-app config Merkle root OID
//! - Any OID-flagged config entries as direct extensions
//!
//! Evidence is exchanged separately on the TLS connection (RA-TLS v2).
//!
//! Incoming TLS connections are routed to the correct certificate via
//! the SNI hostname in the ClientHello.
//!
//! ## Lifecycle
//!
//! 1. **Init** — [`init_cert_store()`] is called from `finalize_and_run()`
//!    after all modules are registered. Initial app identities are
//!    collected and registered.
//! 2. **Runtime** — Modules call [`cert_store().register()`] and
//!    [`cert_store().unregister()`] when apps are dynamically loaded
//!    or unloaded (e.g. WASM apps).
//! 3. **Connection** — The RA-TLS server calls [`cert_store().resolve()`]
//!    with the SNI hostname to get per-app certificate data for cert
//!    generation.

use std::collections::BTreeMap;
use std::string::String;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::vec::Vec;

use ring::digest;

use enclave_os_common::modules::{AppIdentity, AttestedEndpointIdentity, ConfigEntry};

/// Validity of one certificate configuration, shared by its cache and sessions.
/// Replacement revokes the old allocation permanently, including across an
/// unload/reload with identical configuration. It never depends on host time.
#[derive(Clone)]
pub struct ConfigurationLease(Arc<AtomicBool>);

impl ConfigurationLease {
    fn new() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }

    pub fn is_current(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn replace(&mut self) {
        self.0.store(false, Ordering::Release);
        *self = Self::new();
    }
}

// ---------------------------------------------------------------------------
//  Global accessor
// ---------------------------------------------------------------------------

static CERT_STORE: OnceLock<CertStore> = OnceLock::new();

/// Get the global cert store.
///
/// # Panics
///
/// Panics if called before [`init_cert_store()`].
pub fn cert_store() -> &'static CertStore {
    CERT_STORE.get().expect("CertStore not initialised")
}

/// Initialise the global cert store. Called once from `finalize_and_run()`.
pub fn init_cert_store(store: CertStore) {
    let _ = CERT_STORE.set(store);
}

// ---------------------------------------------------------------------------
//  Per-app certificate data (snapshot for cert generation)
// ---------------------------------------------------------------------------

/// Snapshot of a registered app's certificate data.
///
/// Cloned from the store when the RA-TLS server needs to generate
/// a certificate for an incoming connection.
#[derive(Clone)]
pub struct AppCertData {
    /// SNI hostname (used as Subject CN in the leaf certificate).
    pub hostname: String,
    /// Per-app config Merkle root (32-byte SHA-256).
    pub merkle_root: [u8; 32],
    /// Direct OID extensions extracted from config entries.
    ///
    /// Each tuple is `(OID arc sequence, raw value bytes)`.
    pub oid_extensions: Vec<(&'static [u64], Vec<u8>)>,
    /// S1-activated workflow identity selected with this SNI leaf.
    pub attested_endpoint: Option<AttestedEndpointIdentity>,
}

// ---------------------------------------------------------------------------
//  Registered app (internal)
// ---------------------------------------------------------------------------

/// A registered app with pre-computed Merkle tree data.
struct RegisteredApp {
    configuration: ConfigurationLease,
    /// Per-app Merkle root.
    merkle_root: [u8; 32],
    /// Direct OID extensions from config entries.
    oid_extensions: Vec<(&'static [u64], Vec<u8>)>,
    /// S1-activated workflow identity selected with this SNI leaf.
    attested_endpoint: Option<AttestedEndpointIdentity>,
    /// Leaf manifest entries `(key, hash)` for auditing.
    #[allow(dead_code)]
    manifest: Vec<(String, [u8; 32])>,
}

// ---------------------------------------------------------------------------
//  CertStore
// ---------------------------------------------------------------------------

/// SNI-based certificate store for per-app RA-TLS certificates.
///
/// Thread-safe: uses an `RwLock` internally so that the RA-TLS server
/// can read while modules concurrently register/unregister apps.
pub struct CertStore {
    inner: RwLock<StoreState>,
}

struct StoreState {
    apps: BTreeMap<String, RegisteredApp>,
    /// Platform leaves describe the combined workload set. Unknown SNI also
    /// uses this lease, so later registration cannot silently change routing.
    platform: ConfigurationLease,
}

impl CertStore {
    /// Create a metadata store. The ingress server owns the certificate signer.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(StoreState {
                apps: BTreeMap::new(),
                platform: ConfigurationLease::new(),
            }),
        }
    }

    /// Register an app identity.
    ///
    /// Computes the per-app Merkle tree from the identity's config
    /// entries and stores the result. If an app with the same hostname
    /// is already registered, it is replaced.
    pub fn register(&self, identity: AppIdentity) {
        let registered = Self::compute_app(&identity.config, identity.attested_endpoint);
        let mut inner = self.inner.write().expect("CertStore poisoned");
        if let Some(previous) = inner.apps.get_mut(&identity.hostname) {
            previous.configuration.replace();
        }
        inner.platform.replace();
        inner.apps.insert(identity.hostname, registered);
    }

    /// Unregister an app by SNI hostname.
    ///
    /// Returns `true` if the app was found and removed.
    pub fn unregister(&self, hostname: &str) -> bool {
        let mut inner = self.inner.write().expect("CertStore poisoned");
        if let Some(mut previous) = inner.apps.remove(hostname) {
            previous.configuration.replace();
            inner.platform.replace();
            true
        } else {
            false
        }
    }

    /// Revoke cached configurations and existing sessions for this name.
    pub fn invalidate(&self, hostname: &str) {
        let mut inner = self.inner.write().expect("CertStore poisoned");
        if let Some(app) = inner.apps.get_mut(hostname) {
            app.configuration.replace();
        }
        inner.platform.replace();
    }

    /// Capture certificate data and its validity under the same lock. A
    /// concurrent replacement revokes this snapshot, never associates old
    /// certificate contents with a new configuration's validity.
    pub fn snapshot(
        &self,
        hostname: Option<&str>,
    ) -> Result<(Option<AppCertData>, ConfigurationLease), &'static str> {
        let inner = self.inner.read().map_err(|_| "CertStore poisoned")?;
        match hostname.and_then(|name| inner.apps.get(name).map(|app| (name, app))) {
            Some((name, app)) => Ok((Some(Self::app_data(name, app)), app.configuration.clone())),
            None => Ok((None, inner.platform.clone())),
        }
    }

    /// Resolve an app by SNI hostname.
    ///
    /// Returns a cloned snapshot of the app's certificate data, or
    /// `None` if no app is registered for this hostname.
    pub fn resolve(&self, hostname: &str) -> Option<AppCertData> {
        let inner = self.inner.read().ok()?;
        let app = inner.apps.get(hostname)?;
        Some(Self::app_data(hostname, app))
    }

    fn app_data(hostname: &str, app: &RegisteredApp) -> AppCertData {
        AppCertData {
            hostname: hostname.to_string(),
            merkle_root: app.merkle_root,
            oid_extensions: app.oid_extensions.clone(),
            attested_endpoint: app.attested_endpoint,
        }
    }

    /// List all registered hostnames.
    pub fn hostnames(&self) -> Vec<String> {
        self.inner
            .read()
            .map(|inner| inner.apps.keys().cloned().collect())
            .unwrap_or_default()
    }

    // ---- Internal helpers -----------------------------------------------

    /// Compute per-app Merkle root + OID extensions from config entries.
    ///
    /// Merkle root = `SHA-256( SHA-256(e0.value) || SHA-256(e1.value) || … )`
    fn compute_app(
        config: &[ConfigEntry],
        attested_endpoint: Option<AttestedEndpointIdentity>,
    ) -> RegisteredApp {
        let mut leaf_hashes =
            Vec::with_capacity(config.len() + usize::from(attested_endpoint.is_some()));
        let mut manifest = Vec::with_capacity(config.len());
        let mut oid_extensions = Vec::new();

        for entry in config {
            let d = digest::digest(&digest::SHA256, &entry.value);
            let mut h = [0u8; 32];
            h.copy_from_slice(d.as_ref());

            manifest.push((entry.key.clone(), h));
            leaf_hashes.push(h);

            if let Some(oid) = entry.oid {
                oid_extensions.push((oid, entry.value.clone()));
            }
        }

        if let Some(endpoint) = attested_endpoint {
            let mut projection = Vec::with_capacity(188);
            projection.extend_from_slice(&endpoint.endpoint_manifest_id);
            projection.extend_from_slice(&endpoint.endpoint_manifest_digest);
            projection.extend_from_slice(&endpoint.endpoint_id);
            projection.extend_from_slice(&endpoint.operation_id);
            projection.extend_from_slice(&endpoint.workflow_generation_id);
            projection.extend_from_slice(&endpoint.entry_stage_id.to_be_bytes());
            projection.extend_from_slice(&endpoint.workflow_id);
            projection.extend_from_slice(&endpoint.workflow_manifest_digest);
            projection.extend_from_slice(&endpoint.route_digest);
            projection.extend_from_slice(&endpoint.activation_epoch.to_be_bytes());
            let d = digest::digest(&digest::SHA256, &projection);
            let mut h = [0u8; 32];
            h.copy_from_slice(d.as_ref());
            manifest.push(("honest.attested_endpoint".to_string(), h));
            leaf_hashes.push(h);
        }

        // Concatenate leaf hashes and compute root
        let merkle_root = if leaf_hashes.is_empty() {
            [0u8; 32]
        } else {
            let mut preimage = Vec::with_capacity(leaf_hashes.len() * 32);
            for h in &leaf_hashes {
                preimage.extend_from_slice(h);
            }
            let d = digest::digest(&digest::SHA256, &preimage);
            let mut root = [0u8; 32];
            root.copy_from_slice(d.as_ref());
            root
        };

        RegisteredApp {
            configuration: ConfigurationLease::new(),
            merkle_root,
            oid_extensions,
            attested_endpoint,
            manifest,
        }
    }
}

impl Default for CertStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use enclave_os_common::modules::{AppIdentity, AttestedEndpointIdentity};

    use super::CertStore;

    #[test]
    fn configuration_replacement_revokes_only_dependent_snapshots_without_aba() {
        let store = CertStore::new();
        let identity = |name: &str| AppIdentity {
            hostname: name.into(),
            config: vec![],
            attested_endpoint: None,
        };
        let (_, unknown) = store.snapshot(Some("a.test")).unwrap();
        store.register(identity("a.test"));
        assert!(!unknown.is_current());
        store.register(identity("b.test"));
        let (a_data, a) = store.snapshot(Some("a.test")).unwrap();
        let (_, b) = store.snapshot(Some("b.test")).unwrap();
        let (_, platform) = store.snapshot(None).unwrap();
        store.register(identity("a.test"));
        let (replacement_data, replacement) = store.snapshot(Some("a.test")).unwrap();
        assert_eq!(
            a_data.unwrap().merkle_root,
            replacement_data.unwrap().merkle_root
        );
        assert!(!a.is_current());
        assert!(!platform.is_current());
        assert!(b.is_current());
        assert!(replacement.is_current());
        assert!(store.unregister("a.test"));
        assert!(!replacement.is_current());
        store.register(identity("a.test"));
        assert!(!a.is_current());
        assert!(!replacement.is_current());
        let (_, reloaded) = store.snapshot(Some("a.test")).unwrap();
        store.invalidate("a.test");
        assert!(!reloaded.is_current());
        assert!(store.snapshot(Some("a.test")).unwrap().1.is_current());
        assert!(b.is_current());
        let (_, platform) = store.snapshot(None).unwrap();
        assert!(!store.unregister("missing.test"));
        assert!(platform.is_current());
    }

    #[test]
    fn endpoint_identity_is_retained_and_changes_the_app_root() {
        let endpoint = AttestedEndpointIdentity {
            endpoint_manifest_id: [1; 16],
            endpoint_manifest_digest: [2; 32],
            endpoint_id: [3; 16],
            operation_id: [4; 16],
            workflow_generation_id: [5; 16],
            entry_stage_id: 6,
            workflow_id: [7; 16],
            workflow_manifest_digest: [8; 32],
            route_digest: [9; 32],
            activation_epoch: 10,
        };
        let without = CertStore::compute_app(&[], None);
        let with = CertStore::compute_app(&[], Some(endpoint));
        assert_ne!(with.merkle_root, without.merkle_root);
        assert_eq!(with.attested_endpoint, Some(endpoint));
    }
}
