// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Unified sealed configuration.
//!
//! All operator-provided and enclave-generated persistent state is bundled
//! into a single [`SealedConfig`] struct, sealed with MRENCLAVE policy, and
//! stored as one blob on the host.
//!
//! The struct contains:
//! - A **master encryption key** (AES-256, generated on first boot) shared
//!   by all modules for KV store encryption.
//! - Intermediary CA certificate and private key.
//! - Module-specific opaque blobs in `module_data` for additional state.
//!
//! ## Binary layout (v3)
//!
//! ```text
//! [4 bytes: version (LE u32) = 3]
//! [32 bytes: master_key]
//! [4 bytes: ca_cert_der length (LE u32)]  [ca_cert_der]
//! [4 bytes: ca_key_pkcs8 length (LE u32)] [ca_key_pkcs8]
//! [4 bytes: num_entries (LE u32)]
//!   for each entry:
//!     [4 bytes: key_len (LE u32)] [key UTF-8]
//!     [4 bytes: val_len (LE u32)] [value]

use crate::crypto::sealing;

pub(crate) mod serialization;
use enclave_os_common::allocation::AllocationPoolV1;
pub use serialization::{SealConfigError, SerializedConfig};
use std::sync::Arc;

/// KV tag under which the sealed config blob is stored on the host.
const SEALED_CONFIG_TAG: &[u8] = b"__enclave_os_sealed_config__";

/// KV table for system-level data (sealed config, etc.).
const SYSTEM_TABLE: &[u8] = b"system";

/// AAD for MRENCLAVE sealing of the unified config blob.
const SEALED_CONFIG_AAD: &[u8] = b"enclave_os_sealed_config_v3";

pub(crate) use crate::rpc_client::config_buffer as backing;
pub(crate) mod data;
pub use backing::ConfigBytes;
pub use data::{ModuleData, SealedConfig};

impl SealedConfig {
    /// Seal this config and store it on the host.
    pub fn seal_to_disk(&self, pool: &Arc<AllocationPoolV1>) -> Result<(), SealConfigError> {
        let plaintext = self
            .serialize(pool)
            .map_err(SealConfigError::Serialization)?;
        let sealed_blob =
            sealing::seal_with_mrenclave(pool, plaintext.as_slice(), SEALED_CONFIG_AAD)
                .map_err(SealConfigError::Seal)?;

        let tag = config_storage_tag();
        crate::ocall::config_store_put(pool, SYSTEM_TABLE, &tag, &sealed_blob)
            .map_err(SealConfigError::Host)
    }

    /// Unseal a previously stored config from the host.
    pub fn unseal_from_disk(pool: &Arc<AllocationPoolV1>) -> Result<Self, ConfigLoadError> {
        let tag = config_storage_tag();
        let sealed_blob = crate::ocall::config_store_get(pool, SYSTEM_TABLE, &tag)
            .map_err(ConfigLoadError::Host)?
            .ok_or(ConfigLoadError::NotFound)?;
        let (plaintext, _authenticated_aad) =
            sealing::unseal_with_mrenclave(pool, sealed_blob.as_slice())
                .map_err(ConfigLoadError::Unseal)?;
        Self::deserialize(pool, &plaintext).map_err(ConfigLoadError::Decode)
    }
}

/// Deterministic KV tag for the sealed config blob.
fn config_storage_tag() -> [u8; ring::digest::SHA256_OUTPUT_LEN] {
    let hash = ring::digest::digest(&ring::digest::SHA256, SEALED_CONFIG_TAG);
    let mut tag = [0; ring::digest::SHA256_OUTPUT_LEN];
    tag.copy_from_slice(hash.as_ref());
    tag
}

/// Existing load failure boundaries without allocating an error string.
#[derive(Debug)]
pub enum ConfigLoadError {
    Host(i32),
    NotFound,
    Unseal(&'static str),
    Decode(&'static str),
}
impl core::fmt::Display for ConfigLoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Host(code) => write!(f, "Host KV get (config) failed: {code}"),
            Self::NotFound => f.write_str("No sealed config found on disk"),
            Self::Unseal(message) => write!(f, "SealedConfig unseal failed: {message}"),
            Self::Decode(message) => write!(f, "SealedConfig deserialize failed: {message}"),
        }
    }
}
