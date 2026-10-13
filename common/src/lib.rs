// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! enclave-os-common: shared types and constants between host and enclave.
//!
//! Pure `no_std` uses `--no-default-features --features sgx`. Explicit `std`
//! takes precedence and uses the runtime standard library (the SDK on Teaclave).
//! The mutable attestation-server store requires `std` plus `crypto`; pure
//! crypto/JWT profiles contain no runtime-global store or synchronization.

#![cfg_attr(all(feature = "sgx", not(feature = "std")), no_std)]
#![cfg_attr(feature = "fallible-allocation-v1", feature(allocator_api))]

// `alloc` is available in both the no_std (sgx) and std (host) builds, and
// `oidc.rs` uses `alloc::` unconditionally, so the extern crate must not be
// gated on the sgx feature (gating it broke the host build of this crate).
extern crate alloc;
#[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
extern crate std;
// Compile the actual enclave RPC client in the native queue regression.
#[cfg(test)]
extern crate self as enclave_os_common;
pub mod allocation;
pub mod channel;
pub mod core_phase;
pub mod dependencies;
pub mod hex;
pub mod modules;
pub mod ocall;
pub mod oids;
pub mod protocol;
/// Versioned byte geometry only; never source or caller authority.
pub mod source_upload_wire_v1 {
    include!(concat!(env!("OUT_DIR"), "/source_upload_wire_v1.rs"));
}
pub mod queue;
pub mod quote;

/// RA-TLS v2 attestation protocol (messages and `report_data` recipes).
#[cfg(feature = "crypto")]
pub mod attest;
pub mod rpc;
pub mod types;

#[cfg(feature = "jwt")]
pub mod jwt;

#[cfg(feature = "jwt")]
pub mod jwks;

pub mod oidc;

#[cfg(feature = "crypto")]
pub mod aead;

#[cfg(feature = "crypto")]
pub mod drbg;

// Preserve historical std+crypto availability; the named capability explicitly
// selects those requirements for runtime consumers.
#[cfg(all(feature = "crypto", feature = "std"))]
pub mod attestation_servers;

/// Re-export `ring::digest` for downstream crates that need hashing.
#[cfg(feature = "crypto")]
pub use ring::digest;

// ── Convenience logging macros (call through the OCall vtable) ──────────

/// Log an info-level message via the host.
#[macro_export]
macro_rules! enclave_log_info {
    ($($arg:tt)*) => {
        $crate::ocall::log(2, &format!($($arg)*))
    };
}

/// Log an error-level message via the host.
#[macro_export]
macro_rules! enclave_log_error {
    ($($arg:tt)*) => {
        $crate::ocall::log(4, &format!($($arg)*))
    };
}

/// Log a debug-level message via the host.
#[macro_export]
macro_rules! enclave_log_debug {
    ($($arg:tt)*) => {
        $crate::ocall::log(1, &format!($($arg)*))
    };
}
