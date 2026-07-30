// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Workspace and feature boundary for the canonical Honest Wasmtime profile.
//!
//! The descriptor and `Config` factory are introduced by `AOT-CONFIG-001`.
//! This S1.0 repair only establishes one reproducible package shared by the
//! enclave runtime and both AOT tools.

#![forbid(unsafe_code)]

#[cfg(all(feature = "runtime-sgx", feature = "aot"))]
compile_error!("select exactly one Wasmtime role: runtime-sgx or aot");

#[cfg(not(any(feature = "runtime-sgx", feature = "aot")))]
compile_error!("select exactly one Wasmtime role: runtime-sgx or aot");

/// The build role selected by the package consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Wasmtime executes precompiled components inside SGX.
    RuntimeSgx,
    /// Wasmtime compiles components on the host.
    Aot,
}

/// Role selected for this package instance.
#[cfg(feature = "runtime-sgx")]
pub const ROLE: Role = Role::RuntimeSgx;

/// Role selected for this package instance.
#[cfg(feature = "aot")]
pub const ROLE: Role = Role::Aot;

#[cfg(test)]
mod tests {
    use super::{Role, ROLE};

    #[test]
    fn exactly_one_role_is_selected() {
        #[cfg(feature = "runtime-sgx")]
        assert_eq!(ROLE, Role::RuntimeSgx);

        #[cfg(feature = "aot")]
        assert_eq!(ROLE, Role::Aot);
    }
}
