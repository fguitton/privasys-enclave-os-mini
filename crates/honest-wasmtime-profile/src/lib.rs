// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Canonical Wasmtime compatibility profile shared by the enclave and AOT tools.
//!
//! A precompiled Wasmtime component is executable native code. Its compiler and
//! runtime must therefore agree on every compatibility-affecting setting. This
//! crate is the sole source of that configuration and rejects mutated profile
//! descriptors before constructing a [`wasmtime::Config`].

#![forbid(unsafe_code)]

pub use wasmtime;
pub use wasmtime::*;

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

/// Optimization level pinned for AOT output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OptimizationLevel {
    /// Disable optimizations.
    None = 0,
    /// Optimize for execution speed.
    Speed = 1,
    /// Optimize for code size while retaining speed.
    SpeedAndSize = 2,
}

/// Compatibility-affecting Wasmtime settings.
///
/// The role is deliberately absent. Cargo features determine whether this
/// package compiles or executes components, but both roles use these exact
/// semantic settings and emit the same descriptor bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileDescriptor {
    pub schema_version: u16,
    pub wasm_component_model: bool,
    pub wasm_multi_memory: bool,
    pub wasm_simd: bool,
    pub wasm_gc: bool,
    pub wasm_function_references: bool,
    pub wasm_exceptions: bool,
    pub consume_fuel: bool,
    pub memory_reservation: u64,
    pub memory_guard_size: u64,
    pub memory_init_cow: bool,
    pub native_unwind_info: bool,
    pub signals_based_traps: bool,
    pub optimization_level: OptimizationLevel,
}

impl ProfileDescriptor {
    /// Return the only descriptor admitted by this profile version.
    #[must_use]
    pub const fn canonical() -> Self {
        Self {
            schema_version: 1,
            wasm_component_model: true,
            wasm_multi_memory: true,
            wasm_simd: true,
            wasm_gc: true,
            wasm_function_references: true,
            wasm_exceptions: true,
            consume_fuel: true,
            memory_reservation: 4 * 1024 * 1024,
            memory_guard_size: 64 * 1024,
            memory_init_cow: false,
            native_unwind_info: false,
            signals_based_traps: false,
            optimization_level: OptimizationLevel::Speed,
        }
    }

    /// Encode the descriptor in a fixed, role-independent byte format.
    #[must_use]
    pub fn to_canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(34);
        bytes.extend_from_slice(b"HWTP");
        bytes.extend_from_slice(&self.schema_version.to_le_bytes());
        bytes.push(u8::from(self.wasm_component_model));
        bytes.push(u8::from(self.wasm_multi_memory));
        bytes.push(u8::from(self.wasm_simd));
        bytes.push(u8::from(self.wasm_gc));
        bytes.push(u8::from(self.wasm_function_references));
        bytes.push(u8::from(self.wasm_exceptions));
        bytes.push(u8::from(self.consume_fuel));
        bytes.extend_from_slice(&self.memory_reservation.to_le_bytes());
        bytes.extend_from_slice(&self.memory_guard_size.to_le_bytes());
        bytes.push(u8::from(self.memory_init_cow));
        bytes.push(u8::from(self.native_unwind_info));
        bytes.push(u8::from(self.signals_based_traps));
        bytes.push(self.optimization_level as u8);
        bytes
    }
}

/// Cargo-feature role plus the role-independent compatibility descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoleEnvelope {
    role: Role,
    descriptor: ProfileDescriptor,
}

impl RoleEnvelope {
    #[must_use]
    pub const fn new(role: Role) -> Self {
        Self {
            role,
            descriptor: ProfileDescriptor::canonical(),
        }
    }

    #[must_use]
    pub const fn role(self) -> Role {
        self.role
    }

    #[must_use]
    pub const fn descriptor(self) -> ProfileDescriptor {
        self.descriptor
    }

    #[must_use]
    pub fn descriptor_bytes(self) -> Vec<u8> {
        self.descriptor.to_canonical_bytes()
    }
}

/// A non-canonical profile descriptor was presented to the factory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileMismatch {
    field: &'static str,
}

impl ProfileMismatch {
    #[must_use]
    pub const fn field(self) -> &'static str {
        self.field
    }
}

impl core::fmt::Display for ProfileMismatch {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "non-canonical Wasmtime profile field: {}",
            self.field
        )
    }
}

impl std::error::Error for ProfileMismatch {}

fn first_mismatch(descriptor: &ProfileDescriptor) -> Option<&'static str> {
    let canonical = ProfileDescriptor::canonical();

    macro_rules! compare {
        ($field:ident) => {
            if descriptor.$field != canonical.$field {
                return Some(stringify!($field));
            }
        };
    }

    compare!(schema_version);
    compare!(wasm_component_model);
    compare!(wasm_multi_memory);
    compare!(wasm_simd);
    compare!(wasm_gc);
    compare!(wasm_function_references);
    compare!(wasm_exceptions);
    compare!(consume_fuel);
    compare!(memory_reservation);
    compare!(memory_guard_size);
    compare!(memory_init_cow);
    compare!(native_unwind_info);
    compare!(signals_based_traps);
    compare!(optimization_level);
    None
}

/// Construct a Wasmtime configuration after validating the descriptor.
pub fn build_config(descriptor: &ProfileDescriptor) -> Result<wasmtime::Config, ProfileMismatch> {
    if let Some(field) = first_mismatch(descriptor) {
        return Err(ProfileMismatch { field });
    }

    let mut config = wasmtime::Config::new();
    config.wasm_component_model(descriptor.wasm_component_model);
    config.wasm_multi_memory(descriptor.wasm_multi_memory);
    config.wasm_simd(descriptor.wasm_simd);
    config.wasm_gc(descriptor.wasm_gc);
    config.wasm_function_references(descriptor.wasm_function_references);
    config.wasm_exceptions(descriptor.wasm_exceptions);
    config.consume_fuel(descriptor.consume_fuel);
    config.memory_reservation(descriptor.memory_reservation);
    config.memory_guard_size(descriptor.memory_guard_size);
    config.memory_init_cow(descriptor.memory_init_cow);
    config.native_unwind_info(descriptor.native_unwind_info);
    config.signals_based_traps(descriptor.signals_based_traps);
    // Wasmtime exposes this setter only when its Cranelift feature is present.
    // The descriptor remains role-independent; the runtime consumes AOT output
    // but contains no compiler to configure.
    #[cfg(feature = "aot")]
    config.cranelift_opt_level(match descriptor.optimization_level {
        OptimizationLevel::None => wasmtime::OptLevel::None,
        OptimizationLevel::Speed => wasmtime::OptLevel::Speed,
        OptimizationLevel::SpeedAndSize => wasmtime::OptLevel::SpeedAndSize,
    });
    Ok(config)
}

/// Construct the canonical Wasmtime configuration.
#[must_use]
pub fn canonical_config() -> wasmtime::Config {
    match build_config(&ProfileDescriptor::canonical()) {
        Ok(config) => config,
        Err(_) => unreachable!("the compile-time canonical profile must validate"),
    }
}

#[cfg(test)]
mod tests {
    use super::{ProfileDescriptor, Role, ROLE};

    #[test]
    fn exactly_one_role_is_selected() {
        #[cfg(feature = "runtime-sgx")]
        assert_eq!(ROLE, Role::RuntimeSgx);

        #[cfg(feature = "aot")]
        assert_eq!(ROLE, Role::Aot);
    }

    #[test]
    fn canonical_descriptor_encoding_is_stable() {
        assert_eq!(
            ProfileDescriptor::canonical().to_canonical_bytes(),
            b"HWTP\x01\x00\x01\x01\x01\x01\x01\x01\x01\
              \x00\x00\x40\x00\x00\x00\x00\x00\
              \x00\x00\x01\x00\x00\x00\x00\x00\
              \x00\x00\x00\x01"
        );
    }
}
