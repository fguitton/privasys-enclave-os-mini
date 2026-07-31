// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Canonical Wasmtime compatibility profile shared by the enclave and AOT tools.
//!
//! A precompiled Wasmtime component is executable native code. Its compiler and
//! runtime must therefore agree on every compatibility-affecting setting. This
//! crate is the sole source of that configuration and rejects mutated profile
//! descriptors before constructing a [`wasmtime::Config`].

#![deny(unsafe_code)]

// Wasmtime's custom SGX target requires one C-ABI platform implementation.
// Keeping it in this shared runtime-profile crate lets Honest compositions
// link the minimum engine mechanics without linking the legacy WASM module.
#[cfg(all(feature = "runtime-sgx", target_vendor = "teaclave"))]
#[allow(unsafe_code)]
mod sgx_platform;

pub use wasmtime;
pub use wasmtime::*;

#[cfg(all(feature = "runtime-sgx", feature = "aot"))]
compile_error!("select exactly one Wasmtime role: runtime-sgx or aot");

#[cfg(not(any(feature = "runtime-sgx", feature = "aot")))]
compile_error!("select exactly one Wasmtime role: runtime-sgx or aot");

/// Frozen semantic profile identity.
pub const PROFILE_ID: &str = "honest-s2-x86_64-sgx-v1";
/// Pinned Wasmtime source used by both complementary build roles.
pub const WASMTIME_COMMIT: &str = "6d01615eaf52d4e70010290f8444a8ec285d01ae";
/// Explicit AOT target. Supplying it disables host-native feature inference.
pub const TARGET_TRIPLE: &str = "x86_64-unknown-linux-gnu";
/// Conservative x86-64 baseline: architectural SSE2 only, no inferred extras.
pub const CPU_FEATURE_MASK: &str = "x86_64-baseline-sse2";
/// Exact WIT v0.2 source digest bound by this profile.
pub const WIT_PACKAGE_SHA256: [u8; 32] = [
    0xb6, 0x14, 0x14, 0x92, 0x39, 0x55, 0x75, 0xef, 0x92, 0x35, 0x28, 0xaf, 0xb2, 0x28, 0x59, 0x98,
    0xc1, 0x55, 0x5e, 0xd9, 0x2f, 0x70, 0x73, 0xc6, 0x1b, 0x8c, 0x38, 0x53, 0x90, 0xb6, 0x98, 0x82,
];
/// Fuel schedule is part of semantic compatibility, not a local tuning knob.
pub const FUEL_SCHEDULE_ID: &str = "wasmtime-47-default-fuel-v1";
/// Closed host ABI/linker family selected by WIT v0.2.
pub const HOST_LINKER_PROFILE_ID: &str = "honest-stage-host-v0.2.0";
/// Builder/toolchain identity bound by the S2 source lock.
pub const BUILDER_PROFILE_ID: &str = "honest-m0-pinned-component-aot-v1";

/// Exact enabled `wasmparser::WasmFeatures` bits for the pinned Wasmtime.
///
/// This is the pinned default proposal set with SIMD, relaxed SIMD, threads,
/// shared-everything threads and component-async disabled. Recording the full
/// bitset catches newly enabled defaults at the compatibility boundary.
pub const WASM_FEATURE_BITS: u64 = 0x0000_000c_010b_fc3f;

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

/// Compiler strategy pinned for AOT output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CompilerStrategy {
    /// Cranelift is the only admitted compiler.
    Cranelift = 1,
}

/// Compatibility-affecting Wasmtime and Honest ABI settings.
///
/// The role is deliberately absent. Cargo features determine whether this
/// package compiles or executes components, but both roles authenticate these
/// exact descriptor bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileDescriptor {
    pub schema_version: u16,
    pub profile_id: &'static str,
    pub wasmtime_commit: &'static str,
    pub target_triple: &'static str,
    pub cpu_feature_mask: &'static str,
    pub wasm_feature_bits: u64,
    pub consume_fuel: bool,
    pub epoch_interruption: bool,
    pub relaxed_simd_deterministic: bool,
    pub shared_memory: bool,
    pub host_concurrency: bool,
    pub memory_reservation: u64,
    pub memory_reservation_for_growth: u64,
    pub memory_guard_size: u64,
    pub memory_may_move: bool,
    pub memory_init_cow: bool,
    pub memory_guaranteed_dense_image_size: u64,
    pub maximum_wasm_stack: u64,
    pub native_unwind_info: bool,
    pub signals_based_traps: bool,
    pub generate_address_map: bool,
    pub debug_info: bool,
    pub debug_symbols: bool,
    pub guest_debug: bool,
    pub compiler_strategy: CompilerStrategy,
    pub optimization_level: OptimizationLevel,
    pub nan_canonicalization: bool,
    pub parallel_compilation: bool,
    pub fuel_schedule_id: &'static str,
    pub wit_package_sha256: [u8; 32],
    pub host_linker_profile_id: &'static str,
    pub canonical_abi_version: u16,
    pub canonical_result_version: u16,
    pub canonical_trap_version: u16,
    pub transcript_version: u16,
    pub builder_profile_id: &'static str,
}

impl ProfileDescriptor {
    /// Return the only descriptor admitted by this profile version.
    #[must_use]
    pub const fn canonical() -> Self {
        Self {
            schema_version: 2,
            profile_id: PROFILE_ID,
            wasmtime_commit: WASMTIME_COMMIT,
            target_triple: TARGET_TRIPLE,
            cpu_feature_mask: CPU_FEATURE_MASK,
            wasm_feature_bits: WASM_FEATURE_BITS,
            consume_fuel: true,
            epoch_interruption: true,
            relaxed_simd_deterministic: true,
            shared_memory: false,
            host_concurrency: false,
            memory_reservation: 4 * 1024 * 1024,
            memory_reservation_for_growth: 0,
            memory_guard_size: 64 * 1024,
            memory_may_move: false,
            memory_init_cow: false,
            memory_guaranteed_dense_image_size: 0,
            maximum_wasm_stack: 512 * 1024,
            native_unwind_info: false,
            signals_based_traps: false,
            generate_address_map: false,
            debug_info: false,
            debug_symbols: false,
            guest_debug: false,
            compiler_strategy: CompilerStrategy::Cranelift,
            optimization_level: OptimizationLevel::Speed,
            nan_canonicalization: true,
            parallel_compilation: false,
            fuel_schedule_id: FUEL_SCHEDULE_ID,
            wit_package_sha256: WIT_PACKAGE_SHA256,
            host_linker_profile_id: HOST_LINKER_PROFILE_ID,
            canonical_abi_version: 2,
            canonical_result_version: 2,
            canonical_trap_version: 1,
            transcript_version: 1,
            builder_profile_id: BUILDER_PROFILE_ID,
        }
    }

    /// Encode the descriptor in a fixed, role-independent byte format.
    #[must_use]
    pub fn to_canonical_bytes(self) -> Vec<u8> {
        fn string(bytes: &mut Vec<u8>, value: &str) {
            let length = u16::try_from(value.len()).expect("profile strings fit u16");
            bytes.extend_from_slice(&length.to_le_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }

        let mut bytes = Vec::with_capacity(384);
        bytes.extend_from_slice(b"HWTP");
        bytes.extend_from_slice(&self.schema_version.to_le_bytes());
        string(&mut bytes, self.profile_id);
        string(&mut bytes, self.wasmtime_commit);
        string(&mut bytes, self.target_triple);
        string(&mut bytes, self.cpu_feature_mask);
        bytes.extend_from_slice(&self.wasm_feature_bits.to_le_bytes());
        bytes.push(u8::from(self.consume_fuel));
        bytes.push(u8::from(self.epoch_interruption));
        bytes.push(u8::from(self.relaxed_simd_deterministic));
        bytes.push(u8::from(self.shared_memory));
        bytes.push(u8::from(self.host_concurrency));
        bytes.extend_from_slice(&self.memory_reservation.to_le_bytes());
        bytes.extend_from_slice(&self.memory_reservation_for_growth.to_le_bytes());
        bytes.extend_from_slice(&self.memory_guard_size.to_le_bytes());
        bytes.push(u8::from(self.memory_may_move));
        bytes.push(u8::from(self.memory_init_cow));
        bytes.extend_from_slice(&self.memory_guaranteed_dense_image_size.to_le_bytes());
        bytes.extend_from_slice(&self.maximum_wasm_stack.to_le_bytes());
        bytes.push(u8::from(self.native_unwind_info));
        bytes.push(u8::from(self.signals_based_traps));
        bytes.push(u8::from(self.generate_address_map));
        bytes.push(u8::from(self.debug_info));
        bytes.push(u8::from(self.debug_symbols));
        bytes.push(u8::from(self.guest_debug));
        bytes.push(self.compiler_strategy as u8);
        bytes.push(self.optimization_level as u8);
        bytes.push(u8::from(self.nan_canonicalization));
        bytes.push(u8::from(self.parallel_compilation));
        string(&mut bytes, self.fuel_schedule_id);
        bytes.extend_from_slice(&self.wit_package_sha256);
        string(&mut bytes, self.host_linker_profile_id);
        bytes.extend_from_slice(&self.canonical_abi_version.to_le_bytes());
        bytes.extend_from_slice(&self.canonical_result_version.to_le_bytes());
        bytes.extend_from_slice(&self.canonical_trap_version.to_le_bytes());
        bytes.extend_from_slice(&self.transcript_version.to_le_bytes());
        string(&mut bytes, self.builder_profile_id);
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
    compare!(profile_id);
    compare!(wasmtime_commit);
    compare!(target_triple);
    compare!(cpu_feature_mask);
    compare!(wasm_feature_bits);
    compare!(consume_fuel);
    compare!(epoch_interruption);
    compare!(relaxed_simd_deterministic);
    compare!(shared_memory);
    compare!(host_concurrency);
    compare!(memory_reservation);
    compare!(memory_reservation_for_growth);
    compare!(memory_guard_size);
    compare!(memory_may_move);
    compare!(memory_init_cow);
    compare!(memory_guaranteed_dense_image_size);
    compare!(maximum_wasm_stack);
    compare!(native_unwind_info);
    compare!(signals_based_traps);
    compare!(generate_address_map);
    compare!(debug_info);
    compare!(debug_symbols);
    compare!(guest_debug);
    compare!(compiler_strategy);
    compare!(optimization_level);
    compare!(nan_canonicalization);
    compare!(parallel_compilation);
    compare!(fuel_schedule_id);
    compare!(wit_package_sha256);
    compare!(host_linker_profile_id);
    compare!(canonical_abi_version);
    compare!(canonical_result_version);
    compare!(canonical_trap_version);
    compare!(transcript_version);
    compare!(builder_profile_id);
    None
}

/// Construct a Wasmtime configuration after validating the descriptor.
pub fn build_config(descriptor: &ProfileDescriptor) -> Result<wasmtime::Config, ProfileMismatch> {
    if let Some(field) = first_mismatch(descriptor) {
        return Err(ProfileMismatch { field });
    }

    let mut config = wasmtime::Config::new();
    config.wasm_features(wasmtime::WasmFeatures::all(), false);
    config.wasm_features(
        wasmtime::WasmFeatures::from_bits_retain(descriptor.wasm_feature_bits),
        true,
    );
    config.consume_fuel(descriptor.consume_fuel);
    config.epoch_interruption(descriptor.epoch_interruption);
    config.relaxed_simd_deterministic(descriptor.relaxed_simd_deterministic);
    config.shared_memory(descriptor.shared_memory);
    config.concurrency_support(descriptor.host_concurrency);
    config.memory_reservation(descriptor.memory_reservation);
    config.memory_reservation_for_growth(descriptor.memory_reservation_for_growth);
    config.memory_guard_size(descriptor.memory_guard_size);
    config.memory_may_move(descriptor.memory_may_move);
    config.memory_init_cow(descriptor.memory_init_cow);
    config.memory_guaranteed_dense_image_size(descriptor.memory_guaranteed_dense_image_size);
    config.max_wasm_stack(
        usize::try_from(descriptor.maximum_wasm_stack)
            .expect("the frozen maximum Wasm stack fits usize"),
    );
    config.native_unwind_info(descriptor.native_unwind_info);
    config.signals_based_traps(descriptor.signals_based_traps);
    config.generate_address_map(descriptor.generate_address_map);
    config.debug_info(descriptor.debug_info);
    config.debug_symbols(descriptor.debug_symbols);
    // `guest_debug` is compile-disabled in the pinned dependency envelope; its
    // public getter is still asserted false by the profile self-test.

    // The runtime role deliberately contains no compiler. These settings are
    // still authenticated by its descriptor; the complementary AOT role is
    // the only role that can physically apply them.
    #[cfg(feature = "aot")]
    {
        config
            .target(descriptor.target_triple)
            .expect("the frozen AOT target is valid");
        config.strategy(match descriptor.compiler_strategy {
            CompilerStrategy::Cranelift => wasmtime::Strategy::Cranelift,
        });
        config.cranelift_opt_level(match descriptor.optimization_level {
            OptimizationLevel::None => wasmtime::OptLevel::None,
            OptimizationLevel::Speed => wasmtime::OptLevel::Speed,
            OptimizationLevel::SpeedAndSize => wasmtime::OptLevel::SpeedAndSize,
        });
        config.cranelift_nan_canonicalization(descriptor.nan_canonicalization);
        config.parallel_compilation(descriptor.parallel_compilation);
    }
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

/// Digest of the complete role-independent compatibility descriptor.
#[must_use]
pub fn profile_digest() -> [u8; 32] {
    use sha2::Digest as _;

    sha2::Sha256::digest(ProfileDescriptor::canonical().to_canonical_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::{profile_digest, ProfileDescriptor, Role, ROLE, WASM_FEATURE_BITS};

    #[test]
    fn exactly_one_role_is_selected() {
        #[cfg(feature = "runtime-sgx")]
        assert_eq!(ROLE, Role::RuntimeSgx);

        #[cfg(feature = "aot")]
        assert_eq!(ROLE, Role::Aot);
    }

    #[test]
    fn canonical_descriptor_encoding_is_stable() {
        let bytes = ProfileDescriptor::canonical().to_canonical_bytes();
        assert_eq!(&bytes[..6], b"HWTP\x02\x00");
        assert_eq!(bytes.len(), 316);
        assert_eq!(
            ProfileDescriptor::canonical().wasm_feature_bits,
            WASM_FEATURE_BITS
        );
        assert_eq!(
            profile_digest(),
            [
                0xca, 0x6d, 0x25, 0x81, 0xa7, 0x1d, 0xe3, 0x10, 0x8f, 0xd4, 0xc7, 0x04, 0x36, 0xd6,
                0xbe, 0x6e, 0x7c, 0x05, 0xeb, 0xc2, 0xeb, 0xd7, 0xf7, 0xe8, 0xad, 0xef, 0xc4, 0xde,
                0x53, 0xb8, 0xaa, 0xa1,
            ]
        );
    }
}
