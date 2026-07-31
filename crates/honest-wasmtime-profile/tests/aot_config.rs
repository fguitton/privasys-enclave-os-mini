// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

#[cfg(feature = "aot")]
use honest_wasmtime_profile::TARGET_TRIPLE;
use honest_wasmtime_profile::{
    build_config, CompilerStrategy, OptimizationLevel, ProfileDescriptor, RoleEnvelope, ROLE,
    WASM_FEATURE_BITS,
};

fn assert_rejected(descriptor: ProfileDescriptor, field: &'static str) {
    let error = build_config(&descriptor).expect_err("mutated profile must fail closed");
    assert_eq!(error.field(), field);
}

#[test]
fn canonical_descriptor_is_role_independent() {
    let descriptor = ProfileDescriptor::canonical();
    let envelope = RoleEnvelope::new(ROLE);

    assert_eq!(envelope.descriptor(), descriptor);
    assert_eq!(envelope.descriptor_bytes(), descriptor.to_canonical_bytes());
}

#[test]
#[allow(clippy::too_many_lines)]
fn every_compatibility_field_mutation_is_rejected() {
    let canonical = ProfileDescriptor::canonical();

    macro_rules! mutate_bool {
        ($field:ident) => {{
            let mut changed = canonical;
            changed.$field = !changed.$field;
            assert_rejected(changed, stringify!($field));
        }};
    }
    macro_rules! mutate_integer {
        ($field:ident) => {{
            let mut changed = canonical;
            changed.$field += 1;
            assert_rejected(changed, stringify!($field));
        }};
    }
    macro_rules! mutate_string {
        ($field:ident) => {{
            let mut changed = canonical;
            changed.$field = "mutated";
            assert_rejected(changed, stringify!($field));
        }};
    }

    mutate_integer!(schema_version);
    mutate_string!(profile_id);
    mutate_string!(wasmtime_commit);
    mutate_string!(target_triple);
    mutate_string!(cpu_feature_mask);
    mutate_integer!(wasm_feature_bits);
    mutate_bool!(consume_fuel);
    mutate_bool!(epoch_interruption);
    mutate_bool!(relaxed_simd_deterministic);
    mutate_bool!(shared_memory);
    mutate_bool!(host_concurrency);
    mutate_integer!(memory_reservation);
    mutate_integer!(memory_reservation_for_growth);
    mutate_integer!(memory_guard_size);
    mutate_bool!(memory_may_move);
    mutate_bool!(memory_init_cow);
    mutate_integer!(memory_guaranteed_dense_image_size);
    mutate_integer!(maximum_wasm_stack);
    mutate_bool!(native_unwind_info);
    mutate_bool!(signals_based_traps);
    mutate_bool!(generate_address_map);
    mutate_bool!(debug_info);
    mutate_bool!(debug_symbols);
    mutate_bool!(guest_debug);

    let mut changed = canonical;
    changed.compiler_strategy = CompilerStrategy::Cranelift;
    changed.schema_version += 1;
    assert_rejected(changed, "schema_version");

    let mut changed = canonical;
    changed.optimization_level = OptimizationLevel::None;
    assert_rejected(changed, "optimization_level");

    mutate_bool!(nan_canonicalization);
    mutate_bool!(parallel_compilation);
    mutate_string!(fuel_schedule_id);

    let mut changed = canonical;
    changed.wit_package_sha256[0] ^= 1;
    assert_rejected(changed, "wit_package_sha256");

    mutate_string!(host_linker_profile_id);
    mutate_integer!(canonical_abi_version);
    mutate_integer!(canonical_result_version);
    mutate_integer!(canonical_trap_version);
    mutate_integer!(transcript_version);
    mutate_string!(builder_profile_id);
}

#[test]
#[cfg(feature = "aot")]
fn canonical_factory_matches_every_exposed_compatibility_getter() {
    let descriptor = ProfileDescriptor::canonical();
    let config = build_config(&descriptor).expect("canonical descriptor must construct a Config");
    let engine = honest_wasmtime_profile::wasmtime::Engine::new(&config)
        .expect("canonical Config must construct an Engine");

    assert_eq!(engine.get_wasm_features().bits(), WASM_FEATURE_BITS);
    assert!(!engine.get_wasm_features().simd());
    assert!(!engine.get_wasm_features().relaxed_simd());
    assert!(!engine.get_wasm_features().threads());
    assert!(!engine.get_wasm_features().shared_everything_threads());
    assert!(engine.get_consume_fuel());
    assert!(engine.get_epoch_interruption());
    assert!(engine.get_relaxed_simd_deterministic());
    assert!(!engine.get_shared_memory());
    assert!(!engine.get_concurrency_support());
    assert_eq!(
        engine.get_memory_reservation(),
        descriptor.memory_reservation
    );
    assert_eq!(
        engine.get_memory_reservation_for_growth(),
        descriptor.memory_reservation_for_growth
    );
    assert_eq!(engine.get_memory_guard_size(), descriptor.memory_guard_size);
    assert_eq!(engine.get_memory_may_move(), descriptor.memory_may_move);
    assert_eq!(engine.get_memory_init_cow(), descriptor.memory_init_cow);
    assert_eq!(
        engine.get_memory_guaranteed_dense_image_size(),
        descriptor.memory_guaranteed_dense_image_size
    );
    assert_eq!(
        engine.get_max_wasm_stack(),
        usize::try_from(descriptor.maximum_wasm_stack).unwrap()
    );
    assert_eq!(
        engine.get_native_unwind_info(),
        Some(descriptor.native_unwind_info)
    );
    assert_eq!(
        engine.get_signals_based_traps(),
        descriptor.signals_based_traps
    );
    assert_eq!(
        engine.get_generate_address_map(),
        descriptor.generate_address_map
    );
    assert_eq!(engine.get_debug_info(), descriptor.debug_info);
    assert_eq!(engine.get_debug_symbols(), descriptor.debug_symbols);
    assert_eq!(engine.get_guest_debug(), descriptor.guest_debug);
    assert_eq!(engine.get_target().as_deref(), Some(TARGET_TRIPLE));
    assert_eq!(
        engine.get_strategy(),
        Some(honest_wasmtime_profile::wasmtime::Strategy::Cranelift)
    );
    assert_eq!(
        engine.get_cranelift_opt_level(),
        Some(honest_wasmtime_profile::wasmtime::OptLevel::Speed)
    );
    assert_eq!(
        engine.get_cranelift_nan_canonicalization(),
        Some(descriptor.nan_canonicalization)
    );
    assert_eq!(
        engine.get_parallel_compilation(),
        descriptor.parallel_compilation
    );
    assert_eq!(engine.get_cranelift_flags_enabled().count(), 0);
    assert_eq!(engine.get_cranelift_flags_set().count(), 0);
}

#[test]
#[cfg(feature = "aot")]
fn excluded_simd_and_shared_memory_modules_fail_admission() {
    // Minimal module containing `v128.const 0; drop`.
    let simd = [
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03,
        0x02, 0x01, 0x00, 0x0a, 0x17, 0x01, 0x15, 0x00, 0xfd, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x0b,
    ];
    // Minimal module declaring a shared one-page memory with maximum one.
    let shared_memory = [
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x05, 0x04, 0x01, 0x03, 0x01, 0x01,
    ];
    let engine = honest_wasmtime_profile::wasmtime::Engine::new(
        &build_config(&ProfileDescriptor::canonical()).expect("canonical profile"),
    )
    .expect("AOT engine");

    assert!(
        honest_wasmtime_profile::wasmtime::Module::new(&engine, simd).is_err(),
        "SIMD must remain outside profile v1"
    );
    assert!(
        honest_wasmtime_profile::wasmtime::Module::new(&engine, shared_memory).is_err(),
        "shared memory/threads must remain outside profile v1"
    );
}

#[test]
#[cfg(feature = "runtime-sgx")]
fn runtime_factory_matches_non_compiler_compatibility_getters() {
    let descriptor = ProfileDescriptor::canonical();
    let config = build_config(&descriptor).expect("canonical descriptor must construct a Config");
    let engine = honest_wasmtime_profile::wasmtime::Engine::new(&config)
        .expect("canonical runtime Config must construct an Engine");

    assert_eq!(engine.get_wasm_features().bits(), WASM_FEATURE_BITS);
    assert!(!engine.get_wasm_features().simd());
    assert!(!engine.get_wasm_features().relaxed_simd());
    assert!(!engine.get_wasm_features().threads());
    assert!(engine.get_consume_fuel());
    assert!(engine.get_epoch_interruption());
    assert!(!engine.get_shared_memory());
    assert!(!engine.get_concurrency_support());
    assert_eq!(
        engine.get_memory_reservation(),
        descriptor.memory_reservation
    );
    assert_eq!(engine.get_memory_guard_size(), descriptor.memory_guard_size);
    assert_eq!(
        engine.get_max_wasm_stack(),
        usize::try_from(descriptor.maximum_wasm_stack).unwrap()
    );
    assert_eq!(engine.get_native_unwind_info(), None);
    assert_eq!(
        engine.get_signals_based_traps(),
        descriptor.signals_based_traps
    );
}
