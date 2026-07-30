// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

use honest_wasmtime_profile::{
    build_config, OptimizationLevel, ProfileDescriptor, RoleEnvelope, ROLE,
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
fn every_compatibility_field_mutation_is_rejected() {
    let canonical = ProfileDescriptor::canonical();

    let mut changed = canonical;
    changed.schema_version += 1;
    assert_rejected(changed, "schema_version");

    let mut changed = canonical;
    changed.wasm_component_model = !changed.wasm_component_model;
    assert_rejected(changed, "wasm_component_model");

    let mut changed = canonical;
    changed.wasm_multi_memory = !changed.wasm_multi_memory;
    assert_rejected(changed, "wasm_multi_memory");

    let mut changed = canonical;
    changed.wasm_simd = !changed.wasm_simd;
    assert_rejected(changed, "wasm_simd");

    let mut changed = canonical;
    changed.wasm_gc = !changed.wasm_gc;
    assert_rejected(changed, "wasm_gc");

    let mut changed = canonical;
    changed.wasm_function_references = !changed.wasm_function_references;
    assert_rejected(changed, "wasm_function_references");

    let mut changed = canonical;
    changed.wasm_exceptions = !changed.wasm_exceptions;
    assert_rejected(changed, "wasm_exceptions");

    let mut changed = canonical;
    changed.consume_fuel = !changed.consume_fuel;
    assert_rejected(changed, "consume_fuel");

    let mut changed = canonical;
    changed.memory_reservation += 1;
    assert_rejected(changed, "memory_reservation");

    let mut changed = canonical;
    changed.memory_guard_size += 1;
    assert_rejected(changed, "memory_guard_size");

    let mut changed = canonical;
    changed.memory_init_cow = !changed.memory_init_cow;
    assert_rejected(changed, "memory_init_cow");

    let mut changed = canonical;
    changed.native_unwind_info = !changed.native_unwind_info;
    assert_rejected(changed, "native_unwind_info");

    let mut changed = canonical;
    changed.signals_based_traps = !changed.signals_based_traps;
    assert_rejected(changed, "signals_based_traps");

    let mut changed = canonical;
    changed.optimization_level = OptimizationLevel::None;
    assert_rejected(changed, "optimization_level");
}

#[test]
fn canonical_factory_constructs_an_engine() {
    let config = build_config(&ProfileDescriptor::canonical())
        .expect("canonical descriptor must construct a Config");
    honest_wasmtime_profile::wasmtime::Engine::new(&config)
        .expect("canonical Config must construct an Engine");
}
