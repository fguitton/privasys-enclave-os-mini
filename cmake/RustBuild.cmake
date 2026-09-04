# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

# cmake/RustBuild.cmake
# Helpers for building Rust crates via Cargo from CMake.
#
# Toolchain: nightly-2026-06-21
# Enclave target: x86_64-unknown-linux-sgx (defined in Teaclave's rustlib/)

find_program(CARGO_EXECUTABLE cargo REQUIRED)

set(RUST_ENCLAVE_TARGET "x86_64-unknown-linux-sgx" CACHE STRING
    "Rust target triple for SGX enclave builds")

set(RUST_ENCLAVE_TOOLCHAIN "nightly-2026-06-21" CACHE STRING
    "Rustup toolchain name for enclave builds")

set(RUST_ENCLAVE_SOURCE_ROOT "${CMAKE_SOURCE_DIR}" CACHE PATH
    "Source root remapped to /workspace in enclave compiler output")
set(RUST_ENCLAVE_TOOLCHAIN_ROOT "" CACHE PATH
    "Optional toolchain root remapped to /rust-toolchain in compiler output")
set(RUST_ENCLAVE_VENDOR_ROOT "" CACHE PATH
    "Optional Cargo vendor root remapped to /cargo-vendor in compiler output")
set(RUST_ENCLAVE_CARGO_HOME_ROOT "" CACHE PATH
    "Optional Cargo home root remapped to /cargo-home in compiler output")
set(RUST_HOST_TARGET_DIR "${CMAKE_BINARY_DIR}/cargo/host" CACHE PATH
    "Cargo target directory for the untrusted host build")

get_filename_component(RUST_ENCLAVE_SOURCE_REMAP_ROOT
    "${RUST_ENCLAVE_SOURCE_ROOT}" ABSOLUTE)
set(RUST_REPRODUCIBLE_INPUT_REMAP_FLAGS
    " --remap-path-prefix ${RUST_ENCLAVE_SOURCE_REMAP_ROOT}=/workspace")
if(RUST_ENCLAVE_TOOLCHAIN_ROOT)
    get_filename_component(RUST_ENCLAVE_TOOLCHAIN_REMAP_ROOT
        "${RUST_ENCLAVE_TOOLCHAIN_ROOT}" ABSOLUTE)
    string(APPEND RUST_REPRODUCIBLE_INPUT_REMAP_FLAGS
        " --remap-path-prefix ${RUST_ENCLAVE_TOOLCHAIN_REMAP_ROOT}=/rust-toolchain")
endif()
if(RUST_ENCLAVE_VENDOR_ROOT)
    get_filename_component(RUST_ENCLAVE_VENDOR_REMAP_ROOT
        "${RUST_ENCLAVE_VENDOR_ROOT}" ABSOLUTE)
    string(APPEND RUST_REPRODUCIBLE_INPUT_REMAP_FLAGS
        " --remap-path-prefix ${RUST_ENCLAVE_VENDOR_REMAP_ROOT}=/cargo-vendor")
endif()
if(RUST_ENCLAVE_CARGO_HOME_ROOT)
    get_filename_component(RUST_ENCLAVE_CARGO_HOME_REMAP_ROOT
        "${RUST_ENCLAVE_CARGO_HOME_ROOT}" ABSOLUTE)
    string(APPEND RUST_REPRODUCIBLE_INPUT_REMAP_FLAGS
        " --remap-path-prefix ${RUST_ENCLAVE_CARGO_HOME_REMAP_ROOT}=/cargo-home")
endif()

# Build type mapping
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CARGO_BUILD_TYPE "--release")
    set(CARGO_OUT_DIR "release")
else()
    set(CARGO_BUILD_TYPE "")
    set(CARGO_OUT_DIR "debug")
endif()

# ---------------------------------------------------------------------------
# rust_build_host(CRATE_DIR OUTPUT_NAME)
#   Build a host-side Rust crate and produce a binary.
#   The host crate's build.rs handles EDL generation and C compilation itself.
#   NOTE: host is a workspace member → target dir is at the workspace root.
# ---------------------------------------------------------------------------
function(rust_build_host CRATE_DIR OUTPUT_NAME)
    add_custom_target(${OUTPUT_NAME} ALL
        COMMAND ${CMAKE_COMMAND} -E env
            ${HONEST_SGX_SIM_HOST_DEV_PROFILE_ENV}
            "SGX_SDK_PATH=${SGX_SDK_PATH}"
            "SGX_MODE=${SGX_MODE}"
            "RUSTUP_TOOLCHAIN=${RUST_ENCLAVE_TOOLCHAIN}"
            "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
            "CARGO_TARGET_DIR=${RUST_HOST_TARGET_DIR}"
            "CC=${CMAKE_C_COMPILER}"
            "CXX=${CMAKE_CXX_COMPILER}"
            ${CARGO_EXECUTABLE} build
                ${CARGO_BUILD_TYPE}
                --locked
                --manifest-path "${CRATE_DIR}/Cargo.toml"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        COMMENT "Building host Rust crate: ${OUTPUT_NAME}"
        VERBATIM
    )

    # Keep host artifacts inside the caller-selected CMake build tree.
    set(${OUTPUT_NAME}_BINARY
        "${RUST_HOST_TARGET_DIR}/${CARGO_OUT_DIR}/${OUTPUT_NAME}"
        PARENT_SCOPE)
endfunction()

# ---------------------------------------------------------------------------
# rust_build_enclave(CRATE_DIR OUTPUT_NAME FEATURES [TARGET_DIR] [EXACT_FEATURES])
#   Build an enclave-side Rust crate (staticlib) with the SGX sysroot.
#   Requires the sgx_sysroot target to have been built first (from the
#   Teaclave fork's CMakeLists.txt).
#
#   FEATURES (optional): comma-separated Cargo feature names to enable.
#     By default, passed as --no-default-features with the Mini enclave base
#     features. Custom compositions pass EXACT_FEATURES to use their own
#     feature vocabulary without inheriting Mini's `default-ecall` feature.
#     When empty, default features are used.
# ---------------------------------------------------------------------------
function(rust_build_enclave CRATE_DIR OUTPUT_NAME FEATURES)
    set(_FEATURES "${FEATURES}")

    if(NOT TEACLAVE_CHECKOUT)
        message(FATAL_ERROR "TEACLAVE_CHECKOUT not set. Run resolve_teaclave() first.")
    endif()

    set(TARGET_JSON "${TEACLAVE_CHECKOUT}/rustlib/${RUST_ENCLAVE_TARGET}.json")

    # Build the --features flag if modules were requested
    set(_FEATURES_ARGS "")
    if(_FEATURES)
        if(ARGC GREATER 4 AND ARGV4 STREQUAL "EXACT_FEATURES")
            set(_FEATURES_ARGS --no-default-features --features "${_FEATURES}")
        else()
            set(_FEATURES_ARGS --no-default-features --features "sgx,default-ecall,${_FEATURES}")
        endif()
    endif()
    if(ARGC GREATER 3)
        get_filename_component(_ENCLAVE_TARGET_DIR "${ARGV3}" ABSOLUTE)
    else()
        set(_ENCLAVE_TARGET_DIR
            "${CMAKE_SOURCE_DIR}/target/cmake-enclave-${_FEATURES}-${SOURCE_DATE_EPOCH}")
    endif()
    get_filename_component(_TEACLAVE_SOURCE_ROOT
        "${TEACLAVE_CHECKOUT}" ABSOLUTE)
    get_filename_component(_SGX_SYSROOT_ROOT
        "${SGX_SYSROOT_DIR}" ABSOLUTE)
    string(CONCAT _ENCLAVE_RUSTFLAGS
        "--sysroot ${SGX_SYSROOT_DIR} -C target-feature=+rdrand"
        "${RUST_REPRODUCIBLE_INPUT_REMAP_FLAGS}"
        " --remap-path-prefix ${_ENCLAVE_TARGET_DIR}=/cargo-target"
        " --remap-path-prefix ${_TEACLAVE_SOURCE_ROOT}=/teaclave-sdk"
        " --remap-path-prefix ${_SGX_SYSROOT_ROOT}=/sgx-sysroot"
        " --check-cfg=cfg(target_vendor,values(\"teaclave\"))")

    set(_BUILD_COMMENT "Building enclave Rust crate: ${OUTPUT_NAME}")
    if(_FEATURES)
        string(APPEND _BUILD_COMMENT " [${_FEATURES}]")
    endif()

    set(_ENCLAVE_STATIC_LIB
        "${_ENCLAVE_TARGET_DIR}/${RUST_ENCLAVE_TARGET}/${CARGO_OUT_DIR}/lib${OUTPUT_NAME}.a")

    # Cargo records the compiler/sysroot identity in every crate artifact, but
    # it does not know that our externally built SGX sysroot changed. Reusing a
    # target directory across that boundary can therefore surface stale rmeta
    # as E0463 ("can't find crate for std"). Bind each unique Cargo target
    # directory to SYSROOT_STAMP outside the directory being invalidated. The
    # boundary recipe runs once after each stamped sysroot generation and then
    # remains up to date for ordinary warm builds.
    string(SHA256 _ENCLAVE_TARGET_DIR_ID "${_ENCLAVE_TARGET_DIR}")
    string(SUBSTRING "${_ENCLAVE_TARGET_DIR_ID}" 0 16
        _ENCLAVE_TARGET_DIR_ID)
    set(_ENCLAVE_SYSROOT_BOUNDARY_DIR
        "${CMAKE_BINARY_DIR}/enclave-sysroot-cache-boundaries")
    set(_ENCLAVE_SYSROOT_BOUNDARY_STAMP
        "${_ENCLAVE_SYSROOT_BOUNDARY_DIR}/${_ENCLAVE_TARGET_DIR_ID}.stamp")
    set(_ENCLAVE_SYSROOT_BOUNDARY_TARGET
        "enclave_sysroot_cache_boundary_${_ENCLAVE_TARGET_DIR_ID}")
    if(NOT TARGET ${_ENCLAVE_SYSROOT_BOUNDARY_TARGET})
        add_custom_command(
            OUTPUT "${_ENCLAVE_SYSROOT_BOUNDARY_STAMP}"
            COMMAND ${CMAKE_COMMAND} -E rm -rf "${_ENCLAVE_TARGET_DIR}"
            COMMAND ${CMAKE_COMMAND} -E make_directory
                "${_ENCLAVE_SYSROOT_BOUNDARY_DIR}"
            COMMAND ${CMAKE_COMMAND} -E touch
                "${_ENCLAVE_SYSROOT_BOUNDARY_STAMP}"
            DEPENDS "${SYSROOT_STAMP}"
            COMMENT "Invalidating enclave Cargo cache after SGX sysroot change"
            VERBATIM
        )
        add_custom_target(${_ENCLAVE_SYSROOT_BOUNDARY_TARGET}
            DEPENDS "${_ENCLAVE_SYSROOT_BOUNDARY_STAMP}")
        # The file dependency above determines when this recipe must rerun;
        # explicit target ordering also ensures a clean parallel build creates
        # SYSROOT_STAMP before the boundary target's recursive Make invocation.
        add_dependencies(${_ENCLAVE_SYSROOT_BOUNDARY_TARGET} sgx_sysroot)
    endif()

    add_custom_target(${OUTPUT_NAME} ALL
        COMMAND ${CMAKE_COMMAND} -E env
            ${HONEST_CARGO_DEFAULT_DEV_PROFILE_ENV}
            "SGX_SDK_PATH=${SGX_SDK_PATH}"
            "SGX_MODE=${SGX_MODE}"
            "RUSTUP_TOOLCHAIN=${RUST_ENCLAVE_TOOLCHAIN}"
            "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
            "CARGO_TARGET_DIR=${_ENCLAVE_TARGET_DIR}"
            "CC=${CMAKE_C_COMPILER}"
            "CXX=${CMAKE_CXX_COMPILER}"
            "RUSTFLAGS=${_ENCLAVE_RUSTFLAGS}"
            ${CARGO_EXECUTABLE} build
                ${CARGO_BUILD_TYPE}
                -Zjson-target-spec
                --locked
                --manifest-path "${CRATE_DIR}/Cargo.toml"
                --target "${TARGET_JSON}"
                ${_FEATURES_ARGS}
        BYPRODUCTS "${_ENCLAVE_STATIC_LIB}"
        WORKING_DIRECTORY "${CRATE_DIR}"
        COMMENT "${_BUILD_COMMENT}"
        VERBATIM
    )
    add_dependencies(${OUTPUT_NAME} ${_ENCLAVE_SYSROOT_BOUNDARY_TARGET})

    set(${OUTPUT_NAME}_STATIC_LIB
        "${_ENCLAVE_STATIC_LIB}"
        PARENT_SCOPE)
endfunction()

# ---------------------------------------------------------------------------
# sgx_link_enclave(STATIC_LIB EDL_OBJ ENCLAVE_SO)
#   Link the enclave static library + EDL trusted bridge into enclave.so.
#   Uses the Teaclave link recipe (no --whole-archive libsgx_trts).
# ---------------------------------------------------------------------------
function(sgx_link_enclave STATIC_LIB EDL_OBJ VERSION_SCRIPT ENCLAVE_SO)
    add_custom_command(
        OUTPUT "${ENCLAVE_SO}"
        COMMAND ${CMAKE_CXX_COMPILER}
            "${EDL_OBJ}"
            -o "${ENCLAVE_SO}"
            -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles
            -Wl,--start-group "${STATIC_LIB}" -Wl,--end-group
            -Wl,--version-script=${VERSION_SCRIPT}
            -Wl,-z,relro,-z,now,-z,noexecstack
            -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined
            -Wl,-pie -Wl,--export-dynamic
            -Wl,--gc-sections
        DEPENDS "${STATIC_LIB}" "${EDL_OBJ}" "${VERSION_SCRIPT}"
        COMMENT "Linking enclave: ${ENCLAVE_SO}"
        VERBATIM
    )
endfunction()

# ---------------------------------------------------------------------------
# sgx_sign_enclave(ENCLAVE_SO CONFIG_XML KEY_PEM SIGNED_OUTPUT)
#   Sign an enclave shared object.
# ---------------------------------------------------------------------------
function(sgx_sign_enclave ENCLAVE_SO CONFIG_XML KEY_PEM SIGNED_OUTPUT)
    add_custom_command(
        OUTPUT "${SIGNED_OUTPUT}"
        COMMAND ${SGX_SIGN} sign
            -key "${KEY_PEM}"
            -enclave "${ENCLAVE_SO}"
            -out "${SIGNED_OUTPUT}"
            -config "${CONFIG_XML}"
        DEPENDS "${ENCLAVE_SO}" "${CONFIG_XML}" "${KEY_PEM}"
        COMMENT "Signing enclave: ${SIGNED_OUTPUT}"
        VERBATIM
    )
endfunction()
