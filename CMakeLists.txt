# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

cmake_minimum_required(VERSION 3.20)
project(enclave-os-mini LANGUAGES C CXX)

# Feed Cargo a stable build epoch so identical pinned inputs produce the same
# enclave measurement. Deliberate identity rolls may override this cache value.
set(SOURCE_DATE_EPOCH "0" CACHE STRING "Epoch for reproducible Rust artifacts")

if(NOT DEFINED SGX_MODE)
    if(DEFINED ENV{SGX_MODE})
        set(SGX_MODE "$ENV{SGX_MODE}")
    else()
        set(SGX_MODE "HW")
    endif()
endif()
set(SGX_MODE "${SGX_MODE}" CACHE STRING "Intel SGX execution mode: HW or SIM")
set_property(CACHE SGX_MODE PROPERTY STRINGS HW SIM)

# =============================================================================
# Options
# =============================================================================
option(BUILD_HOST    "Build host-side binary"     ON)
option(BUILD_ENCLAVE "Build enclave-side targets" ON)

set(SGX_SDK_PATH "" CACHE PATH "Path to Intel SGX SDK (auto-detected if empty)")

# =============================================================================
# Detect platform
# =============================================================================
if(NOT (UNIX AND NOT APPLE))
    message(FATAL_ERROR "SGX enclaves require Linux. Use WSL or a Linux build host.")
endif()

# =============================================================================
# SGX SDK + Rust helpers
# =============================================================================
include(cmake/SgxConfig.cmake)
include(cmake/RustBuild.cmake)

# =============================================================================
# Memory64 toolchain sources
# =============================================================================
# The reconstructed Wasmtime, wasm-tools and wit-bindgen trees are path
# dependencies, outside Cargo's lockfile checksums. Refuse to configure against
# a tree whose files differ from the digests pinned in sources.json.
if(EXISTS "${CMAKE_SOURCE_DIR}/patches/wasm64/sources.json")
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    execute_process(
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/scripts/acquire-wasm64.py" --verify-only
        RESULT_VARIABLE WASM64_SOURCES_STATUS
    )
    if(NOT WASM64_SOURCES_STATUS EQUAL 0)
        message(FATAL_ERROR
            "memory64 sources differ from patches/wasm64/sources.json; "
            "run scripts/acquire-wasm64.py")
    endif()
endif()

# =============================================================================
# Resolve Teaclave checkout (same logic as build_all.sh's resolve_teaclave)
# =============================================================================
# The Cargo.lock in the workspace pins the teaclave-sgx-sdk commit hash.
# We parse it and find the matching checkout directory under ~/.cargo/git/checkouts.

# Find the sole checkout whose HEAD identity matches Cargo.lock (respect
# CARGO_HOME). A same-prefix directory or a different checkout base must never
# become the enclave compiler merely because it sorts first. Callers that need
# clean compiler bytes, including the SGX-SIM gate, validate the checkout and
# its tree separately before configuration and after each build.
if(DEFINED ENV{CARGO_HOME})
    set(_CARGO_DIR "$ENV{CARGO_HOME}")
else()
    set(_CARGO_DIR "$ENV{HOME}/.cargo")
endif()

# Extract the commit hash from the workspace Cargo.lock
file(READ "${CMAKE_SOURCE_DIR}/Cargo.lock" _CARGO_LOCK)
string(REGEX MATCH "teaclave-sgx-sdk[^\n]*#([0-9a-f]+)" _MATCH "${_CARGO_LOCK}")
set(TEACLAVE_FULL_REV "${CMAKE_MATCH_1}")
string(LENGTH "${TEACLAVE_FULL_REV}" TEACLAVE_REV_LENGTH)
if(NOT TEACLAVE_FULL_REV MATCHES "^[0-9a-f]+$" OR NOT TEACLAVE_REV_LENGTH EQUAL 40)
    message(FATAL_ERROR "Cargo.lock has no exact Teaclave revision")
endif()
string(SUBSTRING "${TEACLAVE_FULL_REV}" 0 7 TEACLAVE_SHORT_REV)

file(GLOB TEACLAVE_BASES "${_CARGO_DIR}/git/checkouts/teaclave-sgx-sdk-*")
set(TEACLAVE_CANDIDATES)
foreach(TEACLAVE_BASE IN LISTS TEACLAVE_BASES)
    set(TEACLAVE_CANDIDATE "${TEACLAVE_BASE}/${TEACLAVE_SHORT_REV}")
    if(IS_DIRECTORY "${TEACLAVE_CANDIDATE}" AND NOT IS_SYMLINK "${TEACLAVE_CANDIDATE}")
        execute_process(
            COMMAND git -C "${TEACLAVE_CANDIDATE}" rev-parse HEAD
            RESULT_VARIABLE TEACLAVE_GIT_STATUS
            OUTPUT_VARIABLE TEACLAVE_GIT_HEAD
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        if(TEACLAVE_GIT_STATUS EQUAL 0 AND TEACLAVE_GIT_HEAD STREQUAL TEACLAVE_FULL_REV)
            list(APPEND TEACLAVE_CANDIDATES "${TEACLAVE_CANDIDATE}")
        endif()
    endif()
endforeach()
list(LENGTH TEACLAVE_CANDIDATES TEACLAVE_CANDIDATE_COUNT)
if(NOT TEACLAVE_CANDIDATE_COUNT EQUAL 1)
    message(FATAL_ERROR
        "Expected exactly one checkout of Teaclave ${TEACLAVE_FULL_REV}; "
        "found ${TEACLAVE_CANDIDATE_COUNT}")
endif()
list(GET TEACLAVE_CANDIDATES 0 TEACLAVE_CHECKOUT)
set(TEACLAVE_IDENTITY_CHECKOUT "${TEACLAVE_CHECKOUT}")

function(require_sdk230_teaclave SOURCE_ROOT)
    set(_FILES
        "sgx_build_helper/download_prebuilt/build.rs"
        "sgx_crypto/sgx_crypto_sys/build.rs"
        "sgx_trts/src/version.rs"
        "sgx_trts/src/inst/sim/inst.rs"
        "sgx_trts/src/inst/sim/mod.rs")
    set(_HASHES
        "fe79813e38a2bb27c7bd2452667e6023db62873f7136674236385d2b357c608b"
        "c4c6eadaecffdd93d5ee94c8b2455c3aa99cb69f0f165caad8ebdb224462d130"
        "90a1992e8836591dc2a01ccaa5d21009dc64c747b364882c3c8e4ea1ed6304af"
        "281acb91eb42a2f22999145d2fd854da8a082fe73abce81a6ab52728b607b4ec"
        "083bae3dcbef18492cd2cc41fefda91662181b4b319a36c9ed96599b94711fc9")
    foreach(_INDEX RANGE 0 4)
        list(GET _FILES ${_INDEX} _FILE)
        list(GET _HASHES ${_INDEX} _EXPECTED)
        if(NOT EXISTS "${SOURCE_ROOT}/${_FILE}" OR IS_SYMLINK "${SOURCE_ROOT}/${_FILE}")
            message(FATAL_ERROR "Teaclave SDK 2.30 compatibility source is unavailable: ${_FILE}")
        endif()
        file(SHA256 "${SOURCE_ROOT}/${_FILE}" _ACTUAL)
        if(NOT _ACTUAL STREQUAL _EXPECTED)
            message(FATAL_ERROR "Prepare the reviewed Teaclave SDK 2.30 patch in the build-owned Cargo source: ${_FILE}")
        endif()
    endforeach()
endfunction()

# Cargo and the separately built sysroot must consume the same reviewed port.
if(BUILD_ENCLAVE)
    require_sdk230_teaclave("${TEACLAVE_CHECKOUT}")
endif()

# The enclave compiles against the fallible-allocation SDK source profile, a
# verified build-owned mirror for both HW and SIM. Identity remains the
# original pinned checkout; no global SDK is edited. Cargo acquisition selects
# the same owned source explicitly.
set(HONEST_PINNED_TEACLAVE_FALLIBLE_SOURCE "" CACHE PATH
    "Build-owned SDK source for the fallible allocation profile")
if(BUILD_ENCLAVE)
    if(NOT HONEST_PINNED_TEACLAVE_FALLIBLE_SOURCE)
        message(FATAL_ERROR "The enclave requires the build-owned fallible-allocation SDK source")
    endif()
    file(REAL_PATH "${HONEST_PINNED_TEACLAVE_FALLIBLE_SOURCE}" _fallible_source_real)
    file(REAL_PATH "${CMAKE_BINARY_DIR}" _fallible_build_real)
    string(FIND "${_fallible_source_real}/" "${_fallible_build_real}/" _fallible_inside)
    if(IS_SYMLINK "${HONEST_PINNED_TEACLAVE_FALLIBLE_SOURCE}" OR NOT _fallible_inside EQUAL 0)
        message(FATAL_ERROR "Fallible SDK source is not owned by this build")
    endif()
    set(TEACLAVE_CHECKOUT "${_fallible_source_real}")
    require_sdk230_teaclave("${TEACLAVE_CHECKOUT}")
endif()

message(STATUS "Teaclave SDK: ${TEACLAVE_CHECKOUT}")

# Paths derived from the Teaclave checkout
set(TEACLAVE_EDL_DIR  "${TEACLAVE_CHECKOUT}/sgx_edl/edl")
set(TEACLAVE_INC_DIR  "${TEACLAVE_CHECKOUT}/common/inc")
set(TEACLAVE_TLIBC    "${TEACLAVE_CHECKOUT}/common/inc/tlibc")
# Both hardware and simulation own every generated sysroot path in this build.
# The source checkout and the SDK's old build_sysroot/target are never outputs.
set(SGX_SYSROOT_DIR "${CMAKE_BINARY_DIR}/sgx-sysroot")
set(SYSROOT_BUILD_DIR "${CMAKE_BINARY_DIR}/teaclave-sysroot-build")
if(BUILD_ENCLAVE)
    include(cmake/TeaclaveSysrootInputs.cmake)
endif()
get_filename_component(TEACLAVE_REMAP_SOURCE_ROOT
    "${TEACLAVE_CHECKOUT}" ABSOLUTE)
get_filename_component(SGX_SYSROOT_REMAP_OUTPUT_ROOT
    "${SGX_SYSROOT_DIR}" ABSOLUTE)
get_filename_component(SGX_SYSROOT_REMAP_BUILD_ROOT
    "${SYSROOT_BUILD_DIR}" ABSOLUTE)
string(CONCAT SGX_SYSROOT_REPRODUCIBLE_RUSTFLAGS
    "--remap-path-prefix ${TEACLAVE_REMAP_SOURCE_ROOT}=/teaclave-sdk"
    " --remap-path-prefix ${SGX_SYSROOT_REMAP_OUTPUT_ROOT}=/sgx-sysroot"
    " --remap-path-prefix ${SGX_SYSROOT_REMAP_BUILD_ROOT}=/sgx-sysroot-build"
    "${RUST_REPRODUCIBLE_INPUT_REMAP_FLAGS}"
    " --check-cfg=cfg(target_vendor,values(\"teaclave\"))")

# =============================================================================
# Step 1: Build SGX sysroot (via the fork's CMake sgx_sysroot target)
# =============================================================================
if(BUILD_ENCLAVE)
    # Use the existing source-locked recipe; its Cargo output and install copy
    # both consume SGX_STD_TARGET_DIR. Input changes choose a fresh owned target.
    set(SYSROOT_STAMP "${CMAKE_BINARY_DIR}/sysroot.stamp")
    add_custom_command(
        OUTPUT "${SYSROOT_STAMP}" "${SGX_SYSROOT_DIR}/build-inputs-v1.txt"
        COMMENT "Building SGX sysroot via Teaclave fork CMake..."
        COMMAND ${CMAKE_COMMAND} -E env
            "PATH=${SGX_SYSROOT_CARGO_BIN_DIR}:$ENV{PATH}"
            "SGX_MODE=${SGX_MODE}"
            "SGX_SDK_PATH=${SGX_SDK_PATH}"
            "SGX_CRYPTO_BACKEND=${SGX_CRYPTO_BACKEND}"
            "USE_OPT_LIBS=0"
            "RUSTUP_TOOLCHAIN=${RUST_ENCLAVE_TOOLCHAIN}"
            "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
            "CARGO_INCREMENTAL=0"
            "RUSTFLAGS=${SGX_SYSROOT_REPRODUCIBLE_RUSTFLAGS}"
            "CC=${CMAKE_C_COMPILER}"
            "CXX=${CMAKE_CXX_COMPILER}"
            ${_btree_std_environment}
            ${CMAKE_COMMAND}
            -S "${TEACLAVE_CHECKOUT}"
            -B "${SYSROOT_BUILD_DIR}"
            -DBUILD_SYSROOT=ON
            -DBUILD_URTS=OFF
            -DSGX_SYSROOT_OUTPUT=${SGX_SYSROOT_DIR}
            -DSGX_STD_TARGET_DIR=${SGX_STD_TARGET_DIR}
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
            -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
        COMMAND ${CMAKE_COMMAND} -E rm -f "${SYSROOT_BUILD_DIR}/sgx_sysroot.stamp"
        COMMAND ${CMAKE_COMMAND} -E env
            "PATH=${SGX_SYSROOT_CARGO_BIN_DIR}:$ENV{PATH}"
            "SGX_MODE=${SGX_MODE}"
            "SGX_SDK_PATH=${SGX_SDK_PATH}"
            "SGX_CRYPTO_BACKEND=${SGX_CRYPTO_BACKEND}"
            "USE_OPT_LIBS=0"
            "RUSTUP_TOOLCHAIN=${RUST_ENCLAVE_TOOLCHAIN}"
            "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
            "CARGO_INCREMENTAL=0"
            "RUSTFLAGS=${SGX_SYSROOT_REPRODUCIBLE_RUSTFLAGS}"
            "CC=${CMAKE_C_COMPILER}"
            "CXX=${CMAKE_CXX_COMPILER}"
            ${_btree_std_environment}
            ${CMAKE_COMMAND}
            --build "${SYSROOT_BUILD_DIR}"
            --target sgx_sysroot
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${SGX_SYSROOT_INPUTS_FILE}" "${SGX_SYSROOT_DIR}/build-inputs-v1.txt"
        COMMAND ${CMAKE_COMMAND} -E touch "${SYSROOT_STAMP}"
        DEPENDS "${SGX_SYSROOT_INPUTS_FILE}" ${SGX_SYSROOT_INPUT_FILES}
        VERBATIM
    )
    add_custom_target(sgx_sysroot
        DEPENDS "${SYSROOT_STAMP}" "${SGX_SYSROOT_DIR}/build-inputs-v1.txt")
endif()

# =============================================================================
# Subdirectories
# =============================================================================
if(BUILD_ENCLAVE)
    add_subdirectory(edl)
    add_subdirectory(enclave)
endif()

if(BUILD_HOST)
    add_subdirectory(host)
endif()

# =============================================================================
# Summary
# =============================================================================
message(STATUS "---------- enclave-os-mini ----------")
message(STATUS "  BUILD_HOST      = ${BUILD_HOST}")
message(STATUS "  BUILD_ENCLAVE   = ${BUILD_ENCLAVE}")
message(STATUS "  CMAKE_BUILD_TYPE= ${CMAKE_BUILD_TYPE}")
message(STATUS "  SGX_SDK_PATH    = ${SGX_SDK_PATH}")
message(STATUS "  SGX_MODE        = ${SGX_MODE}")
message(STATUS "  TEACLAVE        = ${TEACLAVE_CHECKOUT}")
message(STATUS "  SYSROOT         = ${SGX_SYSROOT_DIR}")
message(STATUS "-------------------------------------")
