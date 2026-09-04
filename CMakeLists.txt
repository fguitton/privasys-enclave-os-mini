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
include(cmake/HonestSgxSimHostDevProfile.cmake)

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

# The SGX-SIM gate may mirror the already verified revision into its bounded
# CMake build tree so compiler inputs can be mounted read-only while generated
# Cargo output stays disposable. This is SIM-only, must be inside
# CMAKE_BINARY_DIR, and retains the exact branch-owned patched source.
set(HONEST_PINNED_TEACLAVE_SIM_SOURCE "" CACHE PATH
    "Bounded exact Teaclave source mirror used only by the SGX-SIM gate")
if(HONEST_PINNED_TEACLAVE_SIM_SOURCE)
    if(NOT SGX_MODE STREQUAL "SIM")
        message(FATAL_ERROR "The bounded Teaclave source mirror is SGX-SIM-only")
    endif()
    file(REAL_PATH "${HONEST_PINNED_TEACLAVE_SIM_SOURCE}"
        TEACLAVE_SIM_SOURCE_REAL)
    file(REAL_PATH "${CMAKE_BINARY_DIR}" CMAKE_BINARY_REAL)
    string(FIND "${TEACLAVE_SIM_SOURCE_REAL}" "${CMAKE_BINARY_REAL}/"
        TEACLAVE_SIM_SOURCE_PREFIX)
    if(NOT TEACLAVE_SIM_SOURCE_PREFIX EQUAL 0)
        message(FATAL_ERROR "The bounded Teaclave source mirror is outside the build tree")
    endif()
    set(TEACLAVE_PATCHED_SOURCE
        "${TEACLAVE_SIM_SOURCE_REAL}/sgx_unwind/libunwind/src/mi/mempool.c")
    if(NOT EXISTS "${TEACLAVE_PATCHED_SOURCE}" OR IS_SYMLINK "${TEACLAVE_PATCHED_SOURCE}")
        message(FATAL_ERROR "The bounded Teaclave patched source is invalid")
    endif()
    file(SHA256 "${TEACLAVE_PATCHED_SOURCE}" TEACLAVE_PATCHED_SOURCE_SHA256)
    if(NOT TEACLAVE_PATCHED_SOURCE_SHA256 STREQUAL
        "623824d8f94eaa2a1a39de4a352f35f17417c89378891deef586a4be3fdaed70")
        message(FATAL_ERROR "The bounded Teaclave patched source identity is invalid")
    endif()
    set(TEACLAVE_CHECKOUT "${TEACLAVE_SIM_SOURCE_REAL}")
endif()

message(STATUS "Teaclave SDK: ${TEACLAVE_CHECKOUT}")

# Paths derived from the Teaclave checkout
set(TEACLAVE_EDL_DIR  "${TEACLAVE_CHECKOUT}/sgx_edl/edl")
set(TEACLAVE_INC_DIR  "${TEACLAVE_CHECKOUT}/common/inc")
set(TEACLAVE_TLIBC    "${TEACLAVE_CHECKOUT}/common/inc/tlibc")
if(SGX_MODE STREQUAL "SIM")
    set(SGX_SYSROOT_DIR "${CMAKE_BINARY_DIR}/sgx-sysroot")
    set(SYSROOT_BUILD_DIR "${CMAKE_BINARY_DIR}/teaclave-sysroot-build")
else()
    set(SGX_SYSROOT_DIR "${CMAKE_SOURCE_DIR}/sysroot")
    set(SYSROOT_BUILD_DIR "${TEACLAVE_CHECKOUT}/build_sysroot")
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
    # ExternalProject-like: configure + build the fork's sysroot target
    set(SYSROOT_STAMP "${CMAKE_BINARY_DIR}/sysroot.stamp")
    # Make an in-place reconfiguration replace any sysroot previously built
    # under the retired whole-runtime optimisation. `file(GENERATE)` preserves
    # the timestamp when content is unchanged, so ordinary configure passes
    # keep the expensive default-development sysroot hot.
    set(SYSROOT_PROFILE_INPUT
        "${CMAKE_BINARY_DIR}/sgx-sysroot-cargo-profile.txt")
    file(GENERATE OUTPUT "${SYSROOT_PROFILE_INPUT}"
        CONTENT "cargo-default-dev-v1\n")
    add_custom_command(
        OUTPUT "${SYSROOT_STAMP}"
        COMMENT "Building SGX sysroot via Teaclave fork CMake..."
        # The fork builds std inside its own checkout using the default target
        # directory, then copies that whole deps/ tree into the sysroot. The
        # checkout is shared by every build tree, and each tree's remap flags
        # give std a different metadata hash, so a second tree would leave two
        # candidates behind and every enclave crate would then fail to resolve
        # std. Start from a clean target directory so exactly one set is copied.
        COMMAND ${CMAKE_COMMAND} -E rm -rf
            "${TEACLAVE_CHECKOUT}/rustlib/std/target/${RUST_ENCLAVE_TARGET}"
        COMMAND ${CMAKE_COMMAND} -E env
            ${HONEST_CARGO_DEFAULT_DEV_PROFILE_ENV}
            "SGX_MODE=${SGX_MODE}"
            "RUSTUP_TOOLCHAIN=${RUST_ENCLAVE_TOOLCHAIN}"
            "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
            "CARGO_INCREMENTAL=0"
            "RUSTFLAGS=${SGX_SYSROOT_REPRODUCIBLE_RUSTFLAGS}"
            "CC=${CMAKE_C_COMPILER}"
            "CXX=${CMAKE_CXX_COMPILER}"
            ${CMAKE_COMMAND}
            -S "${TEACLAVE_CHECKOUT}"
            -B "${SYSROOT_BUILD_DIR}"
            -DBUILD_SYSROOT=ON
            -DBUILD_URTS=OFF
            -DSGX_SYSROOT_OUTPUT=${SGX_SYSROOT_DIR}
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
            -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
        # The nested project does not know that the outer profile identity
        # changed. The profile-input dependency runs this recipe exactly when
        # needed; invalidate the nested stamp before asking it to rebuild.
        COMMAND ${CMAKE_COMMAND} -E rm -f
            "${SYSROOT_BUILD_DIR}/sgx_sysroot.stamp"
        COMMAND ${CMAKE_COMMAND} -E env
            ${HONEST_CARGO_DEFAULT_DEV_PROFILE_ENV}
            "SGX_MODE=${SGX_MODE}"
            "RUSTUP_TOOLCHAIN=${RUST_ENCLAVE_TOOLCHAIN}"
            "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
            "CARGO_INCREMENTAL=0"
            "RUSTFLAGS=${SGX_SYSROOT_REPRODUCIBLE_RUSTFLAGS}"
            "CC=${CMAKE_C_COMPILER}"
            "CXX=${CMAKE_CXX_COMPILER}"
            ${CMAKE_COMMAND}
            --build "${SYSROOT_BUILD_DIR}"
            --target sgx_sysroot
        COMMAND ${CMAKE_COMMAND} -E touch "${SYSROOT_STAMP}"
        DEPENDS "${SYSROOT_PROFILE_INPUT}"
        VERBATIM
    )
    add_custom_target(sgx_sysroot DEPENDS "${SYSROOT_STAMP}")
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
