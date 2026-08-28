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
# Resolve Teaclave checkout (same logic as build_all.sh's resolve_teaclave)
# =============================================================================
# The Cargo.lock in the workspace pins the teaclave-sgx-sdk commit hash.
# We parse it and find the matching checkout directory under ~/.cargo/git/checkouts.

# Find the sole checkout whose full Git identity matches Cargo.lock (respect
# CARGO_HOME). A same-prefix directory or a different checkout base must never
# become the enclave compiler merely because it sorts first.
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
# CMake build tree so the pinned SDK's source-relative Cargo target directory
# cannot consume root disk or retain stale metadata. This is SIM-only, must be
# inside CMAKE_BINARY_DIR, and retains the exact branch-owned patched source.
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
else()
    set(SGX_SYSROOT_DIR "${CMAKE_SOURCE_DIR}/sysroot")
endif()

# =============================================================================
# Step 1: Build SGX sysroot (via the fork's CMake sgx_sysroot target)
# =============================================================================
if(BUILD_ENCLAVE)
    if(SGX_MODE STREQUAL "SIM")
        set(SYSROOT_BUILD_DIR "${CMAKE_BINARY_DIR}/teaclave-sysroot-build")
    else()
        set(SYSROOT_BUILD_DIR "${TEACLAVE_CHECKOUT}/build_sysroot")
    endif()

    # ExternalProject-like: configure + build the fork's sysroot target
    set(SYSROOT_STAMP "${CMAKE_BINARY_DIR}/sysroot.stamp")
    add_custom_command(
        OUTPUT "${SYSROOT_STAMP}"
        COMMENT "Building SGX sysroot via Teaclave fork CMake..."
        COMMAND ${CMAKE_COMMAND} -E env "SGX_MODE=${SGX_MODE}" ${CMAKE_COMMAND}
            -S "${TEACLAVE_CHECKOUT}"
            -B "${SYSROOT_BUILD_DIR}"
            -DBUILD_SYSROOT=ON
            -DBUILD_URTS=OFF
            -DSGX_SYSROOT_OUTPUT=${SGX_SYSROOT_DIR}
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        COMMAND ${CMAKE_COMMAND} -E env "SGX_MODE=${SGX_MODE}" ${CMAKE_COMMAND}
            --build "${SYSROOT_BUILD_DIR}"
            --target sgx_sysroot
        COMMAND ${CMAKE_COMMAND} -E touch "${SYSROOT_STAMP}"
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
