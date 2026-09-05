# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

# The persistent cluster-operation gate deliberately retains Debug semantics.
# The untrusted Mini host and the separately built Teaclave sysroot have
# independent, narrowly scoped optimisation controls; a custom enclave
# composition continues to select its own workspace Cargo profile.
set(HONEST_SGX_SIM_HOST_DEV_OPT_LEVEL "" CACHE STRING
    "Optimise only the SGX-SIM untrusted host at this exact level (empty disables)")
set(HONEST_SGX_SIM_SYSROOT_DEV_OPT_LEVEL "" CACHE STRING
    "Optimise only the SGX-SIM Teaclave sysroot at this exact level (empty disables)")

# Reject the former whole-runtime control instead of quietly accepting a stale
# cache entry that would appear to optimise the host while contaminating the
# trusted sysroot and enclave builds as well.
if(DEFINED HONEST_SGX_SIM_DEV_OPT_LEVEL)
    message(FATAL_ERROR
        "HONEST_SGX_SIM_DEV_OPT_LEVEL is unsafe and no longer supported; use a narrowly scoped host or sysroot profile")
endif()

# Do not let either narrow setting (or matching ambient Cargo variables) leak
# across build boundaries. The custom composition's workspace profile remains
# authoritative, and the Teaclave sysroot defaults to Cargo's dev profile.
set(HONEST_CARGO_DEFAULT_DEV_PROFILE_ENV
    "--unset=CARGO_PROFILE_DEV_OPT_LEVEL"
    "--unset=CARGO_PROFILE_DEV_DEBUG_ASSERTIONS"
    "--unset=CARGO_PROFILE_DEV_OVERFLOW_CHECKS")
set(HONEST_SGX_SIM_HOST_DEV_PROFILE_ENV
    ${HONEST_CARGO_DEFAULT_DEV_PROFILE_ENV})
set(HONEST_SGX_SIM_SYSROOT_DEV_PROFILE_ENV
    ${HONEST_CARGO_DEFAULT_DEV_PROFILE_ENV})
set(HONEST_SGX_SIM_SYSROOT_DEV_PROFILE_ID "cargo-default-dev-v1")

if(NOT HONEST_SGX_SIM_HOST_DEV_OPT_LEVEL STREQUAL "")
    if(NOT SGX_MODE STREQUAL "SIM")
        message(FATAL_ERROR
            "HONEST_SGX_SIM_HOST_DEV_OPT_LEVEL is restricted to SGX_MODE=SIM")
    endif()
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        message(FATAL_ERROR
            "HONEST_SGX_SIM_HOST_DEV_OPT_LEVEL is restricted to CMAKE_BUILD_TYPE=Debug")
    endif()
    if(NOT HONEST_SGX_SIM_HOST_DEV_OPT_LEVEL STREQUAL "2")
        message(FATAL_ERROR
            "HONEST_SGX_SIM_HOST_DEV_OPT_LEVEL must be exactly 2 when enabled")
    endif()

    # Cargo profile environment keys override only the named development
    # fields. Keep the two safety-relevant checks explicit at the optimized
    # untrusted boundary.
    set(HONEST_SGX_SIM_HOST_DEV_PROFILE_ENV
        "CARGO_PROFILE_DEV_OPT_LEVEL=${HONEST_SGX_SIM_HOST_DEV_OPT_LEVEL}"
        "CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=true"
        "CARGO_PROFILE_DEV_OVERFLOW_CHECKS=true")
    message(STATUS
        "SGX-SIM untrusted host Cargo dev profile: opt-level=${HONEST_SGX_SIM_HOST_DEV_OPT_LEVEL}, debug-assertions=true, overflow-checks=true")
endif()

if(NOT HONEST_SGX_SIM_SYSROOT_DEV_OPT_LEVEL STREQUAL "")
    if(NOT SGX_MODE STREQUAL "SIM")
        message(FATAL_ERROR
            "HONEST_SGX_SIM_SYSROOT_DEV_OPT_LEVEL is restricted to SGX_MODE=SIM")
    endif()
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        message(FATAL_ERROR
            "HONEST_SGX_SIM_SYSROOT_DEV_OPT_LEVEL is restricted to CMAKE_BUILD_TYPE=Debug")
    endif()
    if(NOT HONEST_SGX_SIM_SYSROOT_DEV_OPT_LEVEL STREQUAL "2")
        message(FATAL_ERROR
            "HONEST_SGX_SIM_SYSROOT_DEV_OPT_LEVEL must be exactly 2 when enabled")
    endif()

    # This profile is intentionally narrower than the retired whole-runtime
    # switch. It reaches only the nested Teaclave std/core/alloc build; the
    # custom enclave workspace, untrusted host and hardware release retain
    # their independently selected profiles.
    set(HONEST_SGX_SIM_SYSROOT_DEV_PROFILE_ENV
        "CARGO_PROFILE_DEV_OPT_LEVEL=${HONEST_SGX_SIM_SYSROOT_DEV_OPT_LEVEL}"
        "CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=true"
        "CARGO_PROFILE_DEV_OVERFLOW_CHECKS=true")
    set(HONEST_SGX_SIM_SYSROOT_DEV_PROFILE_ID
        "cargo-sgx-sim-debug-dev-opt2-assertions-overflow-v1")
    message(STATUS
        "SGX-SIM Teaclave sysroot Cargo dev profile: opt-level=${HONEST_SGX_SIM_SYSROOT_DEV_OPT_LEVEL}, debug-assertions=true, overflow-checks=true")
endif()
