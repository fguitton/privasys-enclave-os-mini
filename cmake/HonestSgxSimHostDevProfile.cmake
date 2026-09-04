# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

# The persistent cluster-operation gate deliberately retains Debug semantics.
# Only the untrusted Mini host receives this explicit optimisation override:
# applying it to the separately built SGX sysroot changes trusted runtime
# behaviour, while a custom enclave composition selects its own Cargo profile.
set(HONEST_SGX_SIM_HOST_DEV_OPT_LEVEL "" CACHE STRING
    "Optimise only the SGX-SIM untrusted host at this exact level (empty disables)")

# Reject the former whole-runtime control instead of quietly accepting a stale
# cache entry that would appear to optimise the host while contaminating the
# trusted sysroot and enclave builds as well.
if(DEFINED HONEST_SGX_SIM_DEV_OPT_LEVEL)
    message(FATAL_ERROR
        "HONEST_SGX_SIM_DEV_OPT_LEVEL is unsafe and no longer supported; use HONEST_SGX_SIM_HOST_DEV_OPT_LEVEL")
endif()

# Do not let the host-only setting (or matching ambient Cargo variables) leak
# into trusted Cargo invocations. The custom composition's workspace profile
# remains authoritative; the Teaclave sysroot retains Cargo's default dev
# profile.
set(HONEST_CARGO_DEFAULT_DEV_PROFILE_ENV
    "--unset=CARGO_PROFILE_DEV_OPT_LEVEL"
    "--unset=CARGO_PROFILE_DEV_DEBUG_ASSERTIONS"
    "--unset=CARGO_PROFILE_DEV_OVERFLOW_CHECKS")
set(HONEST_SGX_SIM_HOST_DEV_PROFILE_ENV
    ${HONEST_CARGO_DEFAULT_DEV_PROFILE_ENV})

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
