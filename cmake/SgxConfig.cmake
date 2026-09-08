# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

# cmake/SgxConfig.cmake
# Detect and configure the Intel SGX SDK paths and compiler flags.

string(TOUPPER "${SGX_MODE}" SGX_MODE)
if(NOT SGX_MODE STREQUAL "HW" AND NOT SGX_MODE STREQUAL "SIM")
    message(FATAL_ERROR "SGX_MODE must be exactly HW or SIM")
endif()
set(SGX_MODE "${SGX_MODE}" CACHE STRING "Intel SGX execution mode: HW or SIM" FORCE)

# ---- Auto-detect SGX SDK ----
if(NOT SGX_SDK_PATH)
    if(EXISTS "/opt/intel/sgxsdk")
        set(SGX_SDK_PATH "/opt/intel/sgxsdk")
    elseif(DEFINED ENV{SGX_SDK})
        set(SGX_SDK_PATH "$ENV{SGX_SDK}")
    endif()
endif()

if(NOT EXISTS "${SGX_SDK_PATH}")
    message(WARNING "SGX SDK not found at '${SGX_SDK_PATH}'. "
        "Set -DSGX_SDK_PATH=... or the SGX_SDK environment variable.")
endif()

# Honest's Teaclave compatibility layer uses the SDK-owned trusted crypto ABI.
# Require the package selected by that reviewed layer before any target builds.
set(SGX_CRYPTO_BACKEND "intel-sdk-2.30")
if(BUILD_ENCLAVE)
    set(_SDK_PACKAGE "${SGX_SDK_PATH}/pkgconfig/libsgx_urts.pc")
    if(NOT EXISTS "${_SDK_PACKAGE}")
        message(FATAL_ERROR "Intel SGX SDK package identity is unavailable")
    endif()
    file(STRINGS "${_SDK_PACKAGE}" _SDK_VERSIONS REGEX "^Version:")
    if(NOT _SDK_VERSIONS STREQUAL "Version: 2.30.101.1")
        message(FATAL_ERROR "The trusted crypto backend requires Intel SDK 2.30.101.1")
    endif()
endif()

# ---- Paths ----
set(SGX_INCLUDE_DIR "${SGX_SDK_PATH}/include")
set(SGX_EDGER8R     "${SGX_SDK_PATH}/bin/x64/sgx_edger8r")
set(SGX_SIGN        "${SGX_SDK_PATH}/bin/x64/sgx_sign")
set(SGX_LIBRARY_DIR "${SGX_SDK_PATH}/lib64")

# ---- Enclave C flags (for compiling EDL trusted stubs) ----
# Defined as a CMake list (no quotes) so each flag is a separate argument.
set(ENCLAVE_C_FLAGS
    -ffreestanding -nostdinc -fvisibility=hidden -fpie
    -fno-strict-overflow -fno-delete-null-pointer-checks -m64)

message(STATUS "SGX SDK: ${SGX_SDK_PATH}")
message(STATUS "SGX mode: ${SGX_MODE}")
