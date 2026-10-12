# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.
# Version 1: owned outputs for the existing reviewed Teaclave sysroot recipe.
# This file verifies inputs and declares build provenance. It never edits the SDK.

foreach(_pair IN ITEMS
    "CMakeLists.txt|2d9182fa1db6d902ad62b0b082997aee8578880f483ce4f11eda02ad3a11f378"
    "rustlib/std/Cargo.lock|e5f79c0fa641c519795bc43c4b204aa0351a94b4f9ee599f8c642be58ac54e99")
    string(REPLACE "|" ";" _parts "${_pair}")
    list(GET _parts 0 _relative)
    list(GET _parts 1 _expected)
    set(_file "${TEACLAVE_CHECKOUT}/${_relative}")
    if(NOT EXISTS "${_file}" OR IS_SYMLINK "${_file}")
        message(FATAL_ERROR "Source-locked sysroot input is unavailable: ${_relative}")
    endif()
    file(SHA256 "${_file}" _actual)
    if(NOT _actual STREQUAL _expected)
        message(FATAL_ERROR "Prepare the reviewed reproducible-sysroot patch: ${_relative}")
    endif()
endforeach()

file(REAL_PATH "${CMAKE_BINARY_DIR}" _build_real)
file(REAL_PATH "${TEACLAVE_CHECKOUT}" _sdk_real)
foreach(_relative IN ITEMS sgx-sysroot teaclave-sysroot-build)
    set(_path "${CMAKE_BINARY_DIR}/${_relative}")
    file(REAL_PATH "${_path}" _real)
    string(FIND "${_real}/" "${_sdk_real}/" _inside_sdk)
    if(IS_SYMLINK "${_path}" OR NOT _real STREQUAL "${_build_real}/${_relative}"
       OR _inside_sdk EQUAL 0)
        message(FATAL_ERROR "Sysroot output is not owned by this build: ${_path}")
    endif()
endforeach()

# The SIM mirror deliberately has no Git metadata. Enumerate the same immutable
# commit in the original identity checkout, then hash the selected patched mirror.
# Do not glob generated Autotools or Cargo output back into the input set.
execute_process(
    COMMAND git -C "${TEACLAVE_IDENTITY_CHECKOUT}" ls-tree -r --name-only "${TEACLAVE_FULL_REV}"
    RESULT_VARIABLE _tree_status OUTPUT_VARIABLE _tree_files
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT _tree_status EQUAL 0 OR _tree_files STREQUAL "")
    message(FATAL_ERROR "Cannot enumerate pinned Teaclave compiler inputs")
endif()
string(REPLACE "\n" ";" _sdk_files "${_tree_files}")
list(APPEND _sdk_files "rustlib/std/Cargo.lock")
list(SORT _sdk_files)
set(SGX_SYSROOT_INPUT_FILES)
set(_inputs "owned-teaclave-sysroot-v1\ncommit=${TEACLAVE_FULL_REV}\n")
foreach(_relative IN LISTS _sdk_files)
    set(_file "${TEACLAVE_CHECKOUT}/${_relative}")
    if(NOT EXISTS "${_file}" OR IS_DIRECTORY "${_file}" OR IS_SYMLINK "${_file}")
        message(FATAL_ERROR "Pinned Teaclave input is unavailable: ${_relative}")
    endif()
    file(SHA256 "${_file}" _sha)
    string(APPEND _inputs "sdk/${_relative}=${_sha}\n")
    list(APPEND SGX_SYSROOT_INPUT_FILES "${_file}")
endforeach()
foreach(_file IN ITEMS
    "${CMAKE_SOURCE_DIR}/Cargo.lock" "${CMAKE_SOURCE_DIR}/CMakeLists.txt"
    "${CMAKE_CURRENT_LIST_FILE}" "${CMAKE_SOURCE_DIR}/cmake/RustBuild.cmake"
    "${CMAKE_SOURCE_DIR}/cmake/SgxConfig.cmake"
    "${CMAKE_C_COMPILER}" "${CMAKE_CXX_COMPILER}" "${CARGO_EXECUTABLE}"
    "${SGX_SDK_PATH}/pkgconfig/libsgx_urts.pc" "${SGX_SDK_PATH}/lib64/libsgx_tcrypto.a")
    file(SHA256 "${_file}" _sha)
    string(APPEND _inputs "input=${_sha}\n")
    list(APPEND SGX_SYSROOT_INPUT_FILES "${_file}")
endforeach()
get_filename_component(SGX_SYSROOT_CARGO_BIN_DIR "${CARGO_EXECUTABLE}" DIRECTORY)
get_filename_component(_cargo_name "${CARGO_EXECUTABLE}" NAME)
if(NOT _cargo_name STREQUAL "cargo")
    message(FATAL_ERROR "The pinned Teaclave recipe requires the selected cargo executable name")
endif()
execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "RUSTUP_TOOLCHAIN=${RUST_ENCLAVE_TOOLCHAIN}"
        "${SGX_SYSROOT_CARGO_BIN_DIR}/rustc" --version --verbose
    RESULT_VARIABLE _rust_status OUTPUT_VARIABLE _rust_version)
if(NOT _rust_status EQUAL 0)
    message(FATAL_ERROR "Cannot identify the selected enclave Rust compiler")
endif()
string(APPEND _inputs
    "rustc=${_rust_version}\nmode=${SGX_MODE}\nbuild_type=${CMAKE_BUILD_TYPE}\n"
    "toolchain=${RUST_ENCLAVE_TOOLCHAIN}\nbackend=${SGX_CRYPTO_BACKEND}\n"
    "epoch=${SOURCE_DATE_EPOCH}\ncc=${CMAKE_C_COMPILER_ID}:${CMAKE_C_COMPILER_VERSION}\n"
    "cxx=${CMAKE_CXX_COMPILER_ID}:${CMAKE_CXX_COMPILER_VERSION}\n"
    "cflags=${CMAKE_C_FLAGS}\ncxxflags=${CMAKE_CXX_FLAGS}\n"
    "input_remaps=${RUST_REPRODUCIBLE_INPUT_REMAP_FLAGS}\n"
    "use_opt_libs=0\ncargo_incremental=0\n")
string(SHA256 SGX_SYSROOT_INPUT_ID "${_inputs}")
# The nested CMake cache is also input-owned. Changing compiler/profile cannot
# reuse a cache whose compiler reset discards the explicit output directory.
set(SYSROOT_BUILD_DIR "${SYSROOT_BUILD_DIR}/${SGX_SYSROOT_INPUT_ID}")
set(SGX_STD_TARGET_DIR "${SYSROOT_BUILD_DIR}/rustlib-std-target")
file(REAL_PATH "${SGX_STD_TARGET_DIR}" _target_real)
if(NOT _target_real STREQUAL
    "${_build_real}/teaclave-sysroot-build/${SGX_SYSROOT_INPUT_ID}/rustlib-std-target")
    message(FATAL_ERROR "Sysroot Cargo output escaped its build owner")
endif()
set(SGX_SYSROOT_INPUTS_FILE "${CMAKE_BINARY_DIR}/teaclave-sysroot-inputs-v1.txt")
file(GENERATE OUTPUT "${SGX_SYSROOT_INPUTS_FILE}" CONTENT "${_inputs}")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${SGX_SYSROOT_INPUT_FILES})
