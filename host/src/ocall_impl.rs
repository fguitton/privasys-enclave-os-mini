// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! OCall implementation – with the SPSC queue architecture, only ONE
//! OCALL remains: `ocall_notify()`.
//!
//! The EDL ABI retains this notification function for response-bearing RPCs.
//! Queue dispatchers currently use bounded polling; this function carries no
//! state and does not wake their separate host threads.

/// The single OCALL: notification from enclave that a request is ready.
///
/// The actual data transfer happens through the shared-memory SPSC queue.
/// This compatibility hook intentionally carries no payload or wake state;
/// the dispatcher's bounded polling loop picks up the message.
#[no_mangle]
pub extern "C" fn ocall_notify() {}

// `sgx_oc_cpuidex` OCALL is provided by Intel's `libsgx_urts.so`, which
// the host links.  No Rust implementation needed — the untrusted runtime
// already executes CPUID on behalf of the enclave.
