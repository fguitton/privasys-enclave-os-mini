// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! OCall implementation – with the SPSC queue architecture, only ONE
//! request notification and bounded execution response waiting use OCALLs.
//!
//! This function is called by the enclave after writing a request to the
//! shared-memory enc_to_host queue. It serves as a lightweight wake-up
//! signal for the host RPC dispatcher.

use crate::dispatcher_wake::DispatcherWake;
use std::sync::{Arc, OnceLock};

static DISPATCHER_WAKE: OnceLock<Arc<DispatcherWake>> = OnceLock::new();

/// Install before either long-lived ECALL enters.
pub fn set_dispatcher_wake(wake: Arc<DispatcherWake>) {
    assert!(
        DISPATCHER_WAKE.set(wake).is_ok(),
        "dispatcher wake already installed"
    );
}

/// Wake both RPC consumers after queue publication. No authority or payload is
/// carried by this untrusted scheduling hint; the framed RPC remains unchanged.
#[no_mangle]
pub extern "C" fn ocall_notify() {
    if let Some(wake) = DISPATCHER_WAKE.get() {
        wake.notify();
    }
}

// `sgx_oc_cpuidex` is provided by Intel's libsgx_urts.

/// Park the execution worker until retained publication or its next finite
/// fence-check boundary. The response remains in its authenticated framed ring.
#[no_mangle]
pub extern "C" fn ocall_wait_execution_response(maximum_micros: u64) -> i32 {
    if maximum_micros == 0 || maximum_micros > 1_000 {
        return -22;
    }
    let Some(wake) = DISPATCHER_WAKE.get() else {
        return -1;
    };
    wake.wait_response(
        enclave_os_common::rpc::RpcRole::Execution,
        std::time::Duration::from_micros(maximum_micros),
    )
}

/// Retain an authenticated enclave-side fence/stop publication hint. The host
/// cannot decide cancellation; the resumed worker rechecks its trusted fence.
#[no_mangle]
pub extern "C" fn ocall_notify_execution_waiter() {
    if let Some(wake) = DISPATCHER_WAKE.get() {
        wake.notify_execution_cancel();
    }
}
