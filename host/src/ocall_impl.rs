// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! OCall implementation – with the SPSC queue architecture, only ONE
//! OCALL remains: `ocall_notify()`.
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
