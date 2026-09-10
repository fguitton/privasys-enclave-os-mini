// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Adapt edger8r's packed thread arguments to Teaclave's aligned Rust ABI.

use sgx_types::error::errno::{EINVAL, ENOMEM};
use sgx_types::types::timespec;
use std::ffi::c_int;
use std::mem::size_of;
use std::ptr;

/// # Safety
/// Non-null `error` must have writable space for one C int, and `tcss` must
/// contain `total` initialized size_t values in one readable allocation.
/// The generated SGX bridge owns these buffers for this synchronous call;
/// neither buffer needs Rust alignment. No pointer is retained by this adapter.
#[no_mangle]
pub unsafe extern "C" fn enclave_os_thread_set_multiple_events_ocall(
    error: *mut c_int,
    tcss: *const usize,
    total: usize,
) -> c_int {
    let mut errno = EINVAL;
    let mut result = -1;
    if !tcss.is_null() && total != 0 && total <= isize::MAX as usize / size_of::<usize>() {
        let mut aligned = Vec::new();
        if aligned.try_reserve_exact(total).is_err() {
            errno = ENOMEM;
        } else {
            for index in 0..total {
                aligned.push(ptr::read_unaligned(tcss.add(index)));
            }
            // Preserve the SDK's zero-TCS filtering, ordering and error result.
            result = sgx_urts::ocall::sync::u_thread_set_multiple_events_ocall(
                &mut errno,
                aligned.as_ptr(),
                aligned.len(),
            );
        }
    }
    if !error.is_null() {
        ptr::write_unaligned(error, errno);
    }
    result
}

/// # Safety
/// The generated bridge provides writable `error` and readable `timeout`
/// storage when non-null. Both may be unaligned and live for this call only.
#[no_mangle]
pub unsafe extern "C" fn enclave_os_thread_wait_event_ocall(
    error: *mut c_int,
    tcs: usize,
    timeout: *const timespec,
    clockid: c_int,
    absolute_time: c_int,
) -> c_int {
    let timeout = (!timeout.is_null()).then(|| ptr::read_unaligned(timeout));
    let mut errno = 0;
    let result = sgx_urts::ocall::sync::u_thread_wait_event_ocall(
        &mut errno,
        tcs,
        // Teaclave's shared C timespec and libc's timespec have the same ABI.
        timeout
            .as_ref()
            .map_or(ptr::null(), |value| (value as *const timespec).cast()),
        clockid,
        absolute_time,
    );
    if !error.is_null() {
        ptr::write_unaligned(error, errno);
    }
    result
}

/// # Safety
/// Same generated-bridge buffer contract as `enclave_os_thread_wait_event_ocall`.
#[no_mangle]
pub unsafe extern "C" fn enclave_os_thread_setwait_events_ocall(
    error: *mut c_int,
    waiter_tcs: usize,
    self_tcs: usize,
    timeout: *const timespec,
    clockid: c_int,
    absolute_time: c_int,
) -> c_int {
    let timeout = (!timeout.is_null()).then(|| ptr::read_unaligned(timeout));
    let mut errno = 0;
    let result = sgx_urts::ocall::sync::u_thread_setwait_events_ocall(
        &mut errno,
        waiter_tcs,
        self_tcs,
        timeout
            .as_ref()
            .map_or(ptr::null(), |value| (value as *const timespec).cast()),
        clockid,
        absolute_time,
    );
    if !error.is_null() {
        ptr::write_unaligned(error, errno);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::align_of;

    #[test]
    fn packed_thread_arguments_preserve_wakes_and_reject_invalid_lengths() {
        // Exercise every alignment residue, including the actual edger8r +4
        // layout. Backing words guarantee that offset zero starts aligned.
        for offset in 0..align_of::<usize>() {
            let mut words = [0usize; 5];
            let bytes = words.as_mut_ptr().cast::<u8>();
            let events = unsafe { bytes.add(offset).cast::<usize>() };
            let mut output = [0xa5u8; 2 * size_of::<c_int>()];
            let error = unsafe { output.as_mut_ptr().add(1).cast::<c_int>() };
            let tcs = 0x484f_0000 + offset;
            unsafe {
                ptr::write_unaligned(events, 0);
                ptr::write_unaligned(events.add(1), tcs);
                ptr::write_unaligned(events.add(2), 0);
                assert_eq!(
                    enclave_os_thread_set_multiple_events_ocall(error, events, 3),
                    0
                );
                assert_eq!(ptr::read_unaligned(error), 0);
                assert_eq!(output[0], 0xa5);
                assert!(output[1 + size_of::<c_int>()..].iter().all(|&v| v == 0xa5));
                // A real SDK wake was recorded, so this consumes it without
                // waiting for another thread or inventing a mock result. A
                // zero timeout bounds the regression if no wake was recorded.
                let mut errno = -1;
                // libc::timespec contains only integer fields.
                let timeout = std::mem::zeroed();
                assert_eq!(
                    sgx_urts::ocall::sync::u_thread_wait_event_ocall(
                        &mut errno, tcs, &timeout, 0, 0,
                    ),
                    0
                );
                assert_eq!(errno, 0);
                // The timeout follows the same packed int output in both
                // wait OCALLs. Copy it before the SDK forms a reference.
                let mut timeout_words = [0usize; 4];
                let packed_timeout = timeout_words
                    .as_mut_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<timespec>();
                ptr::write_unaligned(
                    packed_timeout,
                    timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    },
                );
                assert_eq!(
                    enclave_os_thread_wait_event_ocall(error, tcs, packed_timeout, 0, 0,),
                    -1
                );
                assert_eq!(
                    ptr::read_unaligned(error),
                    sgx_types::error::errno::ETIMEDOUT
                );
                assert_eq!(
                    enclave_os_thread_setwait_events_ocall(error, tcs, tcs, packed_timeout, 0, 0,),
                    0
                );
                assert_eq!(ptr::read_unaligned(error), 0);
                assert_eq!(
                    enclave_os_thread_setwait_events_ocall(error, 0, tcs, packed_timeout, 0, 0,),
                    -1
                );
                assert_eq!(ptr::read_unaligned(error), EINVAL);
                assert_eq!(output[0], 0xa5);
                assert!(output[1 + size_of::<c_int>()..].iter().all(|&v| v == 0xa5));
            }
        }
        let valid = [0usize; 1];
        for (pointer, total) in [
            (ptr::null(), 1),
            (valid.as_ptr(), 0),
            (valid.as_ptr(), isize::MAX as usize / size_of::<usize>() + 1),
            (valid.as_ptr(), usize::MAX),
        ] {
            let mut errno = 0;
            assert_eq!(
                unsafe { enclave_os_thread_set_multiple_events_ocall(&mut errno, pointer, total) },
                -1
            );
            assert_eq!(errno, EINVAL);
        }
        assert_eq!(
            unsafe {
                enclave_os_thread_set_multiple_events_ocall(ptr::null_mut(), valid.as_ptr(), 1)
            },
            0
        );
        // A null timeout retains the SDK's indefinite-wait semantics; an
        // invalid TCS rejects before waiting, even with a null error output.
        assert_eq!(
            unsafe { enclave_os_thread_wait_event_ocall(ptr::null_mut(), 0, ptr::null(), 0, 0) },
            -1
        );
        assert_eq!(
            unsafe {
                enclave_os_thread_setwait_events_ocall(ptr::null_mut(), 0, 0, ptr::null(), 0, 0)
            },
            -1
        );
    }
}
