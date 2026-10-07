// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Retained wake signals for the two independent SPSC consumers.
//!
//! The notification OCALL has no role argument. Wake both consumers, each with
//! its own pending bit: one dispatcher must never consume the other's signal.
//! Queue publication precedes notification. A notification between an empty
//! queue read and `wait` remains pending; notifications during condvar waiting
//! acquire the same mutex. Spurious wakes only recheck the predicate.

use enclave_os_common::rpc::RpcRole;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

pub struct DispatcherWake {
    pending: Mutex<[bool; 2]>,
    ready: Condvar,
    responses: Mutex<([bool; 2], bool)>,
    response_ready: Condvar,
}

impl DispatcherWake {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new([false; 2]),
            ready: Condvar::new(),
            responses: Mutex::new(([false; 2], false)),
            response_ready: Condvar::new(),
        }
    }

    pub fn notify(&self) {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *pending = [true; 2];
        self.ready.notify_all();
    }

    pub fn wait(&self, role: RpcRole, shutdown: &AtomicBool) {
        let index = match role {
            RpcRole::Control => 0,
            RpcRole::Execution => 1,
        };
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut pending = self
            .ready
            .wait_while(pending, |pending| {
                !pending[index] && !shutdown.load(Ordering::Acquire)
            })
            .unwrap_or_else(|error| error.into_inner());
        pending[index] = false;
    }

    /// Called only after successful response-ring publication. The retained
    /// bit closes the race between the worker's empty-ring check and its OCALL.
    pub fn notify_response(&self, role: RpcRole) {
        let index = usize::from(role == RpcRole::Execution);
        let mut state = self
            .responses
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.0[index] = true;
        self.response_ready.notify_all();
    }

    /// A scheduling hint only. Callers must check their exact queue operation
    /// again; an old/coalesced/spurious hint grants neither bytes nor authority.
    /// Timeout is solely a finite fence/cancellation boundary, not pacing.
    pub fn wait_response(&self, role: RpcRole, maximum: Duration) -> i32 {
        let index = usize::from(role == RpcRole::Execution);
        let state = self
            .responses
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (mut state, _) = self
            .response_ready
            .wait_timeout_while(state, maximum, |state| !state.0[index] && !state.1)
            .unwrap_or_else(|error| error.into_inner());
        if state.1 {
            return -1;
        }
        if state.0[index] {
            state.0[index] = false;
            0
        } else {
            1
        }
    }

    pub fn shutdown(&self, shutdown: &AtomicBool) {
        {
            let mut state = self
                .responses
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.1 = true;
            self.response_ready.notify_all();
        }
        shutdown.store(true, Ordering::Release);
        self.notify();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn lost_wakeup_between_queue_check_and_wait_is_retained_for_both_roles() {
        let wake = Arc::new(DispatcherWake::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (done_tx, done_rx) = mpsc::channel();
        let (empty_tx, empty_rx) = mpsc::channel();
        let resume = Arc::new(Barrier::new(2));
        let worker = {
            let (wake, shutdown, resume) = (wake.clone(), shutdown.clone(), resume.clone());
            thread::spawn(move || {
                for _ in 0..128 {
                    // The dispatcher has just found its queue empty.
                    empty_tx.send(()).unwrap();
                    resume.wait();
                    wake.wait(RpcRole::Control, &shutdown);
                    wake.wait(RpcRole::Execution, &shutdown);
                    done_tx.send(()).unwrap();
                }
            })
        };
        for _ in 0..128 {
            empty_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            // Coalescing is safe, and control cannot steal execution's wake.
            wake.notify();
            wake.notify();
            resume.wait();
            let result = done_rx.recv_timeout(Duration::from_secs(2));
            if result.is_err() {
                wake.shutdown(&shutdown);
            }
            result.unwrap();
        }
        worker.join().unwrap();
    }

    #[test]
    fn spurious_wake_does_not_satisfy_the_predicate() {
        for role in [RpcRole::Control, RpcRole::Execution] {
            let wake = Arc::new(DispatcherWake::new());
            let shutdown = Arc::new(AtomicBool::new(false));
            let start = Arc::new(Barrier::new(2));
            let (done_tx, done_rx) = mpsc::channel();
            let worker = {
                let (wake, shutdown, start) = (wake.clone(), shutdown.clone(), start.clone());
                thread::spawn(move || {
                    start.wait();
                    wake.wait(role, &shutdown);
                    done_tx.send(()).unwrap();
                })
            };
            start.wait();
            for _ in 0..8 {
                wake.ready.notify_all();
                thread::yield_now();
            }
            let premature = done_rx.recv_timeout(Duration::from_millis(20));
            wake.notify();
            let completed = done_rx.recv_timeout(Duration::from_secs(2));
            wake.shutdown(&shutdown);
            worker.join().unwrap();
            assert_eq!(premature, Err(mpsc::RecvTimeoutError::Timeout));
            completed.unwrap();
        }
    }

    #[test]
    fn response_publication_between_empty_check_and_wait_is_retained() {
        let wake = Arc::new(DispatcherWake::new());
        let shutdown = AtomicBool::new(false);
        for _ in 0..128 {
            wake.notify_response(RpcRole::Execution);
            wake.notify_response(RpcRole::Execution);
            assert_eq!(
                wake.wait_response(RpcRole::Execution, Duration::from_secs(1)),
                0
            );
            assert_eq!(wake.wait_response(RpcRole::Control, Duration::ZERO), 1);
            assert_eq!(wake.wait_response(RpcRole::Execution, Duration::ZERO), 1);
        }
        wake.shutdown(&shutdown);
        assert_eq!(
            wake.wait_response(RpcRole::Execution, Duration::from_secs(1)),
            -1
        );
    }

    #[test]
    fn response_wait_wakes_on_real_publication_and_stop_without_spurious_completion() {
        for stopping in [false, true] {
            let wake = Arc::new(DispatcherWake::new());
            let shutdown = Arc::new(AtomicBool::new(false));
            let start = Arc::new(Barrier::new(2));
            let (tx, rx) = mpsc::channel();
            let worker = {
                let (wake, start) = (wake.clone(), start.clone());
                thread::spawn(move || {
                    start.wait();
                    tx.send(wake.wait_response(RpcRole::Execution, Duration::from_secs(2)))
                        .unwrap();
                })
            };
            start.wait();
            wake.response_ready.notify_all();
            assert!(rx.recv_timeout(Duration::from_millis(20)).is_err());
            if stopping {
                wake.shutdown(&shutdown);
            } else {
                wake.notify_response(RpcRole::Execution);
            }
            assert_eq!(
                rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                if stopping { -1 } else { 0 }
            );
            worker.join().unwrap();
        }
    }

    #[test]
    fn shutdown_wakes_both_consumers_and_prevents_future_sleep() {
        let wake = Arc::new(DispatcherWake::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let start = Arc::new(Barrier::new(3));
        let (done_tx, done_rx) = mpsc::channel();
        let workers: Vec<_> = [RpcRole::Control, RpcRole::Execution]
            .into_iter()
            .map(|role| {
                let (wake, shutdown, start, done_tx) = (
                    wake.clone(),
                    shutdown.clone(),
                    start.clone(),
                    done_tx.clone(),
                );
                thread::spawn(move || {
                    start.wait();
                    wake.wait(role, &shutdown);
                    assert!(shutdown.load(Ordering::Acquire));
                    wake.wait(role, &shutdown);
                    done_tx.send(()).unwrap();
                })
            })
            .collect();
        start.wait();
        wake.shutdown(&shutdown);
        for _ in 0..2 {
            done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        for worker in workers {
            worker.join().unwrap();
        }
    }
}
