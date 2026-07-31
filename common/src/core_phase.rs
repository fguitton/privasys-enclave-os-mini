// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Shared lifecycle state for the two long-lived enclave entry points.
//!
//! The control TCS is the only writer allowed to publish [`CorePhase::Running`].
//! The execution TCS may enter first, but it cannot perform work until that
//! publication is visible.  Initialisation failure is terminal and releases a
//! waiting worker without requiring a third ECALL.

use core::sync::atomic::{AtomicU8, Ordering};

/// Enclave-owned lifecycle phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CorePhase {
    Initialising = 0,
    Running = 1,
    Failed = 2,
    ShuttingDown = 3,
    Stopped = 4,
}

impl CorePhase {
    fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Initialising,
            1 => Self::Running,
            2 => Self::Failed,
            3 => Self::ShuttingDown,
            4 => Self::Stopped,
            _ => Self::Failed,
        }
    }
}

/// Atomic lifecycle cell shared by the control and execution TCS.
pub struct CorePhaseCell {
    phase: AtomicU8,
}

impl CorePhaseCell {
    pub const fn new() -> Self {
        Self {
            phase: AtomicU8::new(CorePhase::Initialising as u8),
        }
    }

    pub fn load(&self) -> CorePhase {
        CorePhase::from_raw(self.phase.load(Ordering::Acquire))
    }

    /// Publish successful control-plane initialisation.
    pub fn publish_running(&self) -> Result<(), CorePhase> {
        self.transition(CorePhase::Initialising, CorePhase::Running)
    }

    /// Publish failed control-plane initialisation and release the worker.
    pub fn publish_failed(&self) -> Result<(), CorePhase> {
        self.transition(CorePhase::Initialising, CorePhase::Failed)
    }

    /// Begin in-band shutdown. Repeated requests are idempotent.
    pub fn request_shutdown(&self) -> CorePhase {
        loop {
            let current = self.load();
            match current {
                CorePhase::Initialising | CorePhase::Running => {
                    if self
                        .phase
                        .compare_exchange(
                            current as u8,
                            CorePhase::ShuttingDown as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return CorePhase::ShuttingDown;
                    }
                }
                terminal => return terminal,
            }
        }
    }

    /// Publish worker termination after shutdown has begun.
    pub fn publish_stopped(&self) -> Result<(), CorePhase> {
        self.transition(CorePhase::ShuttingDown, CorePhase::Stopped)
    }

    fn transition(&self, from: CorePhase, to: CorePhase) -> Result<(), CorePhase> {
        self.phase
            .compare_exchange(from as u8, to as u8, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(CorePhase::from_raw)
    }
}

impl Default for CorePhaseCell {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{CorePhase, CorePhaseCell};
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn worker_first_waits_for_control_publication() {
        let phase = Arc::new(CorePhaseCell::new());
        let worker_phase = Arc::clone(&phase);
        let worker = thread::spawn(move || loop {
            match worker_phase.load() {
                CorePhase::Initialising => thread::yield_now(),
                visible => return visible,
            }
        });

        assert_eq!(phase.publish_running(), Ok(()));
        assert_eq!(worker.join().unwrap(), CorePhase::Running);
    }

    #[test]
    fn control_first_is_visible_to_late_worker() {
        let phase = CorePhaseCell::new();
        assert_eq!(phase.publish_running(), Ok(()));
        assert_eq!(phase.load(), CorePhase::Running);
    }

    #[test]
    fn failure_releases_waiter_and_cannot_be_overwritten() {
        let phase = CorePhaseCell::new();
        assert_eq!(phase.publish_failed(), Ok(()));
        assert_eq!(phase.load(), CorePhase::Failed);
        assert_eq!(phase.publish_running(), Err(CorePhase::Failed));
    }

    #[test]
    fn shutdown_is_idempotent_and_worker_stops() {
        let phase = CorePhaseCell::new();
        assert_eq!(phase.publish_running(), Ok(()));
        assert_eq!(phase.request_shutdown(), CorePhase::ShuttingDown);
        assert_eq!(phase.request_shutdown(), CorePhase::ShuttingDown);
        assert_eq!(phase.publish_stopped(), Ok(()));
        assert_eq!(phase.request_shutdown(), CorePhase::Stopped);
    }
}
