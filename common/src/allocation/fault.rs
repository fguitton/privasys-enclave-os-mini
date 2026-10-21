//! Fixture: number every admission draw of a pool in order, a lease or
//! header admitted ordinarily or from a lent growth credit and a split of a
//! mandatory token's credit, and refuse the one chosen. A caller learns a
//! step's draws by running it unarmed, then fails it before each in turn.
//! The step's up-front growth and token reservations are not draws.
use super::AllocationPoolV1;
use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub(super) struct Fault {
    drawn: AtomicUsize,
    refused: AtomicUsize,
}

impl Default for Fault {
    fn default() -> Self {
        Self {
            drawn: AtomicUsize::new(0),
            refused: AtomicUsize::new(usize::MAX),
        }
    }
}

impl Fault {
    /// Count one draw; whether it is the one to refuse.
    pub(super) fn refuses(&self) -> bool {
        self.drawn.fetch_add(1, Ordering::AcqRel) == self.refused.load(Ordering::Acquire)
    }
}

impl AllocationPoolV1 {
    /// Fixture: restart draw numbering at zero and refuse draw `refused`, or
    /// none.
    pub fn arm_fault_fixture(&self, refused: Option<usize>) {
        self.fault
            .refused
            .store(refused.unwrap_or(usize::MAX), Ordering::Release);
        self.fault.drawn.store(0, Ordering::Release);
    }
    /// Fixture: draws since the last arming.
    #[must_use]
    pub fn fault_fixture_draws(&self) -> usize {
        self.fault.drawn.load(Ordering::Acquire)
    }
}

#[cfg(all(test, feature = "std"))]
pub(super) fn check() {
    let pool = AllocationPoolV1::new(1000).unwrap();
    let authority = pool.protect_floor(100).unwrap();
    // One step: its growth and token reserved up front, then an ordinary, a
    // mandatory and a lent draw.
    let step = || {
        let token = authority.issue(50)?;
        let growth = pool.reserve_growth(200)?;
        let ordinary = pool.reserve(10)?;
        let mandatory = token.admission().reserve_unpublished(10)?;
        let lend = growth.lend();
        let lent = pool.reserve(10)?;
        drop(lend);
        drop((lent, mandatory, ordinary, growth, token));
        Some(())
    };
    pool.arm_fault_fixture(None);
    step().unwrap();
    assert_eq!(pool.fault_fixture_draws(), 3, "up-front reservations draw nothing");
    assert_eq!(pool.used(), 0);
    for refused in 0..3 {
        pool.arm_fault_fixture(Some(refused));
        assert!(step().is_none(), "draw {refused} is refused");
        assert_eq!(pool.fault_fixture_draws(), refused + 1, "nothing after it is drawn");
        assert_eq!(pool.used(), 0, "every earlier draw returns");
    }
    pool.arm_fault_fixture(Some(3));
    step().unwrap();
    pool.arm_fault_fixture(None);
    drop(authority);
    assert_eq!(pool.used(), 0);
}
