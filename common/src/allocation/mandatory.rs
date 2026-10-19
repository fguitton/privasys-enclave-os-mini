//! A protected floor of pool capacity that only mandatory cleanup may spend.
//!
//! Ordinary admission stops `floor` bytes below capacity. The one authority a
//! pool issues can pre-reserve an exact demand into a token; the token's
//! credit is already counted as used, so splitting it into leases charges
//! nothing again, and dropping the token returns what was not split off.
use super::{AllocationLeaseV1, AllocationPoolV1};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// The single capability that may issue mandatory cleanup tokens for one pool.
/// It is not `Clone`; its owner decides which commands receive tokens.
/// Dropping it lifts the floor, so a refused owner's retry can protect again.
#[derive(Debug)]
pub struct MandatoryAuthorityV1 {
    pool: Arc<AllocationPoolV1>,
}

/// Credit pre-reserved for one cleanup transition. Move-only.
#[derive(Debug)]
pub struct MandatoryTokenV1 {
    credit: Arc<ReservedCreditV1>,
}

/// Bytes already counted as used, split into leases without charging the
/// pool again; whatever is not split returns when its owner closes it.
#[derive(Debug)]
pub struct ReservedCreditV1 {
    pub(super) pool: Arc<AllocationPoolV1>,
    remaining: AtomicUsize,
    closed: AtomicBool,
}

/// Where an allocation's bytes are admitted from: ordinary pool headroom, or
/// a mandatory token's pre-reserved credit while that token lives.
#[derive(Clone, Debug)]
pub enum AdmissionV1 {
    Ordinary(Arc<AllocationPoolV1>),
    Mandatory(Arc<ReservedCreditV1>),
}

impl AllocationPoolV1 {
    /// Protect `floor` bytes from ordinary admission and return the one
    /// authority that may spend them.
    /// Refuses a second protection, a zero floor, or a floor that does not fit
    /// beside the bytes already admitted.
    pub fn protect_floor(self: &Arc<Self>, floor: usize) -> Option<MandatoryAuthorityV1> {
        if floor == 0 {
            return None;
        }
        // Serialized with every admission: at installation the pool holds no
        // more than its new ordinary capacity, and no admission decided
        // against the previous floor can commit afterwards.
        self.serialized(|| {
            if self.floor.load(Ordering::Acquire) != 0
                || self
                    .used
                    .load(Ordering::Acquire)
                    .checked_add(floor)
                    .is_none_or(|bytes| bytes > self.capacity)
            {
                return None;
            }
            self.floor.store(floor, Ordering::Release);
            Some(())
        })?;
        Some(MandatoryAuthorityV1 { pool: self.clone() })
    }
    /// The capacity ordinary admission may use.
    #[must_use]
    pub fn ordinary_capacity(&self) -> usize {
        self.capacity - self.floor.load(Ordering::Acquire)
    }
}

impl MandatoryAuthorityV1 {
    /// Pre-reserve exactly `demand` bytes, floor included, or nothing.
    /// Concurrent tokens never promise the same bytes.
    #[must_use]
    pub fn issue(&self, demand: usize) -> Option<MandatoryTokenV1> {
        if demand == 0 {
            return None;
        }
        self.pool.reserve_mandatory_bytes(demand)?;
        Some(MandatoryTokenV1 {
            credit: Arc::new(ReservedCreditV1::reserved(self.pool.clone(), demand)),
        })
    }
    #[must_use]
    pub fn pool(&self) -> &Arc<AllocationPoolV1> {
        &self.pool
    }
}

impl Drop for MandatoryAuthorityV1 {
    fn drop(&mut self) {
        self.pool
            .serialized(|| self.pool.floor.store(0, Ordering::Release));
    }
}

impl MandatoryTokenV1 {
    /// The admission that draws on this token while it lives.
    #[must_use]
    pub fn admission(&self) -> AdmissionV1 {
        AdmissionV1::Mandatory(self.credit.clone())
    }
    /// Credit not yet split into leases.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.credit.remaining()
    }
}

impl Drop for MandatoryTokenV1 {
    fn drop(&mut self) {
        self.credit.close();
    }
}

impl ReservedCreditV1 {
    /// Credit over `bytes` the caller has already admitted to `pool`.
    pub(super) fn reserved(pool: Arc<AllocationPoolV1>, bytes: usize) -> Self {
        Self {
            pool,
            remaining: AtomicUsize::new(bytes),
            closed: AtomicBool::new(false),
        }
    }
    pub(super) fn remaining(&self) -> usize {
        self.remaining.load(Ordering::Acquire)
    }
    pub(super) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    /// Return `bytes` freed while the credit is open; they stay counted as
    /// used until the credit closes.
    pub(super) fn refund(&self, bytes: usize) -> bool {
        if self.is_closed() {
            return false;
        }
        self.remaining.fetch_add(bytes, Ordering::AcqRel);
        true
    }
    /// Take `bytes` of the credit, all of them or none.
    pub(super) fn take(&self, bytes: usize) -> Option<()> {
        self.remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(bytes)
            })
            .ok()
            .map(|_| ())
    }
    fn split(&self, bytes: usize) -> Option<AllocationLeaseV1> {
        self.take(bytes)?;
        Some(AllocationLeaseV1::already_reserved(
            self.pool.clone(),
            bytes,
        ))
    }
    /// Close first, so allocators that outlive the owner fall back to
    /// ordinary admission and cannot draw on returned credit, then return
    /// what was not taken.
    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let unused = self.remaining.swap(0, Ordering::AcqRel);
        if unused != 0 {
            self.pool.release_backend_bytes(unused, true);
        }
    }
}

impl AdmissionV1 {
    #[must_use]
    pub fn pool(&self) -> &Arc<AllocationPoolV1> {
        match self {
            Self::Ordinary(pool) => pool,
            Self::Mandatory(credit) => &credit.pool,
        }
    }
    /// An unpublished lease of `bytes`. A live token's credit must cover the
    /// whole request; it never falls back to ordinary headroom. A closed
    /// token's admission is ordinary.
    #[must_use]
    pub fn reserve_unpublished(&self, bytes: usize) -> Option<AllocationLeaseV1> {
        match self {
            Self::Ordinary(pool) => pool.reserve_unpublished(bytes),
            Self::Mandatory(credit) => {
                if bytes == 0 {
                    return None;
                }
                if credit.is_closed() {
                    return credit.pool.reserve_unpublished(bytes);
                }
                credit.split(bytes)
            }
        }
    }
}

#[cfg(test)]
pub(super) fn check() {
    use super::SharedAllocationV1;
    // `shared` bytes cover one shared allocation of a u64.
    let shared = SharedAllocationV1::<u64>::required_bytes(0).unwrap();
    let floor = 40 + shared;
    let capacity = 60 + floor;
    // Ordinary admission stops at the floor; mandatory issuance may use it.
    let pool = AllocationPoolV1::new(capacity).unwrap();
    assert!(pool.protect_floor(0).is_none());
    assert!(pool.protect_floor(capacity + 1).is_none());
    let authority = pool.protect_floor(floor).unwrap();
    assert!(
        pool.protect_floor(floor).is_none(),
        "one authority per pool"
    );
    assert_eq!(pool.ordinary_capacity(), 60);
    assert!(pool.reserve(61).is_none());
    let ordinary = pool.reserve(60).unwrap();
    assert!(pool.reserve(1).is_none());
    // Issuance pre-reserves the whole demand atomically, or nothing.
    assert!(authority.issue(0).is_none());
    assert!(authority.issue(floor + 1).is_none());
    assert_eq!(pool.used(), 60);
    let first = authority.issue(25).unwrap();
    assert_eq!(pool.used(), 85);
    let second = authority.issue(15 + shared).unwrap();
    assert_eq!(pool.used(), capacity);
    assert!(authority.issue(1).is_none(), "no promise over spent floor");
    assert_eq!(pool.used(), capacity);
    // Splitting charges nothing again; a lease returns its bytes on drop.
    let admission = first.admission();
    let lease = admission.reserve_unpublished(10).unwrap();
    assert_eq!((pool.used(), first.remaining()), (capacity, 15));
    assert!(admission.reserve_unpublished(16).is_none(), "credit only");
    assert_eq!(pool.used(), capacity);
    // Shared allocations admit through the token as well.
    let value = SharedAllocationV1::<u64>::reserve_in(&second.admission(), 0)
        .unwrap()
        .finish(7);
    assert_eq!(second.remaining(), 15);
    // Dropping a token returns only its unused credit.
    drop(second);
    assert_eq!(pool.used(), capacity - 15);
    drop(value);
    assert_eq!(pool.used(), 85);
    drop(lease);
    assert_eq!(pool.used(), 75);
    drop(first);
    assert_eq!(pool.used(), 60);
    // A closed token's admission is ordinary and respects the floor.
    let late = authority.issue(5).unwrap();
    let outlived = late.admission();
    drop(late);
    assert!(outlived.reserve_unpublished(1).is_none());
    drop(ordinary);
    assert!(outlived.reserve_unpublished(60).is_some_and(|lease| {
        let held = pool.used();
        drop(lease);
        held == 60
    }));
    assert!(outlived.reserve_unpublished(61).is_none());
    assert_eq!(pool.used(), 0);
    // Dropping the authority lifts the floor; the pool may be protected again.
    drop(authority);
    assert_eq!(pool.ordinary_capacity(), capacity);
    assert!(pool.protect_floor(floor).is_some());
    // Admitted state plus the floor must fit: limit+1, limit, and overflow.
    let held = pool.reserve(60).unwrap();
    assert!(pool.protect_floor(floor + 1).is_none());
    assert!(pool.protect_floor(usize::MAX).is_none());
    let bound = pool.protect_floor(floor).unwrap();
    assert_eq!(pool.ordinary_capacity(), 60);
    drop((bound, held));
    floor_installation_races_admission();
}

/// Ordinary reservers race repeated floor installation and removal. Each
/// would fit three at a time without the floor and only one beside it, so an
/// admission decided against a stale limit would push `used` past the
/// protected limit while the floor holds.
#[cfg(test)]
fn floor_installation_races_admission() {
    use core::sync::atomic::{AtomicBool, AtomicUsize};
    let pool = AllocationPoolV1::new(1000).unwrap();
    let stop = AtomicBool::new(false);
    let admitted = AtomicUsize::new(0);
    let mut protected = 0_usize;
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                while !stop.load(Ordering::Acquire) {
                    if let Some(lease) = pool.reserve(300) {
                        admitted.fetch_add(1, Ordering::Relaxed);
                        core::hint::spin_loop();
                        drop(lease);
                    }
                }
            });
        }
        for _ in 0..20_000 {
            if let Some(authority) = pool.protect_floor(600) {
                protected += 1;
                for _ in 0..64 {
                    assert!(pool.used() <= 400, "ordinary admission entered the floor");
                }
                drop(authority);
            }
        }
        stop.store(true, Ordering::Release);
    });
    assert!(protected > 0 && admitted.load(Ordering::Relaxed) > 0);
    assert_eq!(pool.used(), 0);
}
