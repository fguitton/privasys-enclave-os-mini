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
#[derive(Debug)]
pub struct MandatoryAuthorityV1 {
    pool: Arc<AllocationPoolV1>,
}

/// Credit pre-reserved for one cleanup transition. Move-only.
#[derive(Debug)]
pub struct MandatoryTokenV1 {
    credit: Arc<MandatoryCreditV1>,
}

/// A token's pre-reserved credit, shared with the allocators it admits.
#[derive(Debug)]
pub struct MandatoryCreditV1 {
    pool: Arc<AllocationPoolV1>,
    remaining: AtomicUsize,
    closed: AtomicBool,
}

/// Where an allocation's bytes are admitted from: ordinary pool headroom, or
/// a mandatory token's pre-reserved credit while that token lives.
#[derive(Clone, Debug)]
pub enum AdmissionV1 {
    Ordinary(Arc<AllocationPoolV1>),
    Mandatory(Arc<MandatoryCreditV1>),
}

impl AllocationPoolV1 {
    /// Protect `floor` bytes from ordinary admission and return the one
    /// authority that may spend them.
    /// Refuses a second protection, a zero floor or a floor beyond capacity.
    pub fn protect_floor(self: &Arc<Self>, floor: usize) -> Option<MandatoryAuthorityV1> {
        if floor == 0 || floor > self.capacity {
            return None;
        }
        self.floor
            .compare_exchange(0, floor, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
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
            credit: Arc::new(MandatoryCreditV1 {
                pool: self.pool.clone(),
                remaining: AtomicUsize::new(demand),
                closed: AtomicBool::new(false),
            }),
        })
    }
    #[must_use]
    pub fn pool(&self) -> &Arc<AllocationPoolV1> {
        &self.pool
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
        self.credit.remaining.load(Ordering::Acquire)
    }
}

impl Drop for MandatoryTokenV1 {
    fn drop(&mut self) {
        // Close first: allocators that outlive the token fall back to
        // ordinary admission and can no longer draw on returned credit.
        self.credit.closed.store(true, Ordering::Release);
        let unused = self.credit.remaining.swap(0, Ordering::AcqRel);
        if unused != 0 {
            self.credit.pool.release_backend_bytes(unused, true);
        }
    }
}

impl MandatoryCreditV1 {
    fn split(&self, bytes: usize) -> Option<AllocationLeaseV1> {
        self.remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(bytes)
            })
            .ok()?;
        Some(AllocationLeaseV1::already_reserved(
            self.pool.clone(),
            bytes,
        ))
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
                if credit.closed.load(Ordering::Acquire) {
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
}
