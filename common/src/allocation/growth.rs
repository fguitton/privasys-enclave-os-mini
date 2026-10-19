//! Ordinary capacity pre-reserved for one planned step's growth.
//!
//! A step that must not fail part-way reserves its whole ordinary growth in
//! one admission before it starts. While the credit is lent on a thread,
//! every ordinary admission of its pool on that thread draws only on it, and
//! every release of that pool on that thread returns to it: the step can
//! neither run short of headroom other work took meanwhile nor grow past
//! what it declared, and what it frees it may reuse. The credit therefore
//! bounds the step's net growth.
use super::mandatory::ReservedCreditV1;
use super::AllocationPoolV1;
use alloc::sync::Arc;
use core::cell::RefCell;

std::thread_local! {
    static LENT: RefCell<Option<Arc<ReservedCreditV1>>> = const { RefCell::new(None) };
}

/// Ordinary credit reserved for one step's growth. Move-only; unused credit
/// returns when it drops.
#[derive(Debug)]
pub struct GrowthCreditV1 {
    credit: Arc<ReservedCreditV1>,
}

/// While alive, this thread's ordinary admissions of the credit's pool draw
/// only on that credit; dropping it restores the previous lending.
#[derive(Debug)]
pub struct GrowthLendV1<'a> {
    previous: Option<Arc<ReservedCreditV1>>,
    _credit: &'a GrowthCreditV1,
}

impl AllocationPoolV1 {
    /// Reserve `bytes` of ordinary capacity, all or nothing, as one step's
    /// growth credit.
    #[must_use]
    pub fn reserve_growth(self: &Arc<Self>, bytes: usize) -> Option<GrowthCreditV1> {
        self.admit(bytes, false)?;
        Some(GrowthCreditV1 {
            credit: Arc::new(ReservedCreditV1::reserved(self.clone(), bytes)),
        })
    }
}

impl GrowthCreditV1 {
    /// Lend this credit to the current thread's ordinary admissions of its
    /// pool until the returned guard drops.
    #[must_use]
    pub fn lend(&self) -> GrowthLendV1<'_> {
        let previous = LENT.with(|lent| lent.replace(Some(self.credit.clone())));
        GrowthLendV1 {
            previous,
            _credit: self,
        }
    }
    /// Credit not yet taken.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.credit.remaining()
    }
    #[must_use]
    pub fn pool(&self) -> &Arc<AllocationPoolV1> {
        &self.credit.pool
    }
}

impl Drop for GrowthLendV1<'_> {
    fn drop(&mut self) {
        let previous = self.previous.take();
        LENT.with(|lent| *lent.borrow_mut() = previous);
    }
}

impl Drop for GrowthCreditV1 {
    fn drop(&mut self) {
        self.credit.close();
    }
}

/// The lent credit's answer for an ordinary admission of `bytes` from
/// `pool`: taken from the credit, or refused when it cannot cover them. None
/// when no open credit of this pool is lent on this thread.
pub(super) fn admit_lent(pool: &AllocationPoolV1, bytes: usize) -> Option<Option<()>> {
    LENT.with(|lent| {
        let lent = lent.borrow();
        let credit = lent.as_ref()?;
        if !core::ptr::eq(Arc::as_ptr(&credit.pool), pool) || credit.is_closed() {
            return None;
        }
        Some(credit.take(bytes))
    })
}

/// Return `bytes` released from `pool` to the open credit of that pool lent
/// on this thread; false when there is none.
pub(super) fn refund_lent(pool: &AllocationPoolV1, bytes: usize) -> bool {
    LENT.with(|lent| {
        let lent = lent.borrow();
        lent.as_ref().is_some_and(|credit| {
            core::ptr::eq(Arc::as_ptr(&credit.pool), pool) && credit.refund(bytes)
        })
    })
}

#[cfg(test)]
pub(super) fn check() {
    let pool = AllocationPoolV1::new(1000).unwrap();
    let other = AllocationPoolV1::new(1000).unwrap();
    let held = pool.reserve(600).unwrap();
    // Growth is admitted ordinarily, all or nothing.
    assert!(pool.reserve_growth(401).is_none());
    let growth = pool.reserve_growth(300).unwrap();
    assert_eq!(pool.used(), 900);
    {
        let _lend = growth.lend();
        // Lent, the step's ordinary admissions draw only on its credit.
        let first = pool.reserve(200).unwrap();
        assert_eq!((pool.used(), growth.remaining()), (900, 100));
        assert!(pool.reserve(101).is_none(), "credit only, never headroom");
        assert_eq!(pool.used(), 900);
        let second = pool.reserve(100).unwrap();
        assert!(pool.reserve(1).is_none());
        // Another pool is admitted ordinarily.
        drop(other.reserve(10).unwrap());
        // What the step frees returns to its credit, not to the pool: net
        // growth, not gross allocation, is bounded.
        drop(first);
        assert_eq!((pool.used(), growth.remaining()), (900, 200));
        let again = pool.reserve(200).unwrap();
        assert_eq!(growth.remaining(), 0);
        drop((again, second));
        assert_eq!((pool.used(), growth.remaining()), (900, 300));
    }
    // Closing returns the refunded credit to the pool.
    drop(growth);
    assert_eq!(pool.used(), 600);
    // Unlent, ordinary admission and release return to the pool; dropping a
    // credit returns what it holds.
    assert!(pool.reserve(100).is_some_and(|lease| {
        drop(lease);
        true
    }));
    assert_eq!(pool.used(), 600);
    let unused = pool.reserve_growth(50).unwrap();
    assert_eq!(pool.used(), 650);
    drop(unused);
    drop(held);
    assert_eq!(pool.used(), 0);
}
