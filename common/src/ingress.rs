// Copyright (c) 2026 Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

//! Owned capacity accounting for optional incremental ingress adopters.
//! This supplies resource ownership, not appraisal or application authority.

use alloc::{boxed::Box, vec::Vec};

/// Independent resource owner. It must outlive configuration/session/Live
/// replacement. Drop must only refund its ledger, never reenter those locks
/// or Mini's outer ENCLAVE_STATE mutex (crate::state()).
/// Reservations include an explicit adopter allocator-overhead allowance;
/// observed Vec capacity alone does not measure allocator overhead.
pub trait CapacityCharge: Send {
    /// Reserve at least this many actual capacity bytes before allocation.
    /// Successful calls are monotonic; truncating bytes does not refund credit.
    fn reserve(&mut self, capacity: usize) -> Result<(), &'static str>;
}

/// A unique allocation which cannot escape its charge as a Vec or be cloned.
/// Field order frees the allocation before dropping/refunding its charge.
pub struct ChargedBytes {
    bytes: Vec<u8>,
    charge: Box<dyn CapacityCharge>,
    capacity_limit: usize,
    reserved_capacity: usize,
}

impl ChargedBytes {
    pub fn try_new(
        capacity: usize,
        capacity_limit: usize,
        charge: Box<dyn CapacityCharge>,
    ) -> Result<Self, &'static str> {
        if capacity_limit > isize::MAX.unsigned_abs() || capacity > capacity_limit {
            return Err("charged capacity exceeds limit");
        }
        let mut owned = Self {
            bytes: Vec::new(),
            charge,
            capacity_limit,
            reserved_capacity: 0,
        };
        owned.reserve(capacity)?;
        Ok(owned)
    }

    fn reserve(&mut self, needed: usize) -> Result<(), &'static str> {
        if needed > self.capacity_limit {
            return Err("charged capacity exceeds limit");
        }
        if needed <= self.bytes.capacity() {
            return Ok(());
        }
        // Reallocation can keep the old and new allocations alive together.
        // Charge their peak before growth, retaining monotonic credit until
        // this allocation is freed. Preallocation avoids this extra peak.
        let old_capacity = self.bytes.capacity();
        let peak = old_capacity
            .checked_add(needed)
            .ok_or("charged growth overflow")?;
        if peak > self.capacity_limit {
            return Err("charged reallocation peak exceeds limit");
        }
        let reservation = peak.max(self.reserved_capacity);
        self.charge.reserve(reservation)?;
        self.reserved_capacity = reservation;
        self.bytes
            .try_reserve_exact(needed - self.bytes.len())
            .map_err(|_| "charged allocation failed")?;
        let actual = self.bytes.capacity();
        let actual_peak = old_capacity
            .checked_add(actual)
            .ok_or("charged growth overflow")?;
        let reservation = actual_peak.max(self.reserved_capacity);
        if reservation > self.capacity_limit || self.charge.reserve(reservation).is_err() {
            // No payload is accepted in an unexpectedly over-capacity buffer.
            // Free it while the earlier independent reservation remains held.
            self.bytes = Vec::new();
            return Err("actual charged capacity exceeds reservation");
        }
        self.reserved_capacity = reservation;
        Ok(())
    }

    pub fn try_extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        let needed = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or("charged length overflow")?;
        self.reserve(needed)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    /// Monotonic charged high-water, including simultaneous reallocation.
    pub fn reserved_capacity(&self) -> usize {
        self.reserved_capacity
    }
}
