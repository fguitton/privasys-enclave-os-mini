// Copyright (c) 2026 Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

//! Renewal triggers for owners of persistent attested HTTP connections.
//! Clock observations are scheduling hints, not trusted SGX time. The owner
//! may supply nominal elapsed ticks; the request budget still bounds proof
//! reuse if the host freezes or omits scheduling observations.

use std::num::NonZeroU64;

#[derive(Clone, Copy, Debug, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AttestationRenewalPolicy {
    renew_after_seconds: NonZeroU64,
    max_requests: NonZeroU64,
}

impl Default for AttestationRenewalPolicy {
    fn default() -> Self {
        Self {
            renew_after_seconds: NonZeroU64::new(300).unwrap(),
            max_requests: NonZeroU64::new(4096).unwrap(),
        }
    }
}

/// One proof generation's remaining authority budget. Renew by constructing a
/// new budget only after fresh evidence has passed local binding verification.
pub struct AttestationRenewalBudget {
    policy: AttestationRenewalPolicy,
    observed_at: Option<u64>,
    requests: u64,
    retired: bool,
}

impl AttestationRenewalBudget {
    pub fn is_retired(&self) -> bool {
        self.retired
    }

    pub fn new(policy: AttestationRenewalPolicy, observed_at: Option<u64>) -> Self {
        Self {
            policy,
            observed_at,
            requests: 0,
            retired: false,
        }
    }

    /// Check an already admitted request before consuming another response
    /// fragment. The last request in the count budget may finish, but observed
    /// expiry is terminal even if the peer keeps making transport progress.
    /// Owners must not call `renewal_due` until that request has finished.
    pub fn check_active_request(&mut self, now: Option<u64>) -> Result<(), &'static str> {
        let clock_due = match (self.observed_at, now) {
            (Some(start), Some(now)) => now
                .checked_sub(start)
                .is_none_or(|elapsed| elapsed >= self.policy.renew_after_seconds.get()),
            (None, Some(_)) => true,
            _ => false,
        };
        self.retired |= clock_due;
        if self.retired {
            return Err("attestation renewal required");
        }
        Ok(())
    }

    pub fn renewal_due(&mut self, now: Option<u64>) -> bool {
        self.retired = self.check_active_request(now).is_err()
            || self.requests >= self.policy.max_requests.get();
        self.retired
    }

    pub fn record_request(&mut self, now: Option<u64>) -> Result<(), &'static str> {
        if self.renewal_due(now) {
            return Err("attestation renewal required");
        }
        // At most max_requests requests can be accepted, including when the
        // configured bound is u64::MAX. The next call retires without overflow.
        self.requests += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(requests: u64) -> AttestationRenewalPolicy {
        serde_json::from_value(serde_json::json!({
            "renew_after_seconds": 10, "max_requests": requests
        }))
        .unwrap()
    }

    #[test]
    fn renewal_bounds_reuse_under_frozen_missing_and_rewound_host_time() {
        for now in [Some(100), None] {
            let mut budget = AttestationRenewalBudget::new(policy(3), now);
            for _ in 0..3 {
                budget.record_request(now).unwrap();
            }
            assert!(budget.record_request(now).is_err());
            assert!(budget.renewal_due(now));
        }
        let mut budget = AttestationRenewalBudget::new(policy(3), Some(100));
        budget.record_request(Some(109)).unwrap();
        assert!(budget.record_request(Some(110)).is_err());
        assert!(budget.record_request(Some(100)).is_err());
        let mut budget = AttestationRenewalBudget::new(policy(3), Some(100));
        assert!(budget.renewal_due(Some(99)));
        assert!(budget.record_request(Some(100)).is_err());
        let mut budget = AttestationRenewalBudget::new(policy(3), None);
        assert!(budget.renewal_due(Some(100)));
        let mut fresh = AttestationRenewalBudget::new(policy(3), Some(100));
        fresh.record_request(Some(100)).unwrap();
    }

    #[test]
    fn renewal_policy_rejects_disabled_or_ambiguous_limits_and_handles_overflow() {
        for invalid in [
            serde_json::json!({"max_requests":0}),
            serde_json::json!({"renew_after_seconds":0}),
            serde_json::json!({"max_requests":-1}),
            serde_json::json!({"renew_after_seconds":"10"}),
            serde_json::json!({"unknown":true}),
        ] {
            assert!(serde_json::from_value::<AttestationRenewalPolicy>(invalid).is_err());
        }
        let mut budget = AttestationRenewalBudget::new(policy(u64::MAX), Some(u64::MAX - 2));
        budget.requests = u64::MAX - 1;
        budget.record_request(Some(u64::MAX)).unwrap();
        assert!(budget.record_request(Some(u64::MAX)).is_err());
    }

    #[test]
    fn active_request_may_finish_its_count_slot_but_cannot_extend_observed_expiry() {
        let mut budget = AttestationRenewalBudget::new(policy(1), Some(100));
        budget.record_request(Some(100)).unwrap();
        for now in 100..110 {
            budget.check_active_request(Some(now)).unwrap();
        }
        assert!(budget.check_active_request(Some(110)).is_err());
        assert!(budget.check_active_request(Some(100)).is_err());
        assert!(budget.record_request(Some(100)).is_err());

        for now in [Some(100), None] {
            let mut budget = AttestationRenewalBudget::new(policy(1), now);
            budget.record_request(now).unwrap();
            budget.check_active_request(now).unwrap();
            assert!(budget.record_request(now).is_err());
            assert!(budget.check_active_request(now).is_err());
        }
    }
}
