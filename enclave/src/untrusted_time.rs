// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

const NANOS_PER_SECOND: i64 = 1_000_000_000;
const NANOS_PER_MILLISECOND: u64 = 1_000_000;
const MILLIS_PER_SECOND: u64 = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MonotonicTimespecError {
    NegativeSeconds,
    InvalidNanoseconds,
    MillisecondOverflow,
}

pub(crate) fn checked_monotonic_millis(
    seconds: i64,
    nanoseconds: i64,
) -> Result<u64, MonotonicTimespecError> {
    let seconds = u64::try_from(seconds).map_err(|_| MonotonicTimespecError::NegativeSeconds)?;
    let nanoseconds =
        u64::try_from(nanoseconds).map_err(|_| MonotonicTimespecError::InvalidNanoseconds)?;
    if nanoseconds >= NANOS_PER_SECOND as u64 {
        return Err(MonotonicTimespecError::InvalidNanoseconds);
    }

    seconds
        .checked_mul(MILLIS_PER_SECOND)
        .and_then(|millis| millis.checked_add(nanoseconds / NANOS_PER_MILLISECOND))
        .ok_or(MonotonicTimespecError::MillisecondOverflow)
}

#[cfg(test)]
mod tests {
    use super::{checked_monotonic_millis, MonotonicTimespecError};

    #[test]
    fn conversion_rounds_down_to_milliseconds() {
        assert_eq!(checked_monotonic_millis(12, 345_678_901), Ok(12_345));
        assert_eq!(checked_monotonic_millis(0, 999_999), Ok(0));
    }

    #[test]
    fn conversion_rejects_malformed_fields() {
        assert_eq!(
            checked_monotonic_millis(-1, 0),
            Err(MonotonicTimespecError::NegativeSeconds)
        );
        assert_eq!(
            checked_monotonic_millis(0, -1),
            Err(MonotonicTimespecError::InvalidNanoseconds)
        );
        assert_eq!(
            checked_monotonic_millis(0, 1_000_000_000),
            Err(MonotonicTimespecError::InvalidNanoseconds)
        );
    }

    #[test]
    fn conversion_checks_millisecond_overflow() {
        let largest_seconds = u64::MAX / 1_000;
        assert_eq!(
            checked_monotonic_millis(largest_seconds as i64, 615_000_000),
            Ok(u64::MAX)
        );
        assert_eq!(
            checked_monotonic_millis(largest_seconds as i64, 616_000_000),
            Err(MonotonicTimespecError::MillisecondOverflow)
        );
        assert_eq!(
            checked_monotonic_millis(i64::MAX, 0),
            Err(MonotonicTimespecError::MillisecondOverflow)
        );
    }
}
