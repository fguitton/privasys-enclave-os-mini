//! Original quote-time formatter with independently retained paid backing.
use enclave_os_common::allocation::{AllocationPoolV1, SharedAllocationV1};
use std::sync::Arc;
/// Cached original timestamp text, sharing its paid backing across cache hits.
#[derive(Clone)]
pub(crate) struct QuoteTime(SharedAllocationV1<String>);
impl QuoteTime {
    pub(crate) fn new(pool: &Arc<AllocationPoolV1>, unix: i64) -> Option<Self> {
        let bytes = enclave_os_common::attest::quote_time_encoded_len(unix)?;
        let reservation = SharedAllocationV1::<String>::reserve(pool, bytes)?;
        let mut value = String::new();
        value.try_reserve_exact(bytes).ok()?;
        if value.capacity() != bytes {
            return None;
        }
        enclave_os_common::attest::write_quote_time(unix, &mut value).ok()?;
        if value.len() != bytes || value.capacity() != bytes {
            return None;
        }
        #[cfg(feature = "fallible-allocation-v1")]
        let value = reservation.try_finish(value).ok()?;
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let value = reservation.finish(value);
        Some(Self(value))
    }
    pub(crate) fn text(&self) -> &str {
        self.0.as_str()
    }
}
