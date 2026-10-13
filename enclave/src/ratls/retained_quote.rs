//! Retained quote payload. Data only: report/leaf/currentness checks remain at callers.
use enclave_os_common::allocation::{AllocationPoolV1, SharedAllocationV1};
use std::sync::Arc;
#[derive(Clone)]
pub(crate) struct RetainedQuote(SharedAllocationV1<Vec<u8>>);
impl RetainedQuote {
    pub(crate) fn copy_from(pool: &Arc<AllocationPoolV1>, bytes: &[u8]) -> Option<Self> {
        let reservation = SharedAllocationV1::<Vec<u8>>::reserve(pool, bytes.len())?;
        let mut copied = Vec::new();
        copied.try_reserve_exact(bytes.len()).ok()?;
        if copied.capacity() != bytes.len() {
            return None;
        }
        copied.extend_from_slice(bytes);
        #[cfg(feature = "fallible-allocation-v1")]
        let retained = reservation.try_finish(copied).ok()?;
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let retained = reservation.finish(copied);
        Some(Self(retained))
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}
