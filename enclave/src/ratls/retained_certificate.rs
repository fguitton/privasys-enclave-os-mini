//! Immutable served-certificate copy, shared without exposing Arc or Weak.
//! The certificate producer and rustls configuration have separate owners.
use enclave_os_common::allocation::{AllocationPoolV1, SharedAllocationV1};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct RetainedCertificate(SharedAllocationV1<Vec<u8>>);
impl RetainedCertificate {
    pub(crate) fn copy_from(pool: &Arc<AllocationPoolV1>, bytes: &[u8]) -> Option<Self> {
        let reservation = SharedAllocationV1::<Vec<u8>>::reserve(pool, bytes.len())?;
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len()).ok()?;
        if owned.capacity() != bytes.len() {
            return None;
        }
        owned.extend_from_slice(bytes);
        #[cfg(feature = "fallible-allocation-v1")]
        let retained = reservation.try_finish(owned).ok()?;
        // Default metadata construction remains infallible with both layouts paid.
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let retained = reservation.finish(owned);
        Some(Self(retained))
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}
