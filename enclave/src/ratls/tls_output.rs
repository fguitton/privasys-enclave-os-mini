//! Ciphertext backing stays paid until the last synchronous channel copy finishes.
use enclave_os_common::allocation::{AllocationLeaseV1, AllocationPoolV1};
use std::sync::Arc;

/// Borrow-only owned TLS bytes with original physical admission. No authority.
pub struct TlsOutput {
    bytes: Vec<u8>,
    allocation: Option<AllocationLeaseV1>,
    maximum: usize,
}
impl Default for TlsOutput {
    fn default() -> Self {
        Self {
            bytes: Vec::new(),
            allocation: None,
            maximum: usize::MAX,
        }
    }
}
impl core::ops::Deref for TlsOutput {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}
impl AsRef<[u8]> for TlsOutput {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl TlsOutput {
    pub(super) fn bounded(maximum: usize) -> Self {
        Self {
            maximum,
            ..Self::default()
        }
    }
    fn pool() -> Result<Option<Arc<AllocationPoolV1>>, &'static str> {
        #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
        {
            crate::local_allocation_pool()
                .map(Some)
                .ok_or("SDK heap unavailable")
        }
        #[cfg(not(any(target_env = "sgx", target_vendor = "teaclave")))]
        {
            Ok(None)
        }
    }
    pub(super) fn append(&mut self, input: &[u8]) -> Result<(), &'static str> {
        let pool = Self::pool()?;
        self.append_admitted(input, pool.as_ref())
    }
    pub(super) fn append_admitted(
        &mut self,
        input: &[u8],
        pool: Option<&Arc<AllocationPoolV1>>,
    ) -> Result<(), &'static str> {
        let required = self
            .bytes
            .len()
            .checked_add(input.len())
            .ok_or("TLS output length overflow")?;
        if required > self.maximum {
            return Err("TLS output exceeds credit");
        }
        if required > self.bytes.capacity() {
            let capacity =
                enclave_os_common::allocation::bounded_vec_capacity(required, self.maximum)
                    .ok_or("TLS output capacity overflow")?;
            let allocation = match pool {
                Some(pool) => Some(
                    pool.reserve_unpublished(capacity)
                        .ok_or("TLS output admission exhausted")?,
                ),
                None => None,
            };
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(|_| "TLS output allocation failed")?;
            if self.bytes.capacity() != capacity {
                drop(core::mem::take(&mut self.bytes));
                drop(self.allocation.take());
                return Err("TLS output capacity exceeds admission");
            }
            drop(core::mem::replace(&mut self.allocation, allocation));
            if let Some(credit) = &self.allocation {
                credit.activate_release_notification();
            }
        }
        self.bytes.extend_from_slice(input);
        Ok(())
    }
    /// Reserve the exact original encoder output before its closure allocates.
    pub(super) fn encoded(
        length: usize,
        encode: impl FnOnce() -> Result<Vec<u8>, &'static str>,
    ) -> Result<Self, &'static str> {
        let pool = Self::pool()?;
        let allocation = match pool {
            Some(pool) => Some(
                pool.reserve_unpublished(length)
                    .ok_or("TLS header admission exhausted")?,
            ),
            None => None,
        };
        let bytes = encode()?;
        if bytes.len() != length || bytes.capacity() != length {
            return Err("TLS header changed geometry");
        }
        if let Some(credit) = &allocation {
            credit.activate_release_notification();
        }
        Ok(Self {
            bytes,
            allocation,
            maximum: length,
        })
    }
}
