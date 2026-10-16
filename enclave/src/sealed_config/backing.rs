//! One original-payer backing for current sealed-configuration bytes.
use enclave_os_common::allocation::{AllocationLeaseV1, AllocationPoolV1};
use std::sync::Arc;

#[cfg(feature = "fallible-allocation-v1")]
use enclave_os_common::allocation::PoolMapAllocator;

#[cfg(feature = "fallible-allocation-v1")]
type Bytes = Vec<u8, PoolMapAllocator>;
#[cfg(not(feature = "fallible-allocation-v1"))]
type Bytes = Vec<u8>;

/// Shared origin metadata. Cloning retains the same original payer and
/// allocates no new origin or byte backing.
#[derive(Clone)]
pub(crate) struct ConfigAllocator {
    #[cfg(feature = "fallible-allocation-v1")]
    allocator: PoolMapAllocator,
    pool: Arc<AllocationPoolV1>,
}

impl ConfigAllocator {
    pub(crate) fn try_new(pool: &Arc<AllocationPoolV1>) -> Result<Self, &'static str> {
        #[cfg(feature = "fallible-allocation-v1")]
        {
            Ok(Self {
                allocator: PoolMapAllocator::try_new(pool)
                    .map_err(|_| "SealedConfig allocator origin refused")?,
                pool: pool.clone(),
            })
        }
        #[cfg(not(feature = "fallible-allocation-v1"))]
        {
            Ok(Self { pool: pool.clone() })
        }
    }

    #[cfg(feature = "fallible-allocation-v1")]
    pub(crate) fn map_allocator(&self) -> PoolMapAllocator {
        self.allocator.clone()
    }

    #[cfg(feature = "fallible-allocation-v1")]
    pub(crate) fn activate_release_notification(&self) {
        self.allocator.activate_release_notification();
    }

    #[cfg(any(
        test,
        all(
            feature = "sgx-sim-attestation",
            feature = "fallible-allocation-v1",
            target_vendor = "teaclave"
        )
    ))]
    /// Complete fixed metadata demand for the existing owning checks.
    pub(crate) fn metadata_bytes() -> Result<usize, &'static str> {
        #[cfg(feature = "fallible-allocation-v1")]
        {
            PoolMapAllocator::required_metadata_bytes()
                .map_err(|_| "SealedConfig origin layout overflow")
        }
        #[cfg(not(feature = "fallible-allocation-v1"))]
        {
            Ok(0)
        }
    }

    /// Keys use the same fallible System backend as PoolMapAllocator, with
    /// their original-pool credit retained by the opaque paired map entry.
    pub(crate) fn key_backing_bytes(length: usize) -> Result<usize, &'static str> {
        core::alloc::Layout::array::<u8>(length)
            .map(|layout| layout.size())
            .map_err(|_| "SealedConfig key layout overflow")
    }

    pub(crate) fn reserve_key(
        &self,
        length: usize,
    ) -> Result<Option<AllocationLeaseV1>, &'static str> {
        let bytes = Self::key_backing_bytes(length)?;
        if bytes == 0 {
            return Ok(None);
        }
        self.pool
            .reserve_unpublished(bytes)
            .map(Some)
            .ok_or("SealedConfig key admission refused")
    }

    /// Exact byte-allocation layout, including the selected allocator header.
    pub(crate) fn backing_bytes(length: usize) -> Result<usize, &'static str> {
        let layout = core::alloc::Layout::array::<u8>(length)
            .map_err(|_| "SealedConfig buffer layout overflow")?;
        if length == 0 {
            return Ok(0);
        }
        #[cfg(feature = "fallible-allocation-v1")]
        {
            PoolMapAllocator::backend_layout(layout)
                .map(|backend| backend.size())
                .map_err(|_| "SealedConfig backing layout overflow")
        }
        #[cfg(not(feature = "fallible-allocation-v1"))]
        {
            Ok(layout.size())
        }
    }

    pub(crate) fn try_zeroed(&self, length: usize) -> Result<ConfigBytes, &'static str> {
        let demand = Self::backing_bytes(length)?;
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let default_credit = if demand == 0 {
            None
        } else {
            Some(
                self.pool
                    .reserve_unpublished(demand)
                    .ok_or("SealedConfig byte admission refused")?,
            )
        };
        #[cfg(feature = "fallible-allocation-v1")]
        let default_credit = {
            // The selected allocator checks its own original pool at allocation.
            // Computing demand first also refuses impossible layouts before it.
            let _ = demand;
            None
        };
        #[cfg(feature = "fallible-allocation-v1")]
        let mut bytes = allocate_buffer(self.allocator.clone(), length)?;
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let mut bytes = Vec::new();
        #[cfg(not(feature = "fallible-allocation-v1"))]
        bytes
            .try_reserve_exact(length)
            .map_err(|_| "SealedConfig byte backing refused")?;
        if bytes.capacity() != length {
            return Err("SealedConfig backing geometry changed");
        }
        bytes.resize(length, 0);
        Ok(ConfigBytes {
            bytes,
            default_credit,
        })
    }

    pub(crate) fn try_copy(&self, source: &[u8]) -> Result<ConfigBytes, &'static str> {
        let mut output = self.try_zeroed(source.len())?;
        output.as_mut_slice().copy_from_slice(source);
        Ok(output)
    }
}

/// Move-only configuration bytes. Mutable access is limited to the defining
/// crate's codecs and SGX supplied-buffer calls; the backing cannot be detached.
pub struct ConfigBytes {
    // Declaration order frees the actual backing before default-backend credit.
    bytes: Bytes,
    default_credit: Option<AllocationLeaseV1>,
}

impl ConfigBytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub(crate) fn activate_release_notification(&self) {
        if let Some(credit) = &self.default_credit {
            credit.activate_release_notification();
        }
        #[cfg(feature = "fallible-allocation-v1")]
        self.bytes.allocator().activate_release_notification();
    }
}

impl core::ops::Deref for ConfigBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

#[cfg(feature = "fallible-allocation-v1")]
pub(crate) fn allocate_buffer<A: core::alloc::Allocator>(
    allocator: A,
    length: usize,
) -> Result<Vec<u8, A>, &'static str> {
    let mut bytes = Vec::new_in(allocator);
    bytes
        .try_reserve_exact(length)
        .map_err(|_| "SealedConfig output backing refused")?;
    Ok(bytes)
}
