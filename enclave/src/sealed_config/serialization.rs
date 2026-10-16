//! Current sealed-config encoding with an admitted, move-only output buffer.
use enclave_os_common::allocation::{AllocationLeaseV1, AllocationPoolV1};
use enclave_os_common::types::AEAD_KEY_SIZE;
use std::collections::BTreeMap;
use std::sync::Arc;

#[cfg(feature = "fallible-allocation-v1")]
use enclave_os_common::allocation::PoolMapAllocator;

pub(super) const FORMAT_VERSION: u32 = 3;
const LENGTH_BYTES: usize = core::mem::size_of::<u32>();

#[cfg(feature = "fallible-allocation-v1")]
type Buffer = Vec<u8, PoolMapAllocator>;
#[cfg(not(feature = "fallible-allocation-v1"))]
type Buffer = Vec<u8>;

/// The backing is freed before its separate default-backend credit.
/// The selected allocator retains its original pool through the buffer itself.
pub struct SerializedConfig {
    bytes: Buffer,
    credit: Option<AllocationLeaseV1>,
}

/// Failure at an existing sealed-config persistence boundary.
#[derive(Debug)]
pub enum SealConfigError {
    /// Output admission or encoding refused before sealing.
    Serialization(&'static str),
    /// The existing SGX sealing operation refused.
    Seal(&'static str),
    /// The existing host KV operation refused.
    Host(i32),
}

impl core::fmt::Display for SealConfigError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Serialization(message) => formatter.write_str(message),
            Self::Seal(message) => write!(formatter, "SealedConfig seal failed: {message}"),
            Self::Host(code) => write!(formatter, "Host KV put (config) failed: {code}"),
        }
    }
}

impl SerializedConfig {
    /// Borrow the admitted bytes without transferring their backing or payer.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

fn length_header(length: usize) -> Result<u32, &'static str> {
    u32::try_from(length).map_err(|_| "SealedConfig length exceeds its current header")
}

fn add_field(total: usize, length: usize) -> Result<usize, &'static str> {
    length_header(length)?;
    total
        .checked_add(LENGTH_BYTES)
        .and_then(|total| total.checked_add(length))
        .ok_or("SealedConfig encoded length overflow")
}

fn encoded_length(
    certificate: &[u8],
    key: &[u8],
    entries: &BTreeMap<String, Vec<u8>>,
) -> Result<usize, &'static str> {
    length_header(entries.len())?;
    let mut total = LENGTH_BYTES
        .checked_add(AEAD_KEY_SIZE)
        .ok_or("SealedConfig fixed length overflow")?;
    total = add_field(total, certificate.len())?;
    total = add_field(total, key.len())?;
    total = total
        .checked_add(LENGTH_BYTES)
        .ok_or("SealedConfig entry count overflow")?;
    for (name, value) in entries {
        total = add_field(total, name.len())?;
        total = add_field(total, value.len())?;
    }
    core::alloc::Layout::array::<u8>(total).map_err(|_| "SealedConfig buffer layout overflow")?;
    Ok(total)
}

fn required_bytes(length: usize) -> Result<usize, &'static str> {
    #[cfg(feature = "fallible-allocation-v1")]
    {
        let layout = core::alloc::Layout::array::<u8>(length)
            .map_err(|_| "SealedConfig buffer layout overflow")?;
        PoolMapAllocator::required_metadata_bytes()
            .and_then(|metadata| {
                let backing = PoolMapAllocator::backend_layout(layout)?;
                metadata
                    .checked_add(backing.size())
                    .ok_or(core::alloc::AllocError)
            })
            .map_err(|_| "SealedConfig allocator geometry overflow")
    }
    #[cfg(not(feature = "fallible-allocation-v1"))]
    {
        Ok(length)
    }
}

#[cfg(feature = "fallible-allocation-v1")]
fn allocate_buffer<A: core::alloc::Allocator>(
    allocator: A,
    length: usize,
) -> Result<Vec<u8, A>, &'static str> {
    let mut bytes = Vec::new_in(allocator);
    bytes
        .try_reserve_exact(length)
        .map_err(|_| "SealedConfig output backing refused")?;
    Ok(bytes)
}

/// Admit the complete current encoding before creating its output backing.
pub(crate) fn serialize(
    pool: &Arc<AllocationPoolV1>,
    master_key: &[u8; AEAD_KEY_SIZE],
    certificate: &[u8],
    key: &[u8],
    entries: &BTreeMap<String, Vec<u8>>,
) -> Result<SerializedConfig, &'static str> {
    let length = encoded_length(certificate, key, entries)?;
    // Resolve the complete actual allocator geometry before its first request.
    let demand = required_bytes(length)?;
    #[cfg(not(feature = "fallible-allocation-v1"))]
    let credit = Some(
        pool.reserve_unpublished(demand)
            .ok_or("SealedConfig output admission refused")?,
    );
    #[cfg(feature = "fallible-allocation-v1")]
    let credit = None;
    #[cfg(not(feature = "fallible-allocation-v1"))]
    let mut bytes = Vec::new();
    #[cfg(feature = "fallible-allocation-v1")]
    let mut bytes = {
        if pool.capacity().saturating_sub(pool.used()) < demand {
            return Err("SealedConfig output admission refused");
        }
        allocate_buffer(
            PoolMapAllocator::try_new(pool).map_err(|_| "SealedConfig allocator origin refused")?,
            length,
        )?
    };
    #[cfg(not(feature = "fallible-allocation-v1"))]
    bytes
        .try_reserve_exact(length)
        .map_err(|_| "SealedConfig output backing refused")?;
    if bytes.capacity() != length {
        return Err("SealedConfig output backing geometry changed");
    }
    bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(master_key);
    bytes.extend_from_slice(&length_header(certificate.len())?.to_le_bytes());
    bytes.extend_from_slice(certificate);
    bytes.extend_from_slice(&length_header(key.len())?.to_le_bytes());
    bytes.extend_from_slice(key);
    bytes.extend_from_slice(&length_header(entries.len())?.to_le_bytes());
    for (name, value) in entries {
        bytes.extend_from_slice(&length_header(name.len())?.to_le_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&length_header(value.len())?.to_le_bytes());
        bytes.extend_from_slice(value);
    }
    if bytes.len() != length {
        return Err("SealedConfig output length changed");
    }
    let output = SerializedConfig { bytes, credit };
    if let Some(credit) = &output.credit {
        credit.activate_release_notification();
    }
    #[cfg(feature = "fallible-allocation-v1")]
    output.bytes.allocator().activate_release_notification();
    Ok(output)
}

#[cfg(any(
    test,
    all(
        feature = "sgx-sim-attestation",
        feature = "fallible-allocation-v1",
        target_vendor = "teaclave"
    )
))]
#[path = "serialization_checks.rs"]
mod checks;
#[cfg(any(
    test,
    all(
        feature = "sgx-sim-attestation",
        feature = "fallible-allocation-v1",
        target_vendor = "teaclave"
    )
))]
pub(crate) use checks::check_in;

#[cfg(test)]
pub(crate) fn check() {
    let demand = required_bytes(checks::WIRE.len()).unwrap();
    let pool = AllocationPoolV1::new(demand.checked_mul(4).unwrap()).unwrap();
    check_in(&pool).unwrap();
}
