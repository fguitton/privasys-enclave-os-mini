//! One current v3 decoded configuration, retaining each backing's original pool.
use super::backing::{ConfigAllocator, ConfigBytes};
use super::serialization::{self, SerializedConfig, FORMAT_VERSION};
use enclave_os_common::allocation::{AllocationLeaseV1, AllocationPoolV1};
use enclave_os_common::types::AEAD_KEY_SIZE;
use std::alloc::System;
use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::sync::Arc;

// No credit, original pool, mutable alias or allocator state is stored in an
// ordering key. Its only backing is a physically fallible System allocation.
struct ModuleKey(Vec<u8, System>);
struct ModuleEntry {
    value: ConfigBytes,
    key_credit: Option<AllocationLeaseV1>,
}
impl ModuleEntry {
    fn activate(&self) {
        self.value.activate_release_notification();
        if let Some(credit) = &self.key_credit {
            credit.activate_release_notification();
        }
    }
}
impl ModuleKey {
    fn as_str(&self) -> &str {
        // Only validated UTF-8 creates a key, and no mutable backing escapes it.
        std::str::from_utf8(&self.0).expect("validated immutable module key")
    }
}
impl Borrow<str> for ModuleKey {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}
impl PartialEq for ModuleKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}
impl Eq for ModuleKey {}
impl PartialOrd for ModuleKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ModuleKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

#[cfg(feature = "fallible-allocation-v1")]
type Entries = BTreeMap<ModuleKey, ModuleEntry, enclave_os_common::allocation::PoolMapAllocator>;
#[cfg(not(feature = "fallible-allocation-v1"))]
type Entries = BTreeMap<ModuleKey, ModuleEntry>;

/// Ordered module storage. Neither its allocator nor an owned child can escape.
pub struct ModuleData {
    entries: Entries,
    origin: ConfigAllocator,
    published: bool,
}
impl ModuleData {
    fn new(origin: ConfigAllocator) -> Self {
        #[cfg(feature = "fallible-allocation-v1")]
        let entries = BTreeMap::new_in(origin.map_allocator());
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let entries = BTreeMap::new();
        Self {
            entries,
            origin,
            published: false,
        }
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.entries.get(key).map(|entry| entry.value.as_slice())
    }
    pub fn iter(&self) -> impl Clone + ExactSizeIterator<Item = (&str, &[u8])> {
        self.entries
            .iter()
            .map(|(key, entry)| (key.as_str(), entry.value.as_slice()))
    }
    fn try_set(&mut self, key: &str, data: &[u8]) -> Result<(), &'static str> {
        // Preserve BTreeMap's existing duplicate-key semantics: replace the
        // value and retain the first equal key, without admitting another node.
        if let Some(entry) = self.entries.get_mut(key) {
            let replacement = self.origin.try_copy(data)?;
            if self.published {
                replacement.activate_release_notification();
            }
            entry.value = replacement;
            return Ok(());
        }
        // The caller keeps unpublished credit across every consuming insert
        // refusal. No allocation or publication occurs before admission.
        let key_credit = self.origin.reserve_key(key.len())?;
        let mut bytes = Vec::new_in(System);
        bytes
            .try_reserve_exact(key.len())
            .map_err(|_| "SealedConfig key backing refused")?;
        if bytes.capacity() != key.len() {
            return Err("SealedConfig key backing geometry changed");
        }
        bytes.extend_from_slice(key.as_bytes());
        let owned_key = ModuleKey(bytes);
        let value = self.origin.try_copy(data)?;
        let entry = ModuleEntry {
            value,
            key_credit: None,
        };
        #[cfg(feature = "fallible-allocation-v1")]
        self.entries
            .try_insert_alloc(owned_key, entry)
            .map_err(|_| "SealedConfig module node admission refused")?;
        #[cfg(not(feature = "fallible-allocation-v1"))]
        self.entries.insert(owned_key, entry);
        // Exclusive access and the exact immutable key guarantee this lookup.
        // It cannot allocate or fail after the successful insertion above.
        let inserted = self
            .entries
            .get_mut(key)
            .expect("inserted immutable module key");
        inserted.key_credit = key_credit;
        if self.published {
            inserted.activate();
        }
        Ok(())
    }
}

impl ModuleData {
    fn activate(&mut self) {
        self.published = true;
        #[cfg(feature = "fallible-allocation-v1")]
        self.origin.activate_release_notification();
        for entry in self.entries.values() {
            entry.activate();
        }
    }
}
impl Drop for ModuleData {
    fn drop(&mut self) {
        // No key/entry can escape this private map. Even partial decoding and
        // a consuming insertion refusal keep the paired credit until after
        // the actual key backing has been freed. Explicit draining avoids
        // depending on a supplier's key/value destructor ordering.
        while let Some((key, entry)) = self.entries.pop_first() {
            drop(key);
            drop(entry);
        }
    }
}

/// The current configuration's decoded bytes and ordered module backing.
pub struct SealedConfig {
    pub master_key: [u8; AEAD_KEY_SIZE],
    pub ca_cert_der: ConfigBytes,
    pub ca_key_pkcs8: ConfigBytes,
    pub module_data: ModuleData,
}
impl SealedConfig {
    pub fn master_key(&self) -> [u8; AEAD_KEY_SIZE] {
        self.master_key
    }
    pub fn get_module_data(&self, key: &str) -> Option<&[u8]> {
        self.module_data.get(key)
    }
    pub fn set_module_data(&mut self, key: &str, data: &[u8]) -> Result<(), &'static str> {
        self.module_data.try_set(key, data)
    }
    /// Admit copied fresh-builder output. This closes only retained backing;
    /// allocations internal to the supplied CA generator are a separate owner.
    pub(crate) fn from_parts(
        pool: &Arc<AllocationPoolV1>,
        master_key: [u8; AEAD_KEY_SIZE],
        certificate: &[u8],
        key: &[u8],
    ) -> Result<Self, &'static str> {
        let origin = ConfigAllocator::try_new(pool)?;
        let ca_cert_der = origin.try_copy(certificate)?;
        let ca_key_pkcs8 = origin.try_copy(key)?;
        let mut output = Self {
            master_key,
            ca_cert_der,
            ca_key_pkcs8,
            module_data: ModuleData::new(origin),
        };
        output.activate();
        Ok(output)
    }
    pub fn serialize(
        &self,
        pool: &Arc<AllocationPoolV1>,
    ) -> Result<SerializedConfig, &'static str> {
        serialization::serialize(
            pool,
            &self.master_key,
            &self.ca_cert_der,
            &self.ca_key_pkcs8,
            self.module_data.iter(),
        )
    }
    pub fn deserialize(pool: &Arc<AllocationPoolV1>, data: &[u8]) -> Result<Self, &'static str> {
        let mut reader = Reader { data, position: 0 };
        let version = reader.number("Too short for version")?;
        if version != FORMAT_VERSION {
            return Err("Unknown SealedConfig version");
        }
        let master = reader.take(AEAD_KEY_SIZE, "Too short for master_key")?;
        let certificate = reader.field("Too short for ca_cert_len", "Truncated ca_cert")?;
        let key = reader.field("Too short for ca_key_len", "Truncated ca_key")?;
        let count = reader.number("Too short for num_entries")?;
        // Validate the same current codec before any backing request, so an
        // introduced allocation refusal cannot mask malformed input precedence.
        reader.clone().entries(count, |_, _| Ok(()))?;
        let origin = ConfigAllocator::try_new(pool)?;
        let ca_cert_der = origin.try_copy(certificate)?;
        let ca_key_pkcs8 = origin.try_copy(key)?;
        let mut module_data = ModuleData::new(origin);
        reader.entries(count, |key, value| module_data.try_set(key, value))?;
        let mut master_key = [0; AEAD_KEY_SIZE];
        master_key.copy_from_slice(master);
        let mut output = Self {
            master_key,
            ca_cert_der,
            ca_key_pkcs8,
            module_data,
        };
        output.activate();
        Ok(output)
    }
    fn activate(&mut self) {
        self.module_data.activate();
        self.ca_cert_der.activate_release_notification();
        self.ca_key_pkcs8.activate_release_notification();
    }
}

#[derive(Clone)]
struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize, error: &'static str) -> Result<&'a [u8], &'static str> {
        let end = self.position.checked_add(length).ok_or(error)?;
        let bytes = self.data.get(self.position..end).ok_or(error)?;
        self.position = end;
        Ok(bytes)
    }
    fn number(&mut self, error: &'static str) -> Result<u32, &'static str> {
        let bytes = self.take(core::mem::size_of::<u32>(), error)?;
        Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| error)?))
    }
    fn field(
        &mut self,
        header: &'static str,
        truncated: &'static str,
    ) -> Result<&'a [u8], &'static str> {
        let length = usize::try_from(self.number(header)?).map_err(|_| truncated)?;
        self.take(length, truncated)
    }
    fn entries(
        mut self,
        count: u32,
        mut consume: impl FnMut(&'a str, &'a [u8]) -> Result<(), &'static str>,
    ) -> Result<(), &'static str> {
        for _ in 0..count {
            let key = self.field("Too short for module key_len", "Truncated module key")?;
            let key = std::str::from_utf8(key).map_err(|_| "Invalid UTF-8 in module key")?;
            let value = self.field("Too short for module val_len", "Truncated module value")?;
            consume(key, value)?;
        }
        // The current codec ignores trailing bytes; this ownership change
        // preserves that input behavior and the ordered last-value-wins map.
        Ok(())
    }
}

#[cfg(any(
    test,
    all(
        feature = "sgx-sim-attestation",
        feature = "fallible-allocation-v1",
        target_vendor = "teaclave"
    )
))]
#[path = "decoding_checks.rs"]
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
pub(crate) fn test_demand() -> Result<usize, &'static str> {
    checks::demand()
}
