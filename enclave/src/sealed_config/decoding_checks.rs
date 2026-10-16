//! Existing Session/SIM owner: current raw v3 and exact decoded backing.
use super::super::backing::ConfigAllocator;
#[cfg(feature = "fallible-allocation-v1")]
use super::ModuleKey;
use super::SealedConfig;
use core::sync::atomic::{AtomicUsize, Ordering};
use enclave_os_common::allocation::AllocationPoolV1;
use std::sync::Arc;
static RELEASES: AtomicUsize = AtomicUsize::new(0);
fn released() {
    RELEASES.fetch_add(1, Ordering::Relaxed);
}

// Independent Python struct.pack('<I', ...) current v3 fixture. Last module has
// an empty value; ordering remains the original BTreeMap a/z ordering.
const WIRE: &[u8] = &[
    3, 0, 0, 0, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 3, 0, 0, 0, 10, 20, 30, 2, 0, 0, 0, 40, 50, 2, 0, 0, 0, 1, 0, 0, 0, 97, 1, 0, 0, 0,
    60, 1, 0, 0, 0, 122, 0, 0, 0, 0,
];

pub(super) fn demand() -> Result<usize, &'static str> {
    let mut bytes = ConfigAllocator::metadata_bytes()?;
    for length in [3, 2, 1, 0] {
        bytes = bytes
            .checked_add(ConfigAllocator::backing_bytes(length)?)
            .ok_or("decoded quote overflow")?;
    }
    for length in [1, 1] {
        bytes = bytes
            .checked_add(ConfigAllocator::key_backing_bytes(length)?)
            .ok_or("decoded key quote overflow")?;
    }
    #[cfg(feature = "fallible-allocation-v1")]
    {
        use enclave_os_common::allocation::PoolMapAllocator;
        std::collections::BTreeMap::<ModuleKey, super::ModuleEntry, PoolMapAllocator>
            ::try_visit_sorted_build_layouts(2, |layout, count| {
                let backend = PoolMapAllocator::backend_layout(layout)?;
                bytes = bytes.checked_add(backend.size().checked_mul(count)
                    .ok_or(core::alloc::AllocError)?).ok_or(core::alloc::AllocError)?;
                Ok(())
            }).map_err(|_| "decoded actual node geometry")?;
    }
    Ok(bytes)
}

fn valid(config: &SealedConfig) -> bool {
    config.master_key() == [5; enclave_os_common::types::AEAD_KEY_SIZE]
        && config.ca_cert_der.len() == 3
        && !config.ca_cert_der.is_empty()
        && config.ca_cert_der.as_slice() == [10, 20, 30]
        && config.ca_key_pkcs8.as_slice() == [40, 50]
        && config.module_data.len() == 2
        && config.get_module_data("a") == Some([60].as_slice())
        && config.get_module_data("z") == Some([].as_slice())
}

pub(crate) fn check_in(pool: &Arc<AllocationPoolV1>) -> Result<(), &'static str> {
    let quote = demand()?;
    let before = pool.used();
    let fresh = SealedConfig::from_parts(
        pool,
        [5; enclave_os_common::types::AEAD_KEY_SIZE],
        &[10, 20, 30],
        &[40, 50],
    )?;
    if !fresh.module_data.is_empty() || fresh.get_module_data("absent").is_some() {
        return Err("fresh current module capability changed");
    }
    drop(fresh);
    let config = SealedConfig::deserialize(pool, WIRE)?;
    if !valid(&config) || pool.used() != before.checked_add(quote).ok_or("decoded quote sum")? {
        return Err("decoded bytes/original backing changed");
    }
    let serialized = config.serialize(pool)?;
    if serialized.as_slice() != WIRE {
        return Err("decoded current wire changed");
    }
    drop(serialized);
    drop(config);
    if pool.used() != before {
        return Err("decoded backing did not refund");
    }
    for delta in [-1_isize, 0, 1] {
        let capacity = quote
            .checked_add_signed(delta)
            .ok_or("decoded exact boundary")?;
        let release_before = RELEASES.load(Ordering::Relaxed);
        let isolated = AllocationPoolV1::new_with_release(capacity, Some(released))
            .ok_or("decoded test pool")?;
        let result = SealedConfig::deserialize(&isolated, WIRE);
        if delta < 0 {
            if result.is_ok() {
                return Err("decoded one-byte-short published");
            }
            if RELEASES.load(Ordering::Relaxed) != release_before {
                return Err("partial decode published a release notification");
            }
        } else {
            let config = result?;
            if !valid(&config) || isolated.used() != quote {
                return Err("decoded exact backing does not equal real quote");
            }
            drop(config);
        }
        if isolated.used() != 0 {
            return Err("decoded refusal/final refund leaked");
        }
    }
    // Malformed errors precede the newly introduced allocation refusal. This
    // one-byte pool cannot fund selected metadata or any full decoded result.
    let refused = AllocationPoolV1::new(1).ok_or("decoded refusal pool")?;
    for cut in 0..WIRE.len() {
        if SealedConfig::deserialize(&refused, &WIRE[..cut]).is_ok() || refused.used() != 0 {
            return Err("truncated raw config accepted or admitted backing");
        }
    }
    let mut version = WIRE.to_vec();
    version[..core::mem::size_of::<u32>()].copy_from_slice(
        &super::super::serialization::FORMAT_VERSION
            .checked_add(1)
            .ok_or("version overflow")?
            .to_le_bytes(),
    );
    if !matches!(
        SealedConfig::deserialize(&refused, &version),
        Err("Unknown SealedConfig version")
    ) {
        return Err("raw current version refusal changed");
    }
    let first_key = core::mem::size_of::<u32>()
        + enclave_os_common::types::AEAD_KEY_SIZE
        + core::mem::size_of::<u32>()
        + 3
        + core::mem::size_of::<u32>()
        + 2
        + core::mem::size_of::<u32>()
        + core::mem::size_of::<u32>();
    let mut utf8 = WIRE.to_vec();
    utf8[first_key] = u8::MAX;
    if !matches!(
        SealedConfig::deserialize(&refused, &utf8),
        Err("Invalid UTF-8 in module key")
    ) {
        return Err("raw UTF8 error precedence changed");
    }
    if refused.used() != 0 {
        return Err("malformed config allocated before validation");
    }
    let roomy = AllocationPoolV1::new(quote.checked_mul(4).ok_or("decoded room overflow")?)
        .ok_or("decoded room pool")?;
    let mut trailing = WIRE.to_vec();
    trailing.extend_from_slice(&[0xff, 0x7f]);
    let config = SealedConfig::deserialize(&roomy, &trailing)?;
    if !valid(&config) {
        return Err("current trailing input behavior changed");
    }
    drop(config);
    let mut duplicate = WIRE.to_vec();
    let last_key = WIRE.len() - core::mem::size_of::<u32>() - 1;
    duplicate[last_key] = b'a';
    let mut config = SealedConfig::deserialize(&roomy, &duplicate)?;
    if config.module_data.len() != 1
        || config.get_module_data("a") != Some([].as_slice())
        || config.get_module_data("z").is_some()
    {
        return Err("duplicate key last-value-wins changed");
    }
    config.set_module_data("new", &[1, 2])?;
    if config.get_module_data("new") != Some([1, 2].as_slice()) {
        return Err("current module-data write capability changed");
    }
    config.set_module_data("", &[])?;
    if config.get_module_data("") != Some([].as_slice()) {
        return Err("empty current module key/value changed");
    }
    drop(config);
    if roomy.used() != 0 {
        return Err("duplicate/trailing/module owner leaked");
    }
    // A fresh map can fund the actual immutable key but not its first node.
    // The consuming insertion refusal must leave no key, credit or wake.
    #[cfg(feature = "fallible-allocation-v1")]
    {
        let metadata = ConfigAllocator::metadata_bytes()?;
        let capacity = metadata
            .checked_add(ConfigAllocator::key_backing_bytes(1)?)
            .ok_or("key rollback quote overflow")?;
        let rollback = AllocationPoolV1::new_with_release(capacity, Some(released))
            .ok_or("key rollback pool")?;
        let release_before = RELEASES.load(Ordering::Relaxed);
        let origin = ConfigAllocator::try_new(&rollback)?;
        let mut entries = super::ModuleData::new(origin);
        if entries.try_set("a", &[]).is_ok() || !entries.is_empty() || rollback.used() != metadata {
            return Err("consuming key/node refusal published or leaked backing");
        }
        drop(entries);
        if rollback.used() != 0 || RELEASES.load(Ordering::Relaxed) != release_before {
            return Err("unpublished key/node rollback refunded late or notified");
        }
    }
    let isolated = AllocationPoolV1::new(quote).ok_or("decoded lifetime pool")?;
    let weak = Arc::downgrade(&isolated);
    let config = SealedConfig::deserialize(&isolated, WIRE)?;
    drop(isolated);
    if weak
        .upgrade()
        .ok_or("decoded payer lost before children")?
        .used()
        != quote
    {
        return Err("decoded original payer detached");
    }
    drop(config);
    if weak.upgrade().is_some() {
        return Err("decoded original payer retained after children");
    }
    Ok(())
}
