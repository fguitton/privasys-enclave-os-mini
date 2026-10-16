//! Existing Session/SIM owner's current encoding and original-payer controls.
use super::{encoded_length, required_bytes, serialize, AllocationPoolV1, Arc, BTreeMap};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

// Independently encoded with Python struct.pack('<I', ...), preserving sorted
// a/z entries, an empty value, and the current version3 field order.
pub(super) const WIRE: &[u8] = &[
    3, 0, 0, 0, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 3, 0, 0, 0, 10, 20, 30, 2, 0, 0, 0, 40, 50, 2, 0, 0, 0, 1, 0, 0, 0, 97, 1, 0, 0, 0,
    60, 1, 0, 0, 0, 122, 0, 0, 0, 0,
];
static SERIAL: Mutex<()> = Mutex::new(());
static RELEASED: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "fallible-allocation-v1")]
static REFUSED_REQUESTS: AtomicUsize = AtomicUsize::new(0);

fn released() {
    RELEASED.fetch_add(1, Ordering::AcqRel);
}

fn isolated(capacity: usize) -> Result<Arc<AllocationPoolV1>, &'static str> {
    #[cfg(feature = "fallible-allocation-v1")]
    {
        let root = enclave_os_common::allocation::shared_allocation_bytes::<AllocationPoolV1>()
            .ok_or("sealed output root geometry")?;
        AllocationPoolV1::try_new_with_release(
            capacity
                .checked_add(root)
                .ok_or("sealed output root overflow")?,
            Some(released),
        )
        .ok_or("sealed output root refused")
    }
    #[cfg(not(feature = "fallible-allocation-v1"))]
    {
        AllocationPoolV1::new_with_release(capacity, Some(released))
            .ok_or("sealed output root refused")
    }
}

#[cfg(feature = "fallible-allocation-v1")]
struct RefusingBacking {
    // Retain the actual admitted original allocator origin until refusal unwinds.
    _origin: super::PoolMapAllocator,
}

// SAFETY: this test backend never issues a pointer. Allocator::deallocate cannot
// be called under its contract because every actual request returns AllocError.
#[cfg(feature = "fallible-allocation-v1")]
unsafe impl core::alloc::Allocator for RefusingBacking {
    fn allocate(
        &self,
        _layout: core::alloc::Layout,
    ) -> Result<core::ptr::NonNull<[u8]>, core::alloc::AllocError> {
        REFUSED_REQUESTS.fetch_add(1, Ordering::AcqRel);
        Err(core::alloc::AllocError)
    }

    unsafe fn deallocate(&self, _pointer: core::ptr::NonNull<u8>, _layout: core::alloc::Layout) {
        unreachable!("refusing allocator never issued a pointer");
    }
}

pub(crate) fn check_in(pool: &Arc<AllocationPoolV1>) -> Result<(), &'static str> {
    let _serial = SERIAL.lock().map_err(|_| "sealed output check lock")?;
    for (error, expected) in [
        (super::SealConfigError::Serialization("refused"), "refused"),
        (
            super::SealConfigError::Seal("refused"),
            "SealedConfig seal failed: refused",
        ),
        (
            super::SealConfigError::Host(-7),
            "Host KV put (config) failed: -7",
        ),
    ] {
        if error.to_string() != expected {
            return Err("sealed output persistence error bytes changed");
        }
    }
    let master = [5; enclave_os_common::types::AEAD_KEY_SIZE];
    let certificate = [10, 20, 30];
    let key = [40, 50];
    let entries = BTreeMap::from([(String::from("z"), vec![]), (String::from("a"), vec![60])]);
    let length = encoded_length(&certificate, &key, &entries)?;
    if length != WIRE.len()
        || super::length_header(usize::MAX).is_ok()
        || super::add_field(usize::MAX, 1).is_ok()
    {
        return Err("sealed output wire/overflow geometry");
    }
    let demand = required_bytes(length)?;
    let before = pool.used();
    let output = serialize(pool, &master, &certificate, &key, &entries)?;
    if output.as_slice() != WIRE
        || pool.used()
            != before
                .checked_add(demand)
                .ok_or("sealed output observed quote overflow")?
    {
        return Err("sealed output current wire/original origin");
    }
    let alias = pool.clone();
    drop(output);
    if alias.used() != before {
        return Err("sealed output final backing/origin refund");
    }
    drop(alias);
    for extra in [-1_isize, 0, 1] {
        RELEASED.store(0, Ordering::Release);
        let limit = demand
            .checked_add_signed(extra)
            .ok_or("sealed output exact bound")?;
        let isolated = isolated(limit)?;
        let result = serialize(&isolated, &master, &certificate, &key, &entries);
        if extra < 0 {
            if result.is_ok() || RELEASED.load(Ordering::Acquire) != 0 {
                return Err("sealed output one-byte-short published or notified");
            }
        } else {
            let output = result?;
            if output.as_slice() != WIRE
                || isolated.used() != demand
                || RELEASED.load(Ordering::Acquire) != 0
            {
                return Err("sealed output exact/plus-one backing");
            }
            drop(output);
            if RELEASED.load(Ordering::Acquire) == 0 {
                return Err("sealed output published release missing");
            }
        }
        if isolated.used() != 0 {
            return Err("sealed output operation leaked original credit");
        }
    }
    let retained = isolated(demand)?;
    let weak = Arc::downgrade(&retained);
    let output = serialize(&retained, &master, &certificate, &key, &entries)?;
    drop(retained);
    if weak
        .upgrade()
        .ok_or("sealed output lost its original payer")?
        .used()
        != demand
    {
        return Err("sealed output detached from its original payer");
    }
    drop(output);
    if weak.upgrade().is_some() {
        return Err("sealed output retained its payer after final backing free");
    }
    #[cfg(feature = "fallible-allocation-v1")]
    {
        RELEASED.store(0, Ordering::Release);
        REFUSED_REQUESTS.store(0, Ordering::Release);
        let isolated = isolated(demand)?;
        let origin = super::PoolMapAllocator::try_new(&isolated)
            .map_err(|_| "sealed output refusal origin")?;
        if super::allocate_buffer(RefusingBacking { _origin: origin }, length).is_ok()
            || REFUSED_REQUESTS.load(Ordering::Acquire) != 1
            || isolated.used() != 0
            || RELEASED.load(Ordering::Acquire) != 0
        {
            return Err("sealed output actual allocation refusal published or leaked");
        }
    }
    Ok(())
}
