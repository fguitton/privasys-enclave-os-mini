//! Existing signed-SIM owner's actual selected server-cache allocation checks.
use enclave_os_common::allocation::{AllocationPoolV1, LoanAllocator};
use rustls::server::{ServerSessionMemoryCache, StoresServerSessions};
use std::sync::Arc;

fn successful(pool: &Arc<AllocationPoolV1>) -> Result<usize, &'static str> {
    let before = pool.used();
    // The production config carrier prepays this exact Arc payload layout.
    // This primitive owner does the same before the real fallible Arc request.
    let fixed_bytes =
        enclave_os_common::allocation::shared_allocation_bytes::<ServerSessionMemoryCache>()
            .ok_or("cache Arc geometry")?;
    let fixed = pool
        .reserve_unpublished(fixed_bytes)
        .ok_or("cache Arc metadata refused")?;
    let origin = LoanAllocator::from_pool_unpublished(pool).map_err(|_| "cache origin refused")?;
    let cache = ServerSessionMemoryCache::try_new_in(8, origin.owned_allocator())
        .map_err(|_| "cache backing refused")?;
    if !cache.put(vec![7], vec![8, 9]) {
        return Err("cache entry refused");
    }
    let returned = cache.get(&[7]).ok_or("cache copy refused")?;
    let peak = fixed_bytes
        .checked_add(origin.peak_used())
        .ok_or("cache peak overflow")?;
    let taken = cache.take(&[7]).ok_or("cache transfer refused")?;
    if cache.take(&[7]).is_some() {
        return Err("cache take retained an entry");
    }
    let alias = cache.clone();
    origin.activate_release_notification();
    drop(origin);
    drop(cache);
    drop(alias);
    // Free the actual Arc backing before returning its separate fixed credit.
    drop(fixed);
    if returned.as_slice() != [8, 9] || taken.as_slice() != [8, 9] || pool.used() <= before {
        return Err("cache return lost bytes or original origin");
    }
    drop(returned);
    drop(taken);
    if pool.used() != before {
        return Err("cache final backing/origin refund");
    }
    Ok(peak)
}

/// Called only by the original signed registry's selected thread owner.
pub fn check_paid_session_cache(pool: &Arc<AllocationPoolV1>) -> Result<(), &'static str> {
    let before = pool.used();
    let peak = successful(pool)?;
    let root = enclave_os_common::allocation::shared_allocation_bytes::<AllocationPoolV1>()
        .ok_or("cache pool geometry")?;
    let metadata = LoanAllocator::required_origin_bytes().ok_or("cache origin geometry")?;
    let required = root
        .checked_add(metadata)
        .and_then(|n| n.checked_add(peak))
        .ok_or("cache measured geometry overflow")?;
    for extra in [-1_isize, 0, 1] {
        let capacity = required
            .checked_add_signed(extra)
            .ok_or("cache exact bound")?;
        let isolated = AllocationPoolV1::try_new_with_release(capacity, None)
            .ok_or("cache exact pool root")?;
        let result = successful(&isolated);
        if extra < 0 {
            if result.is_ok() {
                return Err("one-byte-short cache operation succeeded");
            }
        } else if result? != peak {
            return Err("cache exact/plus-one geometry changed");
        }
        if isolated.used() != 0 {
            return Err("cache refused/successful operation leaked credit");
        }
    }
    if pool.used() != before {
        return Err("cache owning pool not refunded");
    }
    check_p256(pool)?;
    std::println!("TLS-SESSION-CACHE-SIM: actual-SDK backing entry get take exact-minus-one exact plus-one aliases returned-origin final-refund PASS");
    Ok(())
}

fn p256_successful(pool: &Arc<AllocationPoolV1>) -> Result<usize, &'static str> {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let before = pool.used();
    let mut fixed_bytes = 0_usize;
    for layout in rustls::server::server_config_certificate_payload_layouts()
        .into_iter()
        .skip(2)
    {
        fixed_bytes = fixed_bytes
            .checked_add(
                enclave_os_common::allocation::shared_allocation_bytes_for_layout(layout)
                    .ok_or("P256 Arc geometry")?,
            )
            .ok_or("P256 Arc sum")?;
    }
    let fixed = pool
        .reserve_unpublished(fixed_bytes)
        .ok_or("P256 fixed metadata refused")?;
    let origin = LoanAllocator::from_pool_unpublished(pool).map_err(|_| "P256 origin refused")?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        include_bytes!("fixtures/retained-p256-sim.pk8").as_slice(),
    ));
    let retained =
        rustls::crypto::ring::sign::try_p256_signing_key_in(&key, origin.owned_allocator())
            .map_err(|_| "P256 constructor refused")?;
    let expected = include_bytes!("fixtures/retained-p256-sim.spki").as_slice();
    if retained
        .public_key()
        .ok_or("P256 public key absent")?
        .as_ref()
        != expected
    {
        return Err("P256 independent SPKI bytes");
    }
    let peak = fixed_bytes
        .checked_add(origin.peak_used())
        .ok_or("P256 peak overflow")?;
    let alias = retained.clone();
    origin.activate_release_notification();
    drop(origin);
    drop(retained);
    if pool.used() <= before
        || alias.public_key().ok_or("P256 alias key absent")?.as_ref() != expected
    {
        return Err("P256 alias original origin");
    }
    drop(alias);
    // Last key Arc and its SPKI/backing die before the fixed metadata credit.
    drop(fixed);
    if pool.used() != before {
        return Err("P256 final backing/origin refund");
    }
    Ok(peak)
}
fn check_p256(pool: &Arc<AllocationPoolV1>) -> Result<(), &'static str> {
    let before = pool.used();
    let peak = p256_successful(pool)?;
    let root = enclave_os_common::allocation::shared_allocation_bytes::<AllocationPoolV1>()
        .ok_or("P256 pool root geometry")?;
    let metadata = LoanAllocator::required_origin_bytes().ok_or("P256 origin geometry")?;
    let required = root
        .checked_add(metadata)
        .and_then(|n| n.checked_add(peak))
        .ok_or("P256 exact bound overflow")?;
    for extra in [-1_isize, 0, 1] {
        let capacity = required
            .checked_add_signed(extra)
            .ok_or("P256 exact capacity")?;
        let isolated = AllocationPoolV1::try_new_with_release(capacity, None)
            .ok_or("P256 exact pool root refused")?;
        let result = p256_successful(&isolated);
        if extra < 0 {
            if result.is_ok() {
                return Err("one-byte-short P256 constructor succeeded");
            }
        } else if result? != peak {
            return Err("P256 exact geometry changed");
        }
        if isolated.used() != 0 {
            return Err("P256 partial/successful refund");
        }
    }
    if pool.used() != before {
        return Err("P256 original owning pool changed");
    }
    std::println!("TLS-P256-CONSTRUCTOR-SIM: actual-SDK metadata SPKI exact-minus-one exact plus-one aliases original-origin final-refund PASS");
    Ok(())
}
