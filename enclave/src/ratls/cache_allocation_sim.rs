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
    std::println!("TLS-SESSION-CACHE-SIM: actual-SDK backing entry get take exact-minus-one exact plus-one aliases returned-origin final-refund PASS");
    Ok(())
}
