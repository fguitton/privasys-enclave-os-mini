//! Existing signed-SIM owner's actual selected server-cache allocation checks.
use enclave_os_common::allocation::{AllocationPoolV1, LoanAllocator};
use rustls::server::{ServerSessionMemoryCache, StoresServerSessions};
use std::sync::Arc;

#[path = "client_hello_owner_check.rs"]
mod client_hello_owner_check;
#[path = "transcript_owner_check.rs"]
mod transcript_owner_check;

#[path = "record_owner_check.rs"]
mod record_owner_check;

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
    for (suite, independent) in [
        (
            rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
            &ring::aead::AES_256_GCM,
        ),
        (
            rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            &ring::aead::CHACHA20_POLY1305,
        ),
    ] {
        record_owner_check::check_record_wire(suite, independent);
    }
    std::println!("TLS-RECORD-CIPHER-SIM: actual-SDK inline keys independent-AEAD byte-equality plaintext corruption-refusal PASS");
    check_input_buffer(pool)?;
    client_hello_owner_check::check_in(pool);
    transcript_owner_check::check_in(pool);
    #[cfg(feature = "egress")]
    {
        check_incremental_origin(pool)?;
        std::println!("TLS-INCREMENTAL-ORIGIN-SIM: current-constructor original-pool retained-backing missing-origin origin-refusal child-refusal final-refund PASS");
    }
    std::println!("TLS-TRANSCRIPT-BACKING-SIM: original-pool admission-before-hash clone HRR bytes refusal aliases refund PASS");
    std::println!("TLS-CLIENTHELLO-CHILDREN-SIM: original-pool exact-backing every-refusal clone aliases wire final-refund PASS");
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
    let signature_before = pool.used();
    let signer = retained
        .choose_scheme(&[rustls::SignatureScheme::ECDSA_NISTP256_SHA256])
        .ok_or("P256 selected scheme refused")?;
    let signature = signer
        .sign(b"current signed SDK P256 owner")
        .map_err(|_| "P256 actual SDK signing refused")?;
    let copied_signature = signature.clone();
    drop(signer);
    if pool.used() != signature_before || signature.as_ref() != copied_signature.as_ref() {
        return Err("P256 signer/signature changed owned backing or bytes");
    }
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
    if signature.as_ref().is_empty() || signature.as_ref() != copied_signature.as_ref() {
        return Err("P256 inline signature lost after key/origin refund");
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
    std::println!("TLS-P256-CONSTRUCTOR-SIM: actual-SDK metadata SPKI exact-minus-one exact plus-one aliases original-origin final-refund PASS\nTLS-P256-SIGNER-SIM: actual-SDK inline signer signature clone same-backing same-bytes after-key-origin-refund PASS");
    Ok(())
}

fn input_buffer_once(pool: &Arc<AllocationPoolV1>) -> Result<(), &'static str> {
    let before = pool.used();
    let origin = LoanAllocator::from_pool_unpublished(pool).map_err(|_| "TLS input origin")?;
    let mut acceptor = rustls::server::Acceptor::new_in(origin.owned_allocator());
    let read = acceptor.read_tls(&mut std::io::Cursor::new([7]));
    if read.as_ref().is_ok_and(|n| *n != 1) {
        return Err("TLS input byte count");
    }
    if read.is_ok() {
        origin.activate_release_notification();
    }
    drop(origin);
    if read.is_ok() && pool.used() <= before {
        return Err("TLS input lost original origin");
    }
    drop(acceptor);
    if pool.used() != before {
        return Err("TLS input backing/origin final refund");
    }
    read.map(|_| ()).map_err(|_| "TLS input backing refused")
}
fn check_input_buffer(pool: &Arc<AllocationPoolV1>) -> Result<(), &'static str> {
    input_buffer_once(pool)?;
    let root = enclave_os_common::allocation::shared_allocation_bytes::<AllocationPoolV1>()
        .ok_or("TLS input root layout")?;
    let backend =
        LoanAllocator::required_backend_bytes(rustls::server::Acceptor::initial_read_layout())
            .map_err(|_| "TLS input exact backend")?;
    let bytes = LoanAllocator::required_origin_bytes()
        .and_then(|n| n.checked_add(backend))
        .ok_or("TLS input complete layout")?;
    for extra in [-1_isize, 0, 1] {
        let isolated = AllocationPoolV1::try_new_with_release(
            root.checked_add(bytes)
                .and_then(|n| n.checked_add_signed(extra))
                .ok_or("TLS input exact bound")?,
            None,
        )
        .ok_or("TLS input pool")?;
        let result = input_buffer_once(&isolated);
        if (extra < 0 && result.is_ok()) || (extra >= 0 && result.is_err()) {
            return Err("TLS input exact boundary");
        }
        if isolated.used() != 0 {
            return Err("TLS input leaked on success/refusal");
        }
    }
    std::println!("TLS-INPUT-BUFFER-SIM: actual-SDK original-pool first-read minus-one exact plus-one allocator-lifetime final-refund PASS");
    Ok(())
}

// Actual selected trusted constructor; the native Global type cannot prove this.
// Caller supplies the same real pool as the existing signed ownership registry.
#[cfg(feature = "egress")]
fn check_incremental_origin(pool: &Arc<AllocationPoolV1>) -> Result<(), &'static str> {
    use enclave_os_egress::IncrementalTlsClient;
    let roots = rustls::RootCertStore::empty();
    let missing = IncrementalTlsClient::new("retained.invalid", &roots, None, None);
    if missing.err().as_deref()
        != Some("trusted incremental TLS requires the original allocation pool")
    {
        return Err("incremental missing origin reached handshake construction");
    }
    let before = pool.used();
    let metadata = LoanAllocator::required_origin_bytes().ok_or("incremental origin geometry")?;
    let connection =
        IncrementalTlsClient::new("retained.invalid", &roots, None, Some(pool.clone()))
            .map_err(|_| "incremental paid constructor refused")?;
    if pool.used()
        <= before
            .checked_add(metadata)
            .ok_or("incremental retained sum")?
    {
        return Err("incremental handshake backing did not retain original pool");
    }
    drop(connection);
    if pool.used() != before {
        return Err("incremental constructor backing or origin leaked credit");
    }
    let root = enclave_os_common::allocation::shared_allocation_bytes::<AllocationPoolV1>()
        .ok_or("incremental pool geometry")?;
    // These are actual owner metadata layouts, never a guessed TLS input cap:
    // one short refuses the origin; exact permits only origin metadata and
    // therefore refuses the first actual ClientHello child/backend request.
    let only_origin = root
        .checked_add(metadata)
        .ok_or("incremental exact origin sum")?;
    for extra in [-1_isize, 0] {
        let capacity = only_origin
            .checked_add_signed(extra)
            .ok_or("incremental origin bound")?;
        let isolated = AllocationPoolV1::try_new_with_release(capacity, None)
            .ok_or("incremental refused pool root")?;
        let refused =
            IncrementalTlsClient::new("retained.invalid", &roots, None, Some(isolated.clone()));
        let error = refused
            .err()
            .ok_or("incremental admitted construction without actual child backing")?;
        let expected = if extra < 0 {
            "incremental TLS origin allocation refused"
        } else {
            "incremental TLS init failed: received corrupt message of type AllocationFailed"
        };
        if error != expected {
            return Err("incremental refusal did not come from the expected original owner");
        }
        drop(error);
        if isolated.used() != 0 {
            return Err("incremental refused origin or child leaked credit");
        }
    }
    Ok(())
}
