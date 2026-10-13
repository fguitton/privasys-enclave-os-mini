//! Portable leaf material and the actual server cache's paid shared owner.
use enclave_os_common::allocation::{AllocationPoolV1, SharedAllocationV1};
use ring::{digest, pkcs8::Document, rand::SystemRandom, signature::{self, EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING}};
use std::sync::Arc;
/// A serving leaf key, kept for the existing deterministic serving lifetime across
/// re-mints of the certificate.
#[derive(Clone)]
pub struct LeafKey {
    /// PKCS#8 private key.
    pub pkcs8: Vec<u8>,
    /// DER `SubjectPublicKeyInfo` (91 bytes), the input of every
    /// `report_data` recipe.
    pub spki_der: Vec<u8>,
    /// SHA-256 of `spki_der`: the `leaf` id clients name in an attest request.
    pub spki_hash: [u8; 32],
    /// Creation time (seconds since the Unix epoch).
    pub created: u64,
}

/// Generate a fresh leaf key.
pub fn new_leaf_key(now: u64) -> Result<LeafKey, String> {
    let (pkcs8, key_pair) = generate_keypair().map_err(|e| e.to_string())?;
    let raw_ec_point = signature::KeyPair::public_key(&key_pair).as_ref();
    let spki_der = enclave_os_common::quote::build_p256_spki_der(raw_ec_point);
    let mut spki_hash = [0u8; 32];
    spki_hash.copy_from_slice(digest::digest(&digest::SHA256, &spki_der).as_ref());
    Ok(LeafKey {
        pkcs8,
        spki_der,
        spki_hash,
        created: now,
    })
}

/// Generate an ECDSA P-256 key pair and return `(pkcs8_bytes, key_pair)`.
pub fn generate_keypair() -> Result<(Vec<u8>, EcdsaKeyPair), &'static str> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|_| "Key generation failed")?;
    let pkcs8_bytes = pkcs8.as_ref().to_vec();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8_bytes, &rng)
        .map_err(|_| "Failed to parse generated key")?;
    Ok((pkcs8_bytes, key_pair))
}


/// Cache aliases retain one original key payload and its physical admission.
pub(crate) struct RetainedLeafKey(SharedAllocationV1<LeafKey>);
impl Clone for RetainedLeafKey {
    fn clone(&self) -> Self { Self(self.0.clone()) }
}
impl core::ops::Deref for RetainedLeafKey {
    type Target = LeafKey;
    fn deref(&self) -> &LeafKey { &self.0 }
}
impl RetainedLeafKey {
    pub(crate) fn new(pool: &Arc<AllocationPoolV1>, now: u64) -> Result<Self, String> {
        let rng = SystemRandom::new();
        // ring's returned Document is inline. Its bytes supply the actual child
        // length; this does not claim payment of ring's internal crypto work.
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|_| String::from("Key generation failed"))?;
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &rng)
            .map_err(|_| String::from("Failed to parse generated key"))?;
        Self::from_generated(pool, now, &document, &pair).ok_or_else(String::new)
    }
    fn from_generated(pool: &Arc<AllocationPoolV1>, now: u64, document: &Document, pair: &EcdsaKeyPair) -> Option<Self> {
        let point = signature::KeyPair::public_key(pair).as_ref();
        let spki_bytes = enclave_os_common::quote::p256_spki_der_len(point.len())?;
        let child_bytes = document.as_ref().len().checked_add(spki_bytes)?;
        let reservation = SharedAllocationV1::<LeafKey>::reserve(pool, child_bytes)?;
        let mut pkcs8 = Vec::new();
        pkcs8.try_reserve_exact(document.as_ref().len()).ok()?;
        if pkcs8.capacity() != document.as_ref().len() { return None; }
        pkcs8.extend_from_slice(document.as_ref());
        let mut spki_der = Vec::new();
        spki_der.try_reserve_exact(spki_bytes).ok()?;
        if spki_der.capacity() != spki_bytes { return None; }
        spki_der.resize(spki_bytes, 0);
        enclave_os_common::quote::write_p256_spki_der(point, &mut spki_der)?;
        let mut spki_hash = [0; 32];
        spki_hash.copy_from_slice(digest::digest(&digest::SHA256, &spki_der).as_ref());
        let key = LeafKey { pkcs8, spki_der, spki_hash, created: now };
        #[cfg(feature = "fallible-allocation-v1")]
        let retained = reservation.try_finish(key).ok()?;
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let retained = reservation.finish(key);
        Some(Self(retained))
    }
}

#[cfg(test)]
pub(super) fn check() {
    let rng = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &rng).unwrap();
    let point = signature::KeyPair::public_key(&pair).as_ref();
    let spki_len = enclave_os_common::quote::p256_spki_der_len(point.len()).unwrap();
    // Independent existing P-256 DER wire vector; actual generated point follows.
    let mut expected_spki = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    expected_spki.extend_from_slice(point);
    assert_eq!(spki_len, expected_spki.len());
    assert_eq!(enclave_os_common::quote::build_p256_spki_der(point), expected_spki);
    let mut bounded_spki = vec![0; spki_len];
    assert!(enclave_os_common::quote::write_p256_spki_der(point, &mut bounded_spki).is_some());
    assert_eq!(bounded_spki, expected_spki);
    let required = SharedAllocationV1::<LeafKey>::required_bytes(document.as_ref().len().checked_add(spki_len).unwrap()).unwrap();
    let short = AllocationPoolV1::new(required - 1).unwrap();
    assert!(RetainedLeafKey::from_generated(&short, 17, &document, &pair).is_none());
    assert_eq!(short.used(), 0);
    for available in [required, required + 1] {
        let pool = AllocationPoolV1::new(available).unwrap();
        let key = RetainedLeafKey::from_generated(&pool, 17, &document, &pair).unwrap();
        assert_eq!(pool.used(), required);
        assert_eq!(key.pkcs8, document.as_ref());
        assert_eq!(key.spki_der, enclave_os_common::quote::build_p256_spki_der(point));
        assert_eq!(key.spki_hash.as_slice(), digest::digest(&digest::SHA256, &key.spki_der).as_ref());
        assert_eq!(key.created, 17);
        let restored = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key.pkcs8, &rng).unwrap();
        assert_eq!(signature::KeyPair::public_key(&restored).as_ref(), point);
        let by_name = key.clone();
        let by_spki = key.clone();
        drop(key);
        assert_eq!(pool.used(), required);
        drop(by_name);
        assert_eq!(pool.used(), required);
        drop(by_spki);
        assert_eq!(pool.used(), 0);
    }
    let pool = AllocationPoolV1::new(required).unwrap();
    let fresh = RetainedLeafKey::new(&pool, 19).unwrap();
    assert_eq!(fresh.created, 19);
    assert_eq!(pool.used(), required);
    drop(fresh);
    assert_eq!(pool.used(), 0);
    // Exercise the unchanged legacy producer, not a made-up cache payload.
    let legacy = new_leaf_key(23).unwrap();
    assert_eq!(legacy.created, 23);
    assert!(EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &legacy.pkcs8, &rng).is_ok());
    assert!(enclave_os_common::quote::p256_spki_der_len(usize::MAX).is_none());
    let mut short = vec![0; spki_len - 1];
    assert!(enclave_os_common::quote::write_p256_spki_der(point, &mut short).is_none());
    assert!(short.iter().all(|b| *b == 0));
    let mut long = vec![0; spki_len + 1];
    assert!(enclave_os_common::quote::write_p256_spki_der(point, &mut long).is_none());
    assert!(long.iter().all(|b| *b == 0));
}
