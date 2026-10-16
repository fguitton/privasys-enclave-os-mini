//! One private client-certificate graph, retained through all resolver aliases.
use enclave_os_common::allocation::{AllocationPoolV1, SharedAllocationV1};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    sign::CertifiedKey,
};
use std::{alloc::Layout, sync::Arc};

/// A resource refusal is distinct from an unavailable credential or signing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientCredentialError {
    Allocation,
    Signing,
}
#[cfg(honest_retained_provider)]
impl From<ClientCredentialError> for rustls::Error {
    fn from(error: ClientCredentialError) -> Self {
        match error {
            ClientCredentialError::Allocation => Self::AllocationFailed,
            ClientCredentialError::Signing => {
                Self::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
            }
        }
    }
}

struct Payload {
    key: Arc<CertifiedKey>,
    #[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
    _origin: enclave_os_common::allocation::LoanAllocator,
}
/// The resolver keeps this opaque owner alongside every returned key alias.
/// Neither the original credit nor an owned inner certificate Vec escapes.
#[derive(Clone)]
pub struct ClientCredential(SharedAllocationV1<Payload>);
impl ClientCredential {
    /// Concrete current P-256 retained graph. Input slices remain borrowed;
    /// only admitted final certificate backing is copied.
    pub fn required_bytes(certificates: &[&[u8]], pkcs8: &[u8]) -> Option<usize> {
        let mut bytes = Layout::array::<CertificateDer<'static>>(certificates.len())
            .ok()?
            .size();
        for certificate in certificates {
            bytes = bytes.checked_add(Layout::array::<u8>(certificate.len()).ok()?.size())?;
        }
        bytes = bytes.checked_add(enclave_os_common::allocation::shared_allocation_bytes::<
            CertifiedKey,
        >()?)?;
        #[cfg(feature = "fallible-allocation-v1")]
        {
            use ring::{
                rand::SystemRandom,
                signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
            };
            let pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                pkcs8,
                &SystemRandom::new(),
            )
            .ok()?;
            for payload in rustls::crypto::ring::sign::retained_p256_payload_layouts() {
                bytes = bytes.checked_add(
                    enclave_os_common::allocation::shared_allocation_bytes_for_layout(payload)?,
                )?;
            }
            #[cfg(not(target_vendor = "teaclave"))]
            {
                let layouts = rustls::crypto::ring::sign::retained_p256_spki_layouts(
                    pair.public_key().as_ref().len(),
                )
                .ok()?;
                bytes = bytes.checked_add(layouts.last()?.size())?;
            }
            #[cfg(target_vendor = "teaclave")]
            let _ = pair;
        }
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let _ = pkcs8;
        SharedAllocationV1::<Payload>::required_bytes(bytes)
    }
    /// Peak additional pool requirement for this factory, including the
    /// original allocator metadata and all simultaneous working SPKI blocks.
    pub fn required_pool_bytes(certificates: &[&[u8]], pkcs8: &[u8]) -> Option<usize> {
        let bytes = Self::required_bytes(certificates, pkcs8)?;
        #[cfg(feature = "fallible-allocation-v1")]
        {
            use ring::{
                rand::SystemRandom,
                signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
            };
            let pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                pkcs8,
                &SystemRandom::new(),
            )
            .ok()?;
            let [algorithm, bits, final_spki] =
                rustls::crypto::ring::sign::retained_p256_spki_layouts(
                    pair.public_key().as_ref().len(),
                )
                .ok()?;
            #[cfg(not(target_vendor = "teaclave"))]
            {
                let _ = final_spki;
                bytes
                    .checked_add(algorithm.size())?
                    .checked_add(bits.size())
            }
            #[cfg(target_vendor = "teaclave")]
            {
                use enclave_os_common::allocation::LoanAllocator;
                let mut bytes = bytes.checked_add(LoanAllocator::required_origin_bytes()?)?;
                for layout in [algorithm, bits, final_spki] {
                    bytes =
                        bytes.checked_add(LoanAllocator::required_backend_bytes(layout).ok()?)?;
                }
                Some(bytes)
            }
        }
        #[cfg(not(feature = "fallible-allocation-v1"))]
        Some(bytes)
    }
    /// Refuse before any retained backing is allocated. This is resource
    /// ownership, not a new permission or certificate trust decision.
    pub fn new(
        pool: &Arc<AllocationPoolV1>,
        certificates: &[&[u8]],
        pkcs8: &[u8],
    ) -> Result<Self, ClientCredentialError> {
        // Validate the concrete current key before resource admission, keeping
        // invalid-key refusal distinct from an exhausted original pool.
        ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8,
            &ring::rand::SystemRandom::new(),
        )
        .map_err(|_| ClientCredentialError::Signing)?;
        let bytes =
            Self::required_bytes(certificates, pkcs8).ok_or(ClientCredentialError::Allocation)?;
        let metadata = SharedAllocationV1::<Payload>::required_bytes(0)
            .ok_or(ClientCredentialError::Allocation)?;
        let reservation = SharedAllocationV1::<Payload>::reserve(
            pool,
            bytes
                .checked_sub(metadata)
                .ok_or(ClientCredentialError::Allocation)?,
        )
        .ok_or(ClientCredentialError::Allocation)?;
        let mut certs = Vec::new();
        certs
            .try_reserve_exact(certificates.len())
            .map_err(|_| ClientCredentialError::Allocation)?;
        if certs.capacity() != certificates.len() {
            return Err(ClientCredentialError::Allocation);
        }
        for certificate in certificates {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(certificate.len())
                .map_err(|_| ClientCredentialError::Allocation)?;
            if bytes.capacity() != certificate.len() {
                return Err(ClientCredentialError::Allocation);
            }
            bytes.extend_from_slice(certificate);
            certs.push(CertificateDer::from(bytes));
        }
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8));
        #[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
        let origin = enclave_os_common::allocation::LoanAllocator::from_pool_unpublished(pool)
            .map_err(|_| ClientCredentialError::Allocation)?;
        #[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
        let allocator = origin.owned_allocator();
        #[cfg(all(feature = "fallible-allocation-v1", not(target_vendor = "teaclave")))]
        let allocator = rustls::RetainedAllocator::default();
        // Native capability is explicit Global. Its temporary SPKI requests
        // have their own working credit; final SPKI is in the retained quote.
        #[cfg(all(feature = "fallible-allocation-v1", not(target_vendor = "teaclave")))]
        let working = {
            use ring::{
                rand::SystemRandom,
                signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
            };
            let pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                pkcs8,
                &SystemRandom::new(),
            )
            .map_err(|_| ClientCredentialError::Allocation)?;
            let [algorithm, bits, _] = rustls::crypto::ring::sign::retained_p256_spki_layouts(
                pair.public_key().as_ref().len(),
            )
            .map_err(|_| ClientCredentialError::Allocation)?;
            pool.reserve_unpublished(
                algorithm
                    .size()
                    .checked_add(bits.size())
                    .ok_or(ClientCredentialError::Allocation)?,
            )
            .ok_or(ClientCredentialError::Allocation)?
        };
        #[cfg(feature = "fallible-allocation-v1")]
        let signing_key = rustls::crypto::ring::sign::try_p256_signing_key_in(&key_der, allocator)
            .map_err(|error| match error {
                rustls::server::ServerConfigAllocationError::Allocation => {
                    ClientCredentialError::Allocation
                }
                _ => ClientCredentialError::Signing,
            })?;
        #[cfg(all(feature = "fallible-allocation-v1", not(target_vendor = "teaclave")))]
        drop(working);
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let signing_key = rustls::crypto::ring::default_provider()
            .key_provider
            .load_private_key(key_der.clone_key())
            .map_err(|_| ClientCredentialError::Signing)?;
        let key = CertifiedKey::new(certs, signing_key);
        #[cfg(feature = "fallible-allocation-v1")]
        let key = Arc::try_new(key).map_err(|_| ClientCredentialError::Allocation)?;
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let key = Arc::new(key);
        let payload = Payload {
            key,
            #[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
            _origin: origin,
        };
        #[cfg(feature = "fallible-allocation-v1")]
        let owner = reservation
            .try_finish_unpublished(payload)
            .map_err(|_| ClientCredentialError::Allocation)?;
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let owner = reservation.finish(payload);
        Ok(Self(owner))
    }
    pub(crate) fn key(&self) -> Arc<CertifiedKey> {
        self.0.key.clone()
    }
    pub(crate) fn leaf(&self) -> Option<&[u8]> {
        self.0.key.cert.first().map(AsRef::as_ref)
    }
    pub(crate) fn publish(&self) {
        self.0.activate_release_notification();
        #[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
        self.0._origin.activate_release_notification();
    }
}

#[cfg(feature = "fallible-allocation-v1")]
pub(super) enum Credentials {
    Empty,
    Paid(Vec<ClientCredential, enclave_os_common::allocation::PoolMapAllocator>),
    // Explicit native unmetered capability; never selected after Some refusal.
    #[cfg(not(target_vendor = "teaclave"))]
    Native(Vec<ClientCredential>),
}
#[cfg(feature = "fallible-allocation-v1")]
impl Credentials {
    pub(super) fn prepare(&mut self, pool: Option<&Arc<AllocationPoolV1>>) -> Option<()> {
        if matches!(self, Self::Empty) {
            if let Some(pool) = pool {
                let allocator =
                    enclave_os_common::allocation::PoolMapAllocator::try_new(pool).ok()?;
                *self = Self::Paid(Vec::new_in(allocator));
            } else {
                #[cfg(target_vendor = "teaclave")]
                return None;
                #[cfg(not(target_vendor = "teaclave"))]
                {
                    *self = Self::Native(Vec::new());
                }
            }
        }
        match self {
            Self::Empty => None,
            Self::Paid(values) => values.try_reserve(1).ok(),
            #[cfg(not(target_vendor = "teaclave"))]
            Self::Native(values) => values.try_reserve(1).ok(),
        }
    }
    pub(super) fn push(&mut self, credential: ClientCredential) {
        credential.publish();
        match self {
            Self::Empty => unreachable!("prepared credential backing"),
            Self::Paid(values) => {
                values.push(credential);
                values.allocator().activate_release_notification();
            }
            #[cfg(not(target_vendor = "teaclave"))]
            Self::Native(values) => values.push(credential),
        }
    }
    pub(super) fn last(&self) -> Option<&ClientCredential> {
        match self {
            Self::Empty => None,
            Self::Paid(values) => values.last(),
            #[cfg(not(target_vendor = "teaclave"))]
            Self::Native(values) => values.last(),
        }
    }
}

impl core::fmt::Debug for ClientCredential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientCredential").finish_non_exhaustive()
    }
}
#[cfg(feature = "fallible-allocation-v1")]
impl core::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Credentials").finish_non_exhaustive()
    }
}

#[cfg(all(test, feature = "fallible-allocation-v1"))]
pub(super) fn check(certificates: &[&[u8]], pkcs8: &[u8]) {
    use super::{ClientCertIdentity, EnclaveClientCertSigner, IdentityClientAuth};
    use core::sync::atomic::{AtomicUsize, Ordering};
    let quote = ClientCredential::required_pool_bytes(certificates, pkcs8).unwrap();
    for extra in [-1_isize, 0, 1] {
        let pool = AllocationPoolV1::new(quote.checked_add_signed(extra).unwrap()).unwrap();
        let result = ClientCredential::new(&pool, certificates, pkcs8);
        if extra < 0 {
            assert_eq!(result.err(), Some(ClientCredentialError::Allocation));
            assert_eq!(pool.used(), 0);
        } else {
            let credential = result.unwrap();
            assert_eq!(credential.leaf(), certificates.first().copied());
            let alias = credential.clone();
            let held = pool.used();
            assert!(held > 0);
            drop(credential);
            assert_eq!(pool.used(), held);
            drop(alias);
            assert_eq!(pool.used(), 0);
        }
    }
    struct Signer {
        calls: AtomicUsize,
        refusal: bool,
    }
    impl EnclaveClientCertSigner for Signer {
        fn identity(
            &self,
            _: &ClientCertIdentity,
            _: u64,
            _: Option<&Arc<AllocationPoolV1>>,
        ) -> Result<Option<ClientCredential>, ClientCredentialError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            if self.refusal {
                Err(ClientCredentialError::Allocation)
            } else {
                Ok(None)
            }
        }
        fn evidence(&self, _: &[u8; 64]) -> Option<Vec<u8>> {
            None
        }
    }
    let pool = AllocationPoolV1::new(1).unwrap();
    let occupied = pool.reserve_unpublished(1).unwrap();
    let resolver = IdentityClientAuth {
        identity: ClientCertIdentity {
            code_hash: Vec::new(),
            app_id: None,
        },
        pool: Some(pool.clone()),
        credentials: std::sync::Mutex::new(Credentials::Empty),
    };
    assert!(resolver.resolve_with_signer(None).unwrap().is_none());
    let signer = Signer {
        calls: AtomicUsize::new(0),
        refusal: true,
    };
    assert_eq!(
        resolver.resolve_with_signer(Some(&signer)).err(),
        Some(ClientCredentialError::Allocation)
    );
    assert_eq!(
        signer.calls.load(Ordering::Acquire),
        0,
        "descriptor admission precedes signer work"
    );
    drop(resolver);
    assert_eq!(pool.used(), 1);
    drop(occupied);
    assert_eq!(pool.used(), 0);
    // Derive the actual Vec growth rule by the same owner rather than copying
    // a descriptor capacity constant into this oracle.
    let probe_pool = AllocationPoolV1::new(usize::MAX / 2).unwrap();
    let mut probe = Credentials::Empty;
    probe.prepare(Some(&probe_pool)).unwrap();
    let descriptor_quote = probe_pool.used();
    drop(probe);
    assert_eq!(probe_pool.used(), 0);
    let pool = AllocationPoolV1::new(descriptor_quote).unwrap();
    let resolver = IdentityClientAuth {
        identity: ClientCertIdentity {
            code_hash: Vec::new(),
            app_id: None,
        },
        pool: Some(pool.clone()),
        credentials: std::sync::Mutex::new(Credentials::Empty),
    };
    assert_eq!(
        resolver.resolve_with_signer(Some(&signer)).err(),
        Some(ClientCredentialError::Allocation)
    );
    assert_eq!(signer.calls.load(Ordering::Acquire), 1);
    let decline = Signer {
        calls: AtomicUsize::new(0),
        refusal: false,
    };
    assert!(resolver
        .resolve_with_signer(Some(&decline))
        .unwrap()
        .is_none());
    assert_eq!(decline.calls.load(Ordering::Acquire), 1);
    assert_eq!(pool.used(), descriptor_quote);
    drop(resolver);
    assert_eq!(pool.used(), 0);
}
