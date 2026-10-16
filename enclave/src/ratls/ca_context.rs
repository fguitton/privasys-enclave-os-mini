//! Original CA material and its immutable, original-pool runtime copy.
use enclave_os_common::allocation::{AllocationPoolV1, SharedAllocationV1};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use std::{alloc::Layout, fmt, sync::Arc};

/// Intermediary CA context provided to the enclave at startup.
///
/// The enclave uses it to sign leaf RA-TLS certificates so that the
/// trust chain is: `root / intermediary → leaf`.
///
/// The CA material is generated inside the enclave on first boot and sealed so
/// subsequent restarts can unseal it without host provisioning.
#[derive(Clone)]
pub struct CaContext {
    /// DER-encoded X.509 certificate of the intermediary CA.
    pub ca_cert_der: Vec<u8>,
    /// PKCS#8-encoded private key of the intermediary CA.
    pub ca_key_pkcs8: Vec<u8>,
}

impl CaContext {
    /// Construct from unsealed DER cert and PKCS#8 key.
    ///
    /// Performs a basic validation that the key material is usable
    /// (i.e. it can be parsed as an ECDSA P-256 key pair).
    pub fn from_parts(ca_cert_der: Vec<u8>, ca_key_pkcs8: Vec<u8>) -> Result<Self, String> {
        let rng = SystemRandom::new();
        let _ = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &ca_key_pkcs8, &rng)
            .map_err(|_| String::from("CA key is not valid ECDSA P-256 PKCS#8"))?;

        Ok(Self {
            ca_cert_der,
            ca_key_pkcs8,
        })
    }
}

/// Runtime-owned CA bytes and shared metadata. No raw Arc or mutable context
/// escapes; aliases retain their original pool through final backing free.
#[derive(Clone)]
pub struct RetainedCaContext(SharedAllocationV1<CaContext>);

/// Static refusal cause; diagnostics do not allocate a replacement error string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaRetentionError {
    Admission,
    Allocation,
    InvalidKey,
}
impl fmt::Display for CaRetentionError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(match self {
            Self::Admission => "CA allocation admission refused",
            Self::Allocation => "CA backing allocation refused",
            Self::InvalidKey => "CA key is not valid ECDSA P-256 PKCS#8",
        })
    }
}
impl RetainedCaContext {
    /// Complete requested byte layouts plus the existing paired shared owner.
    /// This excludes allocator-private heap overhead and raw rcgen builders.
    pub fn required_bytes(cert_bytes: usize, key_bytes: usize) -> Option<usize> {
        let cert = Layout::array::<u8>(cert_bytes).ok()?;
        let key = Layout::array::<u8>(key_bytes).ok()?;
        SharedAllocationV1::<CaContext>::required_bytes(cert.size().checked_add(key.size())?)
    }

    /// Admit all requests before copying either child. Preserve original P-256
    /// validation; this grants no certificate, attestation or serving authority.
    /// # Errors
    /// Refuses admission, exact backing/metadata allocation or the original key
    /// parser. No partial owner or credit escapes on any refusal.
    pub fn copy_from_parts(
        pool: &Arc<AllocationPoolV1>,
        ca_cert_der: &[u8],
        ca_key_pkcs8: &[u8],
    ) -> Result<Self, CaRetentionError> {
        let bytes = Layout::array::<u8>(ca_cert_der.len())
            .ok()
            .and_then(|cert| {
                Layout::array::<u8>(ca_key_pkcs8.len())
                    .ok()
                    .and_then(|key| cert.size().checked_add(key.size()))
            })
            .ok_or(CaRetentionError::Admission)?;
        let reservation = SharedAllocationV1::<CaContext>::reserve(pool, bytes)
            .ok_or(CaRetentionError::Admission)?;
        let rng = SystemRandom::new();
        let _ = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, ca_key_pkcs8, &rng)
            .map_err(|_| CaRetentionError::InvalidKey)?;
        let ca_cert_der = copy_exact(ca_cert_der)?;
        let ca_key_pkcs8 = copy_exact(ca_key_pkcs8)?;
        let context = CaContext {
            ca_cert_der,
            ca_key_pkcs8,
        };
        #[cfg(feature = "fallible-allocation-v1")]
        let owner = reservation
            .try_finish(context)
            .map_err(|_| CaRetentionError::Allocation)?;
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let owner = reservation.finish(context);
        Ok(Self(owner))
    }

    pub(crate) fn context(&self) -> &CaContext {
        &self.0
    }
}
/// Inline first-registration storage for the existing process-lifetime signer.
/// It owns no additional heap request and retains the original paired CA owner.
#[cfg(any(test, target_env = "sgx", target_vendor = "teaclave"))]
#[cfg_attr(
    any(target_env = "sgx", target_vendor = "teaclave"),
    cfg(feature = "egress")
)]
pub(crate) struct CaContextRegistration(std::sync::OnceLock<RetainedCaContext>);
#[cfg(any(test, target_env = "sgx", target_vendor = "teaclave"))]
#[cfg_attr(
    any(target_env = "sgx", target_vendor = "teaclave"),
    cfg(feature = "egress")
)]
impl CaContextRegistration {
    pub(crate) const fn new() -> Self {
        Self(std::sync::OnceLock::new())
    }
    pub(crate) fn install(&self, ca: RetainedCaContext) -> &RetainedCaContext {
        self.0.get_or_init(|| ca)
    }
    pub(crate) fn get(&self) -> Option<&RetainedCaContext> {
        self.0.get()
    }
}

fn copy_exact(bytes: &[u8]) -> Result<Vec<u8>, CaRetentionError> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| CaRetentionError::Allocation)?;
    if owned.capacity() != bytes.len() {
        return Err(CaRetentionError::Allocation);
    }
    owned.extend_from_slice(bytes);
    Ok(owned)
}

#[cfg(test)]
pub(crate) fn check_runtime_ca_ownership(cert: &[u8], key: &[u8]) {
    let ordinary = CaContext::from_parts(cert.to_vec(), key.to_vec()).unwrap();
    assert_eq!(ordinary.ca_cert_der, cert);
    assert_eq!(ordinary.ca_key_pkcs8, key);
    let required = RetainedCaContext::required_bytes(cert.len(), key.len()).unwrap();
    for extra in [-1_isize, 0, 1] {
        let pool = AllocationPoolV1::new(required.checked_add_signed(extra).unwrap()).unwrap();
        let copied = RetainedCaContext::copy_from_parts(&pool, cert, key);
        if extra < 0 {
            assert!(matches!(copied, Err(CaRetentionError::Admission)));
        } else {
            let copied = copied.unwrap();
            assert_eq!(pool.used(), required);
            assert_eq!(copied.context().ca_cert_der, cert);
            assert_eq!(copied.context().ca_key_pkcs8, key);
            let alias = copied.clone();
            assert!(std::ptr::eq(copied.context(), alias.context()));
            drop(copied);
            assert_eq!(pool.used(), required);
            assert_eq!(alias.context().ca_cert_der, cert);
            assert_eq!(alias.context().ca_key_pkcs8, key);
            drop(alias);
        }
        assert_eq!(pool.used(), 0);
    }
    let pool = AllocationPoolV1::new(required).unwrap();
    assert!(matches!(
        RetainedCaContext::copy_from_parts(&pool, cert, &[0; 32]),
        Err(CaRetentionError::InvalidKey)
    ));
    assert_eq!(pool.used(), 0);
    assert!(RetainedCaContext::required_bytes(usize::MAX, key.len()).is_none());
    assert!(CaContext::from_parts(cert.to_vec(), vec![0; 32]).is_err());
    check_runtime_ca_registration(cert, key);
}

#[cfg(test)]
fn check_runtime_ca_registration(cert: &[u8], key: &[u8]) {
    let required = RetainedCaContext::required_bytes(cert.len(), key.len()).unwrap();
    let pool = AllocationPoolV1::new(required.checked_mul(2).unwrap()).unwrap();
    let registration = CaContextRegistration::new();
    assert!(registration.get().is_none());
    let first = RetainedCaContext::copy_from_parts(&pool, cert, key).unwrap();
    let pointer = first.context() as *const CaContext;
    assert!(std::ptr::eq(registration.install(first).context(), pointer));
    assert_eq!(pool.used(), required);
    let redundant = RetainedCaContext::copy_from_parts(&pool, cert, key).unwrap();
    assert_eq!(pool.used(), required.checked_mul(2).unwrap());
    assert!(std::ptr::eq(
        registration.install(redundant).context(),
        pointer
    ));
    assert_eq!(pool.used(), required);
    let alias = registration.get().unwrap().clone();
    drop(registration);
    assert_eq!(pool.used(), required);
    assert_eq!(alias.context().ca_cert_der, cert);
    assert_eq!(alias.context().ca_key_pkcs8, key);
    drop(alias);
    assert_eq!(pool.used(), 0);
}
