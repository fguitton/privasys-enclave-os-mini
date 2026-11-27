// Copyright (c) Privasys. All rights reserved.
// Portions copyright (c) 2026 Florian Guitton.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Hybrid post-quantum TLS 1.3 key exchange (`X25519MLKEM768`, IANA `0x11EC`)
//! built over the vendored `fips203` ML-KEM-768 and `ring`'s X25519.
//!
//! Wire layout matches `draft-ietf-tls-ecdhe-mlkem` §3 (`post_quantum_first = true`):
//! - Client key share: `ML-KEM-768 ek (1184 B) || X25519 pk (32 B)` = `1216 B`
//! - Server key share: `ML-KEM-768 ct (1088 B) || X25519 pk (32 B)` = `1120 B`
//! - Shared secret: `ML-KEM-768 ss (32 B) || X25519 ss (32 B)` = `64 B`
//!
//! `ActiveKeyExchange::hybrid_component` exposes the classical X25519 share so
//! `rustls` can also complete 1-RTT handshakes with classical-only third-party
//! peers (for example external NTS servers) when classical groups remain in the
//! provider's allowlist.
//!
//! # Allocation Ownership Scope
//! - Configuration vectors (`cipher_suites`, `kx_groups`) are fallibly reserved
//!   by [`try_default_provider`] and prepaid by config owners.
//! - Per-handshake hybrid objects have separate exact layouts in
//!   [`hybrid_kx_layouts`]: the active ML-KEM holder, client share (`1216 B`),
//!   server share (`1120 B`), and shared-secret copy (`64 B`).
//! - Under `fallible-allocation-v1`, [`start_in`], [`start_and_complete_in`],
//!   and [`ActiveHybridKxIn::complete_in`] carry a caller-supplied
//!   `core::alloc::Allocator` (e.g. [`crate::allocation::PoolMapAllocator`] or
//!   Teaclave's owned loan allocator) through the active ML-KEM holder, public
//!   share buffers, and zeroized shared-secret buffers.
//! - Live `rustls` ingress and egress handshakes bind their connection
//!   [`crate::allocation::AllocationPoolV1`] via [`with_handshake_budget`] so
//!   [`X25519MLKEM768`] charges and releases [`hybrid_kx_client_start_bytes`],
//!   [`hybrid_kx_client_complete_bytes`], and [`hybrid_kx_server_handshake_bytes`]
//!   against the live connection budget before allocating or returning key-share
//!   and shared-secret buffers.
//! - Remaining global-heap scope: upstream `rustls::crypto::SupportedKxGroup`
//!   and `ActiveKeyExchange` trait methods do not accept a `RetainedAllocator`
//!   in `rustls 0.23.45`, and `ring::kx_group::X25519` allocates its classical
//!   exchange state, share, and `SharedSecret` on the global heap. Within that
//!   trait boundary, live handshakes are still admission-gated by the connection
//!   pool, `ActiveX25519MlKem768` keeps its `1216 B` client share inline,
//!   `start_and_complete` uses fallible `try_reserve_exact`, and secret buffers
//!   are zeroized on drop.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::cell::RefCell;
use core::num::NonZeroU32;
use std::sync::Arc;

use crate::allocation::{AllocationLeaseV1, AllocationPoolV1};

#[cfg(feature = "fallible-allocation-v1")]
use core::alloc::Allocator;
#[cfg(feature = "fallible-allocation-v1")]
use zeroize::Zeroize as _;

use fips203::ml_kem_768::{CipherText, DecapsKey, EncapsKey, CT_LEN, EK_LEN, KG};
use fips203::traits::{Decaps as _, Encaps as _, KeyGen as _, SerDes as _};
use fips203::{RngError, SSK_LEN};
use ring::rand::{SecureRandom as _, SystemRandom};
use rustls::crypto::{
    ring as rustls_ring, ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, GetRandomFailed,
    KeyProvider, SecureRandom, SharedSecret, SupportedKxGroup, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion, SignatureScheme};
use webpki::ring as webpki_algs;
use zeroize::Zeroizing;

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);
const X25519_LEN: usize = 32;
/// Encoded client key-share length (`ML-KEM-768 ek (1184 B) || X25519 pk (32 B)`).
pub const CLIENT_SHARE_LEN: usize = EK_LEN + X25519_LEN;
/// Encoded server key-share length (`ML-KEM-768 ct (1088 B) || X25519 pk (32 B)`).
pub const SERVER_SHARE_LEN: usize = CT_LEN + X25519_LEN;
/// Combined hybrid shared-secret length (`ML-KEM-768 ss (32 B) || X25519 ss (32 B)`).
pub const SHARED_SECRET_LEN: usize = SSK_LEN + X25519_LEN;

const _: () = {
    assert!(EK_LEN == 1184);
    assert!(CT_LEN == 1088);
    assert!(SSK_LEN == 32);
    assert!(CLIENT_SHARE_LEN == 1216);
    assert!(SERVER_SHARE_LEN == 1120);
    assert!(SHARED_SECRET_LEN == 64);
};

/// Separate per-object memory layouts for one hybrid `X25519MLKEM768` handshake,
/// distinct from [`try_default_provider`] configuration-vector allocations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HybridKxLayoutsV1 {
    /// Active ML-KEM-768 decapsulation-key holder allocated via the handshake allocator.
    pub active_holder: Layout,
    /// Client public key share (`1216 B`).
    pub client_share: Layout,
    /// Server public key share (`1120 B`).
    pub server_share: Layout,
    /// Combined shared-secret copy (`64 B`).
    pub shared_secret: Layout,
}

/// Exact separate layouts for hybrid handshake state, shares, and secret copies.
#[must_use]
pub const fn hybrid_kx_layouts() -> HybridKxLayoutsV1 {
    HybridKxLayoutsV1 {
        active_holder: Layout::new::<ActiveHybridPayload>(),
        client_share: Layout::new::<[u8; CLIENT_SHARE_LEN]>(),
        server_share: Layout::new::<[u8; SERVER_SHARE_LEN]>(),
        shared_secret: Layout::new::<[u8; SHARED_SECRET_LEN]>(),
    }
}

/// Exact live connection-budget bytes charged by `X25519MLKEM768::start()` for
/// the active client key-exchange holder (including `DecapsKey` and the inline
/// `1216 B` client share) from `start()` until `complete()` or drop.
#[must_use]
pub const fn hybrid_kx_client_start_bytes() -> usize {
    Layout::new::<ActiveX25519MlKem768>().size()
}

/// Exact live connection-budget bytes charged by `ActiveX25519MlKem768::complete()`
/// for the `64 B` combined shared-secret copy.
#[must_use]
pub const fn hybrid_kx_client_complete_bytes() -> usize {
    hybrid_kx_layouts().shared_secret.size()
}

/// Exact live connection-budget bytes charged by `X25519MLKEM768::start_and_complete()`
/// on the server (`1120 B` server share + `64 B` combined shared-secret copy).
#[must_use]
pub const fn hybrid_kx_server_handshake_bytes() -> usize {
    hybrid_kx_layouts().server_share.size() + hybrid_kx_layouts().shared_secret.size()
}

std::thread_local! {
    static ACTIVE_HANDSHAKE_POOL: RefCell<Option<Arc<AllocationPoolV1>>> = const { RefCell::new(None) };
}

fn current_handshake_pool() -> Option<Arc<AllocationPoolV1>> {
    ACTIVE_HANDSHAKE_POOL.with(|cell| cell.borrow().clone())
}

struct HandshakeBudgetGuard {
    previous: Option<Arc<AllocationPoolV1>>,
}

impl Drop for HandshakeBudgetGuard {
    fn drop(&mut self) {
        ACTIVE_HANDSHAKE_POOL.with(|cell| {
            *cell.borrow_mut() = self.previous.take();
        });
    }
}

/// Scope a live TLS handshake operation (`ClientConnection::new`,
/// `ServerConnection::process_new_packets`, `Accepted::into_connection`, etc.)
/// so `X25519MLKEM768` charges and releases its active holder, public shares,
/// and shared-secret buffers against `pool`. Restores any outer binding on
/// normal return or unwind.
pub fn with_handshake_budget<T>(
    pool: Option<&Arc<AllocationPoolV1>>,
    f: impl FnOnce() -> T,
) -> T {
    let previous = ACTIVE_HANDSHAKE_POOL
        .with(|cell| core::mem::replace(&mut *cell.borrow_mut(), pool.cloned()));
    let _guard = HandshakeBudgetGuard { previous };
    f()
}

/// Active ML-KEM-768 decapsulation-key holder paired with the classical X25519
/// exchange state. `DecapsKey` derives `ZeroizeOnDrop` so its secret key bytes
/// are wiped in place before backing deallocation.
pub struct ActiveHybridPayload {
    classical: Option<Box<dyn ActiveKeyExchange>>,
    decaps_key: DecapsKey,
}

/// Hybrid `X25519MLKEM768` (`0x11EC`) key-exchange group for TLS 1.3.
pub static X25519MLKEM768: &dyn SupportedKxGroup = &X25519MlKem768Group;

/// Default key-exchange groups with `X25519MLKEM768` preferred first and
/// classical groups retained for third-party TLS 1.3 interoperability.
pub static DEFAULT_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    X25519MLKEM768,
    rustls_ring::kx_group::X25519,
    rustls_ring::kx_group::SECP256R1,
    rustls_ring::kx_group::SECP384R1,
];

/// Refusal from fallible default-list allocation when building the hybrid provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DefaultProviderAllocationError;

/// Construct the ring-backed `CryptoProvider` with `X25519MLKEM768` first.
#[must_use]
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: rustls_ring::DEFAULT_CIPHER_SUITES.to_vec(),
        kx_groups: DEFAULT_KX_GROUPS.to_vec(),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &RingProvider,
        key_provider: &RingProvider,
    }
}

/// Construct the identical hybrid `CryptoProvider` using fallible exact-capacity
/// backing allocations so callers under `fallible-allocation-v1` prepay exact bytes.
#[cfg(feature = "fallible-allocation-v1")]
pub fn try_default_provider() -> Result<CryptoProvider, DefaultProviderAllocationError> {
    let mut cipher_suites = Vec::new();
    cipher_suites
        .try_reserve_exact(rustls_ring::DEFAULT_CIPHER_SUITES.len())
        .map_err(|_| DefaultProviderAllocationError)?;
    let mut kx_groups = Vec::new();
    kx_groups
        .try_reserve_exact(DEFAULT_KX_GROUPS.len())
        .map_err(|_| DefaultProviderAllocationError)?;
    if cipher_suites.capacity() != rustls_ring::DEFAULT_CIPHER_SUITES.len()
        || kx_groups.capacity() != DEFAULT_KX_GROUPS.len()
    {
        return Err(DefaultProviderAllocationError);
    }
    cipher_suites.extend_from_slice(rustls_ring::DEFAULT_CIPHER_SUITES);
    kx_groups.extend_from_slice(DEFAULT_KX_GROUPS);
    Ok(CryptoProvider {
        cipher_suites,
        kx_groups,
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &RingProvider,
        key_provider: &RingProvider,
    })
}

#[derive(Debug)]
struct RingProvider;

impl SecureRandom for RingProvider {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        SystemRandom::new().fill(buf).map_err(|_| GetRandomFailed)
    }
}

impl KeyProvider for RingProvider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        rustls_ring::sign::any_supported_type(&Zeroizing::new(key_der))
    }
}

static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki_algs::ECDSA_P256_SHA256,
        webpki_algs::ECDSA_P256_SHA384,
        webpki_algs::ECDSA_P384_SHA256,
        webpki_algs::ECDSA_P384_SHA384,
        webpki_algs::ED25519,
        webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        webpki_algs::RSA_PKCS1_2048_8192_SHA256,
        webpki_algs::RSA_PKCS1_2048_8192_SHA384,
        webpki_algs::RSA_PKCS1_2048_8192_SHA512,
        webpki_algs::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
        webpki_algs::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
        webpki_algs::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                webpki_algs::ECDSA_P384_SHA384,
                webpki_algs::ECDSA_P256_SHA384,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                webpki_algs::ECDSA_P256_SHA256,
                webpki_algs::ECDSA_P384_SHA256,
            ],
        ),
        (SignatureScheme::ED25519, &[webpki_algs::ED25519]),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA256],
        ),
    ],
};

struct SystemRngAdapter(SystemRandom);

impl SystemRngAdapter {
    fn new() -> Self {
        Self(SystemRandom::new())
    }
}

impl fips203::RngCore for SystemRngAdapter {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0
            .fill(dest)
            .expect("system RNG failed during ML-KEM-768 operation");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.0
            .fill(dest)
            .map_err(|_| RngError::from(NonZeroU32::new(RngError::CUSTOM_START).expect("nonzero")))
    }
}

impl fips203::CryptoRng for SystemRngAdapter {}

#[derive(Debug)]
struct X25519MlKem768Group;

impl SupportedKxGroup for X25519MlKem768Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let pool = current_handshake_pool();
        let holder_lease = match pool.as_ref() {
            Some(pool) => Some(
                pool.reserve_unpublished(hybrid_kx_client_start_bytes())
                    .ok_or_else(|| Error::General(String::new()))?,
            ),
            None => None,
        };
        let classical = rustls_ring::kx_group::X25519.start()?;
        let mut rng = SystemRngAdapter::new();
        let (ek, dk) =
            KG::try_keygen_with_rng(&mut rng).map_err(|_| Error::FailedToGetRandomBytes)?;
        let ek_bytes = ek.into_bytes();
        let mut combined_pub_key = [0u8; CLIENT_SHARE_LEN];
        combined_pub_key[..EK_LEN].copy_from_slice(&ek_bytes);
        combined_pub_key[EK_LEN..].copy_from_slice(classical.pub_key());
        let active = ActiveX25519MlKem768 {
            payload: ActiveHybridPayload {
                classical: Some(classical),
                decaps_key: dk,
            },
            combined_pub_key,
            pool,
            _holder_lease: holder_lease,
        };
        #[cfg(feature = "fallible-allocation-v1")]
        {
            let boxed = Box::try_new(active).map_err(|_| Error::General(String::new()))?;
            Ok(boxed)
        }
        #[cfg(not(feature = "fallible-allocation-v1"))]
        {
            Ok(Box::new(active))
        }
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if client_share.len() != CLIENT_SHARE_LEN {
            return Err(INVALID_KEY_SHARE);
        }
        let (pq_share, classical_share) = client_share.split_at(EK_LEN);
        let ek_array: [u8; EK_LEN] = pq_share.try_into().map_err(|_| INVALID_KEY_SHARE)?;
        let ek = EncapsKey::try_from_bytes(ek_array).map_err(|_| INVALID_KEY_SHARE)?;

        let pool = current_handshake_pool();
        let _server_share_lease = match pool.as_ref() {
            Some(pool) => Some(
                pool.reserve_unpublished(hybrid_kx_layouts().server_share.size())
                    .ok_or_else(|| Error::General(String::new()))?,
            ),
            None => None,
        };
        let _secret_lease = match pool.as_ref() {
            Some(pool) => Some(
                pool.reserve_unpublished(hybrid_kx_layouts().shared_secret.size())
                    .ok_or_else(|| Error::General(String::new()))?,
            ),
            None => None,
        };

        let classical = rustls_ring::kx_group::X25519.start_and_complete(classical_share)?;
        let mut rng = SystemRngAdapter::new();
        let (pq_secret, ct) = ek
            .try_encaps_with_rng(&mut rng)
            .map_err(|_| Error::FailedToGetRandomBytes)?;

        let pq_secret_bytes = Zeroizing::new(pq_secret.into_bytes());
        let mut combined_pub_key = Vec::new();
        combined_pub_key
            .try_reserve_exact(SERVER_SHARE_LEN)
            .map_err(|_| Error::General(String::new()))?;
        combined_pub_key.extend_from_slice(&ct.into_bytes());
        combined_pub_key.extend_from_slice(&classical.pub_key);

        let mut combined_secret = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
        combined_secret[..SSK_LEN].copy_from_slice(pq_secret_bytes.as_ref());
        combined_secret[SSK_LEN..].copy_from_slice(classical.secret.secret_bytes());

        Ok(CompletedKeyExchange {
            group: NamedGroup::X25519MLKEM768,
            pub_key: combined_pub_key,
            secret: SharedSecret::from(&combined_secret[..]),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct ActiveX25519MlKem768 {
    payload: ActiveHybridPayload,
    combined_pub_key: [u8; CLIENT_SHARE_LEN],
    pool: Option<Arc<AllocationPoolV1>>,
    // Field order is deliberate: `payload` (holding `DecapsKey` with
    // `ZeroizeOnDrop`) drops before `_holder_lease` releases connection credit.
    _holder_lease: Option<AllocationLeaseV1>,
}

impl ActiveKeyExchange for ActiveX25519MlKem768 {
    fn complete(mut self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != SERVER_SHARE_LEN {
            return Err(INVALID_KEY_SHARE);
        }
        let (pq_share, classical_share) = peer_pub_key.split_at(CT_LEN);
        let ct_array: [u8; CT_LEN] = pq_share.try_into().map_err(|_| INVALID_KEY_SHARE)?;
        let ct = CipherText::try_from_bytes(ct_array).map_err(|_| INVALID_KEY_SHARE)?;

        let scoped_pool = current_handshake_pool();
        let budget_pool = self.pool.as_ref().or(scoped_pool.as_ref());
        let _secret_lease = match budget_pool {
            Some(pool) => Some(
                pool.reserve_unpublished(hybrid_kx_client_complete_bytes())
                    .ok_or_else(|| Error::General(String::new()))?,
            ),
            None => None,
        };

        let classical = self
            .payload
            .classical
            .take()
            .ok_or(INVALID_KEY_SHARE)?;
        let classical_secret = classical.complete(classical_share)?;
        let pq_secret = self
            .payload
            .decaps_key
            .try_decaps(&ct)
            .map_err(|_| INVALID_KEY_SHARE)?;
        let pq_secret_bytes = Zeroizing::new(pq_secret.into_bytes());

        let mut combined_secret = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
        combined_secret[..SSK_LEN].copy_from_slice(pq_secret_bytes.as_ref());
        combined_secret[SSK_LEN..].copy_from_slice(classical_secret.secret_bytes());

        Ok(SharedSecret::from(&combined_secret[..]))
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        let classical = self.payload.classical.as_ref()?;
        Some((classical.group(), classical.pub_key()))
    }

    fn complete_hybrid_component(
        mut self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        let classical = self
            .payload
            .classical
            .take()
            .ok_or(INVALID_KEY_SHARE)?;
        classical.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.combined_pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

/// Errors from allocator-carrying hybrid key-exchange operations.
#[cfg(feature = "fallible-allocation-v1")]
#[derive(Debug)]
pub enum HybridKxInError {
    /// The caller's handshake allocator refused one of the hybrid buffers.
    Allocation,
    /// The peer's share had an invalid length or malformed ML-KEM encoding.
    InvalidKeyShare,
    /// System randomness was unavailable.
    RandomFailed,
    /// The underlying classical X25519 exchange rejected the peer share.
    Classical(Error),
}

/// Shared-secret buffer allocated in a caller-owned handshake allocator `A`.
/// Zeroizes its bytes in place on `Drop` before returning backing to `A`.
#[cfg(feature = "fallible-allocation-v1")]
pub struct ZeroizingSharedSecretIn<A: Allocator> {
    bytes: Vec<u8, A>,
}

#[cfg(feature = "fallible-allocation-v1")]
impl<A: Allocator> ZeroizingSharedSecretIn<A> {
    #[must_use]
    pub fn secret_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(feature = "fallible-allocation-v1")]
impl<A: Allocator> Drop for ZeroizingSharedSecretIn<A> {
    fn drop(&mut self) {
        self.bytes.as_mut_slice().zeroize();
    }
}

/// Active client-side hybrid exchange holding the ML-KEM decapsulation key and
/// client public share in separate allocations owned by `A`.
#[cfg(feature = "fallible-allocation-v1")]
pub struct ActiveHybridKxIn<A: Allocator> {
    holder: Box<ActiveHybridPayload, A>,
    pub_key: Vec<u8, A>,
}

#[cfg(feature = "fallible-allocation-v1")]
impl<A: Allocator + Clone> ActiveHybridKxIn<A> {
    #[must_use]
    pub fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    #[must_use]
    pub fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    #[must_use]
    pub fn hybrid_component(&self) -> (NamedGroup, &[u8]) {
        let classical = self
            .holder
            .classical
            .as_ref()
            .expect("active hybrid exchange holds classical component");
        (classical.group(), classical.pub_key())
    }

    /// Complete the client side of `X25519MLKEM768`, allocating the combined
    /// `64 B` shared secret inside `allocator` and zeroizing all secret
    /// material in place on drop (including the ML-KEM `DecapsKey` in `self.holder`).
    pub fn complete_in(
        mut self,
        peer_pub_key: &[u8],
        allocator: A,
    ) -> Result<ZeroizingSharedSecretIn<A>, HybridKxInError> {
        if peer_pub_key.len() != SERVER_SHARE_LEN {
            return Err(HybridKxInError::InvalidKeyShare);
        }
        let (pq_share, classical_share) = peer_pub_key.split_at(CT_LEN);
        let ct_array: [u8; CT_LEN] = pq_share
            .try_into()
            .map_err(|_| HybridKxInError::InvalidKeyShare)?;
        let ct =
            CipherText::try_from_bytes(ct_array).map_err(|_| HybridKxInError::InvalidKeyShare)?;

        let mut secret_bytes = Vec::new_in(allocator);
        secret_bytes
            .try_reserve_exact(SHARED_SECRET_LEN)
            .map_err(|_| HybridKxInError::Allocation)?;
        if secret_bytes.capacity() != SHARED_SECRET_LEN {
            return Err(HybridKxInError::Allocation);
        }

        let classical = self
            .holder
            .classical
            .take()
            .ok_or(HybridKxInError::InvalidKeyShare)?;
        let classical_secret = classical
            .complete(classical_share)
            .map_err(HybridKxInError::Classical)?;
        let pq_secret = self
            .holder
            .decaps_key
            .try_decaps(&ct)
            .map_err(|_| HybridKxInError::InvalidKeyShare)?;
        let pq_secret_bytes = Zeroizing::new(pq_secret.into_bytes());

        secret_bytes.extend_from_slice(pq_secret_bytes.as_ref());
        secret_bytes.extend_from_slice(classical_secret.secret_bytes());
        Ok(ZeroizingSharedSecretIn {
            bytes: secret_bytes,
        })
    }
}

/// Completed server-side hybrid exchange holding the `1120 B` server share and
/// `64 B` zeroizing shared secret in separate allocations owned by `A`.
#[cfg(feature = "fallible-allocation-v1")]
pub struct CompletedHybridKxIn<A: Allocator> {
    pub group: NamedGroup,
    pub pub_key: Vec<u8, A>,
    pub secret: ZeroizingSharedSecretIn<A>,
}

/// Start the client side of `X25519MLKEM768`, allocating the active ML-KEM
/// holder and the `1216 B` client share separately in `allocator`.
#[cfg(feature = "fallible-allocation-v1")]
pub fn start_in<A: Allocator + Clone>(allocator: A) -> Result<ActiveHybridKxIn<A>, HybridKxInError> {
    let mut pub_key = Vec::new_in(allocator.clone());
    pub_key
        .try_reserve_exact(CLIENT_SHARE_LEN)
        .map_err(|_| HybridKxInError::Allocation)?;
    if pub_key.capacity() != CLIENT_SHARE_LEN {
        return Err(HybridKxInError::Allocation);
    }

    let classical = rustls_ring::kx_group::X25519
        .start()
        .map_err(HybridKxInError::Classical)?;
    let mut rng = SystemRngAdapter::new();
    let (ek, dk) = KG::try_keygen_with_rng(&mut rng).map_err(|_| HybridKxInError::RandomFailed)?;
    let ek_bytes = ek.into_bytes();
    pub_key.extend_from_slice(&ek_bytes);
    pub_key.extend_from_slice(classical.pub_key());

    let holder = Box::try_new_in(
        ActiveHybridPayload {
            classical: Some(classical),
            decaps_key: dk,
        },
        allocator,
    )
    .map_err(|_| HybridKxInError::Allocation)?;

    Ok(ActiveHybridKxIn { holder, pub_key })
}

/// Perform the server side of `X25519MLKEM768`, allocating the `1120 B` server
/// share and `64 B` zeroizing shared secret separately in `allocator`.
#[cfg(feature = "fallible-allocation-v1")]
pub fn start_and_complete_in<A: Allocator + Clone>(
    client_share: &[u8],
    allocator: A,
) -> Result<CompletedHybridKxIn<A>, HybridKxInError> {
    if client_share.len() != CLIENT_SHARE_LEN {
        return Err(HybridKxInError::InvalidKeyShare);
    }
    let (pq_share, classical_share) = client_share.split_at(EK_LEN);
    let ek_array: [u8; EK_LEN] = pq_share
        .try_into()
        .map_err(|_| HybridKxInError::InvalidKeyShare)?;
    let ek = EncapsKey::try_from_bytes(ek_array).map_err(|_| HybridKxInError::InvalidKeyShare)?;

    let mut pub_key = Vec::new_in(allocator.clone());
    pub_key
        .try_reserve_exact(SERVER_SHARE_LEN)
        .map_err(|_| HybridKxInError::Allocation)?;
    if pub_key.capacity() != SERVER_SHARE_LEN {
        return Err(HybridKxInError::Allocation);
    }

    let mut secret_bytes = Vec::new_in(allocator);
    secret_bytes
        .try_reserve_exact(SHARED_SECRET_LEN)
        .map_err(|_| HybridKxInError::Allocation)?;
    if secret_bytes.capacity() != SHARED_SECRET_LEN {
        return Err(HybridKxInError::Allocation);
    }

    let classical = rustls_ring::kx_group::X25519
        .start_and_complete(classical_share)
        .map_err(HybridKxInError::Classical)?;
    let mut rng = SystemRngAdapter::new();
    let (pq_secret, ct) = ek
        .try_encaps_with_rng(&mut rng)
        .map_err(|_| HybridKxInError::RandomFailed)?;
    let pq_secret_bytes = Zeroizing::new(pq_secret.into_bytes());

    pub_key.extend_from_slice(&ct.into_bytes());
    pub_key.extend_from_slice(&classical.pub_key);
    secret_bytes.extend_from_slice(pq_secret_bytes.as_ref());
    secret_bytes.extend_from_slice(classical.secret.secret_bytes());

    Ok(CompletedHybridKxIn {
        group: NamedGroup::X25519MLKEM768,
        pub_key,
        secret: ZeroizingSharedSecretIn {
            bytes: secret_bytes,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_mlkem768_round_trip_and_share_lengths() {
        assert_eq!(X25519MLKEM768.name(), NamedGroup::X25519MLKEM768);
        assert_eq!(u16::from(X25519MLKEM768.name()), 0x11EC);
        assert!(X25519MLKEM768.usable_for_version(ProtocolVersion::TLSv1_3));
        assert!(!X25519MLKEM768.usable_for_version(ProtocolVersion::TLSv1_2));

        let client = X25519MLKEM768.start().expect("client start");
        assert_eq!(client.group(), NamedGroup::X25519MLKEM768);
        assert_eq!(client.pub_key().len(), CLIENT_SHARE_LEN);
        let (classical_group, classical_share) = client
            .hybrid_component()
            .expect("hybrid exposes classical component");
        assert_eq!(classical_group, NamedGroup::X25519);
        assert_eq!(classical_share.len(), X25519_LEN);
        assert_eq!(&client.pub_key()[EK_LEN..], classical_share);

        let server = X25519MLKEM768
            .start_and_complete(client.pub_key())
            .expect("server start_and_complete");
        assert_eq!(server.group, NamedGroup::X25519MLKEM768);
        assert_eq!(server.pub_key.len(), SERVER_SHARE_LEN);
        assert_eq!(server.secret.secret_bytes().len(), SHARED_SECRET_LEN);

        let client_secret = client
            .complete(&server.pub_key)
            .expect("client complete");
        assert_eq!(client_secret.secret_bytes(), server.secret.secret_bytes());
    }

    #[test]
    fn x25519_mlkem768_rejects_truncated_and_corrupted_shares() {
        assert!(matches!(
            X25519MLKEM768.start_and_complete(&[0u8; CLIENT_SHARE_LEN - 1]),
            Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))
        ));
        assert!(matches!(
            X25519MLKEM768.start_and_complete(&[0u8; CLIENT_SHARE_LEN + 1]),
            Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))
        ));
        // Invalid ML-KEM-768 encapsulation key (all 0xFF coefficients >= q = 3329).
        assert!(matches!(
            X25519MLKEM768.start_and_complete(&[0xFFu8; CLIENT_SHARE_LEN]),
            Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))
        ));

        let client = X25519MLKEM768.start().expect("client start");
        assert!(matches!(
            client.complete(&[0u8; SERVER_SHARE_LEN - 1]),
            Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))
        ));

        // Corrupted ML-KEM ciphertext yields an implicit-rejection shared secret
        // that does NOT match the server's secret.
        let client = X25519MLKEM768.start().expect("client start");
        let server = X25519MLKEM768
            .start_and_complete(client.pub_key())
            .expect("server start_and_complete");
        let mut tampered = server.pub_key.clone();
        tampered[0] ^= 0x01;
        let client_secret = client.complete(&tampered).expect("implicit rejection");
        assert_ne!(client_secret.secret_bytes(), server.secret.secret_bytes());
    }

    #[test]
    fn x25519_mlkem768_hybrid_component_supports_classical_fallback() {
        let client = X25519MLKEM768.start().expect("client start");
        let (group, classical_client_pub) = client.hybrid_component().expect("hybrid component");
        assert_eq!(group, NamedGroup::X25519);
        let server = rustls_ring::kx_group::X25519
            .start_and_complete(classical_client_pub)
            .expect("classical server complete");
        let client_secret = client
            .complete_hybrid_component(&server.pub_key)
            .expect("classical fallback complete");
        assert_eq!(client_secret.secret_bytes(), server.secret.secret_bytes());
    }

    #[test]
    fn default_provider_places_x25519_mlkem768_first_and_matches_ring_suites() {
        let provider = default_provider();
        assert_eq!(provider.kx_groups.len(), 4);
        assert_eq!(provider.kx_groups[0].name(), NamedGroup::X25519MLKEM768);
        assert_eq!(provider.kx_groups[1].name(), NamedGroup::X25519);
        assert_eq!(provider.kx_groups[2].name(), NamedGroup::secp256r1);
        assert_eq!(provider.kx_groups[3].name(), NamedGroup::secp384r1);
        assert_eq!(
            provider.cipher_suites.len(),
            rustls_ring::DEFAULT_CIPHER_SUITES.len()
        );
    }

    #[cfg(feature = "fallible-allocation-v1")]
    #[test]
    fn hybrid_kx_allocator_accounts_holder_shares_and_secrets_separately_and_zeroizes() {
        use crate::allocation::{AllocationPoolV1, PoolMapAllocator};
        use core::alloc::{AllocError, Allocator};
        use core::cell::RefCell;
        use core::ptr::NonNull;
        use std::rc::Rc;

        #[derive(Default)]
        struct Observed {
            requests: usize,
            refuse: Option<usize>,
            live: usize,
            layouts: Vec<Layout>,
            zeroized_secrets: usize,
            zeroized_holders: usize,
        }

        #[derive(Clone)]
        struct InspectingAllocator {
            inner: PoolMapAllocator,
            state: Rc<RefCell<Observed>>,
        }

        impl InspectingAllocator {
            fn new(pool: &Arc<AllocationPoolV1>) -> Self {
                Self {
                    inner: PoolMapAllocator::try_new(pool).expect("pool allocator"),
                    state: Rc::new(RefCell::new(Observed::default())),
                }
            }

            fn arm(&self, refuse: Option<usize>) {
                let mut state = self.state.borrow_mut();
                state.requests = 0;
                state.refuse = refuse;
            }
        }

        // SAFETY: delegates allocation/deallocation directly to `PoolMapAllocator`
        // and inspects only the live allocation's own initialized bytes right
        // before freeing.
        unsafe impl Allocator for InspectingAllocator {
            fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
                let mut state = self.state.borrow_mut();
                let ordinal = state.requests;
                state.requests += 1;
                if state.refuse == Some(ordinal) {
                    return Err(AllocError);
                }
                let ptr = self.inner.allocate(layout)?;
                state.live += 1;
                state.layouts.push(layout);
                Ok(ptr)
            }

            unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
                let layouts = hybrid_kx_layouts();
                let mut state = self.state.borrow_mut();
                if layout == layouts.shared_secret {
                    // SAFETY: `ZeroizingSharedSecretIn::drop` ran before `Vec` deallocates.
                    let slice = unsafe { core::slice::from_raw_parts(ptr.as_ptr(), layout.size()) };
                    assert!(
                        slice.iter().all(|&b| b == 0),
                        "shared-secret buffer must be zeroized before deallocation"
                    );
                    state.zeroized_secrets += 1;
                } else if layout == layouts.active_holder {
                    // SAFETY: `ActiveHybridPayload` drops `DecapsKey` (ZeroizeOnDrop) in place
                    // before `Box` deallocates the holder backing.
                    let dk_offset = core::mem::offset_of!(ActiveHybridPayload, decaps_key);
                    let dk_size = core::mem::size_of::<DecapsKey>();
                    let slice = unsafe {
                        core::slice::from_raw_parts(ptr.as_ptr().add(dk_offset), dk_size)
                    };
                    assert!(
                        slice.iter().all(|&b| b == 0),
                        "ML-KEM DecapsKey must be zeroized before holder deallocation"
                    );
                    state.zeroized_holders += 1;
                }
                state.live -= 1;
                unsafe { self.inner.deallocate(ptr, layout) };
            }
        }

        let layouts = hybrid_kx_layouts();
        assert_eq!(layouts.client_share.size(), CLIENT_SHARE_LEN);
        assert_eq!(layouts.server_share.size(), SERVER_SHARE_LEN);
        assert_eq!(layouts.shared_secret.size(), SHARED_SECRET_LEN);
        assert!(layouts.active_holder.size() >= core::mem::size_of::<DecapsKey>());

        let metadata = PoolMapAllocator::required_metadata_bytes().unwrap();
        let holder_backend = PoolMapAllocator::backend_layout(layouts.active_holder)
            .unwrap()
            .size();
        let client_share_backend = PoolMapAllocator::backend_layout(layouts.client_share)
            .unwrap()
            .size();
        let server_share_backend = PoolMapAllocator::backend_layout(layouts.server_share)
            .unwrap()
            .size();
        let secret_backend = PoolMapAllocator::backend_layout(layouts.shared_secret)
            .unwrap()
            .size();

        // Exact pool budget for client start + server start_and_complete + client complete.
        let full_budget = metadata
            + holder_backend
            + client_share_backend
            + server_share_backend
            + secret_backend * 2;
        let pool = AllocationPoolV1::new(full_budget).unwrap();
        let alloc = InspectingAllocator::new(&pool);

        // 1. Happy path: separate accounting + full round-trip + zeroization on drop.
        let client = start_in(alloc.clone()).expect("client start_in");
        assert_eq!(pool.used(), metadata + holder_backend + client_share_backend);
        assert_eq!(client.group(), NamedGroup::X25519MLKEM768);
        assert_eq!(client.pub_key().len(), CLIENT_SHARE_LEN);
        assert_eq!(client.hybrid_component().0, NamedGroup::X25519);

        let server =
            start_and_complete_in(client.pub_key(), alloc.clone()).expect("server complete_in");
        assert_eq!(
            pool.used(),
            metadata
                + holder_backend
                + client_share_backend
                + server_share_backend
                + secret_backend
        );
        assert_eq!(server.group, NamedGroup::X25519MLKEM768);
        assert_eq!(server.pub_key.len(), SERVER_SHARE_LEN);
        assert!(server.secret.secret_bytes().iter().any(|&b| b != 0));

        let client_secret = client
            .complete_in(&server.pub_key, alloc.clone())
            .expect("client complete_in");
        assert_eq!(client_secret.secret_bytes(), server.secret.secret_bytes());
        assert_eq!(
            pool.used(),
            metadata + server_share_backend + secret_backend * 2
        );
        drop(client_secret);
        drop(server);
        assert_eq!(pool.used(), metadata);
        {
            let state = alloc.state.borrow();
            assert_eq!(state.live, 0);
            assert_eq!(state.zeroized_secrets, 2);
            assert_eq!(state.zeroized_holders, 1);
            assert!(state.layouts.contains(&layouts.active_holder));
            assert!(state.layouts.contains(&layouts.client_share));
            assert!(state.layouts.contains(&layouts.server_share));
            assert!(state.layouts.contains(&layouts.shared_secret));
        }

        // 2. Refusal at every individual allocation site leaves zero live allocations.
        for refuse_at in [0, 1] {
            alloc.arm(Some(refuse_at));
            assert!(matches!(
                start_in(alloc.clone()),
                Err(HybridKxInError::Allocation)
            ));
            assert_eq!(alloc.state.borrow().live, 0);
            assert_eq!(pool.used(), metadata);
        }

        alloc.arm(None);
        let client_for_server = start_in(alloc.clone()).expect("client share");
        let client_share = client_for_server.pub_key().to_vec();
        drop(client_for_server);
        assert_eq!(pool.used(), metadata);

        for refuse_at in [0, 1] {
            alloc.arm(Some(refuse_at));
            assert!(matches!(
                start_and_complete_in(&client_share, alloc.clone()),
                Err(HybridKxInError::Allocation)
            ));
            assert_eq!(alloc.state.borrow().live, 0);
            assert_eq!(pool.used(), metadata);
        }

        alloc.arm(None);
        let client_refusal = start_in(alloc.clone()).expect("client for refusal");
        let server_valid =
            start_and_complete_in(client_refusal.pub_key(), alloc.clone()).expect("server valid");
        alloc.arm(Some(0));
        assert!(matches!(
            client_refusal.complete_in(&server_valid.pub_key, alloc.clone()),
            Err(HybridKxInError::Allocation)
        ));
        drop(server_valid);
        assert_eq!(alloc.state.borrow().live, 0);
        assert_eq!(pool.used(), metadata);

        // 3. Peer-share validation errors clean up and zeroize the holder.
        alloc.arm(None);
        assert!(matches!(
            start_and_complete_in(&[0u8; CLIENT_SHARE_LEN - 1], alloc.clone()),
            Err(HybridKxInError::InvalidKeyShare)
        ));
        assert_eq!(pool.used(), metadata);

        let client_bad_peer = start_in(alloc.clone()).expect("client bad peer");
        assert!(matches!(
            client_bad_peer.complete_in(&[0u8; SERVER_SHARE_LEN - 1], alloc.clone()),
            Err(HybridKxInError::InvalidKeyShare)
        ));
        assert_eq!(alloc.state.borrow().live, 0);
        assert_eq!(pool.used(), metadata);
        drop(alloc);
        assert_eq!(pool.used(), 0);

        // 4. Exact pool-capacity limit-1 refusal for client start_in.
        let tight_short = AllocationPoolV1::new(metadata + holder_backend + client_share_backend - 1)
            .unwrap();
        let tight_alloc = PoolMapAllocator::try_new(&tight_short).unwrap();
        assert!(matches!(
            start_in(tight_alloc.clone()),
            Err(HybridKxInError::Allocation)
        ));
        assert_eq!(tight_short.used(), metadata);
        drop(tight_alloc);
        assert_eq!(tight_short.used(), 0);

        // 5. Live SupportedKxGroup / ActiveKeyExchange connection-budget charging,
        // exhaustion at limit - 1, early-drop release, classical fallback release,
        // and completion release via `with_handshake_budget`.
        let client_start = hybrid_kx_client_start_bytes();
        let client_complete = hybrid_kx_client_complete_bytes();
        let server_bytes = hybrid_kx_server_handshake_bytes();
        assert_eq!(client_complete, SHARED_SECRET_LEN);
        assert_eq!(server_bytes, SERVER_SHARE_LEN + SHARED_SECRET_LEN);

        let short_start = AllocationPoolV1::new(client_start - 1).unwrap();
        assert!(with_handshake_budget(Some(&short_start), || X25519MLKEM768.start()).is_err());
        assert_eq!(short_start.used(), 0);

        let exact_start = AllocationPoolV1::new(client_start).unwrap();
        let active_drop =
            with_handshake_budget(Some(&exact_start), || X25519MLKEM768.start()).unwrap();
        assert_eq!(exact_start.used(), client_start);
        drop(active_drop);
        assert_eq!(exact_start.used(), 0);

        let active_short_complete =
            with_handshake_budget(Some(&exact_start), || X25519MLKEM768.start()).unwrap();
        assert_eq!(exact_start.used(), client_start);
        let short_server = AllocationPoolV1::new(server_bytes - 1).unwrap();
        assert!(with_handshake_budget(Some(&short_server), || {
            X25519MLKEM768.start_and_complete(active_short_complete.pub_key())
        })
        .is_err());
        assert_eq!(short_server.used(), 0);

        let exact_server = AllocationPoolV1::new(server_bytes).unwrap();
        let server_done = with_handshake_budget(Some(&exact_server), || {
            X25519MLKEM768.start_and_complete(active_short_complete.pub_key())
        })
        .unwrap();
        assert_eq!(exact_server.used(), 0);
        // Client pool only has `client_start`, so `complete()` cannot reserve `64 B`.
        assert!(active_short_complete.complete(&server_done.pub_key).is_err());
        assert_eq!(exact_start.used(), 0);

        let full_client = AllocationPoolV1::new(client_start + client_complete).unwrap();
        let active_ok =
            with_handshake_budget(Some(&full_client), || X25519MLKEM768.start()).unwrap();
        assert_eq!(full_client.used(), client_start);
        let server_ok = with_handshake_budget(Some(&exact_server), || {
            X25519MLKEM768.start_and_complete(active_ok.pub_key())
        })
        .unwrap();
        assert_eq!(exact_server.used(), 0);
        let client_ok = active_ok.complete(&server_ok.pub_key).unwrap();
        assert_eq!(client_ok.secret_bytes(), server_ok.secret.secret_bytes());
        assert_eq!(full_client.used(), 0);

        // Classical hybrid-component completion also releases the active holder credit.
        let active_classical =
            with_handshake_budget(Some(&exact_start), || X25519MLKEM768.start()).unwrap();
        assert_eq!(exact_start.used(), client_start);
        let (_, classical_pk) = active_classical.hybrid_component().unwrap();
        let classical_srv = rustls_ring::kx_group::X25519
            .start_and_complete(classical_pk)
            .unwrap();
        let classical_cli = active_classical
            .complete_hybrid_component(&classical_srv.pub_key)
            .unwrap();
        assert_eq!(
            classical_cli.secret_bytes(),
            classical_srv.secret.secret_bytes()
        );
        assert_eq!(exact_start.used(), 0);
    }
}
