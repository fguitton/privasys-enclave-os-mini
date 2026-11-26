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

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::num::NonZeroU32;
use std::sync::Arc;

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
const CLIENT_SHARE_LEN: usize = EK_LEN + X25519_LEN;
const SERVER_SHARE_LEN: usize = CT_LEN + X25519_LEN;
const SHARED_SECRET_LEN: usize = SSK_LEN + X25519_LEN;

const _: () = {
    assert!(EK_LEN == 1184);
    assert!(CT_LEN == 1088);
    assert!(SSK_LEN == 32);
    assert!(CLIENT_SHARE_LEN == 1216);
    assert!(SERVER_SHARE_LEN == 1120);
    assert!(SHARED_SECRET_LEN == 64);
};

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
        let classical = rustls_ring::kx_group::X25519.start()?;
        let mut rng = SystemRngAdapter::new();
        let (ek, dk) = KG::try_keygen_with_rng(&mut rng).map_err(|_| Error::FailedToGetRandomBytes)?;
        let ek_bytes = ek.into_bytes();
        let mut combined_pub_key = Vec::with_capacity(CLIENT_SHARE_LEN);
        combined_pub_key.extend_from_slice(&ek_bytes);
        combined_pub_key.extend_from_slice(classical.pub_key());
        Ok(Box::new(ActiveX25519MlKem768 {
            classical,
            decaps_key: dk,
            combined_pub_key,
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if client_share.len() != CLIENT_SHARE_LEN {
            return Err(INVALID_KEY_SHARE);
        }
        let (pq_share, classical_share) = client_share.split_at(EK_LEN);
        let ek_array: [u8; EK_LEN] = pq_share.try_into().map_err(|_| INVALID_KEY_SHARE)?;
        let ek = EncapsKey::try_from_bytes(ek_array).map_err(|_| INVALID_KEY_SHARE)?;

        let classical = rustls_ring::kx_group::X25519.start_and_complete(classical_share)?;
        let mut rng = SystemRngAdapter::new();
        let (pq_secret, ct) = ek
            .try_encaps_with_rng(&mut rng)
            .map_err(|_| Error::FailedToGetRandomBytes)?;

        let pq_secret_bytes = Zeroizing::new(pq_secret.into_bytes());
        let mut combined_pub_key = Vec::with_capacity(SERVER_SHARE_LEN);
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
    classical: Box<dyn ActiveKeyExchange>,
    decaps_key: DecapsKey,
    combined_pub_key: Vec<u8>,
}

impl ActiveKeyExchange for ActiveX25519MlKem768 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != SERVER_SHARE_LEN {
            return Err(INVALID_KEY_SHARE);
        }
        let (pq_share, classical_share) = peer_pub_key.split_at(CT_LEN);
        let ct_array: [u8; CT_LEN] = pq_share.try_into().map_err(|_| INVALID_KEY_SHARE)?;
        let ct = CipherText::try_from_bytes(ct_array).map_err(|_| INVALID_KEY_SHARE)?;

        let classical_secret = self.classical.complete(classical_share)?;
        let pq_secret = self
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
        Some((self.classical.group(), self.classical.pub_key()))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        self.classical.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.combined_pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
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
}
