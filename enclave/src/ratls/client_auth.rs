// Copyright (c) 2026 Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

//! TLS proof of possession for certificates appraised after the handshake.
//! Anonymous clients may be allowed by the endpoint, but every supplied leaf
//! must prove possession. Accepting its chain here grants no attested identity.

#[cfg(test)]
use rustls::crypto::ring::default_provider;
use rustls::crypto::verify_tls13_signature;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct AttestedClientAuth {
    required: bool,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl AttestedClientAuth {
    pub(crate) fn new(required: bool, provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self { required, provider }
    }
}

/// Parse the P-256 identity used by a v2 evidence binding. Ordinary key-holder
/// certificates can use other TLS algorithms; a TEE evidence leg cannot.
pub(crate) fn attested_leaf_spki(der: &[u8]) -> Result<Vec<u8>, &'static str> {
    use enclave_os_common::oids;
    use x509_parser::prelude::*;
    if der.is_empty() || der.len() > 64 * 1024 {
        return Err("client leaf exceeds certificate bound");
    }
    let (rest, cert) =
        X509Certificate::from_der(der).map_err(|_| "unparseable client certificate")?;
    if !rest.is_empty() {
        return Err("trailing client certificate bytes");
    }
    if cert.extensions().iter().any(|ext| {
        let oid = ext.oid.to_id_string();
        [
            oids::SGX_QUOTE_OID_STR,
            oids::TDX_QUOTE_OID_STR,
            oids::SGX_SIM_REPORT_OID_STR,
        ]
        .contains(&oid.as_str())
    }) {
        return Err("v1 quote certificates cannot supply v2 client evidence");
    }
    let key = cert.public_key();
    let curve = key
        .algorithm
        .parameters
        .as_ref()
        .and_then(|value| value.as_oid().ok())
        .map(|oid| oid.to_id_string());
    if key.algorithm.algorithm.to_id_string() != "1.2.840.10045.2.1"
        || curve.as_deref() != Some("1.2.840.10045.3.1.7")
        || key.subject_public_key.unused_bits != 0
        || key.subject_public_key.as_ref().len() != 65
        || key.subject_public_key.as_ref()[0] != 4
    {
        return Err("client evidence requires an uncompressed P-256 identity");
    }
    Ok(enclave_os_common::quote::build_p256_spki_der(
        key.subject_public_key.as_ref(),
    ))
}

impl ClientCertVerifier for AttestedClientAuth {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        self.required
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if end_entity.as_ref().is_empty() {
            return Err(Error::General("client certificate is empty".into()));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        Err(Error::General("RA-TLS v2 requires TLS 1.3".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    #[cfg(honest_retained_provider)]
    fn supported_verify_schemes(
        &self,
        visit: &mut dyn FnMut(SignatureScheme) -> Result<(), Error>,
    ) -> Result<(), Error> {
        for (scheme, _) in self.provider.signature_verification_algorithms.mapping {
            visit(*scheme)?;
        }
        Ok(())
    }
    #[cfg(not(honest_retained_provider))]
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::ResolvesClientCert;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::sign::CertifiedKey;
    use rustls::{ClientConfig, ClientConnection, RootCertStore};

    #[derive(Debug)]
    struct UncheckedIdentity(Arc<CertifiedKey>);

    impl ResolvesClientCert for UncheckedIdentity {
        #[cfg(honest_retained_provider)]
        fn resolve(
            &self,
            _: &[&[u8]],
            _: &[SignatureScheme],
        ) -> Result<Option<Arc<CertifiedKey>>, Error> {
            Ok(Some(self.0.clone()))
        }
        #[cfg(not(honest_retained_provider))]
        fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
        fn has_certs(&self) -> bool {
            true
        }
    }

    fn handshake(required: bool, present: bool, wrong_key: bool) -> Result<(), Error> {
        let server_identity =
            rcgen::generate_simple_self_signed(vec!["fixture.test".into()]).unwrap();
        let client_identity =
            rcgen::generate_simple_self_signed(vec!["client.test".into()]).unwrap();
        let different_identity =
            rcgen::generate_simple_self_signed(vec!["different.test".into()]).unwrap();
        let provider = Arc::new(default_provider());
        use crate::ratls::session::retained_tls_config::{ClientAuthentication, RetainedTlsConfig};
        let authentication = ClientAuthentication::Attested { required };
        let certificates = [server_identity.cert.der().clone()];
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            server_identity.key_pair.serialize_der(),
        ));
        let (certificate_bytes, _) =
            crate::ratls::session::retained_tls_config::ConfigReservation::factory_bytes(
                &certificates,
                &private_key,
            )
            .unwrap();
        let config_pool = enclave_os_common::allocation::AllocationPoolV1::new(
            RetainedTlsConfig::required_bytes(authentication)
                .unwrap()
                .checked_add(certificate_bytes)
                .unwrap(),
        )
        .unwrap();
        let server_config = RetainedTlsConfig::reserve(&config_pool, authentication)
            .unwrap()
            .configure(&certificates, private_key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(server_identity.cert.der().clone()).unwrap();
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots);
        let client_config = if present {
            let key = if wrong_key {
                &different_identity.key_pair
            } else {
                &client_identity.key_pair
            };
            let signing_key = provider
                .key_provider
                .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    key.serialize_der(),
                )))
                .unwrap();
            builder.with_client_cert_resolver(Arc::new(UncheckedIdentity(Arc::new(
                CertifiedKey::new(vec![client_identity.cert.der().clone()], signing_key),
            ))))
        } else {
            builder.with_no_client_auth()
        };
        let mut client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from("fixture.test").unwrap(),
        )
        .unwrap();
        let mut server = server_config.connect().unwrap();
        for _ in 0..8 {
            let mut wire = Vec::new();
            client.write_tls(&mut wire).unwrap();
            if !wire.is_empty() {
                server.read_tls(&mut wire.as_slice()).unwrap();
                server.process_new_packets()?;
            }
            wire.clear();
            server.write_tls(&mut wire).unwrap();
            if !wire.is_empty() {
                client.read_tls(&mut wire.as_slice()).unwrap();
                client.process_new_packets()?;
            }
            if !server.is_handshaking() && !client.is_handshaking() {
                return Ok(());
            }
        }
        panic!("fixture TLS handshake did not finish");
    }

    #[test]
    fn optional_and_required_certificates_both_prove_private_key_possession() {
        for required in [false, true] {
            assert!(handshake(required, true, false).is_ok());
            assert!(matches!(
                handshake(required, true, true),
                Err(Error::InvalidCertificate(_))
            ));
        }
        assert!(handshake(false, false, false).is_ok());
        assert!(matches!(
            handshake(true, false, false),
            Err(Error::NoCertificatesPresented)
        ));
    }

    #[test]
    fn evidence_leaf_rejects_legacy_quotes_other_curves_and_trailing_der() {
        let good = rcgen::generate_simple_self_signed(vec!["client.test".into()]).unwrap();
        assert_eq!(
            attested_leaf_spki(good.cert.der()).unwrap(),
            good.key_pair.public_key_der()
        );
        let mut trailing = good.cert.der().to_vec();
        trailing.push(0);
        assert!(attested_leaf_spki(&trailing).is_err());
        assert!(attested_leaf_spki(&[]).is_err());
        assert!(attested_leaf_spki(&vec![0; 64 * 1024 + 1]).is_err());
        for oid in [
            enclave_os_common::oids::SGX_QUOTE_OID,
            enclave_os_common::oids::TDX_QUOTE_OID,
            enclave_os_common::oids::SGX_SIM_REPORT_OID,
        ] {
            let mut params = rcgen::CertificateParams::new(vec!["client.test".into()]).unwrap();
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(oid, vec![1]));
            let cert = params.self_signed(&good.key_pair).unwrap();
            assert!(attested_leaf_spki(cert.der()).is_err());
        }
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["client.test".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        assert!(attested_leaf_spki(cert.der()).is_err());
    }
}
