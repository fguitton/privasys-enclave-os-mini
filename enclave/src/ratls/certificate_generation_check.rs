//! Independent rcgen wire and crypto oracle, called by the existing Session owner.
use super::{certificate_wire, leaf_key::RetainedLeafKey};
use der::Decode;
use enclave_os_common::allocation::AllocationPoolV1;
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, DnValue, IsCa, KeyPair,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use x509_parser::prelude::parse_x509_certificate;

fn tbs(bytes: &[u8]) -> &[u8] {
    let outer = der::asn1::AnyRef::from_der(bytes).unwrap().value();
    let (_, rest) = der::asn1::AnyRef::from_der_partial(outer).unwrap();
    &outer[..outer.len() - rest.len()]
}
fn verify(bytes: &[u8], signer: &KeyPair) {
    let (_, certificate) = parse_x509_certificate(bytes).unwrap();
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_ASN1,
        signer.public_key_raw(),
    )
    .verify(
        certificate.tbs_certificate.as_ref(),
        certificate.signature_value.data.as_ref(),
    )
    .unwrap();
}
pub(super) fn check() {
    // Only a test success fixture. Admission boundaries below derive the exact
    // actual requested buffer length, not this fixture's available capacity.
    let pool = AllocationPoolV1::new(usize::MAX / 2).unwrap();
    let key = RetainedLeafKey::new(&pool, 1_770_000_000).unwrap();
    let signer = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(key.pkcs8.as_slice()),
        &PKCS_ECDSA_P256_SHA256,
    )
    .unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(
        DnType::CommonName,
        DnValue::Utf8String("Honest enclave local CA".into()),
    );
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2124, 1, 1);
    let ordinary = params.self_signed(&signer).unwrap();
    let paid = certificate_wire::ca(&pool, &key).unwrap();
    assert_eq!(tbs(paid.as_slice()), tbs(ordinary.der()));
    verify(paid.as_slice(), &signer);
    let ca =
        super::ca_context::CaContext::from_parts(ordinary.der().to_vec(), signer.serialize_der())
            .unwrap();
    let leaf_key = RetainedLeafKey::new(&pool, key.created).unwrap();
    let leaf_signer = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(leaf_key.pkcs8.as_slice()),
        &PKCS_ECDSA_P256_SHA256,
    )
    .unwrap();
    let names = ["enclave-os.invalid", "127.0.0.1", "::1"];
    let before = rcgen::date_time_ymd(2024, 1, 2);
    let after = rcgen::date_time_ymd(2124, 2, 3);
    let mut extensions = certificate_wire::Extensions::new();
    let custom: &'static [u64] = &[1, 3, 6, 1, 4, 1, 65230, 9, 1];
    extensions.push(&pool, custom, &[0, 1, 0x80, 0xff]).unwrap();
    let mut params = CertificateParams::new(
        names
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    params.distinguished_name.push(
        DnType::CommonName,
        DnValue::Utf8String("Enclave OS RA-TLS".into()),
    );
    params.not_before = before;
    params.not_after = after;
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            custom,
            vec![0, 1, 0x80, 0xff],
        ));
    let ordinary_leaf = params.signed_by(&leaf_signer, &ordinary, &signer).unwrap();
    let paid_leaf = certificate_wire::leaf(
        &pool,
        &leaf_key,
        before,
        after,
        &ca,
        "Enclave OS RA-TLS",
        &names,
        &extensions,
    )
    .unwrap();
    assert_eq!(tbs(paid_leaf.as_slice()), tbs(ordinary_leaf.der()));
    verify(paid_leaf.as_slice(), &signer);
    drop(paid_leaf);
    drop(extensions);
    drop(paid);
    drop(leaf_key);
    drop(key);
    assert_eq!(
        pool.used(),
        0,
        "all working/final/key backing must refund after final free"
    );
    #[cfg(feature = "fallible-allocation-v1")]
    crate::client::check_credential_owner(
        &[ordinary.der(), ordinary_leaf.der()],
        &signer.serialize_der(),
    );
    check_buffer_admission();
}
fn check_buffer_admission() {
    let encoded = [0x04, 3, 0x80, 1, 2];
    for available in [encoded.len() - 1, encoded.len(), encoded.len() + 1] {
        let pool = AllocationPoolV1::new(available).unwrap();
        let result = certificate_wire::PaidDer::encode(&pool, |w| w.write(&encoded));
        if available < encoded.len() {
            assert!(result.is_err());
            assert_eq!(pool.used(), 0);
        } else {
            let bytes = result.unwrap();
            assert_eq!(bytes.as_slice(), encoded);
            assert_eq!(pool.used(), encoded.len());
            drop(bytes);
            assert_eq!(pool.used(), 0);
        }
    }
}
