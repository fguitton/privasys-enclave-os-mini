//! Independent ordinary rcgen oracle for the selected borrowed issuer parser.
use rcgen::{BasicConstraints, CertificateParams, CustomExtension, IsCa, KeyPair};

pub(super) fn check() {
    let key = KeyPair::generate().expect("issuer oracle key");
    let certificate = |extensions: &[(&[u64], &[u8])], ca: IsCa| {
        let mut params = CertificateParams::default();
        params.is_ca = ca;
        for &(id, value) in extensions {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(id, value.to_vec()));
        }
        params
            .self_signed(&key)
            .expect("issuer oracle certificate")
            .der()
            .to_vec()
    };
    let compare = |bytes: &[u8], expected: bool| {
        let ordinary = CertificateParams::from_ca_cert_der(&bytes.into()).is_ok();
        let borrowed = super::certificate_issuer::subject(bytes).is_ok();
        assert_eq!(ordinary, expected, "independent issuer oracle disposition");
        assert_eq!(
            borrowed, ordinary,
            "borrowed issuer parser differs from current ordinary oracle"
        );
    };
    let valid = certificate(&[], IsCa::Ca(BasicConstraints::Unconstrained));
    compare(&valid, true);
    for end in 0..valid.len() {
        compare(&valid[..end], false);
    }
    let mut trailing = valid.clone();
    trailing.extend_from_slice(b"outer trailing bytes");
    compare(&trailing, true);
    // Known extensions retain their original conversion refusals. Unknown
    // extensions and an unparsed basicConstraints retain the old acceptance.
    compare(
        &certificate(
            &[(&[2, 5, 29, 19], &[0x30, 7, 1, 1, 0xff, 2, 2, 1, 0])],
            IsCa::NoCa,
        ),
        false,
    );
    compare(
        &certificate(
            &[(&[2, 5, 29, 19], &[0x30, 7, 1, 1, 0, 2, 2, 1, 0])],
            IsCa::NoCa,
        ),
        true,
    );
    compare(&certificate(&[(&[2, 5, 29, 19], &[0])], IsCa::NoCa), true);
    compare(
        &certificate(
            &[(&[2, 5, 29, 17], &[0x30, 5, 0x87, 3, 1, 2, 3])],
            IsCa::NoCa,
        ),
        false,
    );
    compare(
        &certificate(
            &[(&[2, 5, 29, 17], &[0x30, 6, 0x87, 4, 127, 0, 0, 1])],
            IsCa::NoCa,
        ),
        true,
    );
    compare(
        &certificate(
            &[
                (&[2, 5, 29, 15], &[3, 2, 5, 0xa0]),
                (&[2, 5, 29, 15], &[3, 2, 5, 0xa0]),
            ],
            IsCa::NoCa,
        ),
        false,
    );
    compare(&certificate(&[(&[2, 5, 29, 37], &[0])], IsCa::NoCa), false);
    compare(&certificate(&[(&[2, 5, 29, 30], &[0])], IsCa::NoCa), false);
    compare(&certificate(&[(&[1, 2, 3, 4], &[0xff])], IsCa::NoCa), true);
    let borrowed = super::certificate_issuer::subject(&valid).unwrap();
    let start = valid.as_ptr() as usize;
    let subject = borrowed.as_ptr() as usize;
    assert!(
        subject >= start && subject + borrowed.len() <= start + valid.len(),
        "issuer subject must borrow original DER"
    );
}
