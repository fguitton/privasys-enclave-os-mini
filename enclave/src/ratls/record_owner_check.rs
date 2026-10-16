//! Pure primitive record oracle shared by existing native and signed owners.
pub(super) fn check_record_wire(
    suite: rustls::SupportedCipherSuite,
    independent: &'static ring::aead::Algorithm,
    #[cfg(feature = "fallible-allocation-v1")] allocator: rustls::RetainedAllocator,
) {
    use rustls::crypto::cipher::{
        make_tls13_aad, AeadKey, InboundOpaqueMessage, Iv, Nonce, OutboundChunks,
        OutboundPlainMessage,
    };
    #[cfg(feature = "fallible-allocation-v1")]
    use rustls::crypto::cipher::{MessageDecrypter, MessageEncrypter};
    use rustls::{ContentType, ProtocolVersion};
    let cipher = suite.tls13().unwrap().aead_alg;
    let plaintext = b"retained original record bytes";
    let seq = 7;
    let mut enc = cipher.encrypter(AeadKey::from([7; 32]), Iv::from([0; 12]));
    let message = || OutboundPlainMessage {
        typ: ContentType::ApplicationData,
        version: ProtocolVersion::TLSv1_3,
        payload: OutboundChunks::Single(plaintext),
    };
    #[cfg(feature = "fallible-allocation-v1")]
    let encrypted = {
        use rustls::crypto::cipher::PrefixedPayload;
        let short_allocator = allocator.clone();
        let short = PrefixedPayload::try_with_capacity_in(0, short_allocator).unwrap();
        assert!(matches!(
            enc.encrypt(message(), seq, short),
            Err(rustls::Error::AllocationFailed)
        ));
        let backing = PrefixedPayload::try_with_capacity_in(
            enc.encrypted_payload_len(plaintext.len()),
            allocator,
        )
        .unwrap();
        enc.encrypt(message(), seq, backing).unwrap()
    };
    #[cfg(not(feature = "fallible-allocation-v1"))]
    let encrypted = enc.encrypt(message(), seq).unwrap();
    assert_eq!(encrypted.typ, ContentType::ApplicationData);
    assert_eq!(encrypted.version, ProtocolVersion::TLSv1_2);
    let mut expected = plaintext.to_vec();
    expected.push(u8::from(ContentType::ApplicationData));
    let aad = make_tls13_aad(expected.len() + independent.tag_len());
    ring::aead::LessSafeKey::new(ring::aead::UnboundKey::new(independent, &[7; 32]).unwrap())
        .seal_in_place_append_tag(
            ring::aead::Nonce::assume_unique_for_key(Nonce::new(&Iv::from([0; 12]), seq).0),
            ring::aead::Aad::from(aad),
            &mut expected,
        )
        .unwrap();
    assert_eq!(encrypted.payload.as_ref(), expected);
    let mut current = expected.clone();
    let mut dec = cipher.decrypter(AeadKey::from([7; 32]), Iv::from([0; 12]));
    let decoded = dec
        .decrypt(
            InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut current,
            ),
            seq,
        )
        .unwrap();
    assert_eq!(decoded.typ, ContentType::ApplicationData);
    assert_eq!(decoded.version, ProtocolVersion::TLSv1_3);
    assert_eq!(decoded.payload, plaintext);
    expected[0] ^= 1;
    assert!(dec
        .decrypt(
            InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut expected
            ),
            seq
        )
        .is_err());
}
