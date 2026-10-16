//! The selected P-256 certificate producer. Borrowed DER fields are encoded
//! directly into admitted final slices; no rcgen/yasna builder or PKCS8 copy.
use der::{asn1::AnyRef, Decode, Encode, Header, Length, Reader, Tag, Tagged, Writer};
use enclave_os_common::allocation::{AllocationLeaseV1, AllocationPoolV1};
use ring::{
    digest,
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use std::{alloc::Layout, sync::Arc};
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CertificateError {
    Allocation,
    Encoding,
    Signing,
    InvalidCa,
    InvalidKey,
}
impl From<CertificateError> for String {
    fn from(error: CertificateError) -> Self {
        Self::from(match error {
            CertificateError::Allocation => "certificate allocation refused",
            CertificateError::Encoding => "invalid certificate encoding",
            CertificateError::Signing => "certificate signing failed",
            CertificateError::InvalidCa => "CA cert parse: invalid certificate",
            CertificateError::InvalidKey => "invalid P256 PKCS8 key",
        })
    }
}
pub(crate) type Result<T> = core::result::Result<T, CertificateError>;
const REFUSED: CertificateError = CertificateError::Allocation;
const INVALID: CertificateError = CertificateError::Encoding;
const CERTIFICATE_IDENTIFIER_BYTES: usize = 20;
const SIGNATURE_OID: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
const COMMON_NAME: &[u64] = &[2, 5, 4, 3];
const SUBJECT_ALTERNATIVE_NAME: &[u64] = &[2, 5, 29, 17];
const SUBJECT_KEY_IDENTIFIER: &[u64] = &[2, 5, 29, 14];
const BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];
const ORGANISATION_FIELDS: [&[u8]; 5] = [
    &[85, 4, 6],
    &[85, 4, 8],
    &[85, 4, 7],
    &[85, 4, 10],
    &[85, 4, 11],
];

/// Backing dies before original credit, including unsuccessful working output.
pub(crate) struct PaidDer {
    bytes: Vec<u8>,
    _credit: AllocationLeaseV1,
}
impl PaidDer {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn encode(
        pool: &Arc<AllocationPoolV1>,
        encode: impl Fn(&mut dyn Writer) -> der::Result<()>,
    ) -> Result<Self> {
        let mut measured = Count(0);
        encode(&mut measured).map_err(|_| INVALID)?;
        let layout = Layout::array::<u8>(measured.0).map_err(|_| REFUSED)?;
        let credit = pool.reserve_unpublished(layout.size()).ok_or(REFUSED)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(layout.size())
            .map_err(|_| REFUSED)?;
        if bytes.capacity() != layout.size() {
            return Err(REFUSED);
        }
        bytes.resize(layout.size(), 0);
        let mut writer = der::SliceWriter::new(&mut bytes);
        encode(&mut writer).map_err(|_| INVALID)?;
        writer.finish().map_err(|_| INVALID)?;
        Ok(Self {
            bytes,
            _credit: credit,
        })
    }
}
struct Count(usize);
impl Writer for Count {
    fn write(&mut self, bytes: &[u8]) -> der::Result<()> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or(der::ErrorKind::Overflow)?;
        Length::try_from(self.0)?;
        Ok(())
    }
}
struct Output<'a>(&'a mut dyn Writer);
impl Writer for Output<'_> {
    fn write(&mut self, bytes: &[u8]) -> der::Result<()> {
        self.0.write(bytes)
    }
}
fn tlv(w: &mut dyn Writer, tag: Tag, content: &[u8]) -> der::Result<()> {
    AnyRef::new(tag, content)?.encode(&mut Output(w))
}
fn group(
    w: &mut dyn Writer,
    tag: Tag,
    body: impl Fn(&mut dyn Writer) -> der::Result<()>,
) -> der::Result<()> {
    let mut count = Count(0);
    body(&mut count)?;
    Header::new(tag, Length::try_from(count.0)?).encode(&mut Output(w))?;
    body(w)
}
fn sequence(
    w: &mut dyn Writer,
    body: impl Fn(&mut dyn Writer) -> der::Result<()>,
) -> der::Result<()> {
    group(w, Tag::Sequence, body)
}
fn oid(w: &mut dyn Writer, parts: &[u64]) -> der::Result<()> {
    let [first, second, tail @ ..] = parts else {
        return Err(Tag::ObjectIdentifier.value_error().into());
    };
    // Same accepted u64 OID domain as the previous producer, without a new
    // ObjectIdentifier<N> maximum or temporary owned OID.
    if *first >= 3 || (*first < 2 && *second >= 40) || *second >= u64::MAX - 80 {
        return Err(Tag::ObjectIdentifier.value_error().into());
    }
    let head = first * 40 + second;
    let body = |w: &mut dyn Writer| {
        for value in core::iter::once(&head).chain(tail) {
            let mut bytes = [0u8; u64::BITS.div_ceil(7) as usize];
            let mut position = bytes.len();
            let mut value = *value;
            loop {
                position -= 1;
                bytes[position] = (value & 0x7f) as u8;
                if position + 1 < bytes.len() {
                    bytes[position] |= 0x80;
                }
                value >>= 7;
                if value == 0 {
                    break;
                }
            }
            w.write(&bytes[position..])?;
        }
        Ok(())
    };
    group(w, Tag::ObjectIdentifier, body)
}
fn signature_algorithm(w: &mut dyn Writer) -> der::Result<()> {
    sequence(w, |w| oid(w, SIGNATURE_OID))
}
fn time(w: &mut dyn Writer, value: OffsetDateTime) -> der::Result<()> {
    let year = value.year();
    if !(0..=9999).contains(&year) {
        return Err(Tag::GeneralizedTime.value_error().into());
    }
    let utc = (1950..2050).contains(&year);
    let mut bytes = [0u8; 15];
    let mut position = 0;
    let mut number = |value: u32, width: usize| {
        for offset in (0..width).rev() {
            bytes[position] = b'0' + ((value / 10u32.pow(offset as u32)) % 10) as u8;
            position += 1;
        }
    };
    number(
        if utc {
            (year % 100) as u32
        } else {
            year as u32
        },
        if utc { 2 } else { 4 },
    );
    number(u32::from(u8::from(value.month())), 2);
    number(u32::from(value.day()), 2);
    number(u32::from(value.hour()), 2);
    number(u32::from(value.minute()), 2);
    number(u32::from(value.second()), 2);
    bytes[position] = b'Z';
    position += 1;
    tlv(
        w,
        if utc {
            Tag::UtcTime
        } else {
            Tag::GeneralizedTime
        },
        &bytes[..position],
    )
}
fn next<'a>(bytes: &mut &'a [u8]) -> der::Result<AnyRef<'a>> {
    let (value, rest) = AnyRef::from_der_partial(bytes)?;
    *bytes = rest;
    Ok(value)
}
fn expect<'a>(bytes: &mut &'a [u8], tag: Tag) -> der::Result<&'a [u8]> {
    let value = next(bytes)?;
    if value.tag() != tag {
        return Err(tag.value_error().into());
    }
    Ok(value.value())
}
#[derive(Clone, Copy)]
struct NameValue<'a> {
    tag: u8,
    value: &'a [u8],
}
fn name_value<'a>(bytes: &mut &'a [u8]) -> der::Result<NameValue<'a>> {
    let (&tag, encoded) = bytes.split_first().ok_or(der::ErrorKind::Incomplete {
        expected_len: Length::ONE,
        actual_len: Length::ZERO,
    })?;
    let mut reader = der::SliceReader::new(encoded)?;
    let length = usize::try_from(Length::decode(&mut reader)?)?;
    let head = usize::try_from(reader.position())?;
    let end = head.checked_add(length).ok_or(der::ErrorKind::Overflow)?;
    let value = encoded.get(head..end).ok_or(der::ErrorKind::Overflow)?;
    *bytes = &encoded[end..];
    Ok(NameValue { tag, value })
}
fn write_name_value(w: &mut dyn Writer, value: NameValue<'_>) -> der::Result<()> {
    w.write(&[value.tag])?;
    Length::try_from(value.value.len())?.encode(&mut Output(w))?;
    w.write(value.value)
}
fn attributes<'a>(
    mut bytes: &'a [u8],
    mut visit: impl FnMut(&'a [u8], NameValue<'a>) -> der::Result<()>,
) -> der::Result<()> {
    while !bytes.is_empty() {
        let mut set = expect(&mut bytes, Tag::Set)?;
        while !set.is_empty() {
            let mut attr = expect(&mut set, Tag::Sequence)?;
            let id = expect(&mut attr, Tag::ObjectIdentifier)?;
            let value = name_value(&mut attr)?;
            if !attr.is_empty() {
                return Err(Tag::Sequence.value_error().into());
            }
            validate_name_value(value)?;
            visit(id, value)?;
        }
    }
    Ok(())
}
fn validate_name_value(value: NameValue<'_>) -> der::Result<()> {
    let bytes = value.value;
    let valid = match value.tag {
        0x0c | 0x14 => core::str::from_utf8(bytes).is_ok(),
        0x16 => bytes.is_ascii(),
        0x13 => bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(b)),
        0x1e => {
            bytes.len() % 2 == 0
                && core::char::decode_utf16(
                    bytes
                        .chunks_exact(2)
                        .map(|b| u16::from_be_bytes([b[0], b[1]])),
                )
                .all(|c| c.is_ok_and(|c| u32::from(c) < u32::from(u16::MAX)))
        }
        0x1c => {
            bytes.len() % 4 == 0
                && bytes
                    .chunks_exact(4)
                    .all(|b| char::from_u32(u32::from_be_bytes([b[0], b[1], b[2], b[3]])).is_some())
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(Tag::Utf8String.value_error().into())
    }
}
fn attribute(w: &mut dyn Writer, id: &[u8], value: NameValue<'_>) -> der::Result<()> {
    group(w, Tag::Set, |w| {
        sequence(w, |w| {
            tlv(w, Tag::ObjectIdentifier, id)?;
            write_name_value(w, value)
        })
    })
}
fn common_name(w: &mut dyn Writer, name: &str) -> der::Result<()> {
    group(w, Tag::Set, |w| {
        sequence(w, |w| {
            oid(w, COMMON_NAME)?;
            tlv(w, Tag::Utf8String, name.as_bytes())
        })
    })
}
/// rcgen's current issuer normalisation: first OID order, last value for a
/// repeated OID, one RDN per attribute. This visits borrowed original DER.
fn name(w: &mut dyn Writer, original: Option<&[u8]>, subject: Option<&str>) -> der::Result<()> {
    sequence(w, |w| {
        if let Some(subject) = subject {
            common_name(w, subject)?;
            if let Some(original) = original {
                for id in ORGANISATION_FIELDS {
                    let mut found = None;
                    attributes(original, |candidate, value| {
                        if candidate == id {
                            found = Some(value);
                        }
                        Ok(())
                    })?;
                    if let Some(value) = found {
                        attribute(w, id, value)?;
                    }
                }
            }
        } else if let Some(original) = original {
            let mut index = 0usize;
            attributes(original, |id, _| {
                let current = index;
                index += 1;
                let mut before = 0usize;
                let mut seen = false;
                let mut last = None;
                attributes(original, |candidate, value| {
                    if candidate == id {
                        if before < current {
                            seen = true;
                        }
                        last = Some(value);
                    }
                    before += 1;
                    Ok(())
                })?;
                if !seen {
                    attribute(w, id, last.ok_or(Tag::Sequence.value_error())?)?;
                }
                Ok(())
            })?;
        }
        Ok(())
    })
}
fn issuer_subject(cert: &[u8]) -> der::Result<&[u8]> {
    super::certificate_issuer::subject(cert)
}

pub(crate) struct Extensions {
    values: Vec<(&'static [u64], PaidDer)>,
    credit: Option<AllocationLeaseV1>,
}
impl Extensions {
    pub(crate) fn new() -> Self {
        Self {
            values: Vec::new(),
            credit: None,
        }
    }
    pub(crate) fn push(
        &mut self,
        pool: &Arc<AllocationPoolV1>,
        id: &'static [u64],
        value: &[u8],
    ) -> Result<()> {
        let bytes = PaidDer::encode(pool, |w| w.write(value))?;
        let count = self.values.len().checked_add(1).ok_or(REFUSED)?;
        let layout = Layout::array::<(&'static [u64], PaidDer)>(count).map_err(|_| REFUSED)?;
        let credit = pool.reserve_unpublished(layout.size()).ok_or(REFUSED)?;
        let mut values = Vec::new();
        values.try_reserve_exact(count).map_err(|_| REFUSED)?;
        if values.capacity() != count {
            return Err(REFUSED);
        }
        values.append(&mut self.values);
        values.push((id, bytes));
        let old = core::mem::replace(&mut self.values, values);
        drop(old);
        self.credit = Some(credit);
        Ok(())
    }
}
fn extension(
    w: &mut dyn Writer,
    id: &[u64],
    critical: bool,
    value: impl Fn(&mut dyn Writer) -> der::Result<()>,
) -> der::Result<()> {
    sequence(w, |w| {
        oid(w, id)?;
        if critical {
            tlv(w, Tag::Boolean, &[0xff])?;
        }
        group(w, Tag::OctetString, &value)
    })
}
fn sans(w: &mut dyn Writer, names: &[&str]) -> der::Result<()> {
    sequence(w, |w| {
        for name in names {
            if let Ok(ip) = name.parse::<std::net::IpAddr>() {
                match ip {
                    std::net::IpAddr::V4(ip) => {
                        tlv(w, der::TagNumber(7).context_specific(false), &ip.octets())?
                    }
                    std::net::IpAddr::V6(ip) => {
                        tlv(w, der::TagNumber(7).context_specific(false), &ip.octets())?
                    }
                }
            } else {
                if !name.is_ascii() {
                    return Err(Tag::Ia5String.value_error().into());
                }
                tlv(
                    w,
                    der::TagNumber(2).context_specific(false),
                    name.as_bytes(),
                )?;
            }
        }
        Ok(())
    })
}
struct Certificate<'a> {
    serial: [u8; CERTIFICATE_IDENTIFIER_BYTES],
    spki: &'a [u8],
    issuer: Option<&'a [u8]>,
    subject: &'a str,
    names: &'a [&'a str],
    extensions: &'a Extensions,
    before: OffsetDateTime,
    after: OffsetDateTime,
    ca: bool,
}
impl Certificate<'_> {
    fn tbs(&self, w: &mut dyn Writer) -> der::Result<()> {
        sequence(w, |w| {
            group(w, der::TagNumber(0).context_specific(true), |w| {
                tlv(w, Tag::Integer, &[2])
            })?;
            der::asn1::UintRef::new(&self.serial)?.encode(&mut Output(w))?;
            signature_algorithm(w)?;
            name(
                w,
                self.issuer,
                self.issuer.is_none().then_some(self.subject),
            )?;
            sequence(w, |w| {
                time(w, self.before)?;
                time(w, self.after)
            })?;
            name(w, self.issuer, Some(self.subject))?;
            w.write(self.spki)?;
            if self.ca || !self.names.is_empty() || !self.extensions.values.is_empty() {
                group(w, der::TagNumber(3).context_specific(true), |w| {
                    sequence(w, |w| {
                        if !self.names.is_empty() {
                            extension(w, SUBJECT_ALTERNATIVE_NAME, false, |w| sans(w, self.names))?;
                        }
                        for (id, value) in &self.extensions.values {
                            extension(w, id, false, |w| w.write(value.as_slice()))?;
                        }
                        if self.ca {
                            let key_id = digest::digest(&digest::SHA256, self.spki);
                            extension(w, SUBJECT_KEY_IDENTIFIER, false, |w| {
                                tlv(
                                    w,
                                    Tag::OctetString,
                                    &key_id.as_ref()[..CERTIFICATE_IDENTIFIER_BYTES],
                                )
                            })?;
                            extension(w, BASIC_CONSTRAINTS, true, |w| {
                                sequence(w, |w| tlv(w, Tag::Boolean, &[0xff]))
                            })?;
                        }
                        Ok(())
                    })
                })?;
            }
            Ok(())
        })
    }
}
fn sign(
    pool: &Arc<AllocationPoolV1>,
    certificate: Certificate<'_>,
    key: &EcdsaKeyPair,
) -> Result<PaidDer> {
    let tbs = PaidDer::encode(pool, |w| certificate.tbs(w))?;
    let signature = key
        .sign(&SystemRandom::new(), tbs.as_slice())
        .map_err(|_| CertificateError::Signing)?;
    PaidDer::encode(pool, |w| {
        sequence(w, |w| {
            w.write(tbs.as_slice())?;
            signature_algorithm(w)?;
            der::asn1::BitStringRef::new(0, signature.as_ref())?.encode(&mut Output(w))
        })
    })
}
fn serial(key: &EcdsaKeyPair) -> [u8; CERTIFICATE_IDENTIFIER_BYTES] {
    let digest = digest::digest(&digest::SHA256, key.public_key().as_ref());
    let mut serial = [0; CERTIFICATE_IDENTIFIER_BYTES];
    serial.copy_from_slice(&digest.as_ref()[..CERTIFICATE_IDENTIFIER_BYTES]);
    serial[0] &= 0x7f;
    serial
}
pub(crate) fn ca(pool: &Arc<AllocationPoolV1>, key: &super::leaf_key::LeafKey) -> Result<PaidDer> {
    let pair = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        &key.pkcs8,
        &SystemRandom::new(),
    )
    .map_err(|_| CertificateError::InvalidKey)?;
    let before = time::Date::from_calendar_date(2024, time::Month::January, 1)
        .map_err(|_| INVALID)?
        .midnight()
        .assume_utc();
    let after = time::Date::from_calendar_date(2124, time::Month::January, 1)
        .map_err(|_| INVALID)?
        .midnight()
        .assume_utc();
    sign(
        pool,
        Certificate {
            serial: serial(&pair),
            spki: &key.spki_der,
            issuer: None,
            subject: "Honest enclave local CA",
            names: &[],
            extensions: &Extensions::new(),
            before,
            after,
            ca: true,
        },
        &pair,
    )
}
pub(crate) fn leaf(
    pool: &Arc<AllocationPoolV1>,
    key: &super::leaf_key::LeafKey,
    before: OffsetDateTime,
    after: OffsetDateTime,
    ca: &super::ca_context::CaContext,
    subject: &str,
    names: &[&str],
    extensions: &Extensions,
) -> Result<PaidDer> {
    let issuer = issuer_subject(&ca.ca_cert_der).map_err(|_| CertificateError::InvalidCa)?;
    let leaf = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        &key.pkcs8,
        &SystemRandom::new(),
    )
    .map_err(|_| CertificateError::InvalidKey)?;
    let signer = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        &ca.ca_key_pkcs8,
        &SystemRandom::new(),
    )
    .map_err(|_| CertificateError::InvalidKey)?;
    sign(
        pool,
        Certificate {
            serial: serial(&leaf),
            spki: &key.spki_der,
            issuer: Some(issuer),
            subject,
            names,
            extensions,
            before,
            after,
            ca: false,
        },
        &signer,
    )
}
