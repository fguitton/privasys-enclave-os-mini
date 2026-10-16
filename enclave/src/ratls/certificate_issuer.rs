//! Borrowed validation of the current certificate issuer. No parsed object,
//! extension collection, OID vector or distinguished-name copy is allocated.
use der::{asn1::AnyRef, Decode, Length, Reader, Tag, Tagged};

fn invalid() -> der::Error {
    Tag::Sequence.value_error().into()
}
fn next<'a>(bytes: &mut &'a [u8]) -> der::Result<AnyRef<'a>> {
    let (value, rest) = AnyRef::from_der_partial(bytes)?;
    *bytes = rest;
    Ok(value)
}
fn expect<'a>(bytes: &mut &'a [u8], tag: Tag) -> der::Result<&'a [u8]> {
    let value = next(bytes)?;
    if value.tag() != tag {
        return Err(invalid());
    }
    Ok(value.value())
}
fn done(bytes: &[u8]) -> der::Result<()> {
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(invalid())
    }
}
fn context<'a>(value: AnyRef<'a>, number: u32) -> der::Result<&'a [u8]> {
    if value.tag().is_context_specific() && value.tag().number().value() == number {
        Ok(value.value())
    } else {
        Err(invalid())
    }
}

// OID arcs have the same u64 domain as rcgen's collected issuer OIDs. Do not
// substitute const_oid's fixed-capacity type or introduce a certificate cap.
fn oid(bytes: &[u8]) -> der::Result<()> {
    if bytes.is_empty() {
        return Err(invalid());
    }
    let mut value = 0u64;
    for &byte in bytes {
        value = value
            .checked_mul(128)
            .and_then(|n| n.checked_add(u64::from(byte & 0x7f)))
            .ok_or_else(invalid)?;
        if byte & 0x80 == 0 {
            value = 0;
        }
    }
    if bytes.last().is_some_and(|b| b & 0x80 != 0) {
        return Err(invalid());
    }
    Ok(())
}
fn name(mut bytes: &[u8], converted: bool) -> der::Result<()> {
    while !bytes.is_empty() {
        let mut rdn = expect(&mut bytes, Tag::Set)?;
        if rdn.is_empty() {
            return Err(invalid());
        }
        let mut count = 0usize;
        while !rdn.is_empty() {
            let mut attribute = expect(&mut rdn, Tag::Sequence)?;
            oid(expect(&mut attribute, Tag::ObjectIdentifier)?)?;
            let (tag, value) = name_value_body(&mut attribute)?;
            done(attribute)?;
            if converted {
                name_value(tag, value)?;
            }
            count += 1;
        }
        // The old conversion rejects multi-valued RDNs rather than silently
        // retaining one attribute. Issuer names themselves were not converted.
        if converted && count != 1 {
            return Err(invalid());
        }
    }
    Ok(())
}
fn name_value_body<'a>(bytes: &mut &'a [u8]) -> der::Result<(u8, &'a [u8])> {
    let (&tag, encoded) = bytes.split_first().ok_or_else(invalid)?;
    let mut reader = der::SliceReader::new(encoded)?;
    let length = usize::try_from(Length::decode(&mut reader)?)?;
    let head = usize::try_from(reader.position())?;
    let end = head.checked_add(length).ok_or_else(invalid)?;
    let body = encoded.get(head..end).ok_or_else(invalid)?;
    *bytes = &encoded[end..];
    Ok((tag, body))
}
fn name_value(tag: u8, bytes: &[u8]) -> der::Result<()> {
    let valid = match tag {
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
        Err(invalid())
    }
}
fn algorithm(mut bytes: &[u8]) -> der::Result<()> {
    oid(expect(&mut bytes, Tag::ObjectIdentifier)?)?;
    if !bytes.is_empty() {
        next(&mut bytes)?;
    }
    done(bytes)
}
fn bit_string(bytes: &[u8]) -> der::Result<()> {
    let Some((&unused, data)) = bytes.split_first() else {
        return Err(invalid());
    };
    if unused > 7 || (data.is_empty() && unused != 0) {
        return Err(invalid());
    }
    Ok(())
}
fn validity(mut bytes: &[u8]) -> der::Result<()> {
    for _ in 0..2 {
        let time = next(&mut bytes)?;
        match time.tag() {
            Tag::UtcTime => {
                time.decode_as::<der::asn1::UtcTime>()?;
            }
            Tag::GeneralizedTime => {
                time.decode_as::<der::asn1::GeneralizedTime>()?;
            }
            _ => return Err(invalid()),
        }
    }
    done(bytes)
}

fn general_name(value: AnyRef<'_>, san: bool) -> der::Result<()> {
    if !value.tag().is_context_specific() {
        return Err(invalid());
    }
    let bytes = value.value();
    match value.tag().number().value() {
        0 => {
            let mut content = bytes;
            oid(expect(&mut content, Tag::ObjectIdentifier)?)?;
            if san {
                let mut explicit = context(next(&mut content)?, 0)?;
                let text = expect(&mut explicit, Tag::Utf8String)?;
                core::str::from_utf8(text).map_err(|_| invalid())?;
            }
        }
        1 | 2 | 6 => {
            core::str::from_utf8(bytes).map_err(|_| invalid())?;
            if san && !bytes.is_ascii() {
                return Err(invalid());
            }
        }
        4 => {
            if san {
                return Err(invalid());
            }
            let mut content = bytes;
            name(expect(&mut content, Tag::Sequence)?, true)?;
            done(content)?;
        }
        7 => {
            if san && bytes.len() != 4 && bytes.len() != 16 {
                return Err(invalid());
            }
        }
        3 | 5 | 8 if !san => {}
        _ => return Err(invalid()),
    }
    Ok(())
}
fn alternative_names(bytes: &[u8]) -> der::Result<()> {
    let mut outer = bytes;
    let mut names = expect(&mut outer, Tag::Sequence)?;
    while !names.is_empty() {
        general_name(next(&mut names)?, true)?;
    }
    Ok(())
}
fn name_constraints(bytes: &[u8]) -> der::Result<()> {
    let mut outer = bytes;
    let mut fields = expect(&mut outer, Tag::Sequence)?;
    let mut previous = None;
    while !fields.is_empty() {
        let field = next(&mut fields)?;
        let number = field.tag().number().value();
        if !field.tag().is_context_specific() || number > 1 || previous.is_some_and(|p| p >= number)
        {
            return Err(invalid());
        }
        previous = Some(number);
        let mut subtrees = field.value();
        if subtrees.is_empty() {
            return Err(invalid());
        }
        while !subtrees.is_empty() {
            let mut subtree = expect(&mut subtrees, Tag::Sequence)?;
            general_name(next(&mut subtree)?, false)?;
            // The original parser ignores optional minimum/maximum fields.
        }
    }
    Ok(())
}
fn basic_constraints(bytes: &[u8]) -> der::Result<(bool, Option<u32>)> {
    let mut outer = bytes;
    let mut values = expect(&mut outer, Tag::Sequence)?;
    let mut ca = false;
    if values.first() == Some(&1) {
        ca = next(&mut values)?.decode_as::<bool>()?;
    }
    let path = if values.is_empty() {
        None
    } else {
        Some(next(&mut values)?.decode_as::<u32>()?)
    };
    done(values)?;
    Ok((ca, path))
}
fn extensions(mut bytes: &[u8]) -> der::Result<()> {
    let mut seen = 0u8;
    while !bytes.is_empty() {
        let mut extension = expect(&mut bytes, Tag::Sequence)?;
        let id = expect(&mut extension, Tag::ObjectIdentifier)?;
        oid(id)?;
        if extension.first() == Some(&1) {
            next(&mut extension)?.decode_as::<bool>()?;
        }
        let value = expect(&mut extension, Tag::OctetString)?;
        done(extension)?;
        let kind = match id {
            [85, 29, 19] => 0,
            [85, 29, 17] => 1,
            [85, 29, 15] => 2,
            [85, 29, 37] => 3,
            [85, 29, 30] => 4,
            _ => continue,
        };
        let bit = 1 << kind;
        if seen & bit != 0 {
            return Err(invalid());
        }
        seen |= bit;
        match kind {
            0 => {
                // rcgen treats an unparsed basicConstraints as absent, but
                // refuses a successfully parsed CA path bound above u8::MAX.
                if let Ok((true, Some(path))) = basic_constraints(value) {
                    if path > u32::from(u8::MAX) {
                        return Err(invalid());
                    }
                }
            }
            1 => alternative_names(value)?,
            2 => {
                let mut value = value;
                bit_string(expect(&mut value, Tag::BitString)?)?;
            }
            3 => {
                let mut value = value;
                let mut usages = expect(&mut value, Tag::Sequence)?;
                while !usages.is_empty() {
                    oid(expect(&mut usages, Tag::ObjectIdentifier)?)?;
                }
            }
            4 => name_constraints(value)?,
            _ => unreachable!(),
        }
    }
    Ok(())
}

/// Validate the complete issuer certificate and return only its borrowed
/// subject body. Outer trailing bytes retain the original parser's behavior.
pub(super) fn subject(cert: &[u8]) -> der::Result<&[u8]> {
    let mut input = cert;
    let mut certificate = expect(&mut input, Tag::Sequence)?;
    let mut tbs = expect(&mut certificate, Tag::Sequence)?;
    if tbs.first() == Some(&0xa0) {
        let mut version = context(next(&mut tbs)?, 0)?;
        next(&mut version)?.decode_as::<u32>()?;
        done(version)?;
    }
    expect(&mut tbs, Tag::Integer)?;
    algorithm(expect(&mut tbs, Tag::Sequence)?)?;
    name(expect(&mut tbs, Tag::Sequence)?, false)?;
    validity(expect(&mut tbs, Tag::Sequence)?)?;
    let subject = expect(&mut tbs, Tag::Sequence)?;
    name(subject, true)?;
    let mut spki = expect(&mut tbs, Tag::Sequence)?;
    algorithm(expect(&mut spki, Tag::Sequence)?)?;
    bit_string(expect(&mut spki, Tag::BitString)?)?;
    done(spki)?;
    for number in [1, 2] {
        if tbs.first().is_some_and(|tag| tag & 0xdf == 0x80 + number) {
            bit_string(context(next(&mut tbs)?, u32::from(number))?)?;
        }
    }
    if !tbs.is_empty() {
        let mut explicit = context(next(&mut tbs)?, 3)?;
        extensions(expect(&mut explicit, Tag::Sequence)?)?;
        done(explicit)?;
    }
    done(tbs)?;
    algorithm(expect(&mut certificate, Tag::Sequence)?)?;
    bit_string(expect(&mut certificate, Tag::BitString)?)?;
    done(certificate)?;
    Ok(subject)
}
