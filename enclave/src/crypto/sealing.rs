// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! SGX sealing – encrypt data bound to MRENCLAVE (code identity).
//!
//! Sealed data can only be unsealed by the exact same enclave binary
//! (same measurement / MRENCLAVE). This is used by [`SealedConfig`] to
//! persist all enclave state across restarts.
//!
//! Uses the Intel SGX SDK sealing API via teaclave-sgx-sdk bindings.

use crate::sealed_config::backing::{ConfigAllocator, ConfigBytes};
use enclave_os_common::allocation::AllocationPoolV1;
use std::sync::Arc;

#[cfg(not(feature = "mock"))]
use sgx_tseal::seal::SealedData;

/// Current MRENCLAVE policy, masks and wire; caller storage is admitted before
/// the SDK writes any sealed or decrypted result. The selected SDK provided-
/// buffer primitive performs the existing key/RNG/AES operation directly.
#[cfg(not(feature = "mock"))]
pub fn seal_with_mrenclave(
    pool: &Arc<AllocationPoolV1>,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<ConfigBytes, &'static str> {
    use sgx_types::types::{Attributes, AttributesFlags, KeyPolicy, TSEAL_DEFAULT_MISCMASK};
    let length = SealedData::<[u8]>::sealed_size(plaintext.len(), aad.len())
        .map_err(|_| "sgx_seal_data failed")?;
    let origin = ConfigAllocator::try_new(pool)?;
    let mut output = origin.try_zeroed(length)?;
    SealedData::<[u8]>::seal_with_key_policy_into(
        KeyPolicy::MRENCLAVE,
        Attributes {
            flags: AttributesFlags::DEFAULT_MASK,
            xfrm: 0,
        },
        TSEAL_DEFAULT_MISCMASK,
        plaintext,
        if aad.is_empty() { None } else { Some(aad) },
        output.as_mut_slice(),
    )
    .map_err(|_| "sgx_seal_data failed")?;
    output.activate_release_notification();
    Ok(output)
}

#[cfg(not(feature = "mock"))]
pub fn unseal_with_mrenclave<'a>(
    pool: &Arc<AllocationPoolV1>,
    raw: &'a [u8],
) -> Result<(ConfigBytes, &'a [u8]), &'static str> {
    let length =
        SealedData::<[u8]>::plaintext_size(raw).map_err(|_| "Invalid sealed data format")?;
    let origin = ConfigAllocator::try_new(pool)?;
    let mut output = origin.try_zeroed(length)?;
    // The authenticated domain borrows the original raw owner; neither backing
    // is copied or detached when the caller validates it.
    let aad = SealedData::<[u8]>::unseal_into(raw, output.as_mut_slice())
        .map_err(|_| "sgx_unseal_data failed")?;
    output.activate_release_notification();
    Ok((output, aad))
}

#[cfg(feature = "mock")]
const MOCK_PREFIX: &[u8] = b"MOCK_SEALED:";

#[cfg(feature = "mock")]
pub fn seal_with_mrenclave(
    pool: &Arc<AllocationPoolV1>,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<ConfigBytes, &'static str> {
    let aad_len = u32::try_from(aad.len()).map_err(|_| "Invalid mock sealed data")?;
    let plaintext_len = u32::try_from(plaintext.len()).map_err(|_| "Invalid mock sealed data")?;
    let width = core::mem::size_of::<u32>();
    let length = MOCK_PREFIX
        .len()
        .checked_add(width)
        .and_then(|n| n.checked_add(aad.len()))
        .and_then(|n| n.checked_add(width))
        .and_then(|n| n.checked_add(plaintext.len()))
        .ok_or("Invalid mock sealed data")?;
    let origin = ConfigAllocator::try_new(pool)?;
    let mut output = origin.try_zeroed(length)?;
    let bytes = output.as_mut_slice();
    let mut position = 0;
    for part in [
        MOCK_PREFIX,
        &aad_len.to_le_bytes(),
        aad,
        &plaintext_len.to_le_bytes(),
        plaintext,
    ] {
        let end = position + part.len();
        bytes[position..end].copy_from_slice(part);
        position = end;
    }
    output.activate_release_notification();
    Ok(output)
}

#[cfg(feature = "mock")]
pub fn unseal_with_mrenclave<'a>(
    pool: &Arc<AllocationPoolV1>,
    raw: &'a [u8],
) -> Result<(ConfigBytes, &'a [u8]), &'static str> {
    let mut data = raw
        .strip_prefix(MOCK_PREFIX)
        .ok_or("Not a mock-sealed blob")?;
    fn take<'a>(data: &mut &'a [u8], length: usize) -> Result<&'a [u8], &'static str> {
        let bytes = data.get(..length).ok_or("Invalid mock sealed data")?;
        *data = &data[length..];
        Ok(bytes)
    }
    fn field<'a>(data: &mut &'a [u8]) -> Result<&'a [u8], &'static str> {
        let bytes = take(data, core::mem::size_of::<u32>())?;
        let length = u32::from_le_bytes(bytes.try_into().map_err(|_| "Invalid mock sealed data")?);
        take(
            data,
            usize::try_from(length).map_err(|_| "Invalid mock sealed data")?,
        )
    }
    let aad = field(&mut data)?;
    let plaintext = field(&mut data)?;
    let output = ConfigAllocator::try_new(pool)?.try_copy(plaintext)?;
    output.activate_release_notification();
    Ok((output, aad))
}

#[cfg(all(
    feature = "sgx-sim-attestation",
    feature = "fallible-allocation-v1",
    target_vendor = "teaclave"
))]
pub(crate) fn check_in(pool: &Arc<AllocationPoolV1>) -> Result<(), &'static str> {
    use sgx_types::types::{
        Attributes, AttributesFlags, CAesGcmData, CSealedData, KeyPolicy, KeyRequest,
        TSEAL_DEFAULT_MISCMASK,
    };
    let plaintext = [0x37; enclave_os_common::types::AEAD_KEY_SIZE];
    let aad = [3, 4, 5];
    let before = pool.used();
    let sealed = seal_with_mrenclave(pool, &plaintext, &aad)?;
    let (unsealed, authenticated) = unseal_with_mrenclave(pool, &sealed)?;
    if unsealed.as_slice() != plaintext || authenticated != aad {
        return Err("provided sealed plaintext changed");
    }
    let policy = core::mem::offset_of!(CSealedData, key_request)
        + core::mem::offset_of!(KeyRequest, key_policy);
    let policy_bytes = sealed
        .get(policy..policy + core::mem::size_of::<u16>())
        .ok_or("provided seal policy field")?;
    if u16::from_ne_bytes(policy_bytes.try_into().map_err(|_| "seal policy width")?)
        != KeyPolicy::MRENCLAVE.bits()
    {
        return Err("provided seal key policy changed");
    }
    // The ordinary SDK API is an independent standard C-wire owner. This
    // interoperability oracle allocates its own ordinary SDK test buffers;
    // it makes no original-pool claim for that separate API's intermediates.
    let standard = SealedData::<[u8]>::from_slice(&sealed)
        .map_err(|_| "standard SDK rejected supplied wire")?
        .unseal()
        .map_err(|_| "standard SDK rejected supplied ciphertext")?;
    if standard.to_plaintext() != plaintext || standard.to_aad() != aad {
        return Err("standard SDK supplied wire oracle");
    }
    drop(standard);
    let standard = SealedData::<[u8]>::seal_with_key_policy(
        KeyPolicy::MRENCLAVE,
        Attributes {
            flags: AttributesFlags::DEFAULT_MASK,
            xfrm: 0,
        },
        TSEAL_DEFAULT_MISCMASK,
        &plaintext,
        Some(&aad),
    )
    .map_err(|_| "standard SDK seal oracle")?
    .into_bytes()
    .map_err(|_| "standard SDK wire oracle")?;
    let (crossed, authenticated) = unseal_with_mrenclave(pool, &standard)?;
    if crossed.as_slice() != plaintext || authenticated != aad {
        return Err("supplied standard wire oracle");
    }
    drop(crossed);
    drop(standard);
    let raw_size = SealedData::<[u8]>::sealed_size(plaintext.len(), aad.len())
        .map_err(|_| "provided seal geometry")?;
    let metadata = ConfigAllocator::metadata_bytes()?;
    for (length, decrypt) in [(raw_size, false), (plaintext.len(), true)] {
        let demand = metadata
            .checked_add(ConfigAllocator::backing_bytes(length)?)
            .ok_or("provided result geometry overflow")?;
        for delta in [-1_isize, 0, 1] {
            let limit = demand
                .checked_add_signed(delta)
                .ok_or("provided boundary")?;
            let isolated = AllocationPoolV1::new(limit).ok_or("provided boundary pool")?;
            let result = if decrypt {
                unseal_with_mrenclave(&isolated, &sealed).map(|(output, _)| output)
            } else {
                seal_with_mrenclave(&isolated, &plaintext, &aad)
            };
            if delta < 0 {
                if result.is_ok() {
                    return Err("provided one-byte-short published");
                }
            } else {
                let result = result?;
                if isolated.used() != demand || result.len() != length {
                    return Err("provided result real backing quote");
                }
                drop(result);
            }
            if isolated.used() != 0 {
                return Err("provided result refusal/refund");
            }
        }
    }
    let origin = ConfigAllocator::try_new(pool)?;
    let mut unaligned =
        origin.try_zeroed(sealed.len().checked_add(1).ok_or("unaligned length")?)?;
    unaligned.as_mut_slice()[1..].copy_from_slice(&sealed);
    let (result, authenticated) = unseal_with_mrenclave(pool, &unaligned[1..])?;
    if result.as_slice() != plaintext || authenticated != aad {
        return Err("unaligned supplied raw wire");
    }
    drop(result);
    let header = core::mem::size_of::<CSealedData>();
    for cut in 0..header {
        if SealedData::<[u8]>::plaintext_size(&sealed[..cut]).is_ok() {
            return Err("truncated supplied header accepted");
        }
    }
    let mut malformed = origin.try_copy(&sealed)?;
    let key_name = core::mem::offset_of!(CSealedData, key_request)
        + core::mem::offset_of!(KeyRequest, key_name);
    malformed.as_mut_slice()[key_name..key_name + core::mem::size_of::<u16>()]
        .copy_from_slice(&u16::MAX.to_ne_bytes());
    if SealedData::<[u8]>::plaintext_size(&malformed).is_ok()
        || SealedData::<[u8]>::from_slice(&malformed).is_ok()
    {
        return Err("invalid supplied enum tag accepted");
    }
    let mut untouched = origin.try_zeroed(plaintext.len())?;
    untouched.as_mut_slice().fill(0xa5);
    if SealedData::<[u8]>::unseal_into(&malformed, untouched.as_mut_slice()).is_ok()
        || untouched.iter().any(|byte| *byte != 0xa5)
    {
        return Err("invalid supplied raw preflight mutated output");
    }
    drop(untouched);
    drop(malformed);
    let mut short = origin.try_zeroed(raw_size - 1)?;
    short.as_mut_slice().fill(0xa5);
    if SealedData::<[u8]>::seal_with_key_policy_into(
        KeyPolicy::MRENCLAVE,
        Attributes {
            flags: AttributesFlags::DEFAULT_MASK,
            xfrm: 0,
        },
        TSEAL_DEFAULT_MISCMASK,
        &plaintext,
        Some(&aad),
        short.as_mut_slice(),
    )
    .is_ok()
        || short.iter().any(|byte| *byte != 0xa5)
    {
        return Err("wrong supplied seal length mutated preflight output");
    }
    drop(short);
    let mut short = origin.try_zeroed(plaintext.len() - 1)?;
    short.as_mut_slice().fill(0xa5);
    if SealedData::<[u8]>::unseal_into(&sealed, short.as_mut_slice()).is_ok()
        || short.iter().any(|byte| *byte != 0xa5)
    {
        return Err("wrong supplied plaintext length mutated preflight output");
    }
    drop(short);
    let tag = core::mem::offset_of!(CSealedData, aes_data)
        + core::mem::offset_of!(CAesGcmData, payload_tag);
    for offset in [header, tag, sealed.len() - 1] {
        let mut corrupted = origin.try_copy(&sealed)?;
        corrupted.as_mut_slice()[offset] ^= 1;
        let mut output = origin.try_zeroed(plaintext.len())?;
        output.as_mut_slice().fill(0xa5);
        if SealedData::<[u8]>::unseal_into(&corrupted, output.as_mut_slice()).is_ok()
            || output.iter().any(|byte| *byte != 0)
        {
            return Err("corruption accepted or supplied plaintext not wiped");
        }
    }
    let mut rejected = origin.try_zeroed(raw_size)?;
    rejected.as_mut_slice().fill(0xa5);
    if SealedData::<[u8]>::seal_with_key_policy_into(
        KeyPolicy::empty(),
        Attributes {
            flags: AttributesFlags::DEFAULT_MASK,
            xfrm: 0,
        },
        TSEAL_DEFAULT_MISCMASK,
        &plaintext,
        Some(&aad),
        rejected.as_mut_slice(),
    )
    .is_ok()
        || rejected.iter().any(|byte| *byte != 0)
    {
        return Err("refused provided seal published nonzero output");
    }
    drop(rejected);
    drop(unaligned);
    drop(origin);
    drop(unsealed);
    drop(sealed);
    if pool.used() != before {
        return Err("provided SGX results final refund");
    }
    Ok(())
}
