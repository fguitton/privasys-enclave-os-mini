//! Request-bound decoding for small batches of opaque stored values.
use alloc::vec::Vec;

pub const MAX_BOUNDED_KV_ITEMS: usize = 8;
/// Below the default 2 MiB control queue, including framing and keys.
pub const MAX_BOUNDED_KV_BYTES: usize = 1536 * 1024;

pub fn bounded_kv_limits_valid(maxima: &[usize]) -> bool {
    !maxima.is_empty()
        && maxima.len() <= MAX_BOUNDED_KV_ITEMS
        && maxima
            .iter()
            .all(|n| *n > 0 && *n <= crate::types::KV_MAX_VALUE_SIZE)
        && maxima
            .iter()
            .try_fold(0usize, |n, next| n.checked_add(*next))
            .is_some_and(|n| n <= MAX_BOUNDED_KV_BYTES)
}

/// Authenticate values separately; these bounds establish no storage authority.
/// The host count cannot select the allocation or substitute the request shape.
pub fn decode_kv_multi_get_resp_bounded(
    bytes: &[u8],
    maxima: &[usize],
) -> Option<Vec<Option<Vec<u8>>>> {
    if !bounded_kv_limits_valid(maxima)
        || bytes.len() > 4 + 5 * maxima.len() + maxima.iter().sum::<usize>()
    {
        return None;
    }
    let count = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    if count != maxima.len() {
        return None;
    }
    let mut offset = 4usize;
    let mut result = Vec::with_capacity(maxima.len());
    for maximum in maxima {
        let present = *bytes.get(offset)?;
        offset += 1;
        match present {
            0 => result.push(None),
            1 => {
                let end = offset.checked_add(4)?;
                let length = u32::from_le_bytes(bytes.get(offset..end)?.try_into().ok()?) as usize;
                if length > *maximum {
                    return None;
                }
                offset = end;
                let end = offset.checked_add(length)?;
                result.push(Some(bytes.get(offset..end)?.to_vec()));
                offset = end;
            }
            _ => return None,
        }
    }
    (offset == bytes.len()).then_some(result)
}
