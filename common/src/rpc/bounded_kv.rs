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

/// Caller record geometry intersected with existing Mini batch/transport caps.
/// Bounds grant neither storage authority nor durable publication.
#[derive(Clone, Copy, Debug)]
pub struct KvPutBatchBounds {
    maximum_records: usize,
    maximum_value_bytes: usize,
    maximum_total_value_bytes: usize,
}

impl KvPutBatchBounds {
    pub fn new(
        maximum_records: usize,
        maximum_value_bytes: usize,
        maximum_total_value_bytes: usize,
    ) -> Option<Self> {
        if maximum_records == 0 || maximum_value_bytes == 0 || maximum_total_value_bytes == 0 {
            return None;
        }
        Some(Self {
            maximum_records: maximum_records.min(MAX_BOUNDED_KV_ITEMS),
            maximum_value_bytes: maximum_value_bytes.min(crate::types::KV_MAX_VALUE_SIZE),
            maximum_total_value_bytes: maximum_total_value_bytes.min(MAX_BOUNDED_KV_BYTES),
        })
    }
}

/// Encode borrowed puts with the exact legacy KvWriteBatch wire format.
/// Aggregate value bytes and complete framed request bytes have separate bounds.
pub fn encode_kv_put_batch_req_borrowed(
    table: &[u8],
    records: &[(&[u8], &[u8])],
    bounds: KvPutBatchBounds,
) -> Option<Vec<u8>> {
    if table.is_empty() || records.is_empty() || records.len() > bounds.maximum_records {
        return None;
    }
    let table_len = u16::try_from(table.len()).ok()?;
    let count = u32::try_from(records.len()).ok()?;
    let mut value_bytes = 0usize;
    let mut encoded_bytes = 2usize.checked_add(table.len())?.checked_add(4)?;
    for (key, value) in records {
        if key.is_empty() || key.len() > crate::types::KV_MAX_KEY_SIZE
            || value.is_empty() || value.len() > bounds.maximum_value_bytes
        {
            return None;
        }
        value_bytes = value_bytes.checked_add(value.len())?;
        encoded_bytes = encoded_bytes.checked_add(9)?
            .checked_add(key.len())?.checked_add(value.len())?;
    }
    if value_bytes > bounds.maximum_total_value_bytes
        || !super::framed_payload_len_valid(
            encoded_bytes,
            super::REQ_HEADER_SIZE,
            crate::queue::max_message_bytes(crate::queue::DEFAULT_QUEUE_CAPACITY),
        )
    {
        return None;
    }
    // Checked full framing and caller/transport bounds precede allocation.
    let mut output = Vec::new();
    output.try_reserve_exact(encoded_bytes).ok()?;
    output.extend_from_slice(&table_len.to_le_bytes());
    output.extend_from_slice(table);
    output.extend_from_slice(&count.to_le_bytes());
    for (key, value) in records {
        output.push(0); // Original put tag; record order and duplicates preserved.
        output.extend_from_slice(&u32::try_from(key.len()).ok()?.to_le_bytes());
        output.extend_from_slice(key);
        output.extend_from_slice(&u32::try_from(value.len()).ok()?.to_le_bytes());
        output.extend_from_slice(value);
    }
    Some(output)
}
