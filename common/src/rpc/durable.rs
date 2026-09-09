//! Bounded backend-neutral durable writes of opaque ciphertext.
use super::*;

/// Table/key limits are RPC resource bounds, unrelated to cluster populations.
pub const MAX_DURABLE_KV_TABLE_BYTES: usize = 64;
pub const MAX_DURABLE_KV_KEY_BYTES: usize = 256;

pub fn durable_kv_put_fields_valid(table: &[u8], key: &[u8], value: &[u8]) -> bool {
    !table.is_empty()
        && table.len() <= MAX_DURABLE_KV_TABLE_BYTES
        && table
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(c))
        && !key.is_empty()
        && key.len() <= MAX_DURABLE_KV_KEY_BYTES
        && !value.is_empty()
        && table
            .len()
            .checked_add(key.len())
            .and_then(|n| n.checked_add(value.len()))
            .and_then(|n| n.checked_add(6))
            .is_some_and(|n| n <= MAX_HONEST_RPC_PAYLOAD_BYTES)
}

/// The ordinary KV wire layout with strict pre-allocation length validation.
/// Empty records and invalid table names are not redirected to another table.
pub fn encode_durable_kv_put_req(table: &[u8], key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
    durable_kv_put_fields_valid(table, key, value).then(|| encode_kv_put_req(table, key, value))
}
pub fn decode_durable_kv_put_req(payload: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    if payload.len() > MAX_HONEST_RPC_PAYLOAD_BYTES {
        return None;
    }
    let (table, key, value) = decode_kv_put_req(payload)?;
    durable_kv_put_fields_valid(table, key, value).then_some((table, key, value))
}

/// Require the exact request ID, exact frame length and an empty successful
/// acknowledgement. Host status failures remain failures, including an
/// ambiguous write result. This checks protocol shape, not host honesty.
pub fn decode_durable_kv_put_response(bytes: &[u8], request_id: u64) -> Result<(), i32> {
    let (received, status, payload) = decode_response(bytes).ok_or(-1)?;
    if received != request_id
        || request_id == 0
        || bytes.len() != RESP_HEADER_SIZE
        || !payload.is_empty()
    {
        return Err(-1);
    }
    if status != 0 {
        return Err(status);
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn check_codec() {
    let encoded =
        encode_durable_kv_put_req(b"honest.bft-control", b"sealed-v1", b"ciphertext").unwrap();
    let (table, key, value) = decode_durable_kv_put_req(&encoded).unwrap();
    assert_eq!(
        (table, key, value),
        (
            &b"honest.bft-control"[..],
            &b"sealed-v1"[..],
            &b"ciphertext"[..]
        )
    );
    for (table, key, value) in [
        (&b""[..], &b"k"[..], &b"v"[..]),
        (b"bad/table", b"k", b"v"),
        (b"\xff", b"k", b"v"),
        (b"t", b"", b"v"),
        (b"t", b"k", b""),
    ] {
        assert!(encode_durable_kv_put_req(table, key, value).is_none());
        assert!(decode_durable_kv_put_req(&encode_kv_put_req(table, key, value)).is_none());
    }
    for (table, key, value) in [
        (vec![b't'; MAX_DURABLE_KV_TABLE_BYTES + 1], vec![1], vec![2]),
        (vec![b't'], vec![1; MAX_DURABLE_KV_KEY_BYTES + 1], vec![2]),
        (vec![b't'], vec![1], vec![2; MAX_HONEST_RPC_PAYLOAD_BYTES]),
    ] {
        assert!(encode_durable_kv_put_req(&table, &key, &value).is_none());
        assert!(decode_durable_kv_put_req(&encode_kv_put_req(&table, &key, &value)).is_none());
    }
    let table = vec![b't'; MAX_DURABLE_KV_TABLE_BYTES];
    let key = vec![1; MAX_DURABLE_KV_KEY_BYTES];
    let value = vec![2; MAX_HONEST_RPC_PAYLOAD_BYTES - table.len() - key.len() - 6];
    let maximum = encode_durable_kv_put_req(&table, &key, &value).unwrap();
    assert_eq!(maximum.len(), MAX_HONEST_RPC_PAYLOAD_BYTES);
    assert!(decode_durable_kv_put_req(&maximum).is_some());
    for end in 0..(encoded.len() - b"ciphertext".len() + 1) {
        assert!(decode_durable_kv_put_req(&encoded[..end]).is_none());
    }
    let response = encode_response(9, 0, &[]);
    assert_eq!(decode_durable_kv_put_response(&response, 9), Ok(()));
    for bad in [
        encode_response(8, 0, &[]),
        encode_response(9, 0, &[1]),
        [response.as_slice(), &[0]].concat(),
        response[..response.len() - 1].to_vec(),
    ] {
        assert!(decode_durable_kv_put_response(&bad, 9).is_err());
    }
    assert_eq!(
        decode_durable_kv_put_response(&encode_response(9, -5, &[]), 9),
        Err(-5)
    );
    assert!(decode_durable_kv_put_response(&encode_response(0, 0, &[]), 0).is_err());
}
