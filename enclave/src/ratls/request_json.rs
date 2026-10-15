//! Attestation request parsing with admitted scratch and escaped text.
//! Compiled against the guarded request-JSON supplier profile.
use enclave_os_common::{
    allocation::AllocationPoolV1,
    attest::{request::Seed, AttestRequest},
    request_json::{AdmittedParser, Refusal, Text},
};
use serde::de::DeserializeSeed;
use std::sync::Arc;

pub(super) fn attest<'de>(
    pool: &Arc<AllocationPoolV1>,
    input: &'de [u8],
) -> Result<AttestRequest<Text<'de>>, Refusal> {
    let capacity = serde_json::Deserializer::slice_scratch_capacity(input.len())
        .ok_or(Refusal::Unavailable)?;
    let mut parser = AdmittedParser::new(pool, capacity, |scratch| {
        serde_json::Deserializer::from_slice_with_scratch(input, scratch).ok()
    })?;
    let request = Seed::new(pool)
        .deserialize(parser.parser_mut())
        .map_err(|_| Refusal::Malformed)??;
    parser.parser_mut().end().map_err(|_| Refusal::Malformed)?;
    Ok(request)
}
