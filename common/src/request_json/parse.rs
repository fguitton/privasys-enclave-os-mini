//! One pool-explicit retained JSON parser for independently verified JWT payloads.
use super::{
    value::{Seed, Value},
    AdmittedParser, Refusal,
};
use crate::allocation::AllocationPoolV1;
use alloc::sync::Arc;
use serde::de::DeserializeSeed;

/// Syntax diagnostics are inline; resource refusal cannot become a partial tree.
#[derive(Debug)]
pub enum Error {
    Syntax(serde_json::Error),
    Refused(Refusal),
}
/// Parse the complete payload, retaining independently admitted string/array/map backings.
///
/// # Errors
/// Returns the original syntax diagnostic or the original pool's admission refusal.
pub fn retained(pool: &Arc<AllocationPoolV1>, input: &[u8]) -> Result<Value<'static>, Error> {
    let capacity = serde_json::Deserializer::slice_scratch_capacity(input.len())
        .ok_or(Error::Refused(Refusal::Unavailable))?;
    let mut parser = AdmittedParser::new(pool, capacity, |scratch| {
        serde_json::Deserializer::from_slice_with_scratch(input, scratch).ok()
    })
    .map_err(Error::Refused)?;
    let value = Seed::retained(pool)
        .deserialize(parser.parser_mut())
        .map_err(Error::Syntax)?;
    parser.parser_mut().end().map_err(Error::Syntax)?;
    value.map_err(Error::Refused)
}
