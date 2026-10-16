//! Inbound attestation fields with borrowed or caller-paid text.
//! The supplying parser separately admits scratch and uses inline syntax errors.
use super::AttestRequest;
use crate::{
    allocation::AllocationPoolV1,
    request_json::{
        fields::{optional_text, required_text, FieldsSeed, NumericFirstFields, Value},
        Refusal, Text,
    },
};
use alloc::sync::Arc;
use serde::de::DeserializeSeed;
/// Visit the same object and sequence field model as `AttestRequest<String>`.
pub struct Seed<'a> {
    pool: &'a Arc<AllocationPoolV1>,
}
impl<'a> Seed<'a> {
    pub fn new(pool: &'a Arc<AllocationPoolV1>) -> Self {
        Self { pool }
    }
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Result<AttestRequest<Text<'de>>, Refusal>;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        Ok(FieldsSeed::new(
            &[
                "v",
                "mode",
                "leaf",
                "context",
                "tee",
                "quote",
                "gpu_evidence",
                "quote_time",
            ],
            NumericFirstFields { pool: self.pool },
        )
        .deserialize(deserializer)?
        .and_then(finish))
    }
}
fn finish(mut values: [Option<Value<'_>>; 8]) -> Result<AttestRequest<Text<'_>>, Refusal> {
    let v = match values[0].take() {
        Some(Value::Unsigned(value)) => u32::try_from(value).map_err(|_| Refusal::Malformed)?,
        Some(Value::Signed(value)) => u32::try_from(value).map_err(|_| Refusal::Malformed)?,
        Some(Value::Unavailable) => return Err(Refusal::Unavailable),
        _ => return Err(Refusal::Malformed),
    };
    let mode = required_text(values[1].take())?;
    let leaf = match values[2].take() {
        None => Text::default(),
        value => required_text(value)?,
    };
    Ok(AttestRequest {
        v,
        mode,
        leaf,
        context: optional_text(values[3].take())?,
        tee: optional_text(values[4].take())?,
        quote: optional_text(values[5].take())?,
        gpu_evidence: optional_text(values[6].take())?,
        quote_time: optional_text(values[7].take())?,
    })
}
