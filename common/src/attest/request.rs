//! Inbound attestation fields with borrowed or caller-paid text.
//!
//! Semantic refusals are values, rather than dynamically formatted serde errors.
//! The slice parser supplying this visitor must separately admit its scratch and
//! use inline syntax errors; this visitor alone makes no parser allocation claim.
use super::AttestRequest;
use crate::{
    allocation::AllocationPoolV1,
    request_json::{Refusal, Text},
};
use alloc::sync::Arc;
use core::fmt;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};

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
        deserializer.deserialize_any(RequestVisitor { pool: self.pool })
    }
}

struct RequestVisitor<'a> {
    pool: &'a Arc<AllocationPoolV1>,
}
impl<'de> Visitor<'de> for RequestVisitor<'_> {
    type Value = Result<AttestRequest<Text<'de>>, Refusal>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("attestation request")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut fields = Fields::new();
        while let Some(field) = map.next_key_seed(FieldSeed)? {
            if let Some(index) = field {
                if fields.values[index].is_some() {
                    fields.duplicate = true;
                    map.next_value::<IgnoredAny>()?;
                } else {
                    fields.values[index] =
                        Some(map.next_value_seed(ValueSeed { pool: self.pool })?);
                }
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(fields.finish())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut fields = Fields::new();
        for slot in &mut fields.values {
            let Some(value) = seq.next_element_seed(ValueSeed { pool: self.pool })? else {
                return Ok(fields.finish());
            };
            *slot = Some(value);
        }
        while seq.next_element::<IgnoredAny>()?.is_some() {
            fields.duplicate = true;
        }
        Ok(fields.finish())
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(Err(Refusal::Malformed))
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(Err(Refusal::Malformed))
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(Err(Refusal::Malformed))
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(Err(Refusal::Malformed))
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(Err(Refusal::Malformed))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(Err(Refusal::Malformed))
    }
}

struct Fields<'de> {
    values: [Option<Value<'de>>; 8],
    duplicate: bool,
}
impl<'de> Fields<'de> {
    fn new() -> Self {
        Self {
            values: core::array::from_fn(|_| None),
            duplicate: false,
        }
    }
    fn finish(mut self) -> Result<AttestRequest<Text<'de>>, Refusal> {
        if self.duplicate {
            return Err(Refusal::Malformed);
        }
        let v = match self.values[0].take() {
            Some(Value::Unsigned(value)) => u32::try_from(value).map_err(|_| Refusal::Malformed)?,
            Some(Value::Signed(value)) => u32::try_from(value).map_err(|_| Refusal::Malformed)?,
            Some(Value::Unavailable) => return Err(Refusal::Unavailable),
            _ => return Err(Refusal::Malformed),
        };
        let mode = required_text(self.values[1].take())?;
        let leaf = match self.values[2].take() {
            None => Text::default(),
            value => required_text(value)?,
        };
        Ok(AttestRequest {
            v,
            mode,
            leaf,
            context: optional_text(self.values[3].take())?,
            tee: optional_text(self.values[4].take())?,
            quote: optional_text(self.values[5].take())?,
            gpu_evidence: optional_text(self.values[6].take())?,
            quote_time: optional_text(self.values[7].take())?,
        })
    }
}
fn required_text(value: Option<Value<'_>>) -> Result<Text<'_>, Refusal> {
    match value {
        Some(Value::Text(value)) => Ok(value),
        Some(Value::Unavailable) => Err(Refusal::Unavailable),
        _ => Err(Refusal::Malformed),
    }
}
fn optional_text(value: Option<Value<'_>>) -> Result<Option<Text<'_>>, Refusal> {
    match value {
        None | Some(Value::Null) => Ok(None),
        value => required_text(value).map(Some),
    }
}

struct FieldSeed;
impl<'de> DeserializeSeed<'de> for FieldSeed {
    type Value = Option<usize>;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_identifier(FieldVisitor)
    }
}
struct FieldVisitor;
impl Visitor<'_> for FieldVisitor {
    type Value = Option<usize>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("request field")
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(match value {
            "v" => Some(0),
            "mode" => Some(1),
            "leaf" => Some(2),
            "context" => Some(3),
            "tee" => Some(4),
            "quote" => Some(5),
            "gpu_evidence" => Some(6),
            "quote_time" => Some(7),
            _ => None,
        })
    }
}

enum Value<'de> {
    Text(Text<'de>),
    Unsigned(u64),
    Signed(i64),
    Null,
    Other,
    Unavailable,
}
struct ValueSeed<'a> {
    pool: &'a Arc<AllocationPoolV1>,
}
impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = Value<'de>;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(ValueVisitor { pool: self.pool })
    }
}
struct ValueVisitor<'a> {
    pool: &'a Arc<AllocationPoolV1>,
}
impl<'de> Visitor<'de> for ValueVisitor<'_> {
    type Value = Value<'de>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("request field value")
    }
    fn visit_borrowed_str<E: serde::de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
        Ok(Value::Text(Text::borrowed(value)))
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(match Text::copy(self.pool, value) {
            Ok(text) => Value::Text(text),
            Err(_) => Value::Unavailable,
        })
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Unsigned(value))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Signed(value))
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(Value::Other)
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(Value::Other)
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Value::Other)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Value::Other)
    }
}
