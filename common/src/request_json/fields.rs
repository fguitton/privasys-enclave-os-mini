//! Fixed-field request visitors sharing the original serde grammar.
//! Semantic failures remain values; no dynamically formatted custom errors.
use super::{Refusal, Text};
use crate::allocation::AllocationPoolV1;
use alloc::sync::Arc;
use core::fmt;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};

pub(crate) trait FieldDecoder<'de>: Copy {
    type Value;
    fn decode<D: serde::Deserializer<'de>>(
        self,
        index: usize,
        deserializer: D,
    ) -> Result<Self::Value, D::Error>;
}

pub(crate) struct FieldsSeed<S, const N: usize> {
    names: &'static [&'static str; N],
    decoder: S,
}
impl<S, const N: usize> FieldsSeed<S, N> {
    pub(crate) fn new(names: &'static [&'static str; N], decoder: S) -> Self {
        Self { names, decoder }
    }
}
impl<'de, S: FieldDecoder<'de>, const N: usize> DeserializeSeed<'de> for FieldsSeed<S, N> {
    type Value = Result<[Option<S::Value>; N], Refusal>;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}
impl<'de, S: FieldDecoder<'de>, const N: usize> Visitor<'de> for FieldsSeed<S, N> {
    type Value = Result<[Option<S::Value>; N], Refusal>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("request object or sequence")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut values = core::array::from_fn(|_| None);
        let mut duplicate = false;
        while let Some(field) = map.next_key_seed(FieldSeed(self.names))? {
            if let Some(index) = field {
                if values[index].is_some() {
                    duplicate = true;
                    map.next_value::<IgnoredAny>()?;
                } else {
                    values[index] = Some(map.next_value_seed(EntrySeed {
                        decoder: self.decoder,
                        index,
                    })?);
                }
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(if duplicate {
            Err(Refusal::Malformed)
        } else {
            Ok(values)
        })
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut values = core::array::from_fn(|_| None);
        for (index, slot) in values.iter_mut().enumerate() {
            let Some(value) = seq.next_element_seed(EntrySeed {
                decoder: self.decoder,
                index,
            })?
            else {
                return Ok(Ok(values));
            };
            *slot = Some(value);
        }
        let mut extra = false;
        while seq.next_element::<IgnoredAny>()?.is_some() {
            extra = true;
        }
        Ok(if extra {
            Err(Refusal::Malformed)
        } else {
            Ok(values)
        })
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
struct EntrySeed<S> {
    decoder: S,
    index: usize,
}
impl<'de, S: FieldDecoder<'de>> DeserializeSeed<'de> for EntrySeed<S> {
    type Value = S::Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        self.decoder.decode(self.index, deserializer)
    }
}
struct FieldSeed<const N: usize>(&'static [&'static str; N]);
impl<'de, const N: usize> DeserializeSeed<'de> for FieldSeed<N> {
    type Value = Option<usize>;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_identifier(self)
    }
}
impl<const N: usize> Visitor<'_> for FieldSeed<N> {
    type Value = Option<usize>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("request field")
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(self.0.iter().position(|name| *name == value))
    }
}
/// The current Attest and EncAuth records both start with a numeric field.
/// Wrong-typed strings are consumed without creating an escaped-text child.
#[derive(Clone, Copy)]
pub(crate) struct NumericFirstFields<'a> {
    pub(crate) pool: &'a Arc<AllocationPoolV1>,
}
impl<'de> FieldDecoder<'de> for NumericFirstFields<'_> {
    type Value = Value<'de>;
    fn decode<D: serde::Deserializer<'de>>(
        self,
        index: usize,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(ValueVisitor {
            pool: self.pool,
            text: index != 0,
        })
    }
}

pub(crate) fn required_text(value: Option<Value<'_>>) -> Result<Text<'_>, Refusal> {
    match value {
        Some(Value::Text(value)) => Ok(value),
        Some(Value::Unavailable) => Err(Refusal::Unavailable),
        _ => Err(Refusal::Malformed),
    }
}
pub(crate) fn optional_text(value: Option<Value<'_>>) -> Result<Option<Text<'_>>, Refusal> {
    match value {
        None | Some(Value::Null) => Ok(None),
        value => required_text(value).map(Some),
    }
}

pub(crate) enum Value<'de> {
    Text(Text<'de>),
    Unsigned(u64),
    Signed(i64),
    Null,
    Other,
    Unavailable,
}
#[derive(Clone, Copy)]
pub(crate) struct ValueSeed<'a> {
    pub(crate) pool: &'a Arc<AllocationPoolV1>,
}
impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = Value<'de>;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(ValueVisitor {
            pool: self.pool,
            text: true,
        })
    }
}
struct ValueVisitor<'a> {
    pool: &'a Arc<AllocationPoolV1>,
    text: bool,
}
impl<'de> Visitor<'de> for ValueVisitor<'_> {
    type Value = Value<'de>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("request field value")
    }
    fn visit_borrowed_str<E: serde::de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
        Ok(if self.text {
            Value::Text(Text::borrowed(value))
        } else {
            Value::Other
        })
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if !self.text {
            return Ok(Value::Other);
        }
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
