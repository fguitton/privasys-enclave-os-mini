//! Current JSON values with borrowed text and original-pool owned backings.
//! Object ordering and duplicate replacement match serde_json's current sorted map.
use super::{sequence::Sequence, Refusal, Text};
use crate::allocation::{ordered_map::PaidOrderedMapV1, AllocationPoolV1};
use alloc::sync::Arc;
use core::fmt;
use serde::{
    de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor},
    ser::{SerializeMap, SerializeSeq},
    Serialize,
};

/// Parsed JSON; no implicit child clones or conversion to an unpaid JSON tree.
pub enum Value<'a> {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(Text<'a>),
    Array(Sequence<Value<'a>>),
    Object(PaidOrderedMapV1<Text<'a>, Value<'a>>),
}
impl Value<'_> {
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(map) => map.get(key),
            _ => None,
        }
    }
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(text) => Some(text),
            _ => None,
        }
    }
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(values) => Some(values.as_slice()),
            _ => None,
        }
    }
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(number) => number.as_u64(),
            _ => None,
        }
    }
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}
impl fmt::Debug for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("Null"),
            Self::Bool(value) => value.fmt(f),
            Self::Number(value) => value.fmt(f),
            Self::String(value) => value.fmt(f),
            Self::Array(values) => f.debug_list().entries(values.as_slice()).finish(),
            Self::Object(map) => f.debug_map().entries(map.iter()).finish(),
        }
    }
}
impl Serialize for Value<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Number(value) => value.serialize(serializer),
            Self::String(value) => value.serialize(serializer),
            Self::Array(values) => {
                let mut seq = serializer.serialize_seq(Some(values.as_slice().len()))?;
                for value in values.as_slice() {
                    seq.serialize_element(value)?;
                }
                seq.end()
            }
            Self::Object(map) => {
                let mut object = serializer.serialize_map(Some(map.len()))?;
                for (key, value) in map.iter() {
                    object.serialize_entry(key, value)?;
                }
                object.end()
            }
        }
    }
}
/// Visit the current standard numeric JSON profile, borrowing unescaped input.
pub struct Seed<'a> {
    pool: &'a Arc<AllocationPoolV1>,
}
impl<'a> Seed<'a> {
    pub fn new(pool: &'a Arc<AllocationPoolV1>) -> Self {
        Self { pool }
    }
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Result<Value<'de>, Refusal>;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Result<Value<'de>, Refusal>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON value")
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Ok(Value::Bool(value)))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Ok(Value::Number(value.into())))
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Ok(Value::Number(value.into())))
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Ok(serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or(Refusal::Malformed))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(Ok(Value::Null))
    }
    fn visit_borrowed_str<E: serde::de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
        Ok(Ok(Value::String(Text::borrowed(value))))
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Text::copy(self.pool, value).map(Value::String))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut values = Sequence::new(Arc::clone(self.pool));
        while let Some(value) = seq.next_element_seed(Seed::new(self.pool))? {
            if let Err(error) = value.and_then(|value| values.try_push(value)) {
                drop(values);
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                return Ok(Err(error));
            }
        }
        Ok(Ok(Value::Array(values)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut values = PaidOrderedMapV1::new(Arc::clone(self.pool));
        while let Some(key) = map.next_key_seed(KeySeed(self.pool))? {
            let value = map.next_value_seed(Seed::new(self.pool))?;
            let result = key.and_then(|key| {
                value.and_then(|value| {
                    values
                        .try_insert(key, value)
                        .map(|_| ())
                        .map_err(|_| Refusal::Unavailable)
                })
            });
            if let Err(error) = result {
                drop(values);
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                return Ok(Err(error));
            }
        }
        Ok(Ok(Value::Object(values)))
    }
}
struct KeySeed<'a>(&'a Arc<AllocationPoolV1>);
impl<'de> DeserializeSeed<'de> for KeySeed<'_> {
    type Value = Result<Text<'de>, Refusal>;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_str(self)
    }
}
impl<'de> Visitor<'de> for KeySeed<'_> {
    type Value = Result<Text<'de>, Refusal>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON object key")
    }
    fn visit_borrowed_str<E: serde::de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
        Ok(Ok(Text::borrowed(value)))
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Text::copy(self.0, value))
    }
}
