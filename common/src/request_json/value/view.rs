//! Borrow the current paid tree for typed projections; never clone an unpaid JSON tree.
//! Allocations made by the projected domain type remain that consumer's responsibility.
use super::Value;
use serde::de::{self, DeserializeSeed, IntoDeserializer, MapAccess, SeqAccess, Visitor};

impl<'de> IntoDeserializer<'de, serde_json::Error> for &'de Value<'_> {
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}
struct Array<'a, 'text>(core::slice::Iter<'a, Value<'text>>);
impl<'de> SeqAccess<'de> for Array<'de, '_> {
    type Error = serde_json::Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Self::Error> {
        self.0
            .next()
            .map(|value| seed.deserialize(value))
            .transpose()
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.0.len())
    }
}
struct Object<'a, 'text, I: Iterator<Item = (&'a super::Text<'text>, &'a Value<'text>)>> {
    entries: I,
    value: Option<&'a Value<'text>>,
}
impl<'de, 'text, I: Iterator<Item = (&'de super::Text<'text>, &'de Value<'text>)>> MapAccess<'de>
    for Object<'de, 'text, I>
{
    type Error = serde_json::Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        match self.entries.next() {
            Some((key, value)) => {
                self.value = Some(value);
                seed.deserialize(Key(key.as_str())).map(Some)
            }
            None => Ok(None),
        }
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        seed.deserialize(
            self.value
                .take()
                .ok_or_else(|| de::Error::custom("value is missing"))?,
        )
    }
    fn size_hint(&self) -> Option<usize> {
        self.entries.size_hint().1
    }
}
struct Key<'a>(&'a str);
macro_rules! key_number {
    ($($name:ident => $visit:ident),*) => {$ (
        fn $name<V:Visitor<'de>>(self,visitor:V)->Result<V::Value,Self::Error>{
            if !matches!(self.0.as_bytes().first(),Some(b'0'..=b'9' | b'-')) {
                return Err(de::Error::custom("invalid value: expected key to be a number in quotes"));
            }
            let mut parser=serde_json::Deserializer::from_str(self.0);
            let value=de::Deserializer::$name(&mut parser,visitor)?;
            if parser.into_iter::<de::IgnoredAny>().byte_offset()!=self.0.len() {
                return Err(de::Error::custom("invalid value: expected key to be a number in quotes"));
            }
            Ok(value)
        }
    )*};
}
impl<'de> de::Deserializer<'de> for Key<'de> {
    type Error = serde_json::Error;
    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_borrowed_str(self.0)
    }
    key_number! {deserialize_i8=>visit_i8,deserialize_i16=>visit_i16,deserialize_i32=>visit_i32,deserialize_i64=>visit_i64,deserialize_i128=>visit_i128,
    deserialize_u8=>visit_u8,deserialize_u16=>visit_u16,deserialize_u32=>visit_u32,deserialize_u64=>visit_u64,deserialize_u128=>visit_u128,
    deserialize_f32=>visit_f32,deserialize_f64=>visit_f64}
    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            "true" => visitor.visit_bool(true),
            "false" => visitor.visit_bool(false),
            _ => Err(de::Error::invalid_type(
                de::Unexpected::Str(self.0),
                &visitor,
            )),
        }
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        de::value::BorrowedStrDeserializer::new(self.0).deserialize_enum(name, variants, visitor)
    }
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_some(self)
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }
    serde::forward_to_deserialize_any! { char str string bytes byte_buf unit unit_struct seq tuple tuple_struct map struct identifier ignored_any }
}
impl<'de> de::Deserializer<'de> for &'de Value<'_> {
    type Error = serde_json::Error;
    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self {
            Value::Null => visitor.visit_unit(),
            Value::Bool(value) => visitor.visit_bool(*value),
            Value::Number(value) => de::Deserializer::deserialize_any(value, visitor),
            Value::String(value) => visitor.visit_borrowed_str(value.as_str()),
            Value::Array(values) => {
                let mut array = Array(values.as_slice().iter());
                let result = visitor.visit_seq(&mut array)?;
                if array.0.len() == 0 {
                    Ok(result)
                } else {
                    Err(de::Error::invalid_length(
                        values.as_slice().len(),
                        &"fewer elements in array",
                    ))
                }
            }
            Value::Object(values) => {
                let mut object = Object {
                    entries: values.iter(),
                    value: None,
                };
                let result = visitor.visit_map(&mut object)?;
                if object.entries.next().is_none() {
                    Ok(result)
                } else {
                    Err(de::Error::invalid_length(
                        values.len(),
                        &"fewer elements in map",
                    ))
                }
            }
        }
    }
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        if self.is_null() {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        match self {
            Value::String(value) => de::value::BorrowedStrDeserializer::new(value.as_str())
                .deserialize_enum(name, variants, visitor),
            Value::Object(values) if values.len() == 1 => {
                let (key, value) = values.iter().next().expect("one enum variant");
                visitor.visit_enum(Enum {
                    key: key.as_str(),
                    value,
                })
            }
            Value::Object(_) => Err(de::Error::invalid_value(
                de::Unexpected::Map,
                &"map with a single key",
            )),
            _ => Err(de::Error::invalid_type(unexpected(self), &"string or map")),
        }
    }
    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_unit()
    }
    serde::forward_to_deserialize_any! { bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf unit unit_struct seq tuple tuple_struct map struct identifier }
}
fn unexpected<'a>(value: &'a Value<'_>) -> de::Unexpected<'a> {
    match value {
        Value::Null => de::Unexpected::Unit,
        Value::Bool(v) => de::Unexpected::Bool(*v),
        Value::String(v) => de::Unexpected::Str(v.as_str()),
        Value::Array(_) => de::Unexpected::Seq,
        Value::Object(_) => de::Unexpected::Map,
        Value::Number(v) => {
            if let Some(n) = v.as_u64() {
                de::Unexpected::Unsigned(n)
            } else if let Some(n) = v.as_i64() {
                de::Unexpected::Signed(n)
            } else {
                de::Unexpected::Float(v.as_f64().expect("finite JSON number"))
            }
        }
    }
}
struct Enum<'a, 'text> {
    key: &'a str,
    value: &'a Value<'text>,
}
impl<'de, 'text> de::EnumAccess<'de> for Enum<'de, 'text> {
    type Error = serde_json::Error;
    type Variant = Self;
    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant), Self::Error> {
        seed.deserialize(Key(self.key))
            .map(|variant| (variant, self))
    }
}
impl<'de> de::VariantAccess<'de> for Enum<'de, '_> {
    type Error = serde_json::Error;
    fn unit_variant(self) -> Result<(), Self::Error> {
        serde::Deserialize::deserialize(self.value)
    }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> Result<T::Value, Self::Error> {
        seed.deserialize(self.value)
    }
    fn tuple_variant<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        match self.value {
            Value::Array(values) if values.as_slice().is_empty() => visitor.visit_unit(),
            Value::Array(_) => de::Deserializer::deserialize_any(self.value, visitor),
            _ => Err(de::Error::invalid_type(
                unexpected(self.value),
                &"tuple variant",
            )),
        }
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        match self.value {
            Value::Object(_) => de::Deserializer::deserialize_any(self.value, visitor),
            _ => Err(de::Error::invalid_type(
                unexpected(self.value),
                &"struct variant",
            )),
        }
    }
}
