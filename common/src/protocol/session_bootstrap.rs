//! Bootstrap and voucher JSON with borrowed or admitted escaped fields.
use super::{EncAuthEnvelope, SessionBootstrapRequest};
use crate::{
    allocation::AllocationPoolV1,
    request_json::{
        fields::{required_text, FieldDecoder, FieldsSeed, NumericFirstFields, Value, ValueSeed},
        Refusal, Text,
    },
};
use alloc::sync::Arc;
use core::fmt;
use serde::de::{DeserializeSeed, Visitor};

/// Same object/sequence/default model as `SessionBootstrapRequest<String>`.
pub struct Seed<'a> {
    pool: &'a Arc<AllocationPoolV1>,
}
impl<'a> Seed<'a> {
    pub fn new(pool: &'a Arc<AllocationPoolV1>) -> Self {
        Self { pool }
    }
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Result<SessionBootstrapRequest<Text<'de>>, Refusal>;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        Ok(
            FieldsSeed::new(&["sdk_pub", "encauth"], BootstrapField { pool: self.pool })
                .deserialize(deserializer)?
                .and_then(|mut fields| {
                    let sdk_pub = match fields[0].take() {
                        Some(BootstrapValue::Text(value)) => required_text(Some(value))?,
                        _ => return Err(Refusal::Malformed),
                    };
                    let encauth = match fields[1].take() {
                        None => None,
                        Some(BootstrapValue::Envelope(value)) => value?,
                        _ => return Err(Refusal::Malformed),
                    };
                    Ok(SessionBootstrapRequest { sdk_pub, encauth })
                }),
        )
    }
}
enum BootstrapValue<'de> {
    Text(Value<'de>),
    Envelope(Result<Option<EncAuthEnvelope<Text<'de>>>, Refusal>),
}
#[derive(Clone, Copy)]
struct BootstrapField<'a> {
    pool: &'a Arc<AllocationPoolV1>,
}
impl<'de> FieldDecoder<'de> for BootstrapField<'_> {
    type Value = BootstrapValue<'de>;
    fn decode<D: serde::Deserializer<'de>>(
        self,
        index: usize,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        if index == 0 {
            ValueSeed { pool: self.pool }
                .deserialize(deserializer)
                .map(BootstrapValue::Text)
        } else {
            deserializer
                .deserialize_option(EnvelopeVisitor { pool: self.pool })
                .map(BootstrapValue::Envelope)
        }
    }
}
struct EnvelopeVisitor<'a> {
    pool: &'a Arc<AllocationPoolV1>,
}
impl<'de> Visitor<'de> for EnvelopeVisitor<'_> {
    type Value = Result<Option<EncAuthEnvelope<Text<'de>>>, Refusal>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("optional EncAuth envelope")
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(Ok(None))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(Ok(None))
    }
    fn visit_some<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        Ok(FieldsSeed::new(
            &["v", "payload", "hw_sig", "idp_sig"],
            NumericFirstFields { pool: self.pool },
        )
        .deserialize(deserializer)?
        .and_then(|mut fields| {
            let v = match fields[0].take() {
                Some(Value::Unsigned(value)) => {
                    u8::try_from(value).map_err(|_| Refusal::Malformed)?
                }
                Some(Value::Signed(value)) => {
                    u8::try_from(value).map_err(|_| Refusal::Malformed)?
                }
                Some(Value::Unavailable) => return Err(Refusal::Unavailable),
                _ => return Err(Refusal::Malformed),
            };
            Ok(Some(EncAuthEnvelope {
                v,
                payload: required_text(fields[1].take())?,
                hw_sig: required_text(fields[2].take())?,
                idp_sig: match fields[3].take() {
                    None => Text::default(),
                    value => required_text(value)?,
                },
            }))
        }))
    }
}
