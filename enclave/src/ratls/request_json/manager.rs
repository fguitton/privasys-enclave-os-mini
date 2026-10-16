//! Typed management request decoding with caller-owned semantic diagnostics.
use enclave_os_common::{
    allocation::AllocationPoolV1,
    protocol::AttestationServer,
    request_json::{sequence::Sequence, AdmittedParser, Refusal, Text},
};
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Unexpected, Visitor};
use std::{cell::RefCell, fmt, sync::Arc};

type Servers = Sequence<AttestationServer<Text<'static>>>;
/// The diagnostic backing remains admitted through the caller's response formatting.
#[derive(Debug)]
pub(crate) enum Error {
    Syntax(serde_json::Error),
    Semantic {
        message: Text<'static>,
        line: usize,
        column: usize,
    },
    Unavailable,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => error.fmt(f),
            Self::Semantic {
                message,
                line,
                column,
            } => {
                f.write_str(message.as_str())?;
                if *line != 0 {
                    write!(f, " at line {line} column {column}")?;
                }
                Ok(())
            }
            Self::Unavailable => f.write_str("request allocation unavailable"),
        }
    }
}
struct Context<'a> {
    pool: &'a Arc<AllocationPoolV1>,
    diagnostic: RefCell<Option<Result<Text<'static>, Refusal>>>,
}
impl Context<'_> {
    fn abort<E: serde::de::Error>(&self, message: &impl fmt::Display) -> E {
        *self.diagnostic.borrow_mut() = Some(Text::display(self.pool, message));
        E::custom(serde_json::Error::request_semantic_abort())
    }
    fn unavailable<E: serde::de::Error>(&self) -> E {
        *self.diagnostic.borrow_mut() = Some(Err(Refusal::Unavailable));
        E::custom(serde_json::Error::request_semantic_abort())
    }
    fn invalid<E: serde::de::Error>(&self, value: Unexpected<'_>, expected: &'static str) -> E {
        if matches!(value, Unexpected::Map | Unexpected::Seq) {
            *self.diagnostic.borrow_mut() = Some(Text::display(
                self.pool,
                &serde_json::Error::request_invalid_type(value, expected),
            ));
            E::custom(serde_json::Error::request_container_abort())
        } else {
            self.abort(&serde_json::Error::request_invalid_type(value, expected))
        }
    }
    fn finish(&self, error: serde_json::Error) -> Error {
        if !error.is_request_semantic_abort() {
            return Error::Syntax(error);
        }
        match self.diagnostic.borrow_mut().take() {
            Some(Ok(message)) => Error::Semantic {
                message,
                line: error.line(),
                column: error.column(),
            },
            _ => Error::Unavailable,
        }
    }
}
// Override serde's dynamically allocated default invalid-type diagnostics.
macro_rules! reject_scalars {
    ($expected:expr) => {
        fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
            Err(self.0.invalid(Unexpected::Bool(value), $expected))
        }
        fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
            Err(self.0.invalid(Unexpected::Signed(value), $expected))
        }
        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
            Err(self.0.invalid(Unexpected::Unsigned(value), $expected))
        }
        fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
            Err(self.0.invalid(Unexpected::Float(value), $expected))
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Err(self.0.invalid(Unexpected::Unit, $expected))
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            Err(self.0.invalid(Unexpected::Str(value), $expected))
        }
    };
}
struct StringSeed<'a, 'p>(&'a Context<'p>);
impl<'de> DeserializeSeed<'de> for StringSeed<'_, '_> {
    type Value = Text<'static>;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for StringSeed<'_, '_> {
    type Value = Text<'static>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Text::copy(self.0.pool, value).map_err(|_| self.0.unavailable())
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
        Err(self.0.invalid(Unexpected::Bool(v), "a string"))
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
        Err(self.0.invalid(Unexpected::Signed(v), "a string"))
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
        Err(self.0.invalid(Unexpected::Unsigned(v), "a string"))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
        Err(self.0.invalid(Unexpected::Float(v), "a string"))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Err(self.0.invalid(Unexpected::Unit, "a string"))
    }
    fn visit_map<A: MapAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> {
        Err(self.0.invalid(Unexpected::Map, "a string"))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> {
        Err(self.0.invalid(Unexpected::Seq, "a string"))
    }
}
struct TokenSeed<'a, 'p>(&'a Context<'p>);
impl<'de> DeserializeSeed<'de> for TokenSeed<'_, '_> {
    type Value = Option<Text<'static>>;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_option(self)
    }
}
impl<'de> Visitor<'de> for TokenSeed<'_, '_> {
    type Value = Option<Text<'static>>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("option")
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        StringSeed(self.0).deserialize(d).map(Some)
    }
}
struct KeySeed(&'static [&'static str]);
impl<'de> DeserializeSeed<'de> for KeySeed {
    type Value = Option<usize>;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_identifier(self)
    }
}
impl Visitor<'_> for KeySeed {
    type Value = Option<usize>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("field identifier")
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(self.0.iter().position(|name| *name == v))
    }
}
struct ServerSeed<'a, 'p>(&'a Context<'p>);
impl<'de> DeserializeSeed<'de> for ServerSeed<'_, '_> {
    type Value = AttestationServer<Text<'static>>;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for ServerSeed<'_, '_> {
    type Value = AttestationServer<Text<'static>>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("struct AttestationServer")
    }
    reject_scalars!("struct AttestationServer");
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let url = seq.next_element_seed(StringSeed(self.0))?.ok_or_else(|| {
            self.0
                .abort(&"invalid length 0, expected struct AttestationServer with 2 elements")
        })?;
        let token = seq.next_element_seed(TokenSeed(self.0))?.unwrap_or(None);
        Ok(AttestationServer { url, token })
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let (mut url, mut token) = (None, None);
        while let Some(key) = map.next_key_seed(KeySeed(&["url", "token"]))? {
            match key {
                Some(0) => {
                    if url.is_some() {
                        return Err(self.0.abort(&"duplicate field `url`"));
                    }
                    url = Some(map.next_value_seed(StringSeed(self.0))?);
                }
                Some(1) => {
                    if token.is_some() {
                        return Err(self.0.abort(&"duplicate field `token`"));
                    }
                    token = Some(map.next_value_seed(TokenSeed(self.0))?);
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        let url = url.ok_or_else(|| self.0.abort(&"missing field `url`"))?;
        Ok(AttestationServer {
            url,
            token: token.unwrap_or(None),
        })
    }
}
struct ListSeed<'a, 'p>(&'a Context<'p>);
impl<'de> DeserializeSeed<'de> for ListSeed<'_, '_> {
    type Value = Servers;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for ListSeed<'_, '_> {
    type Value = Servers;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a sequence")
    }
    reject_scalars!("a sequence");
    fn visit_map<A: MapAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> {
        Err(self.0.invalid(Unexpected::Map, "a sequence"))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut servers = Sequence::new(Arc::clone(self.0.pool));
        while let Some(server) = seq.next_element_seed(ServerSeed(self.0))? {
            servers.try_push(server).map_err(|_| self.0.unavailable())?;
        }
        Ok(servers)
    }
}
struct RequestSeed<'a, 'p>(&'a Context<'p>);
impl<'de> DeserializeSeed<'de> for RequestSeed<'_, '_> {
    type Value = Servers;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for RequestSeed<'_, '_> {
    type Value = Servers;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("struct SetAttestationServersRequest")
    }
    reject_scalars!("struct SetAttestationServersRequest");
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        seq.next_element_seed(ListSeed(self.0))?.ok_or_else(|| {
            self.0.abort(
                &"invalid length 0, expected struct SetAttestationServersRequest with 1 element",
            )
        })
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut servers = None;
        while let Some(key) = map.next_key_seed(KeySeed(&["servers"]))? {
            if key == Some(0) {
                if servers.is_some() {
                    return Err(self.0.abort(&"duplicate field `servers`"));
                }
                servers = Some(map.next_value_seed(ListSeed(self.0))?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        servers.ok_or_else(|| self.0.abort(&"missing field `servers`"))
    }
}
/// Decode exactly the existing manager DTO; retained children survive the HTTP body.
pub(crate) fn parse(pool: &Arc<AllocationPoolV1>, input: &[u8]) -> Result<Servers, Error> {
    let capacity =
        serde_json::Deserializer::slice_scratch_capacity(input.len()).ok_or(Error::Unavailable)?;
    let mut parser = AdmittedParser::new(pool, capacity, |scratch| {
        serde_json::Deserializer::from_slice_with_scratch(input, scratch).ok()
    })
    .map_err(|_| Error::Unavailable)?;
    let context = Context {
        pool,
        diagnostic: RefCell::new(None),
    };
    let servers = RequestSeed(&context)
        .deserialize(parser.parser_mut())
        .map_err(|error| context.finish(error))?;
    parser.parser_mut().end().map_err(Error::Syntax)?;
    Ok(servers)
}

#[path = "manager/configuration.rs"]
pub(crate) mod configuration;
