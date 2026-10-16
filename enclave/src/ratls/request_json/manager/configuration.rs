//! Startup grammar reuses the current typed/error owner and retained value seed.
use super::*;
use enclave_os_common::{
    allocation::ordered_map::PaidOrderedMapV1,
    oidc::{self, retained::RetainedOidcConfig},
    request_json::{
        configuration::{EnclaveConfig, DEFAULT_BACKLOG, DEFAULT_PORT},
        value,
    },
};

#[derive(Clone, Copy)]
enum Integer {
    Port,
    Backlog,
}
impl Integer {
    fn expected(self) -> &'static str {
        match self {
            Self::Port => "u16",
            Self::Backlog => "i32",
        }
    }
    fn accepts(self, value: i128) -> bool {
        match self {
            Self::Port => u16::try_from(value).is_ok(),
            Self::Backlog => i32::try_from(value).is_ok(),
        }
    }
}
struct NumberSeed<'a, 'p>(&'a Context<'p>, Integer);
impl<'de> DeserializeSeed<'de> for NumberSeed<'_, '_> {
    type Value = i128;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for NumberSeed<'_, '_> {
    type Value = i128;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.1.expected())
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
        if self.1.accepts(i128::from(value)) {
            Ok(i128::from(value))
        } else {
            Err(self.0.abort(&serde_json::Error::request_invalid_value(
                Unexpected::Signed(value),
                self.1.expected(),
            )))
        }
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
        if self.1.accepts(i128::from(value)) {
            Ok(i128::from(value))
        } else {
            Err(self.0.abort(&serde_json::Error::request_invalid_value(
                Unexpected::Unsigned(value),
                self.1.expected(),
            )))
        }
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Err(self.0.invalid(Unexpected::Unit, self.1.expected()))
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
        Err(self.0.invalid(Unexpected::Bool(v), self.1.expected()))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
        Err(self.0.invalid(Unexpected::Float(v), self.1.expected()))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Err(self.0.invalid(Unexpected::Str(v), self.1.expected()))
    }
    fn visit_map<A: MapAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> {
        Err(self.0.invalid(Unexpected::Map, self.1.expected()))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> {
        Err(self.0.invalid(Unexpected::Seq, self.1.expected()))
    }
}
const OIDC_FIELDS: &[&str] = &[
    "issuer",
    "audience",
    "jwks_uri",
    "role_claim",
    "manager_role",
    "monitoring_role",
];
struct OidcSeed<'a, 'p>(&'a Context<'p>);
impl OidcSeed<'_, '_> {
    fn complete<E: serde::de::Error>(
        self,
        fields: [Option<Text<'static>>; OIDC_FIELDS.len()],
    ) -> Result<RetainedOidcConfig, E> {
        let [issuer, audience, jwks_uri, role_claim, manager_role, monitoring_role] = fields;
        let issuer = issuer.ok_or_else(|| self.0.abort(&"missing field `issuer`"))?;
        let audience = audience.ok_or_else(|| self.0.abort(&"missing field `audience`"))?;
        let default = |value: Option<Text<'static>>, fallback| {
            value.map_or_else(
                || Text::copy(self.0.pool, fallback).map_err(|_| self.0.unavailable()),
                Ok,
            )
        };
        let jwks_uri = default(jwks_uri, "")?;
        let role_claim = default(role_claim, oidc::DEFAULT_ROLE_CLAIM)?;
        let manager_role = default(manager_role, oidc::DEFAULT_MANAGER_ROLE)?;
        let monitoring_role = default(monitoring_role, oidc::DEFAULT_MONITORING_ROLE)?;
        RetainedOidcConfig::new(
            issuer,
            audience,
            jwks_uri,
            role_claim,
            manager_role,
            monitoring_role,
        )
        .map_err(|_| self.0.unavailable())
    }
}
impl<'de> DeserializeSeed<'de> for OidcSeed<'_, '_> {
    type Value = RetainedOidcConfig;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for OidcSeed<'_, '_> {
    type Value = RetainedOidcConfig;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("struct OidcConfig")
    }
    reject_scalars!("struct OidcConfig");
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut fields = core::array::from_fn(|_| None);
        while let Some(key) = map.next_key_seed(KeySeed(OIDC_FIELDS))? {
            if let Some(index) = key {
                if fields[index].is_some() {
                    return Err(self
                        .0
                        .abort(&format_args!("duplicate field `{}`", OIDC_FIELDS[index])));
                }
                fields[index] = Some(map.next_value_seed(StringSeed(self.0))?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        self.complete(fields)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut fields = core::array::from_fn(|_| None);
        for (index, field) in fields.iter_mut().enumerate() {
            *field = seq.next_element_seed(StringSeed(self.0))?;
            if field.is_none() {
                if index < 2 {
                    return Err(self.0.abort(&format_args!(
                        "invalid length {index}, expected struct OidcConfig with {} elements",
                        OIDC_FIELDS.len()
                    )));
                }
                break;
            }
        }
        self.complete(fields)
    }
}
struct OptionalOidcSeed<'a, 'p>(&'a Context<'p>);
impl<'de> DeserializeSeed<'de> for OptionalOidcSeed<'_, '_> {
    type Value = Option<RetainedOidcConfig>;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_option(self)
    }
}
impl<'de> Visitor<'de> for OptionalOidcSeed<'_, '_> {
    type Value = Option<RetainedOidcConfig>;
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
        OidcSeed(self.0).deserialize(d).map(Some)
    }
}
enum ConfigKey {
    Port,
    Backlog,
    Oidc,
    Extra(Text<'static>),
}
struct ConfigKeySeed<'a, 'p>(&'a Context<'p>);
impl<'de> DeserializeSeed<'de> for ConfigKeySeed<'_, '_> {
    type Value = ConfigKey;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_identifier(self)
    }
}
impl Visitor<'_> for ConfigKeySeed<'_, '_> {
    type Value = ConfigKey;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("field identifier")
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(match v {
            "port" => ConfigKey::Port,
            "backlog" => ConfigKey::Backlog,
            "oidc" => ConfigKey::Oidc,
            _ => ConfigKey::Extra(Text::copy(self.0.pool, v).map_err(|_| self.0.unavailable())?),
        })
    }
}
struct ConfigSeed<'a, 'p>(&'a Context<'p>);
impl<'de> DeserializeSeed<'de> for ConfigSeed<'_, '_> {
    type Value = EnclaveConfig;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for ConfigSeed<'_, '_> {
    type Value = EnclaveConfig;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("struct EnclaveConfig")
    }
    reject_scalars!("struct EnclaveConfig");
    fn visit_seq<A: SeqAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> {
        Err(self.0.invalid(Unexpected::Seq, "struct EnclaveConfig"))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let (mut port, mut backlog, mut oidc) = (None, None, None);
        let mut extra = PaidOrderedMapV1::new(Arc::clone(self.0.pool));
        while let Some(key) = map.next_key_seed(ConfigKeySeed(self.0))? {
            match key {
                ConfigKey::Port => {
                    if port.is_some() {
                        return Err(self.0.abort(&"duplicate field `port`"));
                    }
                    let value = map.next_value_seed(NumberSeed(self.0, Integer::Port))?;
                    port = Some(u16::try_from(value).map_err(|_| self.0.unavailable())?);
                }
                ConfigKey::Backlog => {
                    if backlog.is_some() {
                        return Err(self.0.abort(&"duplicate field `backlog`"));
                    }
                    let value = map.next_value_seed(NumberSeed(self.0, Integer::Backlog))?;
                    backlog = Some(i32::try_from(value).map_err(|_| self.0.unavailable())?);
                }
                ConfigKey::Oidc => {
                    if oidc.is_some() {
                        return Err(self.0.abort(&"duplicate field `oidc`"));
                    }
                    oidc = Some(map.next_value_seed(OptionalOidcSeed(self.0))?);
                }
                ConfigKey::Extra(key) => {
                    let value = map
                        .next_value_seed(value::Seed::retained(self.0.pool))?
                        .map_err(|_| self.0.unavailable())?;
                    extra
                        .try_insert(key, value)
                        .map_err(|_| self.0.unavailable())?;
                }
            }
        }
        Ok(EnclaveConfig {
            port: port.unwrap_or(DEFAULT_PORT),
            backlog: backlog.unwrap_or(DEFAULT_BACKLOG),
            oidc: oidc.unwrap_or(None),
            extra,
        })
    }
}
/// Retain all variable children before returning from the untrusted host buffer.
pub(crate) fn parse(pool: &Arc<AllocationPoolV1>, input: &[u8]) -> Result<EnclaveConfig, Error> {
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
    let config = ConfigSeed(&context)
        .deserialize(parser.parser_mut())
        .map_err(|error| context.finish(error))?;
    parser.parser_mut().end().map_err(Error::Syntax)?;
    Ok(config)
}
