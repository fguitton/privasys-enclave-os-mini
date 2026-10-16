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

/// Parse the current bootstrap object using the same admitted parser supplier.
pub(super) fn bootstrap<'de>(
    pool: &Arc<AllocationPoolV1>,
    input: &'de [u8],
) -> Result<enclave_os_common::protocol::SessionBootstrapRequest<Text<'de>>, Refusal> {
    let capacity = serde_json::Deserializer::slice_scratch_capacity(input.len())
        .ok_or(Refusal::Unavailable)?;
    let mut parser = AdmittedParser::new(pool, capacity, |scratch| {
        serde_json::Deserializer::from_slice_with_scratch(input, scratch).ok()
    })?;
    let request = enclave_os_common::protocol::session_bootstrap::Seed::new(pool)
        .deserialize(parser.parser_mut())
        .map_err(|_| Refusal::Malformed)??;
    parser.parser_mut().end().map_err(|_| Refusal::Malformed)?;
    Ok(request)
}

/// Syntax errors retain the original serde diagnostic without allocating a message.
#[derive(Debug)]
pub(super) enum ValueError {
    Syntax(serde_json::Error),
    Refused(Refusal),
}
pub(super) fn value<'de>(
    pool: &Arc<AllocationPoolV1>,
    input: &'de [u8],
) -> Result<enclave_os_common::request_json::value::Value<'de>, ValueError> {
    let capacity = serde_json::Deserializer::slice_scratch_capacity(input.len())
        .ok_or(ValueError::Refused(Refusal::Unavailable))?;
    let mut parser = AdmittedParser::new(pool, capacity, |scratch| {
        serde_json::Deserializer::from_slice_with_scratch(input, scratch).ok()
    })
    .map_err(ValueError::Refused)?;
    let request = enclave_os_common::request_json::value::Seed::new(pool)
        .deserialize(parser.parser_mut())
        .map_err(ValueError::Syntax)?;
    parser.parser_mut().end().map_err(ValueError::Syntax)?;
    request.map_err(ValueError::Refused)
}

/// Existing module-envelope encoding is separate from parsed-tree admission.
/// Borrow parsed children through encoding; never clone them into an unpaid tree.
pub(super) fn rpc(
    pool: &Arc<AllocationPoolV1>,
    input: &[u8],
    app: &str,
    function: &str,
    header_billing: Option<&str>,
) -> Result<Vec<u8>, ValueError> {
    use enclave_os_common::request_json::value::Value;
    let parsed = if input.is_empty() {
        Value::Object(
            enclave_os_common::allocation::ordered_map::PaidOrderedMapV1::new(Arc::clone(pool)),
        )
    } else {
        value(pool, input)?
    };
    let (body, app_auth, billing) = match parsed {
        Value::Object(mut map) => {
            let app_auth = map.remove("app_auth");
            let billing = map.remove("billing_approved");
            (Value::Object(map), app_auth, billing)
        }
        other => (other, None, None),
    };
    #[derive(serde::Serialize)]
    struct Envelope<T> {
        connect_call: T,
    }
    // Field order matches the existing sorted serde_json object encoding.
    #[derive(serde::Serialize)]
    struct Call<'a, 'de> {
        app: &'a str,
        app_auth: Option<&'a str>,
        billing_approved: Option<&'a str>,
        body: &'a Value<'de>,
        function: &'a str,
    }
    Ok(serde_json::to_vec(&Envelope {
        connect_call: Call {
            app,
            app_auth: app_auth.as_ref().and_then(Value::as_str),
            billing_approved: header_billing.or_else(|| billing.as_ref().and_then(Value::as_str)),
            body: &body,
            function,
        },
    })
    .unwrap_or_default())
}

pub(super) fn mcp(
    pool: &Arc<AllocationPoolV1>,
    input: &[u8],
    app: &str,
    function: &str,
    header_auth: Option<&str>,
) -> Result<Vec<u8>, ValueError> {
    use enclave_os_common::request_json::value::Value;
    let parsed = if input.is_empty() {
        Value::Object(
            enclave_os_common::allocation::ordered_map::PaidOrderedMapV1::new(Arc::clone(pool)),
        )
    } else {
        value(pool, input)?
    };
    let (body, app_auth) = match parsed {
        Value::Object(mut map) => {
            let app_auth = map.remove("app_auth");
            (Value::Object(map), app_auth)
        }
        other => (other, None),
    };
    #[derive(serde::Serialize)]
    struct Envelope<T> {
        connect_call: T,
    }
    #[derive(serde::Serialize)]
    struct Call<'a, 'de> {
        app: &'a str,
        app_auth: Option<&'a str>,
        body: &'a Value<'de>,
        function: &'a str,
    }
    Ok(serde_json::to_vec(&Envelope {
        connect_call: Call {
            app,
            app_auth: app_auth.as_ref().and_then(Value::as_str).or(header_auth),
            body: &body,
            function,
        },
    })
    .unwrap_or_default())
}

/// Project the existing MCP tools response without cloning its parsed children.
pub(super) fn mcp_tools_response(
    pool: &Arc<AllocationPoolV1>,
    input: &[u8],
) -> Result<Option<(u16, Vec<u8>)>, ValueError> {
    use enclave_os_common::request_json::value::Value;
    let parsed = value(pool, input)?;
    match parsed.get("status").and_then(Value::as_str) {
        Some("mcp_tools") => {
            let tools = parsed
                .get("manifest")
                .and_then(|manifest| manifest.get("tools"))
                .and_then(Value::as_array)
                .unwrap_or(&[]);
            #[derive(serde::Serialize)]
            struct Envelope<T> {
                tools: T,
            }
            struct Tools<'a, 'de>(&'a [Value<'de>]);
            impl serde::Serialize for Tools<'_, '_> {
                fn serialize<S: serde::Serializer>(
                    &self,
                    serializer: S,
                ) -> Result<S::Ok, S::Error> {
                    use serde::ser::SerializeSeq;
                    let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
                    for tool in self.0 {
                        sequence.serialize_element(&Tool(tool))?;
                    }
                    sequence.end()
                }
            }
            struct Tool<'a, 'de>(&'a Value<'de>);
            impl serde::Serialize for Tool<'_, '_> {
                fn serialize<S: serde::Serializer>(
                    &self,
                    serializer: S,
                ) -> Result<S::Ok, S::Error> {
                    use serde::ser::SerializeMap;
                    let description = self.0.get("description").filter(|value| !value.is_null());
                    let schema = self
                        .0
                        .get("inputSchema")
                        .or_else(|| self.0.get("input_schema"));
                    let name = self.0.get("name");
                    let mut map = serializer.serialize_map(Some(
                        usize::from(description.is_some())
                            + usize::from(schema.is_some())
                            + usize::from(name.is_some()),
                    ))?;
                    // Existing sorted-object wire order, including null name/schema.
                    if let Some(value) = description {
                        map.serialize_entry("description", value)?;
                    }
                    if let Some(value) = schema {
                        map.serialize_entry("input_schema", value)?;
                    }
                    if let Some(value) = name {
                        map.serialize_entry("name", value)?;
                    }
                    map.end()
                }
            }
            Ok(Some((
                200,
                serde_json::to_vec(&Envelope {
                    tools: Tools(tools),
                })
                .unwrap_or_default(),
            )))
        }
        Some("error" | "not_found") => {
            let message = parsed
                .get("message")
                .and_then(Value::as_str)
                .or_else(|| parsed.get("name").and_then(Value::as_str))
                .unwrap_or("error");
            Ok(Some((400, mcp_error(message))))
        }
        _ => Ok(None),
    }
}

pub(super) fn mcp_call_response(
    pool: &Arc<AllocationPoolV1>,
    input: &[u8],
) -> Result<Option<(u16, Vec<u8>)>, ValueError> {
    use enclave_os_common::request_json::value::Value;
    let parsed = value(pool, input)?;
    match parsed.get("status").and_then(Value::as_str) {
        Some("ok") => {
            let returns = parsed
                .get("returns")
                .and_then(Value::as_array)
                .unwrap_or(&[]);
            struct Returns<'a, 'de>(&'a [Value<'de>]);
            impl serde::Serialize for Returns<'_, '_> {
                fn serialize<S: serde::Serializer>(
                    &self,
                    serializer: S,
                ) -> Result<S::Ok, S::Error> {
                    use serde::ser::SerializeSeq;
                    let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
                    for result in self.0 {
                        seq.serialize_element(result.get("value").unwrap_or(&Value::Null))?;
                    }
                    seq.end()
                }
            }
            #[derive(serde::Serialize)]
            struct Empty {}
            let encoded = match returns {
                [] => serde_json::to_vec(&Empty {}),
                [only] => serde_json::to_vec(only.get("value").unwrap_or(&Value::Null)),
                _ => serde_json::to_vec(&Returns(returns)),
            };
            Ok(Some((200, encoded.unwrap_or_default())))
        }
        Some("error") => Ok(Some((
            400,
            mcp_error(
                parsed
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("error"),
            ),
        ))),
        _ => Ok(None),
    }
}
fn mcp_error(message: &str) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct Error<'a> {
        error: &'a str,
    }
    serde_json::to_vec(&Error { error: message }).unwrap_or_default()
}

/// Preserve the existing FIDO route/query projection without an unpaid JSON tree.
pub(super) fn fido<'a>(
    pool: &Arc<AllocationPoolV1>,
    input: &'a [u8],
    route: &'a str,
    query: Option<&'a str>,
) -> Result<Vec<u8>, ValueError> {
    use enclave_os_common::{
        allocation::ordered_map::PaidOrderedMapV1, request_json::value::Value,
    };
    let mut object = match value(pool, input) {
        Ok(Value::Object(object)) => object,
        Err(ValueError::Refused(Refusal::Unavailable)) => {
            return Err(ValueError::Refused(Refusal::Unavailable))
        }
        _ => PaidOrderedMapV1::new(Arc::clone(pool)),
    };
    object
        .try_insert(Text::borrowed("type"), Value::String(Text::borrowed(route)))
        .map_err(|_| ValueError::Refused(Refusal::Unavailable))?;
    if let Some(query) = query {
        for pair in query.split('&') {
            if let Some((key, text)) = pair.split_once('=') {
                let key = if key == "session_id" {
                    "sessionId"
                } else {
                    key
                };
                if object.contains_key(key) {
                    continue;
                }
                let text =
                    Text::display(pool, &PercentDecoded(text)).map_err(ValueError::Refused)?;
                object
                    .try_insert(Text::borrowed(key), Value::String(text))
                    .map_err(|_| ValueError::Refused(Refusal::Unavailable))?;
            }
        }
    }
    Ok(serde_json::to_vec(&Value::Object(object)).unwrap_or_else(|_| input.to_vec()))
}
/// Existing byte-by-byte percent decoding, including its malformed-pair behavior.
/// Rendering is allocation-free; Text::display admits the actual UTF-8 byte count.
struct PercentDecoded<'a>(&'a str);
impl core::fmt::Display for PercentDecoded<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use core::fmt::Write;
        let mut bytes = self.0.as_bytes().iter();
        while let Some(&byte) = bytes.next() {
            if byte == b'%' {
                if let (Some(&high), Some(&low)) = (bytes.next(), bytes.next()) {
                    let high = (high as char).to_digit(16).unwrap_or(0) as u8;
                    let low = (low as char).to_digit(16).unwrap_or(0) as u8;
                    f.write_char(((high << 4) | low) as char)?;
                }
            } else {
                f.write_char(byte as char)?;
            }
        }
        Ok(())
    }
}

#[path = "request_json/manager.rs"]
pub(crate) mod manager;
