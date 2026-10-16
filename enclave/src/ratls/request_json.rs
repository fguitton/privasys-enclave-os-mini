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
