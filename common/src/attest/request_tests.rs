#[path = "../../../enclave/src/ratls/request_json.rs"]
mod endpoint;
#[cfg(test)]
mod tests {
    use super::endpoint;
    use enclave_os_common::{
        allocation::AllocationPoolV1, attest::AttestRequest, request_json::Refusal,
    };
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        cell::Cell,
    };
    thread_local! { static COUNT: Cell<Option<(usize, usize)>> = const { Cell::new(None) }; }
    struct Counting;
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            COUNT.with(|count| {
                if let Some((n, b)) = count.get() {
                    count.set(Some((n + 1, b + layout.size())));
                }
            });
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe {
                System.dealloc(ptr, layout);
            }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new: usize) -> *mut u8 {
            COUNT.with(|count| {
                if let Some((n, b)) = count.get() {
                    count.set(Some((n + 1, b + new)));
                }
            });
            unsafe { System.realloc(ptr, layout, new) }
        }
    }
    #[global_allocator]
    static ALLOC: Counting = Counting;
    fn measured<T>(f: impl FnOnce() -> T) -> (T, (usize, usize)) {
        COUNT.with(|c| {
            assert!(c.get().is_none());
            c.set(Some((0, 0)));
        });
        let result = f();
        let count = COUNT.with(|c| c.replace(None).unwrap());
        (result, count)
    }
    fn compare(input: &[u8]) {
        let pool = AllocationPoolV1::new(1 << 20).unwrap();
        let original = serde_json::from_slice::<AttestRequest>(input);
        let admitted = endpoint::attest(&pool, input);
        assert_eq!(
            original.is_ok(),
            admitted.is_ok(),
            "{}",
            String::from_utf8_lossy(input)
        );
        if let (Ok(original), Ok(admitted)) = (original, admitted) {
            assert_eq!(original.v, admitted.v);
            assert_eq!(original.mode, admitted.mode.as_str());
            assert_eq!(original.leaf, admitted.leaf.as_str());
            assert_eq!(original.context.as_deref(), admitted.context.as_deref());
            assert_eq!(original.tee.as_deref(), admitted.tee.as_deref());
            assert_eq!(original.quote.as_deref(), admitted.quote.as_deref());
            assert_eq!(
                original.gpu_evidence.as_deref(),
                admitted.gpu_evidence.as_deref()
            );
            assert_eq!(
                original.quote_time.as_deref(),
                admitted.quote_time.as_deref()
            );
        }
        assert_eq!(pool.used(), 0);
    }
    #[test]
    fn original_object_sequence_unicode_and_refusal_acceptance() {
        for input in [
            r#"{"v":2,"mode":"challenge"}"#,
            r#"[2,"present"]"#,
            r#"[2,"present","",null,null,null,null,null]"#,
            r#"{"v":2,"mo\u0064e":"ch\u0061llenge","leaf":"\uD834\uDD1E","context":"\n\t\\\"","other":{"deep":[1,true,null,{"x":"\u0061"}]},"other":3}"#,
            r#"{"v":2,"mode":"日本😀","leaf":"é"}"#,
            r#"{"v":2,"mode":"x","context":null,"context":null}"#,
            r#"{"v":2,"mode":"x","mode":"y"}"#,
            r#"{"v":2,"mode":"x","\u006dode":"y"}"#,
            r#"[2,"x","",null,null,null,null,null,0]"#,
            r#"{"v":2,"mode":"\uD800"}"#,
            r#"{"v":2,"mode":"\uDC00"}"#,
            r#"{"v":2,"mode":"x"} []"#,
            r#"{"v":2,"mode":"x","unknown":1e400}"#,
            r#"{"v":2,"mode":"x","unknown":"\uD800"}"#,
        ] {
            compare(input.as_bytes());
        }
        for input in [
            b"\xff".as_slice(),
            b"",
            b"[",
            b"{",
            b"null",
            b"true",
            b"\"x\"",
            b"1",
            b"1.0",
            b"{}",
            b"[]",
            b"[2]",
        ] {
            compare(input);
        }
    }
    #[test]
    fn every_current_field_type_default_duplicate_and_array_boundary() {
        let fields = [
            "v",
            "mode",
            "leaf",
            "context",
            "tee",
            "quote",
            "gpu_evidence",
            "quote_time",
        ];
        let values = [
            "null",
            "true",
            "2",
            "-0",
            "-1",
            "4294967295",
            "4294967296",
            "2.0",
            "\"x\"",
            "\"\\u0061\"",
            "[]",
            "{}",
        ];
        for field in fields {
            for value in values {
                let mut map = serde_json::Map::new();
                map.insert("v".into(), 2.into());
                map.insert("mode".into(), "present".into());
                map.remove(field);
                let prefix = serde_json::to_string(&map).unwrap();
                let stem = &prefix[..prefix.len() - 1];
                let comma = if map.is_empty() { "" } else { "," };
                compare(format!("{stem}{comma}\"{field}\":{value}}}").as_bytes());
                compare(
                    format!("{stem}{comma}\"{field}\":{value},\"{field}\":{value}}}").as_bytes(),
                );
            }
        }
        for n in 0..=10 {
            let values = [
                "2",
                "\"present\"",
                "\"\"",
                "null",
                "null",
                "null",
                "null",
                "null",
                "0",
                "0",
            ];
            compare(format!("[{}]", values[..n].join(",")).as_bytes());
        }
    }
    #[test]
    fn scratch_and_escaped_text_backing_remain_paid_until_last_use() {
        let input = br#"{"v":2,"mode":"pre\u0073ent","leaf":"raw","quote":"\uD834\uDD1E"}"#;
        let scratch = serde_json::Deserializer::slice_scratch_capacity(input.len()).unwrap();
        let pool = AllocationPoolV1::new(scratch + 7 + 4).unwrap();
        let (request, count) = measured(|| endpoint::attest(&pool, input));
        let request = request.unwrap();
        assert_eq!(count, (3, scratch + 7 + 4));
        assert_eq!(pool.used(), 11);
        let bounds = input.as_ptr_range();
        let borrowed = request.leaf.as_ptr();
        assert!(borrowed >= bounds.start && borrowed < bounds.end);
        let owned = request.mode.as_ptr();
        assert!(owned < bounds.start || owned >= bounds.end);
        assert_eq!(request.mode.as_str(), "present");
        assert_eq!(request.quote.as_deref(), Some("𝄞"));
        drop(request);
        assert_eq!(pool.used(), 0);
    }
    #[test]
    fn scratch_and_text_shortage_refuse_before_unpaid_backing_and_refund() {
        let input = br#"{"v":2,"mode":"pre\u0073ent"}"#;
        let scratch = serde_json::Deserializer::slice_scratch_capacity(input.len()).unwrap();
        for capacity in [scratch - 1, scratch + 6, scratch + 7] {
            let pool = AllocationPoolV1::new(capacity).unwrap();
            let (result, count) = measured(|| endpoint::attest(&pool, input));
            if capacity == scratch + 7 {
                assert!(result.is_ok());
                assert_eq!(count, (2, scratch + 7));
                assert_eq!(pool.used(), 7);
            } else {
                assert_eq!(*result.as_ref().unwrap_err(), Refusal::Unavailable);
                assert_eq!(
                    count,
                    if capacity < scratch {
                        (0, 0)
                    } else {
                        (1, scratch)
                    }
                );
            }
            drop(result);
            assert_eq!(pool.used(), 0);
        }
    }
    #[test]
    fn malformed_slice_errors_and_semantic_refusals_do_not_allocate_messages() {
        for input in [
            br#"{"v":2,"mode":"x",}"#.as_slice(),
            br#"{"v":2}"#,
            br#"{"v":2,"mode":true}"#,
            br#"{"v":2,"mode":"x","mode":"y"}"#,
            br#"{"v":"\u0032","mode":"x"}"#,
            br#"[2,"x",null]"#,
            br#""\u0061""#,
            br#"{"v":2,"mode":"\uD800"}"#,
        ] {
            let scratch = serde_json::Deserializer::slice_scratch_capacity(input.len()).unwrap();
            let pool = AllocationPoolV1::new(scratch).unwrap();
            let (result, count) = measured(|| endpoint::attest(&pool, input));
            assert_eq!(*result.as_ref().unwrap_err(), Refusal::Malformed);
            assert_eq!(count, (1, scratch));
            assert_eq!(pool.used(), 0);
        }
        let input = br#"{"v":2,"mode":"pre\u0073ent",}"#;
        let scratch = serde_json::Deserializer::slice_scratch_capacity(input.len()).unwrap();
        let pool = AllocationPoolV1::new(scratch + 7).unwrap();
        let (result, count) = measured(|| endpoint::attest(&pool, input));
        assert_eq!(*result.as_ref().unwrap_err(), Refusal::Malformed);
        assert_eq!(count, (2, scratch + 7));
        assert_eq!(pool.used(), 0);
    }
    #[test]
    fn unescaped_fields_and_ignored_unknown_children_only_allocate_parser_scratch() {
        let input=br#"{"v":2,"mode":"present","leaf":"x","context":"y","tee":"z","quote":"q","gpu_evidence":"g","quote_time":"t","unknown":{"escaped":"\u0061"}}"#;
        let scratch = serde_json::Deserializer::slice_scratch_capacity(input.len()).unwrap();
        let pool = AllocationPoolV1::new(scratch).unwrap();
        let (request, count) = measured(|| endpoint::attest(&pool, input));
        let request = request.unwrap();
        assert_eq!(count, (1, scratch));
        assert_eq!(pool.used(), 0);
        assert_eq!(request.quote.as_deref(), Some("q"));
    }
    fn compare_bootstrap(input: &[u8]) {
        let pool = AllocationPoolV1::new(1 << 20).unwrap();
        let original =
            serde_json::from_slice::<enclave_os_common::protocol::SessionBootstrapRequest>(input);
        let admitted = endpoint::bootstrap(&pool, input);
        assert_eq!(
            original.is_ok(),
            admitted.is_ok(),
            "{}",
            String::from_utf8_lossy(input)
        );
        if let (Ok(original), Ok(admitted)) = (original, admitted) {
            assert_eq!(original.sdk_pub, admitted.sdk_pub.as_str());
            match (original.encauth, admitted.encauth) {
                (None, None) => (),
                (Some(original), Some(admitted)) => {
                    assert_eq!(original.v, admitted.v);
                    assert_eq!(original.payload, admitted.payload.as_str());
                    assert_eq!(original.hw_sig, admitted.hw_sig.as_str());
                    assert_eq!(original.idp_sig, admitted.idp_sig.as_str());
                }
                _ => panic!("optional envelope differs"),
            }
        }
        assert_eq!(pool.used(), 0);
    }
    #[test]
    fn bootstrap_object_array_nested_defaults_unicode_and_refusals_match_current_model() {
        for input in [
            r#"{"sdk_pub":"raw"}"#,
            r#"["raw"]"#,
            r#"["raw",null]"#,
            r#"{"sdk_pub":"\uD834\uDD1E","encauth":[1,"p","s"]}"#,
            r#"["raw",{"v":1,"payload":"p","hw_sig":"s","idp_sig":"i"}]"#,
            r#"{"sdk_pub":"x","sdk_\u0070ub":"y"}"#,
            r#"{"sdk_pub":"x","encauth":null,"encauth":null}"#,
            r#"{"sdk_pub":"x","unknown":{"x":[true,"\u0061"]},"unknown":1}"#,
            r#"{"sdk_pub":"x","encauth":{"v":1,"payload":"p","hw_sig":"s","idp_sig":null}}"#,
            r#"["raw",[1,"p","s","i",0]]"#,
            r#"{"sdk_pub":"x","encauth":{"v":1,"payload":"p","hw_sig":"s","v":1}}"#,
            r#"{"sdk_pub":"x","encauth":[1,"p"]}"#,
            r#"{"sdk_pub":"\uD800"}"#,
            r#"{"sdk_pub":"raw"}[]"#,
            r#"{"sdk_pub":"raw","unknown":1e400}"#,
            r#"[]"#,
            r#"{}"#,
            r#"null"#,
            r#"true"#,
            r#"1"#,
            r#""x""#,
        ] {
            compare_bootstrap(input.as_bytes());
        }
        for field in ["v", "payload", "hw_sig", "idp_sig"] {
            for value in [
                "null",
                "true",
                "-1",
                "-0",
                "1",
                "255",
                "256",
                "1.0",
                "[]",
                "{}",
                "\"x\"",
                "\"\\u0061\"",
            ] {
                let mut object = serde_json::json!({"v":1,"payload":"p","hw_sig":"s"})
                    .as_object()
                    .unwrap()
                    .clone();
                object.remove(field);
                let prefix = serde_json::to_string(&object).unwrap();
                let stem = &prefix[..prefix.len() - 1];
                compare_bootstrap(
                    format!("{{\"sdk_pub\":\"raw\",\"encauth\":{stem},\"{field}\":{value}}}}}")
                        .as_bytes(),
                );
                compare_bootstrap(format!("{{\"sdk_pub\":\"raw\",\"encauth\":{stem},\"{field}\":{value},\"{field}\":{value}}}}}").as_bytes());
            }
        }
        for value in ["null", "true", "1", "1.0", "[]", "{}", "\"x\""] {
            compare_bootstrap(format!("{{\"sdk_pub\":{value}}}").as_bytes());
            compare_bootstrap(format!("{{\"sdk_pub\":\"x\",\"encauth\":{value}}}").as_bytes());
        }
        for input in [b"\xff".as_slice(), b"", b"{", b"["] {
            compare_bootstrap(input);
        }
    }
    #[test]
    fn bootstrap_nested_text_lifetime_and_each_allocation_boundary_are_paid() {
        let input = br#"{"sdk_pub":"s\u0064k","encauth":{"v":1,"payload":"p\u0061y","hw_sig":"h\u0077","idp_sig":"raw"}}"#;
        let scratch = serde_json::Deserializer::slice_scratch_capacity(input.len()).unwrap();
        for extra in [0, 2, 3, 5, 6, 7, 8] {
            let pool = AllocationPoolV1::new(scratch + extra).unwrap();
            let (request, count) = measured(|| endpoint::bootstrap(&pool, input));
            // Parsing still validates later fields after an admission refusal;
            // a smaller later field can fit and must also refund on rejection.
            let (allocations, admitted_text) = match extra {
                0 => (1, 0),
                2 => (2, 2),
                3 => (2, 3),
                5 => (3, 5),
                6 | 7 => (3, 6),
                8 => (4, 8),
                _ => unreachable!(),
            };
            assert_eq!(count, (allocations, scratch + admitted_text));
            if extra < 8 {
                assert_eq!(*request.as_ref().unwrap_err(), Refusal::Unavailable);
                assert_eq!(pool.used(), 0);
            } else {
                let request = request.as_ref().unwrap();
                assert_eq!(request.sdk_pub.as_str(), "sdk");
                let envelope = request.encauth.as_ref().unwrap();
                assert_eq!(
                    (
                        envelope.v,
                        envelope.payload.as_str(),
                        envelope.hw_sig.as_str(),
                        envelope.idp_sig.as_str()
                    ),
                    (1, "pay", "hw", "raw")
                );
                let bounds = input.as_ptr_range();
                assert!(
                    envelope.idp_sig.as_ptr() >= bounds.start
                        && envelope.idp_sig.as_ptr() < bounds.end
                );
                assert_eq!(pool.used(), 8);
            }
            drop(request);
            assert_eq!(pool.used(), 0);
        }
        let pool = AllocationPoolV1::new(scratch - 1).unwrap();
        let (request, count) = measured(|| endpoint::bootstrap(&pool, input));
        assert_eq!(*request.as_ref().unwrap_err(), Refusal::Unavailable);
        assert_eq!(count, (0, 0));
        assert_eq!(pool.used(), 0);
    }
    #[test]
    fn bootstrap_malformed_and_semantic_errors_refund_without_custom_messages() {
        for input in [
            br#"{"sdk_pub":"x","encauth":{"v":1,"payload":"p","hw_sig":null}}"#.as_slice(),
            br#"{"sdk_pub":"x","encauth":{"v":1,"payload":"p","hw_sig":"s",}}"#,
            br#"{"sdk_pub":"x","encauth":[1,"p","s",null]}"#,
            br#"{"sdk_pub":"x","encauth":[1,"p","s","i",0]}"#,
            br#"{"sdk_pub":"x","encauth":{"v":1,"v":1,"payload":"p","hw_sig":"s"}}"#,
            br#"{"sdk_pub":"x","encauth":"\u0061"}"#,
            br#"{"sdk_pub":"x","encauth":{"v":"\u0031","payload":"p","hw_sig":"s"}}"#,
        ] {
            let scratch = serde_json::Deserializer::slice_scratch_capacity(input.len()).unwrap();
            let pool = AllocationPoolV1::new(scratch).unwrap();
            let (result, count) = measured(|| endpoint::bootstrap(&pool, input));
            assert_eq!(*result.as_ref().unwrap_err(), Refusal::Malformed);
            assert_eq!(count, (1, scratch));
            assert_eq!(pool.used(), 0);
        }
    }
    #[test]
    fn value_acceptance_numbers_unicode_sorted_keys_and_last_duplicate_match_original() {
        for input in [
            r#"null"#,
            r#"true"#,
            r#"false"#,
            r#"0"#,
            r#"-0"#,
            r#"-1"#,
            r#"1.25e-200"#,
            r#"-9223372036854775808"#,
            r#"18446744073709551615"#,
            r#"18446744073709551616"#,
            r#""日本😀""#,
            r#""\uD834\uDD1E""#,
            r#"{"z":1,"a":[true,null,"\u0061"],"z":2,"\u0061":{}}"#,
            r#"[]"#,
            r#"{}"#,
            r#"[1,{}]"#,
            r#"1e400"#,
            r#"[1,]"#,
            r#"{"x":}"#,
            r#""\uD800""#,
            r#"null []"#,
        ] {
            let pool = AllocationPoolV1::new(1 << 20).unwrap();
            let original = serde_json::from_str::<serde_json::Value>(input);
            let admitted = endpoint::value(&pool, input.as_bytes());
            assert_eq!(original.is_ok(), admitted.is_ok(), "{input}");
            if let (Ok(original), Ok(admitted)) = (original, admitted) {
                assert_eq!(
                    serde_json::to_vec(&original).unwrap(),
                    serde_json::to_vec(&admitted).unwrap()
                );
            }
            assert_eq!(pool.used(), 0);
        }
    }
    #[test]
    fn value_actual_array_map_and_escaped_children_keep_their_backings_paid() {
        use enclave_os_common::request_json::{value::Value, Text};
        let input = br#"["raw","\u0061",7]"#;
        let scratch = serde_json::Deserializer::slice_scratch_capacity(input.len()).unwrap();
        let item = core::mem::size_of::<Value<'_>>();
        let pool = AllocationPoolV1::new(1 << 20).unwrap();
        let (value, count) = measured(|| endpoint::value(&pool, input));
        let value = value.unwrap();
        assert_eq!(count, (5, scratch + item * (1 + 2 + 4) + 1));
        assert_eq!(pool.used(), item * 4 + 1);
        let values = value.as_array().unwrap();
        assert_eq!(values[0].as_str(), Some("raw"));
        assert_eq!(values[1].as_str(), Some("a"));
        let bounds = input.as_ptr_range();
        let raw = values[0].as_str().unwrap().as_ptr();
        assert!(raw >= bounds.start && raw < bounds.end);
        drop(value);
        assert_eq!(pool.used(), 0);
        let input = br#"{"raw":"borrowed","\u0065sc":"\u0061"}"#;
        let scratch = serde_json::Deserializer::slice_scratch_capacity(input.len()).unwrap();
        let entry = core::mem::size_of::<(Text<'_>, Value<'_>)>();
        let (value, count) = measured(|| endpoint::value(&pool, input));
        let value = value.unwrap();
        assert_eq!(count, (5, scratch + entry * (1 + 2) + 4));
        assert_eq!(pool.used(), entry * 2 + 4);
        assert_eq!(value.get("esc").unwrap().as_str(), Some("a"));
        assert_eq!(value.get("raw").unwrap().as_str(), Some("borrowed"));
        drop(value);
        assert_eq!(pool.used(), 0);
    }
    #[test]
    fn value_growth_admits_both_live_buffers_before_allocation_and_refunds_refusal() {
        use enclave_os_common::request_json::{value::Value, Text};
        for (input, unit) in [
            (
                br#"[true,false]"#.as_slice(),
                core::mem::size_of::<Value<'_>>(),
            ),
            (
                br#"{"a":true,"b":false}"#,
                core::mem::size_of::<(Text<'_>, Value<'_>)>(),
            ),
        ] {
            let scratch = serde_json::Deserializer::slice_scratch_capacity(input.len()).unwrap();
            for extra in [unit * 3 - 1, unit * 3] {
                let pool = AllocationPoolV1::new(scratch + extra).unwrap();
                let (value, count) = measured(|| endpoint::value(&pool, input));
                if extra == unit * 3 {
                    assert!(value.is_ok());
                    assert_eq!(count, (3, scratch + unit * 3));
                    assert_eq!(pool.used(), unit * 2);
                } else {
                    assert!(matches!(
                        value,
                        Err(endpoint::ValueError::Refused(Refusal::Unavailable))
                    ));
                    assert_eq!(count, (2, scratch + unit));
                    assert_eq!(pool.used(), 0);
                }
                drop(value);
                assert_eq!(pool.used(), 0);
            }
        }
    }
    #[test]
    fn rpc_and_mcp_envelopes_preserve_transport_field_precedence_and_exact_bytes() {
        for input in [
            br#""#.as_slice(),
            br#"null"#,
            br#"[1,"x"]"#,
            br#"{"x":"\u0061","app_auth":"body","billing_approved":"yes"}"#,
            br#"{"app_auth":false,"billing_approved":7,"z":1,"a":2,"z":3}"#,
        ] {
            for header in [None, Some("header")] {
                let pool = AllocationPoolV1::new(1 << 20).unwrap();
                let parsed: serde_json::Value = if input.is_empty() {
                    serde_json::json!({})
                } else {
                    serde_json::from_slice(input).unwrap()
                };
                let auth = parsed.get("app_auth").and_then(|v| v.as_str());
                let billing =
                    header.or_else(|| parsed.get("billing_approved").and_then(|v| v.as_str()));
                let mut params = parsed.clone();
                if let Some(object) = params.as_object_mut() {
                    object.remove("app_auth");
                    object.remove("billing_approved");
                }
                let expected = serde_json::to_vec(&serde_json::json!({"connect_call":{"app":"app","function":"call","body":params,"app_auth":auth,"billing_approved":billing}})).unwrap();
                assert_eq!(
                    endpoint::rpc(&pool, input, "app", "call", header).unwrap(),
                    expected
                );
                assert_eq!(pool.used(), 0);
                let mut params = parsed.clone();
                if let Some(object) = params.as_object_mut() {
                    object.remove("app_auth");
                }
                let expected = serde_json::to_vec(&serde_json::json!({"connect_call":{"app":"app","function":"call","body":params,"app_auth":auth.or(header)}})).unwrap();
                assert_eq!(
                    endpoint::mcp(&pool, input, "app", "call", header).unwrap(),
                    expected
                );
                assert_eq!(pool.used(), 0);
            }
        }
        let input = br#"{"x":]}"#;
        let pool = AllocationPoolV1::new(1 << 20).unwrap();
        let original = serde_json::from_slice::<serde_json::Value>(input).unwrap_err();
        let error = endpoint::rpc(&pool, input, "app", "call", None).unwrap_err();
        let endpoint::ValueError::Syntax(error) = error else {
            panic!("syntax failure lost");
        };
        assert_eq!(error.to_string(), original.to_string());
        assert_eq!(pool.used(), 0);
        let pool = AllocationPoolV1::new(1).unwrap();
        assert!(matches!(
            endpoint::mcp(&pool, br#"{}"#, "app", "call", None),
            Err(endpoint::ValueError::Refused(Refusal::Unavailable))
        ));
        assert_eq!(pool.used(), 0);
    }
    #[test]
    fn mcp_tools_projection_keeps_exact_null_schema_fallback_and_error_bytes() {
        for (input, expected) in [
            (
                r#"{"status":"mcp_tools","manifest":{"tools":[{"name":"n","description":null,"inputSchema":{"type":"object"},"input_schema":7},{"name":null,"description":"d","input_schema":null},42]}}"#,
                Some((
                    200,
                    r#"{"tools":[{"input_schema":{"type":"object"},"name":"n"},{"description":"d","input_schema":null,"name":null},{}]}"#,
                )),
            ),
            (
                r#"{"status":"mcp_tools","manifest":{"tools":null}}"#,
                Some((200, r#"{"tools":[]}"#)),
            ),
            (
                r#"{"status":"error","message":"bad\nquote\""}"#,
                Some((400, r#"{"error":"bad\nquote\""}"#)),
            ),
            (
                r#"{"status":"not_found","name":"missing"}"#,
                Some((400, r#"{"error":"missing"}"#)),
            ),
            (
                r#"{"status":"error","message":4,"name":null}"#,
                Some((400, r#"{"error":"error"}"#)),
            ),
            (r#"{"status":"other"}"#, None),
        ] {
            let pool = AllocationPoolV1::new(1 << 20).unwrap();
            let result = endpoint::mcp_tools_response(&pool, input.as_bytes()).unwrap();
            assert_eq!(
                result
                    .as_ref()
                    .map(|(status, bytes)| (*status, bytes.as_slice())),
                expected.map(|(status, bytes)| (status, bytes.as_bytes()))
            );
            assert_eq!(pool.used(), 0);
        }
    }
    #[test]
    fn mcp_call_projection_keeps_exact_empty_single_multiple_and_error_bytes() {
        for (input, expected) in [
            (r#"{"status":"ok","returns":[]}"#, Some((200, r#"{}"#))),
            (r#"{"status":"ok","returns":null}"#, Some((200, r#"{}"#))),
            (
                r#"{"status":"ok","returns":[{"value":{"z":1,"a":"\u0061"}}]}"#,
                Some((200, r#"{"a":"a","z":1}"#)),
            ),
            (r#"{"status":"ok","returns":[{}]}"#, Some((200, r#"null"#))),
            (
                r#"{"status":"ok","returns":[{"value":1},true,{"value":null}]}"#,
                Some((200, r#"[1,null,null]"#)),
            ),
            (
                r#"{"status":"error","message":"bad\tthing"}"#,
                Some((400, r#"{"error":"bad\tthing"}"#)),
            ),
            (
                r#"{"status":"error","message":null}"#,
                Some((400, r#"{"error":"error"}"#)),
            ),
            (r#"{"status":"not_found"}"#, None),
        ] {
            let pool = AllocationPoolV1::new(1 << 20).unwrap();
            let result = endpoint::mcp_call_response(&pool, input.as_bytes()).unwrap();
            assert_eq!(
                result
                    .as_ref()
                    .map(|(status, bytes)| (*status, bytes.as_slice())),
                expected.map(|(status, bytes)| (status, bytes.as_bytes()))
            );
            assert_eq!(pool.used(), 0);
        }
        let pool = AllocationPoolV1::new(1 << 20).unwrap();
        assert!(matches!(
            endpoint::mcp_tools_response(&pool, b"{"),
            Err(endpoint::ValueError::Syntax(_))
        ));
        assert_eq!(pool.used(), 0);
        let pool = AllocationPoolV1::new(1).unwrap();
        assert!(matches!(
            endpoint::mcp_call_response(&pool, b"{}"),
            Err(endpoint::ValueError::Refused(Refusal::Unavailable))
        ));
        assert_eq!(pool.used(), 0);
    }
    #[test]
    fn fido_route_query_and_malformed_body_projection_preserve_exact_existing_bytes() {
        for (body, query, expected) in [
            (r#"{}"#, None, r#"{"type":"register/begin"}"#),
            (
                r#"{"type":"old","sessionId":"body","z":null}"#,
                Some("session_id=query&unknown=x%20y"),
                r#"{"sessionId":"body","type":"register/begin","unknown":"x y","z":null}"#,
            ),
            (
                r#"{"sessionId":null}"#,
                Some("session_id=query"),
                r#"{"sessionId":null,"type":"register/begin"}"#,
            ),
            (
                r#"{"#,
                Some("empty="),
                r#"{"empty":"","type":"register/begin"}"#,
            ),
            (
                r#"null"#,
                Some("truncated=%A&bad=%GG&plus=+&byte=%FF"),
                r#"{"bad":"\u0000","byte":"ÿ","plus":"+","truncated":"","type":"register/begin"}"#,
            ),
            (
                r#"[1]"#,
                Some("ignored&session_id=first&session_id=second"),
                r#"{"sessionId":"first","type":"register/begin"}"#,
            ),
        ] {
            let pool = AllocationPoolV1::new(1 << 20).unwrap();
            assert_eq!(
                endpoint::fido(&pool, body.as_bytes(), "register/begin", query).unwrap(),
                expected.as_bytes()
            );
            assert_eq!(pool.used(), 0);
        }
        let pool = AllocationPoolV1::new(1).unwrap();
        assert!(endpoint::fido(&pool, b"{}", "register/begin", None).is_err());
        assert_eq!(pool.used(), 0);
    }
    #[test]
    fn formatted_text_admits_exact_utf8_and_refuses_changed_length_without_growth() {
        use enclave_os_common::request_json::Text;
        for capacity in [1, 2] {
            let pool = AllocationPoolV1::new(capacity).unwrap();
            let (result, count) = measured(|| Text::display(&pool, "ÿ"));
            if capacity == 2 {
                assert_eq!(result.as_ref().unwrap().as_str(), "ÿ");
                assert_eq!(count, (1, 2));
                assert_eq!(pool.used(), 2);
            } else {
                assert_eq!(*result.as_ref().unwrap_err(), Refusal::Unavailable);
                assert_eq!(count, (0, 0));
            }
            drop(result);
            assert_eq!(pool.used(), 0);
        }
        struct Changed(Cell<bool>);
        impl core::fmt::Display for Changed {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(if self.0.replace(true) { "ab" } else { "a" })
            }
        }
        let pool = AllocationPoolV1::new(2).unwrap();
        let (result, count) = measured(|| Text::display(&pool, &Changed(Cell::new(false))));
        assert_eq!(*result.as_ref().unwrap_err(), Refusal::Unavailable);
        assert_eq!(count, (1, 1));
        assert_eq!(pool.used(), 0);
    }
    #[test]
    fn private_semantic_token_never_matches_ordinary_identical_custom_messages() {
        use serde::de::Error as _;
        let (token, count) =
            measured(|| serde_json::Error::custom(serde_json::Error::request_semantic_abort()));
        assert!(token.is_request_semantic_abort());
        assert!(token.is_data());
        assert_eq!(count, (0, 0));
        struct Same;
        impl core::fmt::Display for Same {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("request JSON semantic abort")
            }
        }
        let (ordinary, count) = measured(|| serde_json::Error::custom(Same));
        assert!(!ordinary.is_request_semantic_abort());
        assert!(ordinary.is_data());
        assert_eq!(ordinary.to_string(), "request JSON semantic abort");
        assert_eq!(count, (1, "request JSON semantic abort".len()));
        for message in [
            "request JSON semantic abort",
            " request JSON semantic abort ",
            "\n ü😀  at line 12 column 34",
        ] {
            let ordinary = serde_json::Error::custom(message);
            assert!(!ordinary.is_request_semantic_abort());
            assert_eq!(ordinary.to_string(), message);
        }
        let formatted =
            serde_json::Error::custom(format_args!("{}", "request JSON semantic abort"));
        assert!(!formatted.is_request_semantic_abort());
        assert_eq!(formatted.to_string(), "request JSON semantic abort");
        let diagnostic = serde_json::Error::request_invalid_type(
            serde::de::Unexpected::Str("a\n\"😀"),
            "a sequence",
        );
        let expected = "invalid type: string \"a\\n\\\"😀\", expected a sequence";
        let pool = AllocationPoolV1::new(expected.len()).unwrap();
        let (owned, count) =
            measured(|| enclave_os_common::request_json::Text::display(&pool, &diagnostic));
        let owned = owned.unwrap();
        assert_eq!(owned.as_str(), expected);
        assert_eq!(count, (1, expected.len()));
        assert_eq!(pool.used(), expected.len());
        drop(owned);
        assert_eq!(pool.used(), 0);
        let pool = AllocationPoolV1::new(expected.len() - 1).unwrap();
        let (refused, count) =
            measured(|| enclave_os_common::request_json::Text::display(&pool, &diagnostic));
        assert_eq!(*refused.as_ref().unwrap_err(), Refusal::Unavailable);
        assert_eq!(count, (0, 0));
        assert_eq!(pool.used(), 0);
    }
    #[test]
    fn retained_value_copies_all_text_and_outlives_its_temporary_input() {
        use enclave_os_common::request_json::{
            value::{Seed, Value},
            AdmittedParser,
        };
        use serde::de::DeserializeSeed;
        let pool = AllocationPoolV1::new(1 << 20).unwrap();
        let value = {
            let input = String::from(r#"{"plain":["raw","\u0061"]}"#);
            let capacity = serde_json::Deserializer::slice_scratch_capacity(input.len()).unwrap();
            let mut parser = AdmittedParser::new(&pool, capacity, |scratch| {
                serde_json::Deserializer::from_slice_with_scratch(input.as_bytes(), scratch).ok()
            })
            .unwrap();
            let value: Value<'static> = Seed::retained(&pool)
                .deserialize(parser.parser_mut())
                .unwrap()
                .unwrap();
            parser.parser_mut().end().unwrap();
            value
        };
        assert_eq!(
            value.get("plain").unwrap().as_array().unwrap()[0].as_str(),
            Some("raw")
        );
        assert_eq!(
            serde_json::to_vec(&value).unwrap(),
            br#"{"plain":["raw","a"]}"#
        );
        let entry = core::mem::size_of::<(enclave_os_common::request_json::Text<'_>, Value<'_>)>();
        let item = core::mem::size_of::<Value<'_>>();
        assert_eq!(
            pool.used(),
            "plain".len() + "raw".len() + "a".len() + entry + 2 * item
        );
        drop(value);
        assert_eq!(pool.used(), 0);
    }
    #[derive(serde::Deserialize)]
    struct SetAttestationServersRequest {
        servers: Vec<enclave_os_common::protocol::AttestationServer>,
    }
    fn compare_manager(input: &[u8]) {
        let pool = AllocationPoolV1::new(1 << 20).unwrap();
        let original = serde_json::from_slice::<SetAttestationServersRequest>(input);
        let admitted = endpoint::manager::parse(&pool, input);
        match (original, admitted) {
            (Ok(original), Ok(admitted)) => {
                assert_eq!(original.servers.len(), admitted.as_slice().len());
                for (original, admitted) in original.servers.iter().zip(admitted.as_slice()) {
                    assert_eq!(original.url, admitted.url.as_str());
                    assert_eq!(original.token.as_deref(), admitted.token.as_deref());
                }
            }
            (Err(original), Err(admitted)) => assert_eq!(
                original.to_string(),
                admitted.to_string(),
                "{}",
                String::from_utf8_lossy(input)
            ),
            _ => panic!(
                "manager outcome mismatch: {}",
                String::from_utf8_lossy(input)
            ),
        }
        assert_eq!(pool.used(), 0);
    }
    #[test]
    fn manager_typed_object_sequence_and_error_diagnostics_match_original() {
        for input in [
            r#"{"servers":[]}"#,
            r#"[[]]"#,
            r#"{"servers":[{"url":"raw"},{"url":"\u0061","token":"日本😀"}]}"#,
            r#"[[["url"],["url",null],["u","token"]]]"#,
            r#"{"servers":[{"url":"a","token":null,"other":{"a":[1,"x"]}}],"x":true}"#,
            r#"{"ser\u0076ers":[{"u\u0072l":"\uD834\uDD1E","token":"\n\t\\\""}]}"#,
            r#"{}"#,
            r#"[]"#,
            r#"[[],0]"#,
            r#"{"servers":[],"servers":[]}"#,
            r#"{"servers":[{}]}"#,
            r#"{"servers":[[]]}"#,
            r#"{"servers":[["a",null,3]]}"#,
            r#"{"servers":[{"url":"a","url":"b"}]}"#,
            r#"{"servers":[{"url":"a","token":null,"token":null}]}"#,
            r#"{"servers":null}"#,
            r#"{"servers":{}}"#,
            r#"{"servers":true}"#,
            r#"{"servers":1}"#,
            r#"{"servers":-1}"#,
            r#"{"servers":1.0}"#,
            r#"{"servers":"x😀"}"#,
            r#"{"servers":[null]}"#,
            r#"{"servers":[false]}"#,
            r#"{"servers":[-1.2]}"#,
            r#"{"servers":["x"]}"#,
            r#"{"servers":[{"url":null}]}"#,
            r#"{"servers":[{"url":{}}]}"#,
            r#"{"servers":[{"url":[]}]}"#,
            r#"{"servers":[{"url":false}]}"#,
            r#"{"servers":[{"url":12}]}"#,
            r#"{"servers":[{"url":"a","token":12}]}"#,
            r#"{"servers":0,broken"#,
            r#"{"servers":[],broken"#,
            r#"{"servers":[]} null"#,
            r#"{"servers":[{"url":"\uD800"}]}"#,
            r#"{"servers":[{"url":"a","token":"\uDC00"}]}"#,
            "null",
            "true",
            "1",
            "-1",
            "1.0",
            r#""x""#,
            "",
            "{",
            "[",
            "[null]",
        ] {
            compare_manager(input.as_bytes());
        }
    }
    #[test]
    fn manager_semantic_message_has_exact_admission_and_refund() {
        let input = br#"{\n \"servers\": 1}"#;
        // Use real newlines; the escaped spelling above is intentionally malformed.
        compare_manager(input);
        let input = b"{\n \"servers\": 1}";
        let original = serde_json::from_slice::<SetAttestationServersRequest>(input)
            .err()
            .unwrap()
            .to_string();
        let message = "invalid type: integer `1`, expected a sequence";
        let scratch = serde_json::Deserializer::slice_scratch_capacity(input.len()).unwrap();
        let pool = AllocationPoolV1::new(scratch + message.len()).unwrap();
        let (error, count) = measured(|| endpoint::manager::parse(&pool, input).err().unwrap());
        assert_eq!(error.to_string(), original);
        assert_eq!(count, (2, scratch + message.len()));
        assert_eq!(pool.used(), message.len());
        drop(error);
        assert_eq!(pool.used(), 0);
        let pool = AllocationPoolV1::new(scratch + message.len() - 1).unwrap();
        let (error, count) = measured(|| endpoint::manager::parse(&pool, input).err().unwrap());
        assert!(matches!(error, endpoint::manager::Error::Unavailable));
        assert_eq!(count, (1, scratch));
        assert_eq!(pool.used(), 0);
        let pool = AllocationPoolV1::new(scratch - 1).unwrap();
        let (error, count) = measured(|| endpoint::manager::parse(&pool, input).err().unwrap());
        assert!(matches!(error, endpoint::manager::Error::Unavailable));
        assert_eq!(count, (0, 0));
        assert_eq!(pool.used(), 0);
    }
    #[test]
    fn manager_retained_children_survive_input_and_partial_refusals_refund() {
        let pool = AllocationPoolV1::new(1 << 20).unwrap();
        let servers = {
            let input = String::from(r#"{"servers":[{"url":"raw","token":"\u0061"}]}"#);
            endpoint::manager::parse(&pool, input.as_bytes()).unwrap()
        };
        assert_eq!(servers.as_slice()[0].url.as_str(), "raw");
        assert_eq!(servers.as_slice()[0].token.as_deref(), Some("a"));
        let bytes = core::mem::size_of::<
            enclave_os_common::protocol::AttestationServer<
                enclave_os_common::request_json::Text<'static>,
            >,
        >();
        assert_eq!(pool.used(), 3 + 1 + bytes);
        drop(servers);
        assert_eq!(pool.used(), 0);
        let input = br#"{"servers":[{"url":"raw","token":"token"},{"url":"another"}]}"#;
        let scratch = serde_json::Deserializer::slice_scratch_capacity(input.len()).unwrap();
        for capacity in [
            scratch,
            scratch + 2,
            scratch + 3,
            scratch + 8,
            scratch + 8 + bytes,
            scratch + 15 + bytes,
        ] {
            let pool = AllocationPoolV1::new(capacity).unwrap();
            assert!(matches!(
                endpoint::manager::parse(&pool, input),
                Err(endpoint::manager::Error::Unavailable)
            ));
            assert_eq!(pool.used(), 0);
        }
    }

    #[test]
    fn manager_store_moves_original_children_and_releases_only_after_replacement() {
        use enclave_os_common::{attestation_servers as store, request_json::sequence::Sequence};
        let pool = AllocationPoolV1::new(1 << 20).unwrap();
        let servers = endpoint::manager::parse(
            &pool,
            br#"{"servers":[{"url":"z","token":"secret"},{"url":"a"},{"url":"z"}]}"#,
        )
        .unwrap();
        let retained = pool.used();
        let (count, hash) = store::set(&pool, servers).unwrap();
        assert_eq!(count, 3);
        assert_eq!(store::server_urls(), ["z", "a", "z"]);
        assert_eq!(store::token_for("z").as_deref(), Some("secret"));
        assert_eq!(
            store::canonical_form().as_deref(),
            Some(b"a\nz\nz".as_slice())
        );
        let expected = ring::digest::digest(&ring::digest::SHA256, b"a\nz\nz");
        assert_eq!(hash.as_ref().map(|h| h.as_slice()), Some(expected.as_ref()));
        assert_eq!(pool.used(), retained + b"a\nz\nz".len());
        let input = br#"{"servers":[{"url":"replacement"}]}"#;
        let scratch = serde_json::Deserializer::slice_scratch_capacity(input.len()).unwrap();
        let entry = core::mem::size_of::<
            enclave_os_common::protocol::AttestationServer<
                enclave_os_common::request_json::Text<'static>,
            >,
        >();
        let refused = AllocationPoolV1::new(scratch + "replacement".len() + entry).unwrap();
        let servers = endpoint::manager::parse(&refused, input).unwrap();
        // Fill the released parser-scratch headroom so the next physical
        // reference buffer must refuse before allocation or state mutation.
        let remaining = refused.reserve_unpublished(scratch).unwrap();
        assert_eq!(store::set(&refused, servers), Err(Refusal::Unavailable));
        assert_eq!(
            store::canonical_form().as_deref(),
            Some(b"a\nz\nz".as_slice())
        );
        assert_eq!(refused.used(), scratch);
        drop(remaining);
        assert_eq!(refused.used(), 0);
        let empty = AllocationPoolV1::new(1).unwrap();
        assert_eq!(
            store::set(&empty, Sequence::new(std::sync::Arc::clone(&empty))).unwrap(),
            (0, None)
        );
        assert_eq!(pool.used(), 0);
        assert_eq!(empty.used(), 0);
        assert_eq!(store::hash(), None);
        assert_eq!(store::canonical_form(), None);
    }
    #[test]
    fn oidc_shared_owner_moves_paid_fields_and_refunds_only_after_last_alias() {
        use enclave_os_common::{
            allocation::SharedAllocationV1, oidc::retained::RetainedOidcConfig, request_json::Text,
        };
        let pool = AllocationPoolV1::new(1 << 20).unwrap();
        let field = |text| Text::copy(&pool, text).unwrap();
        let config = RetainedOidcConfig::new(
            field("issuer"),
            field("audience"),
            field(""),
            field("roles"),
            field("manager"),
            field("monitor"),
        )
        .unwrap();
        let children =
            "issuer".len() + "audience".len() + "roles".len() + "manager".len() + "monitor".len();
        assert_eq!(pool.used(), children);
        let expected = SharedAllocationV1::<RetainedOidcConfig>::required_bytes(0).unwrap();
        let reservation = SharedAllocationV1::reserve(&pool, 0).unwrap();
        let (shared, allocations) = measured(|| reservation.finish(config));
        assert_eq!(allocations.0, 2);
        assert_eq!(allocations.1, expected);
        assert_eq!(pool.used(), children + expected);
        let (alias, allocations) = measured(|| shared.clone());
        assert_eq!(allocations, (0, 0));
        drop(shared);
        assert_eq!(alias.issuer, "issuer");
        assert_eq!(alias.manager_role, "manager");
        assert_eq!(pool.used(), children + expected);
        drop(alias);
        assert_eq!(pool.used(), 0);
        let refused = RetainedOidcConfig::new(
            field("paid"),
            Text::borrowed("not owned"),
            field(""),
            field("r"),
            field("m"),
            field("n"),
        );
        assert!(matches!(refused, Err(Refusal::Unavailable)));
        assert_eq!(pool.used(), 0);
        let short = AllocationPoolV1::new(expected - 1).unwrap();
        let (refused, allocations) =
            measured(|| SharedAllocationV1::<RetainedOidcConfig>::reserve(&short, 0));
        assert!(refused.is_none());
        assert_eq!(allocations, (0, 0));
        assert_eq!(short.used(), 0);
    }
    fn compare_configuration(input: &[u8]) {
        #[derive(serde::Deserialize)]
        struct EnclaveConfig {
            #[serde(default = "port")]
            port: u16,
            #[serde(default = "backlog")]
            backlog: i32,
            oidc: Option<enclave_os_common::oidc::OidcConfig>,
            #[serde(flatten)]
            extra: serde_json::Map<String, serde_json::Value>,
        }
        fn port() -> u16 {
            443
        }
        fn backlog() -> i32 {
            128
        }
        let original = serde_json::from_slice::<EnclaveConfig>(input);
        let pool = AllocationPoolV1::new(1 << 20).unwrap();
        let current = endpoint::manager::configuration::parse(&pool, input);
        match (original, current) {
            (Ok(original), Ok(current)) => {
                assert_eq!(original.port, current.port);
                assert_eq!(original.backlog, current.backlog);
                assert_eq!(
                    serde_json::to_value(&original.oidc).unwrap(),
                    current
                        .oidc
                        .as_ref()
                        .map(|v| serde_json::to_value(&**v).unwrap())
                        .unwrap_or(serde_json::Value::Null)
                );
                assert_eq!(original.extra.len(), current.extra.len());
                for (key, value) in original.extra {
                    assert_eq!(
                        value,
                        serde_json::to_value(current.extra.get(key.as_str()).unwrap()).unwrap()
                    );
                }
            }
            (Err(original), Err(current)) => assert_eq!(
                original.to_string(),
                current.to_string(),
                "{}",
                String::from_utf8_lossy(input)
            ),
            _ => panic!(
                "startup outcome mismatch: {}",
                String::from_utf8_lossy(input)
            ),
        }
        assert_eq!(pool.used(), 0);
    }
    #[test]
    fn startup_configuration_original_flatten_defaults_types_and_errors_are_preserved() {
        for input in [
            r#"{}"#,
            r#"{"port":0,"backlog":-2147483648}"#,
            r#"{"port":65535,"backlog":2147483647}"#,
            r#"{"oidc":null,"extra":{"deep":[1,true,null,"\u0061"]},"extra":7}"#,
            r#"{"oidc":{"issuer":"i","audience":"a"},"unknown":"日本😀"}"#,
            r#"{"oidc":["i","a"]}"#,
            r#"{"oidc":["i","a","","r","m","n"]}"#,
            r#"{"oidc":{"issuer":"\uD834\uDD1E","audience":"a","role_claim":"x","unknown":null}}"#,
            r#"{"attestation_servers":true}"#,
            r#"{"attestation_servers":[{"url":"a"}],"attestation_servers":null}"#,
            r#"{"port":-1}"#,
            r#"{"port":65536}"#,
            r#"{"port":1.0}"#,
            r#"{"port":"\u0031"}"#,
            r#"{"port":null}"#,
            r#"{"port":{}}"#,
            r#"{"port":[]}"#,
            r#"{"backlog":2147483648}"#,
            r#"{"backlog":-2147483649}"#,
            r#"{"backlog":true}"#,
            r#"{"port":1,"port":2}"#,
            r#"{"oidc":null,"oidc":null}"#,
            r#"{"oidc":{}}"#,
            r#"{"oidc":{"issuer":"i"}}"#,
            r#"{"oidc":[]}"#,
            r#"{"oidc":["i"]}"#,
            r#"{"oidc":["i","a","","r","m","n",0]}"#,
            r#"{"oidc":true}"#,
            r#"{"oidc":"x"}"#,
            r#"{"oidc":{"issuer":"i","issuer":"j","audience":"a"}}"#,
            r#"{"oidc":{"issuer":{},"audience":"a"}}"#,
            r#"{"oidc":{"issuer":"i","audience":"a","role_claim":null}}"#,
            r#"{"port":false,broken"#,
            r#"{"oidc":{},broken"#,
            r#"{"x":true,broken"#,
            r#"{"x":"\uD800"}"#,
            r#"{} null"#,
            "null",
            "true",
            "1",
            "-1",
            "1.0",
            r#""x""#,
            "[]",
            "[{}]",
            "",
            "{",
        ] {
            compare_configuration(input.as_bytes());
        }
    }
    #[test]
    fn startup_retains_original_host_children_and_each_shortage_refunds() {
        let pool = AllocationPoolV1::new(1 << 20).unwrap();
        let config = {
            let input =
                String::from(r#"{"oidc":{"issuer":"i","audience":"a"},"store":{"path":"raw"}}"#);
            endpoint::manager::configuration::parse(&pool, input.as_bytes()).unwrap()
        };
        assert_eq!(config.oidc.as_ref().unwrap().issuer, "i");
        assert_eq!(
            config
                .extra
                .get("store")
                .unwrap()
                .get("path")
                .unwrap()
                .as_str(),
            Some("raw")
        );
        assert!(pool.used() > 0);
        drop(config);
        assert_eq!(pool.used(), 0);
        let input = br#"{"oidc":{"issuer":"i","audience":"a"},"store":{"path":"raw"}}"#;
        let scratch = serde_json::Deserializer::slice_scratch_capacity(input.len()).unwrap();
        let full = AllocationPoolV1::new(1 << 20).unwrap();
        let value = endpoint::manager::configuration::parse(&full, input).unwrap();
        let retained = full.used();
        drop(value);
        assert_eq!(full.used(), 0);
        for capacity in [
            scratch - 1,
            scratch,
            scratch + 1,
            scratch + 2,
            scratch + retained - 1,
        ] {
            let pool = AllocationPoolV1::new(capacity).unwrap();
            assert!(matches!(
                endpoint::manager::configuration::parse(&pool, input),
                Err(endpoint::manager::Error::Unavailable)
            ));
            assert_eq!(pool.used(), 0);
        }
    }

    #[test]
    fn startup_server_projection_moves_strings_and_keeps_original_invalid_list_default() {
        use enclave_os_common::{
            attestation_servers as store, protocol::AttestationServer, request_json::Text,
        };
        for field in [
            r#"null"#,
            r#"true"#,
            r#"{}"#,
            r#"[]"#,
            r#"[[]]"#,
            r#"[{"url":"a"}]"#,
            r#"[["a"],["b",null],["c","t"]]"#,
            r#"[{"url":"a","url":"b","token":null,"unknown":[1,2]}]"#,
            r#"[{"url":"a"},{"url":false}]"#,
            r#"[["a",null,0]]"#,
        ] {
            let expected: Vec<AttestationServer> = serde_json::from_str::<serde_json::Value>(field)
                .and_then(serde_json::from_value)
                .unwrap_or_default();
            let input = format!("{{\"attestation_servers\":{field}}}");
            let pool = AllocationPoolV1::new(1 << 20).unwrap();
            let mut config =
                endpoint::manager::configuration::parse(&pool, input.as_bytes()).unwrap();
            let servers =
                store::from_configuration(&pool, config.extra.remove("attestation_servers"))
                    .unwrap();
            drop(config);
            assert_eq!(expected.len(), servers.as_slice().len());
            for (expected, actual) in expected.iter().zip(servers.as_slice()) {
                assert_eq!(expected.url, actual.url.as_str());
                assert_eq!(expected.token.as_deref(), actual.token.as_deref());
            }
            drop(servers);
            assert_eq!(pool.used(), 0);
        }
        let pool = AllocationPoolV1::new(1 << 20).unwrap();
        let mut config = endpoint::manager::configuration::parse(
            &pool,
            br#"{"attestation_servers":[{"url":"a"},{"url":"b"},{"url":"c","token":"t"}]}"#,
        )
        .unwrap();
        let value = config.extra.remove("attestation_servers");
        let (servers, count) = measured(|| store::from_configuration(&pool, value).unwrap());
        drop(config);
        let entry = core::mem::size_of::<AttestationServer<Text<'static>>>();
        assert_eq!(count, (3, (1 + 2 + 4) * entry));
        assert_eq!(pool.used(), 4 + 4 * entry);
        drop(servers);
        assert_eq!(pool.used(), 0);
        let mut config = endpoint::manager::configuration::parse(
            &pool,
            br#"{"attestation_servers":[{"url":"a"},{"url":"b"},{"url":"c"}]}"#,
        )
        .unwrap();
        let value = config.extra.remove("attestation_servers");
        let remaining = pool.reserve_unpublished((1 << 20) - pool.used()).unwrap();
        let (refused, count) = measured(|| store::from_configuration(&pool, value));
        assert!(matches!(refused, Err(Refusal::Unavailable)));
        assert_eq!(count, (1, entry));
        drop(config);
        drop(remaining);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn borrowed_paid_value_projects_current_config_shapes_and_refuses_extra_tuple_items() {
        #[derive(Debug, PartialEq, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct CurrentInput {
            hosts: std::collections::BTreeMap<String, Vec<String>>,
            pin: [u8; 3],
            enabled: Option<bool>,
        }
        for input in [
            r#"{"hosts":{"a":["1","2"]},"pin":[1,2,3],"enabled":true}"#,
            r#"{"hosts":{},"pin":[1,2,3],"enabled":null}"#,
            r#"{"hosts":{},"pin":[1,2,3,4]}"#,
            r#"{"hosts":{},"pin":[1,2]}"#,
            r#"{"hosts":{},"pin":[1,2,256]}"#,
            r#"{"hosts":[],"pin":[1,2,3]}"#,
            r#"{"hosts":{"a":3},"pin":[1,2,3]}"#,
            r#"{"hosts":{"a":[null]},"pin":[1,2,3]}"#,
            r#"{"hosts":{},"pin":[1,2,3],"enabled":false,"unknown":1}"#,
        ] {
            let old: serde_json::Value = serde_json::from_str(input).unwrap();
            let original = serde_json::from_value::<CurrentInput>(old);
            let pool = AllocationPoolV1::new(1 << 20).unwrap();
            let paid = endpoint::value(&pool, input.as_bytes()).unwrap();
            let current = CurrentInput::deserialize(&paid);
            match (original, current) {
                (Ok(original), Ok(current)) => assert_eq!(original, current),
                (Err(original), Err(current)) => {
                    assert_eq!(original.to_string(), current.to_string())
                }
                _ => panic!("typed config projection mismatch: {input}"),
            }
            drop(paid);
            assert_eq!(pool.used(), 0);
        }
        #[derive(Debug, PartialEq, serde::Deserialize)]
        enum Projection {
            Unit,
            Pair(u8, u8),
            Object { x: u8 },
        }
        for input in [
            r#""Unit""#,
            r#"{"Unit":null}"#,
            r#"{"Pair":[1,2]}"#,
            r#"{"Object":{"x":1}}"#,
            r#"{}"#,
            r#"{"Unit":null,"Pair":[1,2]}"#,
            r#"{"Pair":[]}"#,
            r#"{"Pair":[1]}"#,
            r#"{"Pair":[1,2,3]}"#,
            r#"{"Pair":null}"#,
            r#"{"Object":[1]}"#,
            r#"{"Object":{}}"#,
        ] {
            let original =
                serde_json::from_value::<Projection>(serde_json::from_str(input).unwrap());
            let pool = AllocationPoolV1::new(1 << 20).unwrap();
            let value = endpoint::value(&pool, input.as_bytes()).unwrap();
            let current = Projection::deserialize(&value);
            match (original, current) {
                (Ok(a), Ok(b)) => assert_eq!(a, b),
                (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string()),
                _ => panic!("enum projection mismatch: {input}"),
            }
            drop(value);
            assert_eq!(pool.used(), 0);
        }
        for input in [
            r#"{"1":7}"#,
            r#"{"-1":7}"#,
            r#"{"01":7}"#,
            r#"{"1 ":7}"#,
            r#"{"+1":7}"#,
            r#"{"x":7}"#,
            r#"{"1.0":7}"#,
        ] {
            type Map = std::collections::BTreeMap<i32, u64>;
            let original = serde_json::from_value::<Map>(serde_json::from_str(input).unwrap());
            let pool = AllocationPoolV1::new(1 << 20).unwrap();
            let value = endpoint::value(&pool, input.as_bytes()).unwrap();
            let current = Map::deserialize(&value);
            match (original, current) {
                (Ok(a), Ok(b)) => assert_eq!(a, b),
                (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string()),
                _ => panic!("numeric-key projection mismatch: {input}"),
            }
            drop(value);
            assert_eq!(pool.used(), 0);
        }
        use serde::Deserialize;
        #[derive(Deserialize)]
        struct Borrowed<'a> {
            name: &'a str,
            number: u64,
        }
        let pool = AllocationPoolV1::new(1 << 20).unwrap();
        let paid = endpoint::value(&pool, br#"{"name":"raw","number":7}"#).unwrap();
        let (view, count) = measured(|| Borrowed::deserialize(&paid).unwrap());
        assert_eq!(count, (0, 0));
        assert_eq!(view.name, "raw");
        assert_eq!(view.number, 7);
        drop(paid);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn global_oidc_borrows_the_installed_owner_and_keeps_first_writer_without_allocation() {
        use enclave_os_common::{
            allocation::SharedAllocationV1,
            oidc::{self, retained::RetainedOidcConfig, OidcConfig},
            request_json::Text,
        };
        static OWNER: std::sync::OnceLock<SharedAllocationV1<RetainedOidcConfig>> =
            std::sync::OnceLock::new();
        static OTHER: OidcConfig = OidcConfig {
            issuer: String::new(),
            audience: String::new(),
            jwks_uri: String::new(),
            role_claim: String::new(),
            manager_role: String::new(),
            monitoring_role: String::new(),
        };
        let pool = AllocationPoolV1::new(1 << 20).unwrap();
        let field = |value| Text::copy(&pool, value).unwrap();
        let config = RetainedOidcConfig::new(
            field("global issuer"),
            field("a"),
            field(""),
            field("r"),
            field("m"),
            field("n"),
        )
        .unwrap();
        let owner = SharedAllocationV1::reserve(&pool, 0)
            .unwrap()
            .finish(config);
        assert!(OWNER.set(owner).is_ok());
        let reference: &'static OidcConfig = OWNER.get().unwrap();
        let (before, count) = measured(|| {
            oidc::set_global_oidc_config(reference);
            pool.used()
        });
        assert_eq!(count, (0, 0));
        assert!(core::ptr::eq(
            reference,
            oidc::global_oidc_config().unwrap()
        ));
        assert!(oidc::is_oidc_configured());
        let ((), count) = measured(|| oidc::set_global_oidc_config(&OTHER));
        assert_eq!(count, (0, 0));
        assert_eq!(pool.used(), before);
        assert!(core::ptr::eq(
            reference,
            oidc::global_oidc_config().unwrap()
        ));
        assert_eq!(oidc::global_oidc_config().unwrap().issuer, "global issuer");
    }
}
