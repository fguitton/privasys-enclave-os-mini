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
}
