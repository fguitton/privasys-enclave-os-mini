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
}
