//! Actual compiler-selected protocol capabilities; no attestation authority.
pub(crate) fn compiled() -> serde_json::Value {
    let features: Vec<_> = env!("ENCLAVE_OS_HOST_COMPILED_FEATURES")
        .split(',')
        .filter(|name| !name.is_empty())
        .collect();
    serde_json::json!({"schema_version":1,"features":features,"debug_assertions":cfg!(debug_assertions),
        "sgx_mode":if cfg!(sgx_mode_sim) {"SIM"} else {"HW"}})
}
#[cfg(test)]
pub(crate) fn check() {
    let value = compiled();
    assert_eq!(
        value["features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "stream-read-credit"),
        cfg!(feature = "stream-read-credit")
    );
    assert_eq!(value["debug_assertions"], cfg!(debug_assertions));
    assert_eq!(
        value["sgx_mode"],
        if cfg!(sgx_mode_sim) { "SIM" } else { "HW" }
    );
}
