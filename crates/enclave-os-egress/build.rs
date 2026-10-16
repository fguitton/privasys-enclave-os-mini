// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

fn main() {
    require_retained_provider();
    // The imported enclave sources also serve the private native owner fixture.
    // Declare its selector without enabling it or adding a product feature.
    println!("cargo:rustc-check-cfg=cfg(feature, values(\"native-deferred-fixture\"))");
    println!("cargo:rustc-check-cfg=cfg(target_vendor, values(\"teaclave\"))");
}

fn require_retained_provider() {
    println!("cargo:rerun-if-env-changed=HONEST_RETAINED_PROVIDER_SOURCE_RECEIPT");
    println!("cargo:rustc-check-cfg=cfg(honest_retained_provider)");
    let receipt = std::env::var_os("HONEST_RETAINED_PROVIDER_SOURCE_RECEIPT")
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_absolute() && path.is_file());
    if let Some(path) = &receipt {
        println!("cargo:rustc-cfg=honest_retained_provider");
        println!("cargo:rerun-if-changed={}", path.display());
    }
    if std::env::var_os("CARGO_FEATURE_FALLIBLE_ALLOCATION_V1").is_none() {
        return;
    }
    assert!(receipt.is_some(), "fallible TLS requires the verified retained provider; invoke scripts/run-request-json-cargo.py --cargo ABS_CARGO --manifest-path ABS_MANIFEST --build-root NEW_BUILD_DIR -- CARGO_COMMAND [ARGS] from enclave-os-mini");
}
