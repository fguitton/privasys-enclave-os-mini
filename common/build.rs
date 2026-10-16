fn main() {
    require_request_json_supplier();
    generate_source_wire_bindings();
}
fn generate_source_wire_bindings() {
    let root = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let owner = root.join("contracts");
    println!(
        "cargo:rerun-if-changed={}",
        owner.join("source-upload-wire-v1.json").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        owner.join("source_upload_wire.py").display()
    );
    println!("cargo:rerun-if-env-changed=HONEST_SOURCE_WIRE_PYTHON");
    println!("cargo:rerun-if-env-changed=LD_LIBRARY_PATH");
    println!("cargo:rerun-if-env-changed=LD_PRELOAD");
    println!("cargo:rerun-if-env-changed=LD_AUDIT");
    let requested = std::env::var_os("HONEST_SOURCE_WIRE_PYTHON").map_or_else(
        || std::path::PathBuf::from("/usr/bin/python3"),
        std::path::PathBuf::from,
    );
    assert!(
        requested.is_absolute(),
        "source wire Python must be an absolute interpreter path"
    );
    let python = requested
        .canonicalize()
        .expect("source wire Python interpreter missing");
    assert!(python.is_file(), "source wire Python must be a file");
    for path in [&requested, &python] {
        let text = path
            .to_str()
            .expect("source wire Python path must be UTF-8");
        assert!(
            !text.contains('\n') && !text.contains('\r'),
            "invalid source wire Python path"
        );
        println!("cargo:rerun-if-changed={text}");
    }
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let provenance = output.join("source_upload_wire_build_provenance.json");
    match std::fs::remove_file(&provenance) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("cannot clear owned codegen provenance: {error}"),
    }
    let result = std::process::Command::new(&python)
        .args(["-I", "-B"])
        .arg(owner.join("source_upload_wire.py"))
        .arg("--rust")
        .arg("--provenance")
        .arg(&provenance)
        .arg("--interpreter")
        .arg(&python)
        .output()
        .expect("source wire generator requires Python 3");
    assert!(
        result.status.success(),
        "invalid source wire contract: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    for line in String::from_utf8_lossy(&result.stderr).lines() {
        if line.starts_with("cargo:rerun-if-changed=") {
            println!("{line}");
        } else {
            eprintln!("{line}");
        }
    }
    assert!(!result.stdout.is_empty(), "source wire bindings missing");
    assert!(provenance.is_file(), "source wire build provenance missing");
    std::fs::write(output.join("source_upload_wire_v1.rs"), result.stdout).unwrap();
}

fn require_request_json_supplier() {
    println!("cargo:rerun-if-env-changed=HONEST_REQUEST_JSON_SOURCE_RECEIPT");
    if std::env::var_os("CARGO_FEATURE_REQUEST_JSON_PARSER").is_none() {
        return;
    }
    let receipt = std::env::var_os("HONEST_REQUEST_JSON_SOURCE_RECEIPT")
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_absolute() && path.is_file());
    assert!(receipt.is_some(), "request-json-parser requires its verified supplier; invoke scripts/run-request-json-cargo.py --cargo ABS_CARGO --manifest-path ABS_MANIFEST --build-root NEW_BUILD_DIR -- CARGO_COMMAND [ARGS] from enclave-os-mini");
    println!("cargo:rerun-if-changed={}", receipt.unwrap().display());
}
