// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! AOT compiler for WASM components targeting Enclave OS.
//!
//! This tool pre-compiles a WASM Component (`.wasm`) into a native
//! code artefact (`.cwasm`) that can be loaded inside the SGX enclave
//! via `Component::deserialize`.
//!
//! # Why AOT?
//!
//! Cranelift JIT compilation inside SGX is impractical:
//!   - SGX2 EDMM page operations are orders of magnitude slower
//!     than normal `mmap`/`mprotect`.
//!   - Debug builds of Cranelift are especially slow.
//!   - Even release builds take 20+ minutes for a small component.
//!
//! AOT compilation runs on the host (outside the enclave) at full
//! speed, then the enclave simply deserializes the pre-compiled
//! native code — essentially a fast `memcpy` + relocation fixup.
//!
//! # Important
//!
//! The **wasmtime version** and **Engine configuration** in this tool
//! MUST exactly match what the enclave uses.  If they diverge, the
//! enclave will reject the `.cwasm` with a version mismatch error.
//!
//! # Usage
//!
//! ```bash
//! enclave-os-wasm-compile input.wasm -o output.cwasm
//! ```

use clap::Parser;
use honest_wasmtime_profile::wasmtime::component::Component;
use honest_wasmtime_profile::wasmtime::Engine;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "enclave-os-wasm-compile")]
#[command(about = "AOT-compile a WASM Component for Enclave OS")]
struct Cli {
    /// Path to the input `.wasm` Component file.
    input: PathBuf,

    /// Path for the output `.cwasm` (pre-compiled) file.
    /// Defaults to `<input>.cwasm`.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();

    // Determine output path
    let output = cli.output.unwrap_or_else(|| {
        let mut out = cli.input.clone();
        out.set_extension("cwasm");
        out
    });

    // Read input WASM
    let wasm_bytes = std::fs::read(&cli.input).unwrap_or_else(|e| {
        eprintln!("error: cannot read '{}': {}", cli.input.display(), e);
        std::process::exit(1);
    });
    eprintln!(
        "Input : {} ({} bytes)",
        cli.input.display(),
        wasm_bytes.len()
    );

    // Create engine with matching config
    let config = honest_wasmtime_profile::canonical_config();
    let engine = Engine::new(&config).unwrap_or_else(|e| {
        eprintln!("error: engine creation failed: {}", e);
        std::process::exit(1);
    });

    // AOT compile
    eprintln!("Compiling...");
    let cwasm = engine
        .precompile_component(&wasm_bytes)
        .unwrap_or_else(|e| {
            eprintln!("error: compilation failed: {}", e);
            std::process::exit(1);
        });

    // Verify round-trip (optional sanity check)
    unsafe {
        Component::deserialize(&engine, &cwasm).unwrap_or_else(|e| {
            eprintln!("error: deserialize sanity check failed: {}", e);
            std::process::exit(1);
        });
    }

    // Write output
    std::fs::write(&output, &cwasm).unwrap_or_else(|e| {
        eprintln!("error: cannot write '{}': {}", output.display(), e);
        std::process::exit(1);
    });

    eprintln!("Output: {} ({} bytes)", output.display(), cwasm.len());
    eprintln!("Done.");
}
