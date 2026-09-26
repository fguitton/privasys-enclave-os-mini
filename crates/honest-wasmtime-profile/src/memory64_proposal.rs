//! Shared compiler/runtime settings for the core-memory64 migration prototype.
//!
//! The component pipeline shares these memory settings. Core probe callers must
//! reject memory32 modules, use an i64 pointer/length ABI, install the returned
//! store limits, and maintain fuel and an active epoch deadline source.
use sha2::{Digest, Sha256};
use wasmtime::{Config, StoreLimits, StoreLimitsBuilder};

pub const PROFILE_ID: &str = "honest-core-memory64-proposal-v1";
pub const SCHEMA_VERSION: u16 = 3;
pub const MAX_MEMORY: u64 = super::MAX_LINEAR_MEMORY;
pub const CHUNK: u64 = 1024 * 1024;

/// The production base descriptor plus explicit, authenticated proposal fields.
/// Both complementary Cargo roles construct the same bytes and digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Descriptor {
    pub schema_version: u16,
    pub address_bits: u8,
    pub memory_reservation: u64,
    pub memory_reservation_for_growth: u64,
    pub memory_may_move: bool,
    pub maximum_memory: u64,
    pub maximum_host_transfer: u64,
}

impl Descriptor {
    pub const fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            address_bits: 64,
            memory_reservation: 4 * CHUNK,
            memory_reservation_for_growth: CHUNK,
            memory_may_move: true,
            maximum_memory: MAX_MEMORY,
            maximum_host_transfer: CHUNK,
        }
    }

    pub fn to_canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"HW64");
        bytes.extend_from_slice(&self.schema_version.to_le_bytes());
        bytes.extend_from_slice(PROFILE_ID.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&super::ProfileDescriptor::canonical().to_canonical_bytes());
        bytes.push(self.address_bits);
        bytes.extend_from_slice(&self.memory_reservation.to_le_bytes());
        bytes.extend_from_slice(&self.memory_reservation_for_growth.to_le_bytes());
        bytes.push(u8::from(self.memory_may_move));
        bytes.extend_from_slice(&self.maximum_memory.to_le_bytes());
        bytes.extend_from_slice(&self.maximum_host_transfer.to_le_bytes());
        bytes
    }
}

/// Fail closed on drift instead of exposing unauthenticated tuning knobs.
pub fn build_config(descriptor: &Descriptor) -> Result<Config, &'static str> {
    if *descriptor != Descriptor::canonical() {
        return Err("non-canonical memory64 proposal descriptor");
    }
    if usize::BITS != 64 {
        return Err("memory64 proposal requires a 64-bit host");
    }
    let mut config = super::canonical_config();
    config.wasm_memory64(true);
    config.memory_reservation(descriptor.memory_reservation);
    config.memory_reservation_for_growth(descriptor.memory_reservation_for_growth);
    config.memory_may_move(descriptor.memory_may_move);
    // Keep explicit bounds checks, fuel, epochs, no CoW, and the exact same
    // conservative AOT target/features as the SGX base profile.
    Ok(config)
}

pub fn canonical_config() -> Config {
    build_config(&Descriptor::canonical()).expect("canonical memory64 proposal")
}

pub fn profile_digest() -> [u8; 32] {
    Sha256::digest(Descriptor::canonical().to_canonical_bytes()).into()
}

/// Per-store ceiling only. A production scheduler must additionally account for
/// all stores, retained artifacts, SQL, and transient copies during relocation.
pub fn store_limits(budget: u64) -> Result<StoreLimits, &'static str> {
    if budget == 0 || budget > MAX_MEMORY {
        return Err("memory64 budget outside profile ceiling");
    }
    let bytes = usize::try_from(budget).map_err(|_| "memory64 budget exceeds host usize")?;
    Ok(StoreLimitsBuilder::new()
        .memory_size(bytes)
        .memories(1)
        .instances(1)
        .tables(1)
        .table_elements(1024)
        .build())
}
