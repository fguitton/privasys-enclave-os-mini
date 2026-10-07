// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Versioned, role-owned Honest RPC envelope.

#[cfg(feature = "sgx")]
use alloc::vec::Vec;
#[cfg(not(feature = "sgx"))]
use std::vec::Vec;

use super::RpcMethod;

/// Magic prefix distinguishing bounded Honest frames from legacy Mini RPC.
pub const HONEST_RPC_MAGIC: [u8; 4] = *b"HRPC";
/// Frozen first version of the role-owned transport envelope.
pub const HONEST_RPC_PROFILE_VERSION: u16 = 1;
/// Honest RPC payloads must fit within one bounded shared-memory frame.
pub const MAX_HONEST_RPC_PAYLOAD_BYTES: usize = 1024 * 1024;
/// Request header: magic, version, role/reserved, node/generation/operation,
/// method and payload length.
pub const HONEST_REQ_HEADER_SIZE: usize = 38;
/// Response header adds one signed status to the complete request identity.
pub const HONEST_RESP_HEADER_SIZE: usize = 42;

/// Physical and logical owner of one Honest RPC frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RpcRole {
    Control = 1,
    Execution = 2,
}

impl RpcRole {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Control),
            2 => Some(Self::Execution),
            _ => None,
        }
    }
}

/// Complete correlation identity echoed by an Honest host response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HonestRpcIdentity {
    pub role: RpcRole,
    pub node_id: u64,
    pub node_generation: u64,
    pub operation_id: u64,
    pub method: RpcMethod,
}

/// Borrowed, strictly bounded request frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HonestRpcRequest<'a> {
    pub identity: HonestRpcIdentity,
    pub payload: &'a [u8],
}

/// Borrowed, strictly bounded response frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HonestRpcResponse<'a> {
    pub identity: HonestRpcIdentity,
    pub status: i32,
    pub payload: &'a [u8],
}

/// Fail-closed framed RPC codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HonestRpcFrameError {
    NotHonestFrame,
    Malformed,
    UnsupportedProfile,
    InvalidRole,
    InvalidIdentity,
    UnexpectedIdentity,
    PayloadBound,
}

/// Return whether the bytes claim the Honest framed profile.
#[must_use]
pub fn has_honest_rpc_magic(data: &[u8]) -> bool {
    data.get(..HONEST_RPC_MAGIC.len()) == Some(HONEST_RPC_MAGIC.as_slice())
}

fn validate_honest_identity(identity: HonestRpcIdentity) -> Result<(), HonestRpcFrameError> {
    if identity.node_id == 0 || identity.node_generation == 0 || identity.operation_id == 0 {
        return Err(HonestRpcFrameError::InvalidIdentity);
    }
    Ok(())
}

fn encode_honest_identity(encoded: &mut Vec<u8>, identity: HonestRpcIdentity) {
    encoded.extend_from_slice(&HONEST_RPC_MAGIC);
    encoded.extend_from_slice(&HONEST_RPC_PROFILE_VERSION.to_le_bytes());
    encoded.push(identity.role as u8);
    encoded.push(0);
    encoded.extend_from_slice(&identity.node_id.to_le_bytes());
    encoded.extend_from_slice(&identity.node_generation.to_le_bytes());
    encoded.extend_from_slice(&identity.operation_id.to_le_bytes());
    encoded.extend_from_slice(&(identity.method as u16).to_le_bytes());
}

fn decode_honest_identity(
    encoded: &[u8],
    minimum_length: usize,
) -> Result<HonestRpcIdentity, HonestRpcFrameError> {
    if !has_honest_rpc_magic(encoded) {
        return Err(HonestRpcFrameError::NotHonestFrame);
    }
    if encoded.len() < minimum_length {
        return Err(HonestRpcFrameError::Malformed);
    }
    if u16::from_le_bytes(
        encoded[4..6]
            .try_into()
            .map_err(|_| HonestRpcFrameError::Malformed)?,
    ) != HONEST_RPC_PROFILE_VERSION
    {
        return Err(HonestRpcFrameError::UnsupportedProfile);
    }
    if encoded[7] != 0 {
        return Err(HonestRpcFrameError::Malformed);
    }
    let identity = HonestRpcIdentity {
        role: RpcRole::from_u8(encoded[6]).ok_or(HonestRpcFrameError::InvalidRole)?,
        node_id: u64::from_le_bytes(
            encoded[8..16]
                .try_into()
                .map_err(|_| HonestRpcFrameError::Malformed)?,
        ),
        node_generation: u64::from_le_bytes(
            encoded[16..24]
                .try_into()
                .map_err(|_| HonestRpcFrameError::Malformed)?,
        ),
        operation_id: u64::from_le_bytes(
            encoded[24..32]
                .try_into()
                .map_err(|_| HonestRpcFrameError::Malformed)?,
        ),
        method: RpcMethod::from_u16(u16::from_le_bytes(
            encoded[32..34]
                .try_into()
                .map_err(|_| HonestRpcFrameError::Malformed)?,
        ))
        .ok_or(HonestRpcFrameError::Malformed)?,
    };
    validate_honest_identity(identity)?;
    Ok(identity)
}

/// Encode one bounded role-owned request.
pub fn encode_honest_request(
    identity: HonestRpcIdentity,
    payload: &[u8],
) -> Result<Vec<u8>, HonestRpcFrameError> {
    validate_honest_identity(identity)?;
    if payload.len() > MAX_HONEST_RPC_PAYLOAD_BYTES {
        return Err(HonestRpcFrameError::PayloadBound);
    }
    let mut encoded = Vec::with_capacity(HONEST_REQ_HEADER_SIZE + payload.len());
    encode_honest_identity(&mut encoded, identity);
    encoded.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

/// Decode one complete bounded role-owned request.
pub fn decode_honest_request(encoded: &[u8]) -> Result<HonestRpcRequest<'_>, HonestRpcFrameError> {
    let identity = decode_honest_identity(encoded, HONEST_REQ_HEADER_SIZE)?;
    let payload_length = u32::from_le_bytes(
        encoded[34..38]
            .try_into()
            .map_err(|_| HonestRpcFrameError::Malformed)?,
    ) as usize;
    if payload_length > MAX_HONEST_RPC_PAYLOAD_BYTES {
        return Err(HonestRpcFrameError::PayloadBound);
    }
    if encoded.len() != HONEST_REQ_HEADER_SIZE + payload_length {
        return Err(HonestRpcFrameError::Malformed);
    }
    Ok(HonestRpcRequest {
        identity,
        payload: &encoded[HONEST_REQ_HEADER_SIZE..],
    })
}

/// Encode one response that echoes the complete request identity.
pub fn encode_honest_response(
    identity: HonestRpcIdentity,
    status: i32,
    payload: &[u8],
) -> Result<Vec<u8>, HonestRpcFrameError> {
    validate_honest_identity(identity)?;
    if payload.len() > MAX_HONEST_RPC_PAYLOAD_BYTES {
        return Err(HonestRpcFrameError::PayloadBound);
    }
    let mut encoded = Vec::with_capacity(HONEST_RESP_HEADER_SIZE + payload.len());
    encode_honest_identity(&mut encoded, identity);
    encoded.extend_from_slice(&status.to_le_bytes());
    encoded.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

/// Decode one complete bounded role-owned response.
pub fn decode_honest_response(
    encoded: &[u8],
) -> Result<HonestRpcResponse<'_>, HonestRpcFrameError> {
    let identity = decode_honest_identity(encoded, HONEST_RESP_HEADER_SIZE)?;
    let status = i32::from_le_bytes(
        encoded[34..38]
            .try_into()
            .map_err(|_| HonestRpcFrameError::Malformed)?,
    );
    let payload_length = u32::from_le_bytes(
        encoded[38..42]
            .try_into()
            .map_err(|_| HonestRpcFrameError::Malformed)?,
    ) as usize;
    if payload_length > MAX_HONEST_RPC_PAYLOAD_BYTES {
        return Err(HonestRpcFrameError::PayloadBound);
    }
    if encoded.len() != HONEST_RESP_HEADER_SIZE + payload_length {
        return Err(HonestRpcFrameError::Malformed);
    }
    Ok(HonestRpcResponse {
        identity,
        status,
        payload: &encoded[HONEST_RESP_HEADER_SIZE..],
    })
}

/// Decode a response and require the exact submitted identity.
pub fn decode_honest_response_for(
    encoded: &[u8],
    expected: HonestRpcIdentity,
) -> Result<HonestRpcResponse<'_>, HonestRpcFrameError> {
    let response = decode_honest_response(encoded)?;
    if response.identity != expected {
        return Err(HonestRpcFrameError::UnexpectedIdentity);
    }
    Ok(response)
}

/// Frozen method allowlist for framed Honest traffic.
#[must_use]
pub fn honest_role_allows_method(role: RpcRole, method: RpcMethod) -> bool {
    match role {
        RpcRole::Control => matches!(method, RpcMethod::KvPutDurable),
        RpcRole::Execution => matches!(
            method,
            RpcMethod::NetTcpConnect
                | RpcMethod::NetSend
                | RpcMethod::NetRecv
                | RpcMethod::NetClose
                | RpcMethod::WorkerStorage
        ),
    }
}

/// Private scratch storage operation class. Durability is a private-storage
/// barrier, never a BFT journal acknowledgement or accepted artifact authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WorkerStorageOperation {
    Get = 0,
    Put = 1,
    DurablePut = 2,
    Delete = 3,
    PutBatch = 4,
}

pub fn encode_worker_storage_request(
    operation: WorkerStorageOperation,
    payload: &[u8],
) -> Result<Vec<u8>, HonestRpcFrameError> {
    let length = payload
        .len()
        .checked_add(1)
        .ok_or(HonestRpcFrameError::PayloadBound)?;
    if length > MAX_HONEST_RPC_PAYLOAD_BYTES {
        return Err(HonestRpcFrameError::PayloadBound);
    }
    let mut bytes = Vec::with_capacity(length);
    bytes.push(operation as u8);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

pub fn decode_worker_storage_request(bytes: &[u8]) -> Option<(WorkerStorageOperation, &[u8])> {
    let (operation, payload) = bytes.split_first()?;
    let operation = match operation {
        0 => WorkerStorageOperation::Get,
        1 => WorkerStorageOperation::Put,
        2 => WorkerStorageOperation::DurablePut,
        3 => WorkerStorageOperation::Delete,
        4 => WorkerStorageOperation::PutBatch,
        _ => return None,
    };
    Some((operation, payload))
}

/// Private accepted-data batch: bounded ciphertext records, never a durable ACK.
pub const MAX_WORKER_STORAGE_BATCH_BYTES: usize = 768 * 1024;
pub const MAX_WORKER_STORAGE_BATCH_RECORDS: usize = 64;
pub fn encode_worker_storage_put_batch(table: &[u8], records: &[(&[u8], &[u8])]) -> Option<Vec<u8>> {
    if table.is_empty() || table.len()>256 || records.is_empty() || records.len()>MAX_WORKER_STORAGE_BATCH_RECORDS { return None; }
    let mut length=4usize.checked_add(table.len())?;
    for (key,value) in records {
        if key.is_empty() || key.len()>512 || value.is_empty() { return None; }
        length=length.checked_add(6)?.checked_add(key.len())?.checked_add(value.len())?;
    }
    if length>MAX_WORKER_STORAGE_BATCH_BYTES { return None; }
    let mut out=Vec::with_capacity(length);
    out.extend_from_slice(&u16::try_from(table.len()).ok()?.to_le_bytes());out.extend_from_slice(table);
    out.extend_from_slice(&u16::try_from(records.len()).ok()?.to_le_bytes());
    for (key,value) in records {
        out.extend_from_slice(&u16::try_from(key.len()).ok()?.to_le_bytes());out.extend_from_slice(&u32::try_from(value.len()).ok()?.to_le_bytes());
        out.extend_from_slice(key);out.extend_from_slice(value);
    }
    Some(out)
}
pub type WorkerStorageBatchRecords<'a> = Vec<(&'a [u8], &'a [u8])>;
pub fn decode_worker_storage_put_batch(bytes: &[u8]) -> Option<(&[u8], WorkerStorageBatchRecords<'_>)> {
    if bytes.len()>MAX_WORKER_STORAGE_BATCH_BYTES { return None; }
    let table_len=usize::from(u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?));
    if table_len==0 || table_len>256 { return None; }
    let table=bytes.get(2..2+table_len)?;let mut offset=2+table_len;
    let count=usize::from(u16::from_le_bytes(bytes.get(offset..offset+2)?.try_into().ok()?));offset+=2;
    if count==0 || count>MAX_WORKER_STORAGE_BATCH_RECORDS { return None; }
    let mut records=Vec::with_capacity(count);
    for _ in 0..count {
        let key_len=usize::from(u16::from_le_bytes(bytes.get(offset..offset+2)?.try_into().ok()?));
        let value_len=usize::try_from(u32::from_le_bytes(bytes.get(offset+2..offset+6)?.try_into().ok()?)).ok()?;offset+=6;
        if key_len==0 || key_len>512 || value_len==0 { return None; }
        let key=bytes.get(offset..offset.checked_add(key_len)?)?;offset+=key_len;
        let value=bytes.get(offset..offset.checked_add(value_len)?)?;offset+=value_len;
        records.push((key,value));
    }
    (offset==bytes.len()).then_some((table,records))
}
