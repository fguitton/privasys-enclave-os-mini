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
        RpcRole::Control => method == RpcMethod::PersistRaftReadyBatch,
        RpcRole::Execution => matches!(
            method,
            RpcMethod::NetTcpConnect
                | RpcMethod::NetSend
                | RpcMethod::NetRecv
                | RpcMethod::NetClose
        ),
    }
}
