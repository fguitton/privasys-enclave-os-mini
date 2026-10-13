//! Original parser output keeps its independent physical allocation admission.
use enclave_os_common::{
    allocation::{AllocationLeaseV1, AllocationPoolV1},
    protocol,
};
use std::sync::Arc;
/// Borrow-only request; parsing and capacity confer no caller authority.
pub struct PaidHttpRequest {
    request: protocol::HttpRequest,
    _allocation: Option<AllocationLeaseV1>,
}
impl core::ops::Deref for PaidHttpRequest {
    type Target = protocol::HttpRequest;
    fn deref(&self) -> &Self::Target {
        &self.request
    }
}
impl PaidHttpRequest {
    pub(super) fn parse(
        bytes: &[u8],
        pool: Option<&Arc<AllocationPoolV1>>,
    ) -> Result<Option<(Self, usize)>, &'static str> {
        let required = match protocol::http_request_allocation_bound(bytes) {
            Ok(required) => required,
            Err(error) => return Self::parse_error(error),
        };
        let allocation = match pool {
            Some(pool) => Some(
                pool.reserve_unpublished(required)
                    .ok_or("HTTP request admission exhausted")?,
            ),
            None => None,
        };
        match protocol::parse_http_request(bytes) {
            Ok((request, consumed)) => {
                if let Some(credit) = &allocation {
                    credit.activate_release_notification();
                }
                Ok(Some((
                    Self {
                        request,
                        _allocation: allocation,
                    },
                    consumed,
                )))
            }
            Err(error) => Self::parse_error(error),
        }
    }
    /// The returned header owns its metadata credit through Slot and Work.
    /// Both selectors and strict validation still use their original parsers.
    pub(super) fn parse_head(
        bytes: &[u8],
        pool: Option<&Arc<AllocationPoolV1>>,
        strict: bool,
    ) -> Result<Option<(Self, usize, usize)>, &'static str> {
        // Preserve the original peek's incomplete result for overlong headers.
        if bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .is_none_or(|end| end + 4 > protocol::MAX_REQUEST_HEAD_BYTES)
        {
            return if strict && bytes.len() > protocol::MAX_REQUEST_HEAD_BYTES {
                Err("malformed streaming HTTP header")
            } else {
                Ok(None)
            };
        }
        let required = protocol::http_request_head_allocation_bound(bytes)
            .map_err(|_| "malformed streaming HTTP header")?;
        let allocation = match pool {
            Some(pool) => Some(
                pool.reserve_unpublished(required)
                    .ok_or("HTTP header admission exhausted")?,
            ),
            None => None,
        };
        let parsed = if strict {
            protocol::parse_http_stream_request_head(bytes)
        } else {
            protocol::peek_http_stream_request_head(bytes)
        };
        match parsed {
            Ok((request, head, length)) => {
                if let Some(credit) = &allocation {
                    credit.activate_release_notification();
                }
                Ok(Some((
                    Self {
                        request,
                        _allocation: allocation,
                    },
                    head,
                    length,
                )))
            }
            Err(protocol::HttpParseError::Incomplete) => Ok(None),
            Err(_) => Err("malformed streaming HTTP header"),
        }
    }
    fn parse_error(error: protocol::HttpParseError) -> Result<Option<(Self, usize)>, &'static str> {
        match error {
            protocol::HttpParseError::Incomplete => Ok(None),
            protocol::HttpParseError::TooManyHeaders => Err("HTTP: too many headers"),
            protocol::HttpParseError::BodyTooLarge => Err("HTTP body too large"),
            _ => Err("malformed HTTP request"),
        }
    }
}
