// Copyright (c) 2026 Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

//! Explicit resource bounds for trusted large-object callers. This is not an
//! admission or network capability: the caller must supply both authorities.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpsBodyLimitsV1 {
    request: usize,
    response: usize,
}
impl HttpsBodyLimitsV1 {
    /// Validate allocation arithmetic without allocating a workload buffer.
    /// Bounds come from the caller's admitted resource profile, never a remote
    /// Content-Length. Header, certificate and network-buffer bounds stay fixed.
    pub fn new(request: u64, response: u64) -> Result<Self, String> {
        let request = usize::try_from(request).map_err(|_| "request limit overflow")?;
        let response = usize::try_from(response).map_err(|_| "response limit overflow")?;
        if request > isize::MAX as usize
            || response
                .checked_add(MAX_RESPONSE_HEADER_BYTES)
                .is_none_or(|n| n > isize::MAX as usize)
        {
            return Err("HTTP body limits exceed address space".into());
        }
        Ok(Self { request, response })
    }
}

/// Borrowed body with explicit admitted request/response budgets. It does not
/// copy the payload when constructing HTTP framing. Responses are still owned
/// in memory; this interface does not claim constant-memory receiving.
pub struct ResourceBoundHttpsRequest<'a> {
    metadata: BoundedHttpsRequest,
    body: Option<&'a [u8]>,
    limits: HttpsBodyLimitsV1,
}
impl<'a> ResourceBoundHttpsRequest<'a> {
    pub fn new(
        method: impl Into<String>,
        url: impl Into<String>,
        headers: Vec<(String, String)>,
        body: Option<&'a [u8]>,
        limits: HttpsBodyLimitsV1,
    ) -> Result<Self, String> {
        if body.is_some_and(|b| b.len() > limits.request)
            || headers.iter().any(|(name, _)| {
                name.eq_ignore_ascii_case("content-length")
                    || name.eq_ignore_ascii_case("transfer-encoding")
                    || name.eq_ignore_ascii_case("host")
                    || name.eq_ignore_ascii_case("connection")
            })
        {
            return Err("HTTP body exceeds profile or overrides transport framing".into());
        }
        let metadata = BoundedHttpsRequest::new(method, url, headers, None)?;
        Ok(Self {
            metadata,
            body,
            limits,
        })
    }
}
impl fmt::Debug for ResourceBoundHttpsRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceBoundHttpsRequest")
            .field("metadata", &self.metadata)
            .field("body", &"<protected>")
            .field("limits", &self.limits)
            .finish()
    }
}

/// Same TLS, optional RA-TLS, pre-dispatch authorization, injected interruptible
/// I/O and ambiguity semantics as the bounded client, with explicit body limits.
pub fn https_fetch_resource_authorized_interruptible_detailed(
    io: &mut dyn InterruptibleBlockingNetIo,
    request: &ResourceBoundHttpsRequest<'_>,
    root_store: &RootCertStore,
    ratls: Option<&RaTlsPolicy>,
    authorize_peer: &mut dyn FnMut(&TlsPeerCertificateChain) -> Result<(), String>,
) -> Result<HttpResponse, HttpsFetchError> {
    fetch_authorized(
        io,
        RequestInput {
            metadata: &request.metadata,
            body: request.body,
            response_limit: request.limits.response,
        },
        root_store,
        ratls,
        authorize_peer,
    )
}
