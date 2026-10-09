//! Optional adopter-owned admission held until the actual response body drops.
use std::any::Any;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

/// An immutable body and its optional shared reservation. The adopter acquires
/// admission before allocating or growing the body; this wrapper only carries
/// that admission through HTTP/TLS ownership. It confers no request authority.
/// There is no method that separates a leased allocation from its owner.
pub struct HttpResponseBody {
    // Declaration order frees the allocation before dropping its reservation.
    bytes: Vec<u8>,
    owner: Option<Arc<dyn Any + Send + Sync>>,
}
impl HttpResponseBody {
    pub fn with_owner(bytes: Vec<u8>, owner: Arc<dyn Any + Send + Sync>) -> Self {
        Self {
            bytes,
            owner: Some(owner),
        }
    }
}
impl From<Vec<u8>> for HttpResponseBody {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes, owner: None }
    }
}
impl Deref for HttpResponseBody {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}
impl fmt::Debug for HttpResponseBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponseBody")
            .field("bytes", &self.bytes.len())
            .field("capacity", &self.bytes.capacity())
            .field("has_owner", &self.owner.is_some())
            .finish()
    }
}

/// Outgoing body: an ordinary contiguous body or a small owned prefix followed
/// by one immutable shared allocation. No flattening or payload-sized copy is
/// performed. The shared allocation must carry its own allocation admission;
/// `owner` separately retains the adopter's response/encoding admission.
pub enum HttpResponsePayload {
    Contiguous(HttpResponseBody),
    Shared {
        prefix: Vec<u8>,
        bytes: Arc<dyn AsRef<[u8]> + Send + Sync>,
        owner: Arc<dyn Any + Send + Sync>,
        length: usize,
    },
}
impl HttpResponsePayload {
    pub fn shared(
        prefix: Vec<u8>, bytes: Arc<dyn AsRef<[u8]> + Send + Sync>,
        owner: Arc<dyn Any + Send + Sync>,
    ) -> Result<Self, &'static str> {
        let length = prefix.len().checked_add(bytes.as_ref().as_ref().len())
            .ok_or("response length overflow")?;
        Ok(Self::Shared { prefix, bytes, owner, length })
    }
    pub fn len(&self) -> usize {
        match self { Self::Contiguous(body) => body.len(), Self::Shared { length, .. } => *length }
    }
    pub fn is_empty(&self) -> bool { self.len() == 0 }
    /// Return one bounded contiguous part, never combine the two allocations.
    pub fn part(&self, offset: usize, limit: usize) -> Option<&[u8]> {
        if offset > self.len() { return None; }
        match self {
            Self::Contiguous(body) => body.get(offset..offset.saturating_add(limit).min(body.len())),
            Self::Shared { prefix, bytes, .. } => {
                if offset < prefix.len() {
                    prefix.get(offset..offset.saturating_add(limit).min(prefix.len()))
                } else {
                    let bytes = bytes.as_ref().as_ref();
                    let start = offset - prefix.len();
                    bytes.get(start..start.saturating_add(limit).min(bytes.len()))
                }
            }
        }
    }
    /// Only receive-side/legacy contiguous bodies can be borrowed as one slice.
    pub fn contiguous(&self) -> Option<&[u8]> {
        match self { Self::Contiguous(body) => Some(body), Self::Shared { .. } => None }
    }
}
impl From<Vec<u8>> for HttpResponsePayload {
    fn from(bytes: Vec<u8>) -> Self { Self::Contiguous(bytes.into()) }
}
impl From<HttpResponseBody> for HttpResponsePayload {
    fn from(body: HttpResponseBody) -> Self { Self::Contiguous(body) }
}
impl fmt::Debug for HttpResponsePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponsePayload").field("bytes", &self.len())
            .field("shared", &matches!(self, Self::Shared { .. })).finish()
    }
}
