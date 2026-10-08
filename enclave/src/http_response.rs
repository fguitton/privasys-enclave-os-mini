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
