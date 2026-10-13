//! Optional adopter-owned admission held until the actual response body drops.
use std::any::Any;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

// The function pointer retains the exact concrete credit type without another
// allocation. The erased Arcs remain private and no Weak owner can escape.
struct PairedCredit {
    credit: Option<Arc<dyn Any + Send + Sync>>,
    release: fn(Arc<dyn Any + Send + Sync>),
}
impl Drop for PairedCredit {
    fn drop(&mut self) {
        if let Some(credit) = self.credit.take() {
            (self.release)(credit);
        }
    }
}
fn release_paired_credit<C: Any + Send + Sync>(credit: Arc<dyn Any + Send + Sync>) {
    // Only with_paired_owner can create this private pair, using this exact C.
    let credit = Arc::downcast::<C>(credit).unwrap_or_else(|_| unreachable!("paired credit type"));
    drop(Arc::into_inner(credit));
}
/// An immutable body and its optional shared reservation. The adopter acquires
/// admission before allocating or growing the body; this wrapper only carries
/// that admission through HTTP/TLS ownership. It confers no request authority.
/// There is no method that separates a leased allocation from its owner.
pub struct HttpResponseBody {
    // Declaration order frees the allocation before dropping its reservation.
    bytes: Vec<u8>,
    owner: Option<Arc<dyn Any + Send + Sync>>,
    allocation: Option<enclave_os_common::allocation::AllocationLeaseV1>,
    // Last: both body and payload Arc allocation are gone before credit returns.
    paired_credit: Option<PairedCredit>,
}
impl HttpResponseBody {
    /// The adopter reserved this exact Vec before copying the HTTP body.
    /// Actual bytes are destroyed before the move-only allocation credit.
    pub fn with_allocation(
        bytes: Vec<u8>,
        allocation: Option<enclave_os_common::allocation::AllocationLeaseV1>,
    ) -> Self {
        Self {
            bytes,
            owner: None,
            allocation,
            paired_credit: None,
        }
    }
    /// Adopt an already-paid opaque payload/credit pair without allocating.
    /// The caller must have charged both Arc layouts before creating them and
    /// keep every alias paired; no external Weak or raw Arc escape is permitted.
    /// Body bytes drop first, then payload, then the final credit Arc allocation,
    /// and only then the concrete credit value can return admission.
    pub fn with_paired_owner<T: Any + Send + Sync, C: Any + Send + Sync>(
        bytes: Vec<u8>,
        payload: Arc<T>,
        credit: Arc<C>,
    ) -> Self {
        Self {
            bytes,
            owner: Some(payload),
            allocation: None,
            paired_credit: Some(PairedCredit {
                credit: Some(credit),
                release: release_paired_credit::<C>,
            }),
        }
    }
    /// A paid credit Arc follows body bytes through final alias destruction.
    /// The caller admits its Arc layout before allocation and exposes no Weak.
    pub fn with_shared_credit<C: Any + Send + Sync>(bytes: Vec<u8>, credit: Arc<C>) -> Self {
        Self {
            bytes,
            owner: None,
            allocation: None,
            paired_credit: Some(PairedCredit {
                credit: Some(credit),
                release: release_paired_credit::<C>,
            }),
        }
    }
    pub fn with_owner(bytes: Vec<u8>, owner: Arc<dyn Any + Send + Sync>) -> Self {
        Self {
            bytes,
            owner: Some(owner),
            allocation: None,
            paired_credit: None,
        }
    }
}
impl From<Vec<u8>> for HttpResponseBody {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            owner: None,
            allocation: None,
            paired_credit: None,
        }
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
            .field("has_allocation", &self.allocation.is_some())
            .field("has_paired_credit", &self.paired_credit.is_some())
            .finish()
    }
}

/// Outgoing body: an ordinary contiguous body or a small owned prefix followed
/// by one immutable shared allocation. No flattening or payload-sized copy is
/// performed. The shared allocation must carry its own allocation admission;
/// `owner` separately retains the adopter's response/encoding admission.
pub enum HttpResponsePayload {
    Contiguous(HttpResponseBody),
    Shared(SharedResponse),
}
/// Private fields prevent separating shared range metadata from its admission.
pub struct SharedResponse {
    prefix: Vec<u8>,
    bytes: Arc<dyn AsRef<[u8]> + Send + Sync>,
    owner: HttpResponseBody,
    length: usize,
}

impl HttpResponsePayload {
    pub fn shared(
        prefix: Vec<u8>,
        bytes: Arc<dyn AsRef<[u8]> + Send + Sync>,
        owner: Arc<dyn Any + Send + Sync>,
    ) -> Result<Self, &'static str> {
        let length = prefix
            .len()
            .checked_add(bytes.as_ref().as_ref().len())
            .ok_or("response length overflow")?;
        Ok(Self::Shared(SharedResponse {
            prefix,
            bytes,
            owner: HttpResponseBody::with_owner(Vec::new(), owner),
            length,
        }))
    }
    /// Carry a separately paid response credit through shared-prefix teardown.
    pub fn shared_with_credit<C: Any + Send + Sync>(
        prefix: Vec<u8>,
        bytes: Arc<dyn AsRef<[u8]> + Send + Sync>,
        credit: Arc<C>,
    ) -> Result<Self, &'static str> {
        let owner = HttpResponseBody::with_shared_credit(Vec::new(), credit);
        let length = prefix
            .len()
            .checked_add(bytes.as_ref().as_ref().len())
            .ok_or("response length overflow")?;
        Ok(Self::Shared(SharedResponse {
            prefix,
            bytes,
            owner,
            length,
        }))
    }
    pub fn len(&self) -> usize {
        match self {
            Self::Contiguous(body) => body.len(),
            Self::Shared(shared) => shared.length,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Return one bounded contiguous part, never combine the two allocations.
    pub fn part(&self, offset: usize, limit: usize) -> Option<&[u8]> {
        if offset > self.len() {
            return None;
        }
        match self {
            Self::Contiguous(body) => {
                body.get(offset..offset.saturating_add(limit).min(body.len()))
            }
            Self::Shared(shared) => {
                let prefix = &shared.prefix;
                let bytes = &shared.bytes;
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
        match self {
            Self::Contiguous(body) => Some(body),
            Self::Shared(_) => None,
        }
    }
}
impl From<Vec<u8>> for HttpResponsePayload {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Contiguous(bytes.into())
    }
}
impl From<HttpResponseBody> for HttpResponsePayload {
    fn from(body: HttpResponseBody) -> Self {
        Self::Contiguous(body)
    }
}
impl fmt::Debug for HttpResponsePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponsePayload")
            .field("bytes", &self.len())
            .field("shared", &matches!(self, Self::Shared(_)))
            .field(
                "shared_owner",
                &match self {
                    Self::Shared(body) => Some(&body.owner),
                    Self::Contiguous(_) => None,
                },
            )
            .finish()
    }
}
