//! Data-only evidence ownership; callers retain all original binding checks.
use enclave_os_common::allocation::{AllocationPoolV1, SharedAllocationV1};
use enclave_os_common::modules::PeerEvidence;
use std::sync::Arc;

pub(crate) struct EvidenceRef<'a> {
    pub(crate) tee: &'a str,
    pub(crate) quote: &'a [u8],
    pub(crate) gpu_evidence: Option<&'a [u8]>,
    pub(crate) quote_time: &'a str,
    pub(crate) context: Option<[u8; 32]>,
    pub(crate) hctx: Option<[u8; 32]>,
}
impl EvidenceRef<'_> {
    pub(crate) fn children_bytes(&self) -> Option<usize> {
        self.tee
            .len()
            .checked_add(self.quote.len())?
            .checked_add(self.gpu_evidence.map_or(0, <[u8]>::len))?
            .checked_add(self.quote_time.len())
    }
}

#[derive(Clone)]
pub(crate) struct RetainedEvidence(SharedAllocationV1<PeerEvidence>);
impl RetainedEvidence {
    pub(crate) fn copy_from(pool: &Arc<AllocationPoolV1>, value: &EvidenceRef<'_>) -> Option<Self> {
        let reservation =
            SharedAllocationV1::<PeerEvidence>::reserve(pool, value.children_bytes()?)?;
        // Each requested child layout is admitted before the first copy. Partial
        // children drop before the still-unpublished shared reservation refunds.
        let tee = copied_string(value.tee)?;
        let quote = copied_bytes(value.quote)?;
        let gpu_evidence = match value.gpu_evidence {
            Some(bytes) => Some(copied_bytes(bytes)?),
            None => None,
        };
        let quote_time = copied_string(value.quote_time)?;
        let evidence = PeerEvidence {
            tee,
            quote,
            gpu_evidence,
            quote_time,
            context: value.context,
            hctx: value.hctx,
        };
        #[cfg(feature = "fallible-allocation-v1")]
        let value = reservation.try_finish(evidence).ok()?;
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let value = reservation.finish(evidence);
        Some(Self(value))
    }
    pub(crate) fn evidence(&self) -> &PeerEvidence {
        &self.0
    }
}
fn copied_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut copied = Vec::new();
    copied.try_reserve_exact(bytes.len()).ok()?;
    if copied.capacity() != bytes.len() {
        return None;
    }
    copied.extend_from_slice(bytes);
    Some(copied)
}
fn copied_string(value: &str) -> Option<String> {
    let mut copied = String::new();
    copied.try_reserve_exact(value.len()).ok()?;
    if copied.capacity() != value.len() {
        return None;
    }
    copied.push_str(value);
    Some(copied)
}
