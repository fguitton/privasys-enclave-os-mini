//! Owned, data-only continuation for one admitted ingress request.
//! Neither the token nor readiness grants application or publication authority.
use crate::HonestIngressResponse;
use enclave_os_common::{modules::RequestContext, protocol::HttpRequest};

/// Global bounded transport ownership; one request may occupy each session.
pub const MAX_DEFERRED_INGRESS_REQUESTS: usize = 16;
/// Only small request metadata may be retained; response bodies stay separate.
pub const MAX_DEFERRED_INGRESS_REQUEST_BYTES: usize = 4096;

/// Inert correlation only. The adopter keeps the exact admitted request in its
/// bounded private table and must independently authorize every completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HonestPendingIngress(pub u64);

/// Immediate responses preserve their existing representation and ownership.
pub enum HonestIngressStart {
    Ready(HonestIngressResponse),
    Pending(HonestPendingIngress),
}

/// Side-effect-free selector; operation eligibility is never authorization.
pub type HonestDeferredIngressEligible = fn(&HttpRequest, &RequestContext) -> bool;

/// Called only after Mini reserves a session slot; None must have no effects.
pub type HonestDeferredIngressHook =
    fn(&HttpRequest, &RequestContext) -> Option<HonestIngressStart>;
/// Must be nonblocking and recheck current application authority using context.
pub type HonestDeferredIngressPoll =
    fn(HonestPendingIngress, &RequestContext) -> Option<HonestIngressResponse>;
/// Releases the adopter's charged request metadata, without granting authority.
pub type HonestDeferredIngressCancel = fn(HonestPendingIngress);

/// Exactly one fixed-size marker stays in Mini while its token is polled outside
/// STATE. Neither a reused connection ID nor a returned body can replace this join.
pub(crate) struct PendingSession {
    pub nonce: u64,
    pub binding: [u8; 32],
    pub token: Option<HonestPendingIngress>,
    pub close: bool,
    pub started: std::time::Instant,
}

/// Extracted work is polled after releasing Mini STATE. The fixed marker remains
/// reserved until completion/cancellation, preventing connection-ID reuse joins.
pub(crate) struct DeferredWork {
    pub connection: u32,
    pub nonce: u64,
    pub binding: [u8; 32],
    pub token: HonestPendingIngress,
    pub context: Option<RequestContext>,
    pub context_charge: Option<ContextCharge>,
}

static REVISION: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
/// Independent retained scheduling revision; grants no authority or progress.
pub fn notify_deferred_ingress() {
    REVISION.store(true, std::sync::atomic::Ordering::Release);
}
pub(crate) fn take_deferred_revision() -> bool {
    REVISION.swap(false, std::sync::atomic::Ordering::AcqRel)
}

/// One transient actual-session context may coexist with a completion body.
/// Admission precedes cloning certificate/evidence buffers, not a guessed body.
const MAX_CONTEXT_BYTES: usize = 128 * 1024;
static CONTEXT_BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(crate) struct ContextCharge;
impl ContextCharge {
    pub(crate) fn reserve(bytes: usize) -> Option<Self> {
        if bytes > MAX_CONTEXT_BYTES { return None; }
        CONTEXT_BUSY.compare_exchange(false, true, std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire).ok().map(|_| Self)
    }
}
impl Drop for ContextCharge {
    fn drop(&mut self) { CONTEXT_BUSY.store(false, std::sync::atomic::Ordering::Release); }
}
