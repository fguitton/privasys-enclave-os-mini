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
/// Upper bound of metadata retained by the adopter, checked before admission.
/// Original wire/body storage remains separately bounded by the HTTP parser.
pub type HonestDeferredIngressMetadata = fn(&HttpRequest, &RequestContext) -> Option<usize>;

pub(crate) fn legacy_metadata(request: &HttpRequest, _: &RequestContext) -> Option<usize> {
    Some(request.body.len())
}

pub(crate) fn metadata_fits(bytes: Option<usize>) -> bool {
    bytes.is_some_and(|bytes| bytes <= MAX_DEFERRED_INGRESS_REQUEST_BYTES)
}
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
    pub _context_charge: Option<ContextCharge>,
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
pub(crate) struct ContextCharge {
    allocation: Option<enclave_os_common::allocation::AllocationLeaseV1>,
}
impl ContextCharge {
    pub(crate) fn reserve(bytes: usize) -> Option<Self> {
        #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
        let pool = Some(crate::local_allocation_pool()?);
        #[cfg(not(any(target_env = "sgx", target_vendor = "teaclave")))]
        let pool = None;
        Self::reserve_from(bytes, pool.as_ref())
    }
    fn reserve_from(
        bytes: usize,
        pool: Option<&std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>>,
    ) -> Option<Self> {
        if bytes > MAX_CONTEXT_BYTES {
            return None;
        }
        CONTEXT_BUSY
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .ok()?;
        // Own logical rollback before attempting the independent physical pool.
        let mut charge = Self { allocation: None };
        if let Some(pool) = pool {
            charge.allocation = Some(pool.reserve_unpublished(bytes)?);
            charge.allocation.as_ref()?.activate_release_notification();
        }
        Some(charge)
    }
}
impl Drop for ContextCharge {
    fn drop(&mut self) {
        // Work declares the copied context before this credit. Its children are
        // already gone; refund physical storage before reopening logical admission.
        drop(self.allocation.take());
        CONTEXT_BUSY.store(false, std::sync::atomic::Ordering::Release);
        // The physical-pool callback may already have woken a scheduler while
        // logical admission was still busy. Publish the logical release too;
        // both original revisions coalesce without granting authority.
        notify_deferred_ingress();
        crate::stream_ingress::notify_honest_stream_ingress();
    }
}

pub(crate) fn select_pending(
    slots: &crate::ratls::session::ordered_map::OrderedMap<u32, PendingSession>,
    cursor: u32,
    seen: &[u64],
) -> Option<u32> {
    let eligible = |slot: &PendingSession| slot.token.is_some() && !seen.contains(&slot.nonce);
    slots
        .range((
            std::ops::Bound::Excluded(cursor),
            std::ops::Bound::Unbounded,
        ))
        .find(|(_, slot)| eligible(slot))
        .or_else(|| slots.iter().find(|(_, slot)| eligible(slot)))
        .map(|(id, _)| *id)
}
impl PendingSession {
    pub(crate) fn matches_inflight(&self, nonce: u64, binding: [u8; 32]) -> bool {
        self.nonce == nonce
            && self.binding == binding
            && self.token.is_none()
            && self.started.elapsed() < std::time::Duration::from_secs(60)
    }
}
#[cfg(test)]
pub(crate) fn check_pending_for_native() {
    use enclave_os_common::allocation::AllocationPoolV1;
    assert!(metadata_fits(Some(256)));
    assert!(metadata_fits(Some(4096)));
    assert!(!metadata_fits(Some(4097)));
    assert!(!metadata_fits(None));
    // Legacy admission retains its original wire bound; compact metadata can
    // fit even when the independently bounded original request is 4220 bytes.
    assert!(!metadata_fits(Some(4220)));

    let bytes = core::alloc::Layout::array::<(u32, PendingSession)>(MAX_DEFERRED_INGRESS_REQUESTS)
        .unwrap()
        .size()
        + crate::ratls::session::cancellation::Queue::<HonestPendingIngress>::bytes(
            MAX_DEFERRED_INGRESS_REQUESTS,
        )
        .unwrap();
    for maximum in [bytes - 1, bytes, bytes + 1] {
        let pool = AllocationPoolV1::new(maximum).unwrap();
        let mut owner = CancellationOwner::default();
        assert_eq!(owner.prepare_from(&pool), maximum >= bytes);
        assert_eq!(pool.used(), if maximum >= bytes { bytes } else { 0 });
        drop(owner);
        assert_eq!(pool.used(), 0);
    }
    let pool = AllocationPoolV1::new(bytes * 2).unwrap();
    let mut slots = crate::ratls::session::ordered_map::OrderedMap::default();
    slots
        .prepare_from(&pool, MAX_DEFERRED_INGRESS_REQUESTS)
        .unwrap();
    for id in 1..=16 {
        slots.insert_prepared(
            id,
            PendingSession {
                nonce: id as u64,
                binding: [id as u8; 32],
                token: Some(HonestPendingIngress(id as u64)),
                close: false,
                started: std::time::Instant::now(),
            },
        );
    }
    let mut seen = Vec::new();
    let mut cursor = 0;
    for _ in 0..16 {
        let id = select_pending(&slots, cursor, &seen).unwrap();
        cursor = id;
        let slot = slots.get_mut(&id).unwrap();
        let token = slot.token.take().unwrap();
        assert!(slot.matches_inflight(id as u64, [id as u8; 32]));
        assert!(!slot.matches_inflight(id as u64 + 16, [id as u8; 32]));
        assert!(!slot.matches_inflight(id as u64, [0; 32]));
        seen.push(slot.nonce);
        // First None is retained; other Ready/cancelled entries disappear.
        if id == 1 {
            slot.token = Some(token);
        } else {
            slots.remove(&id);
        }
    }
    assert_eq!(seen.len(), 16);
    assert!(select_pending(&slots, cursor, &seen).is_none());
    assert_eq!(select_pending(&slots, cursor, &[]), Some(1));
    let old = slots.remove(&1).unwrap();
    slots.insert_prepared(
        1,
        PendingSession {
            nonce: 99,
            binding: [99; 32],
            token: None,
            close: false,
            started: std::time::Instant::now(),
        },
    );
    assert!(!slots[&1].matches_inflight(old.nonce, old.binding));
    let mut cancelled =
        crate::ratls::session::cancellation::Queue::new(&pool, MAX_DEFERRED_INGRESS_REQUESTS)
            .unwrap();
    slots.clear();
    for id in 1..=16 {
        slots.insert_prepared(
            id,
            PendingSession {
                nonce: id as u64,
                binding: [id as u8; 32],
                token: Some(HonestPendingIngress(id as u64)),
                close: false,
                started: std::time::Instant::now(),
            },
        );
    }
    assert!(!pending_capacity(slots.len(), cancelled.len()));
    // Extracted token still occupies the real marker before invalidation.
    let extracted = slots.get_mut(&1).unwrap().token.take().unwrap();
    assert!(!pending_capacity(slots.len(), cancelled.len()));
    for id in 2..=16 {
        invalidate_pending(&mut slots, &mut cancelled, id);
    }
    assert!(!pending_capacity(slots.len(), cancelled.len()));
    invalidate_pending(&mut slots, &mut cancelled, 2);
    assert_eq!(cancelled.len(), 15, "cancel once");
    let mut released = Vec::new();
    while let Some(token) = cancelled.pop_front() {
        released.push(token.0);
    }
    assert_eq!(released.len(), 15);
    assert!(pending_capacity(slots.len(), cancelled.len()));
    invalidate_pending(&mut slots, &mut cancelled, 1);
    assert!(cancelled.is_empty(), "extracted owner cancels outside join");
    assert_eq!(extracted.0, 1);
    assert!(pending_capacity(0, 0));
    assert!(!pending_capacity(usize::MAX, 1));
    notify_deferred_ingress();
    assert!(take_deferred_revision());
    assert!(!take_deferred_revision());
    notify_deferred_ingress();
    assert!(
        take_deferred_revision(),
        "publication after take stays pending"
    );
    let mut owner = CancellationOwner::default();
    assert!(owner.prepare_from(&pool));
    for id in 1..=16 {
        owner.pending.insert_prepared(
            id,
            PendingSession {
                nonce: id as u64,
                binding: [id as u8; 32],
                token: Some(HonestPendingIngress(id as u64)),
                close: false,
                started: std::time::Instant::now(),
            },
        );
    }
    for id in 1..=8 {
        invalidate_pending(&mut owner.pending, &mut owner.cancelled, id);
    }
    let extracted = owner.pending.get_mut(&16).unwrap().token.take().unwrap();
    let simulated_state = std::sync::Mutex::new(());
    let held_state = simulated_state.lock().unwrap();
    // The actual lifecycle destructor performs no adopter callbacks here.
    drop(owner);
    assert_eq!(
        pool.used(),
        bytes,
        "retired metadata freed, independent original table retained"
    );
    assert_eq!(
        terminal_count(),
        15,
        "extracted token remains separately owned"
    );
    drop(held_state);
    handoff_terminal(extracted);

    handoff_terminal(HonestPendingIngress(1));
    assert_eq!(terminal_count(), 16);
    assert!(
        !pending_capacity(0, terminal_count()),
        "destruction debt blocks readmission"
    );
    let mut released = Vec::new();
    while let Some(token) = take_terminal() {
        released.push(token.0);
    }
    released.sort();
    assert_eq!(released, (1..=16).collect::<Vec<_>>());
    assert!(
        pending_capacity(0, terminal_count()),
        "outside-STATE cancel permits readmission"
    );
    drop(slots);
    drop(cancelled);
    assert_eq!(pool.used(), 0, "last retained metadata backing refunded");
    let lease = ContextCharge::reserve(128 * 1024).unwrap();
    assert!(ContextCharge::reserve(1).is_none());
    drop(lease);
    assert!(ContextCharge::reserve(128 * 1024 + 1).is_none());
    assert!(ContextCharge::reserve(1).is_some());
    eprintln!("DEFERRED-FRAME-PENDING: 16nonces/None+Ready fairness/lateReady reuse/wake-no-loss/contextcapacity-overlap PASS");
}

/// Production admission counts pending and cancelled-but-not-released requests.
/// Extracted requests keep their marker; no response-readiness claim is involved.
pub(crate) fn pending_capacity(pending: usize, cancelled: usize) -> bool {
    pending
        .checked_add(cancelled)
        .is_some_and(|count| count < MAX_DEFERRED_INGRESS_REQUESTS)
}
pub(crate) fn invalidate_pending(
    slots: &mut crate::ratls::session::ordered_map::OrderedMap<u32, PendingSession>,
    cancelled: &mut crate::ratls::session::cancellation::Queue<HonestPendingIngress>,
    id: u32,
) {
    if let Some(slot) = slots.remove(&id) {
        if let Some(token) = slot.token {
            cancelled.push_back(token);
        }
    }
}

/// Drop cannot call the adopter while Mini STATE may be held. Fixed handoff
/// slots retain terminal tokens until the outside-STATE service releases them.
static TERMINAL_TOKENS: std::sync::Mutex<
    [Option<HonestPendingIngress>; MAX_DEFERRED_INGRESS_REQUESTS],
> = std::sync::Mutex::new([None; MAX_DEFERRED_INGRESS_REQUESTS]);
pub(crate) fn handoff_terminal(token: HonestPendingIngress) {
    let mut tokens = TERMINAL_TOKENS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if tokens.iter().flatten().any(|value| *value == token) {
        return;
    }
    let slot = tokens
        .iter_mut()
        .find(|slot| slot.is_none())
        .expect("one adopted server/table admits at most16 terminal tokens");
    *slot = Some(token);
    notify_deferred_ingress();
}
pub(crate) fn take_terminal() -> Option<HonestPendingIngress> {
    TERMINAL_TOKENS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .iter_mut()
        .find_map(Option::take)
}
pub(crate) fn terminal_count() -> usize {
    TERMINAL_TOKENS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .iter()
        .flatten()
        .count()
}

/// The actual server owns this terminal debt. Its destructor only hands off
/// fixed tokens; the adopter callback is invoked later after STATE is released.
#[derive(Default)]
pub(crate) struct CancellationOwner {
    pub pending: crate::ratls::session::ordered_map::OrderedMap<u32, PendingSession>,
    pub cancelled: crate::ratls::session::cancellation::Queue<HonestPendingIngress>,
}
impl CancellationOwner {
    pub(crate) fn prepare_from(
        &mut self,
        pool: &std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
    ) -> bool {
        if self
            .pending
            .prepared_for(pool, MAX_DEFERRED_INGRESS_REQUESTS)
            && self
                .cancelled
                .prepared_for(pool, MAX_DEFERRED_INGRESS_REQUESTS)
        {
            return true;
        }
        if self.pending.has_admission() || self.cancelled.has_admission() {
            return false;
        }
        let mut pending = crate::ratls::session::ordered_map::OrderedMap::default();
        if pending
            .prepare_from(pool, MAX_DEFERRED_INGRESS_REQUESTS)
            .is_err()
        {
            return false;
        }
        let Some(cancelled) =
            crate::ratls::session::cancellation::Queue::new(pool, MAX_DEFERRED_INGRESS_REQUESTS)
        else {
            return false;
        };
        self.pending = pending;
        self.cancelled = cancelled;
        true
    }
    #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
    pub(crate) fn prepare(&mut self) -> bool {
        crate::local_allocation_pool().is_some_and(|pool| self.prepare_from(&pool))
    }
    pub(crate) fn take_tokens(&mut self) -> Drain {
        Drain {
            pending: std::mem::take(&mut self.pending).into_iter(),
            cancelled: std::mem::take(&mut self.cancelled).into_iter(),
        }
    }
}
pub(crate) struct Drain {
    pending: crate::ratls::session::ordered_map::Entries<u32, PendingSession>,
    cancelled: crate::ratls::session::cancellation::Drain<HonestPendingIngress>,
}
impl Iterator for Drain {
    type Item = HonestPendingIngress;
    fn next(&mut self) -> Option<HonestPendingIngress> {
        for (_, slot) in self.pending.by_ref() {
            if let Some(value) = slot.token {
                return Some(value);
            }
        }
        self.cancelled.next()
    }
}

impl Drop for CancellationOwner {
    fn drop(&mut self) {
        for token in self.take_tokens() {
            handoff_terminal(token);
        }
    }
}

#[cfg(test)]
pub(crate) fn check_context_physical_for_native() {
    // Exercise the same provider seam used before real fresh_context cloning.
    use enclave_os_common::allocation::AllocationPoolV1;
    let small = AllocationPoolV1::new(MAX_CONTEXT_BYTES - 1).unwrap();
    assert!(ContextCharge::reserve_from(MAX_CONTEXT_BYTES, Some(&small)).is_none());
    assert_eq!(small.used(), 0);
    assert!(!CONTEXT_BUSY.load(std::sync::atomic::Ordering::Acquire));
    for limit in [MAX_CONTEXT_BYTES, MAX_CONTEXT_BYTES + 1] {
        let pool = AllocationPoolV1::new(limit).unwrap();
        let credit = ContextCharge::reserve_from(MAX_CONTEXT_BYTES, Some(&pool)).unwrap();
        assert_eq!(pool.used(), MAX_CONTEXT_BYTES);
        assert!(ContextCharge::reserve_from(1, Some(&pool)).is_none());
        assert_eq!(pool.used(), MAX_CONTEXT_BYTES);
        drop(credit);
        assert_eq!(pool.used(), 0);
        assert!(!CONTEXT_BUSY.load(std::sync::atomic::Ordering::Acquire));
        assert!(ContextCharge::reserve_from(MAX_CONTEXT_BYTES + 1, Some(&pool)).is_none());
        assert_eq!(pool.used(), 0);
        assert!(ContextCharge::reserve_from(1, Some(&pool)).is_some());
        assert_eq!(pool.used(), 0);
    }
    // A real pool callback can run a scheduler between physical refund and
    // logical release. Consume its wakes while actual admission still refuses.
    fn released_before_logical_admission() {
        notify_deferred_ingress();
        crate::stream_ingress::notify_honest_stream_ingress();
        assert!(take_deferred_revision());
        assert!(crate::stream_ingress::take_revision());
        assert!(crate::stream_ingress::take_credit_ready());
        assert!(ContextCharge::reserve_from(1, None).is_none());
    }
    let pool = AllocationPoolV1::new_with_release(
        MAX_CONTEXT_BYTES,
        Some(released_before_logical_admission),
    )
    .unwrap();
    let credit = ContextCharge::reserve_from(MAX_CONTEXT_BYTES, Some(&pool)).unwrap();
    take_deferred_revision();
    crate::stream_ingress::take_revision();
    crate::stream_ingress::take_credit_ready();
    drop(credit);
    assert_eq!(pool.used(), 0);
    assert!(
        take_deferred_revision(),
        "logical release republishes deferred wake"
    );
    assert!(
        crate::stream_ingress::take_revision(),
        "logical release republishes stream wake"
    );
    assert!(crate::stream_ingress::take_credit_ready());
    assert!(!take_deferred_revision(), "wake remains coalesced");
    assert!(!crate::stream_ingress::take_revision());
    assert!(!crate::stream_ingress::take_credit_ready());
    let readmitted = ContextCharge::reserve_from(MAX_CONTEXT_BYTES, Some(&pool)).unwrap();
    drop(readmitted);
    assert_eq!(pool.used(), 0);
    eprintln!("CONTEXT-RELEASE-WAKE: actual pool callback consumed early wake; post-clear re-admission PASS");
    eprintln!("CONTEXT-PHYSICAL: original pool minus/exact/plus/logical rollback/refund PASS");
}
