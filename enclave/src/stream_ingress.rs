//! Optional bounded input ownership. Tokens and header/body bytes grant no right.
use crate::HonestIngressResponse;
use enclave_os_common::{modules::RequestContext, protocol::HttpRequest};

pub const MAX_STREAM_INGRESS_SESSIONS: usize = 16;
pub const MAX_STREAM_INGRESS_FRAGMENT: usize = 64 * 1024;
/// An adopter owns separately charged body resources. Every callback is invoked
/// outside Mini STATE, never inside a selector or TLS/session lock. Drop must not
/// wait for a peer; cancellation/destruction likewise happens outside STATE.
/// Pending leaves the complete supplied fragment logically unconsumed. The
/// transport retains it exactly once until an actual stage-credit wakeup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HonestStreamIngressPush {
    Consumed,
    Pending,
}
pub trait HonestStreamIngressReceiver: Send {
    fn push(&mut self, bytes: &[u8], context: &RequestContext) -> Result<(), ()>;
    fn push_with_backpressure(
        &mut self,
        bytes: &[u8],
        context: &RequestContext,
    ) -> Result<HonestStreamIngressPush, ()> {
        self.push(bytes, context)
            .map(|()| HonestStreamIngressPush::Consumed)
    }
    fn finish(self: Box<Self>, context: &RequestContext) -> HonestIngressResponse;
}
/// Eligibility only: no state access, allocation, I/O, or application authority.
pub type HonestStreamIngressEligible = fn(&HttpRequest, usize) -> bool;
/// Called outside STATE after a fixed session marker has been reserved. The
/// adopter must authorize current header/context and charge all body allocations
/// before constructing the receiver. Refusal closes this claimed request.
pub type HonestStreamIngressBegin =
    fn(
        &HttpRequest,
        usize,
        &RequestContext,
    ) -> Result<Box<dyn HonestStreamIngressReceiver>, HonestIngressResponse>;
pub(crate) type Hooks = (HonestStreamIngressEligible, HonestStreamIngressBegin);

pub(crate) struct SlotCharge {
    _allocation: Option<crate::ratls::session::StreamAllocation>,
    metadata: Option<enclave_os_common::allocation::AllocationLeaseV1>,
}
#[derive(Clone)]
pub(crate) struct SlotLease(Option<std::sync::Arc<SlotCharge>>);
impl SlotLease {
    fn same(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(self.0.as_ref().unwrap(), other.0.as_ref().unwrap())
    }
}
impl Drop for SlotLease {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            drop(std::sync::Arc::into_inner(owner));
        }
    }
}
static OWNED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
impl SlotCharge {
    pub(crate) fn metadata_bytes() -> Option<usize> {
        enclave_os_common::allocation::shared_allocation_bytes::<Self>()
    }
    #[cfg(any(test, not(any(target_env = "sgx", target_vendor = "teaclave"))))]
    pub(crate) fn reserve() -> Option<SlotLease> {
        Self::reserve_inner(None, None)
    }
    fn reserve_inner(
        allocation: Option<crate::ratls::session::StreamAllocation>,
        metadata: Option<enclave_os_common::allocation::AllocationLeaseV1>,
    ) -> Option<SlotLease> {
        OWNED
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |n| (n < MAX_STREAM_INGRESS_SESSIONS).then_some(n + 1),
            )
            .ok()
            .map(|_| {
                SlotLease(Some(std::sync::Arc::new(Self {
                    _allocation: allocation,
                    metadata,
                })))
            })
    }
}
#[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
impl SlotCharge {
    // Count remains the existing logical marker policy. Allocation is a shared
    // actual session/fragment owner, retained through terminal receiver teardown.
    pub(crate) fn reserve_for_session(
        session: &mut crate::ratls::session::RaTlsSession,
    ) -> Option<SlotLease> {
        let allocation = session.reserve_stream_allocation().ok()?;
        Self::reserve_with_allocation(allocation)
    }
}
impl SlotCharge {
    pub(crate) fn reserve_with_allocation(
        allocation: crate::ratls::session::StreamAllocation,
    ) -> Option<SlotLease> {
        if allocation.bytes() < crate::ratls::session::RaTlsSession::stream_allocation_bytes()? {
            return None;
        }
        let metadata = allocation.reserve_slot(Self::metadata_bytes()?)?;
        let slot = Self::reserve_inner(Some(allocation), Some(metadata))?;
        if let Some(credit) = &slot.0.as_ref()?.metadata {
            credit.activate_release_notification();
        }
        Some(slot)
    }
}
impl Drop for SlotCharge {
    fn drop(&mut self) {
        OWNED.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}
pub(crate) struct ChargedReceiver {
    pub value: Box<dyn HonestStreamIngressReceiver>,
    // Destruction of the receiver precedes its retained final slot alias.
    pub _lease: SlotLease,
}
pub(crate) struct Slot {
    pub nonce: u64,
    pub generation: u64,
    pub binding: [u8; 32],
    pub header: Option<crate::ratls::session::PaidHttpRequest>,
    pub receiver: Option<ChargedReceiver>,
    pub remaining: usize,
    pub fragment: Vec<u8>,
    pub parked: bool,
    pub length: usize,
    pub close: bool,
    pub started: std::time::Instant,
    // Actual fragment/context/receiver fields die before the final credit alias.
    pub lease: SlotLease,
}
/// The fixed session marker remains reserved during this move-only work. The
/// actual TLS context is checked again before committing any completion.
pub(crate) struct Work {
    pub connection: u32,
    pub nonce: u64,
    pub generation: u64,
    pub binding: [u8; 32],
    pub context: Option<RequestContext>,
    pub _context_charge: Option<crate::deferred_ingress::ContextCharge>,
    pub header: Option<crate::ratls::session::PaidHttpRequest>,
    pub receiver: Option<Box<dyn HonestStreamIngressReceiver>>,
    pub bytes: Vec<u8>,
    pub length: usize,
    pub remaining: usize,
    pub pending: bool,
    // Release the transport charge after receiver/body/context destruction.
    pub lease: SlotLease,
}
/// Restore one exact selected fragment after the caller's fresh TLS/nonce join.
/// This private accounting helper performs no application authorization or I/O.
pub(crate) fn retain_work(slot: &mut Slot, work: &mut Work) -> Result<(), ()> {
    if slot.nonce != work.nonce
        || slot.generation != work.generation
        || slot.binding != work.binding
        || slot.receiver.is_some()
        || !slot.lease.same(&work.lease)
        || !slot.fragment.is_empty()
        || slot.remaining.checked_sub(work.bytes.len()) != Some(work.remaining)
        || work.bytes.len() > MAX_STREAM_INGRESS_FRAGMENT
        || (work.pending && work.bytes.is_empty())
    {
        return Err(());
    }
    let receiver = work.receiver.take().ok_or(())?;
    slot.receiver = Some(ChargedReceiver {
        value: receiver,
        _lease: work.lease.clone(),
    });
    slot.parked = work.pending;
    if work.pending {
        slot.fragment = std::mem::take(&mut work.bytes);
    } else {
        slot.remaining = work.remaining;
    }
    Ok(())
}
impl Slot {
    pub(crate) fn credit_ready(&mut self) {
        self.parked = false;
    }
}
static CREDIT_READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Notify after an actual adopter stage-completion/credit/context event. This
/// grants no consumption, authority or lease extension. The caller's existing
/// control wake delivers the event; transport timers never retry parked work.
pub fn notify_honest_stream_ingress() {
    CREDIT_READY.store(true, std::sync::atomic::Ordering::Release);
    notify();
}
pub(crate) fn take_credit_ready() -> bool {
    CREDIT_READY.swap(false, std::sync::atomic::Ordering::AcqRel)
}
static REVISION: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(crate) fn notify() {
    REVISION.store(true, std::sync::atomic::Ordering::Release);
}
pub(crate) fn take_revision() -> bool {
    REVISION.swap(false, std::sync::atomic::Ordering::AcqRel)
}
static TERMINAL: std::sync::Mutex<[Option<ChargedReceiver>; MAX_STREAM_INGRESS_SESSIONS]> =
    std::sync::Mutex::new([const { None }; MAX_STREAM_INGRESS_SESSIONS]);
fn handoff_terminal(receiver: ChargedReceiver) {
    let mut slots = TERMINAL.lock().unwrap_or_else(|e| e.into_inner());
    *slots
        .iter_mut()
        .find(|slot| slot.is_none())
        .expect("fixed input ownership includes terminal debt") = Some(receiver);
    notify();
}
pub(crate) fn take_terminal() -> Option<ChargedReceiver> {
    TERMINAL
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter_mut()
        .find_map(Option::take)
}
pub(crate) fn terminal_count() -> usize {
    TERMINAL
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .flatten()
        .count()
}
#[derive(Default)]
pub(crate) struct CancellationOwner {
    pub pending: crate::ratls::session::ordered_map::OrderedMap<u32, Slot>,
    pub cancelled: crate::ratls::session::cancellation::Queue<ChargedReceiver>,
}
impl CancellationOwner {
    pub(crate) fn invalidate(&mut self, id: u32) {
        if let Some(slot) = self.pending.remove(&id) {
            if let Some(receiver) = slot.receiver {
                self.cancelled.push_back(receiver);
            }
            notify();
        }
    }
    pub(crate) fn prepare_from(
        &mut self,
        pool: &std::sync::Arc<enclave_os_common::allocation::AllocationPoolV1>,
    ) -> bool {
        if self.pending.prepared_for(pool, MAX_STREAM_INGRESS_SESSIONS)
            && self
                .cancelled
                .prepared_for(pool, MAX_STREAM_INGRESS_SESSIONS)
        {
            return true;
        }
        if self.pending.has_admission() || self.cancelled.has_admission() {
            return false;
        }
        let mut pending = crate::ratls::session::ordered_map::OrderedMap::default();
        if pending
            .prepare_from(pool, MAX_STREAM_INGRESS_SESSIONS)
            .is_err()
        {
            return false;
        }
        let Some(cancelled) =
            crate::ratls::session::cancellation::Queue::new(pool, MAX_STREAM_INGRESS_SESSIONS)
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
    pub(crate) fn take_receivers(&mut self) -> Drain {
        Drain {
            pending: std::mem::take(&mut self.pending).into_iter(),
            cancelled: std::mem::take(&mut self.cancelled).into_iter(),
        }
    }
}
pub(crate) struct Drain {
    pending: crate::ratls::session::ordered_map::Entries<u32, Slot>,
    cancelled: crate::ratls::session::cancellation::Drain<ChargedReceiver>,
}
impl Iterator for Drain {
    type Item = ChargedReceiver;
    fn next(&mut self) -> Option<ChargedReceiver> {
        for (_, slot) in self.pending.by_ref() {
            if let Some(value) = slot.receiver {
                return Some(value);
            }
        }
        self.cancelled.next()
    }
}

impl Drop for CancellationOwner {
    fn drop(&mut self) {
        for receiver in self.take_receivers() {
            handoff_terminal(receiver);
        }
    }
}
#[cfg(test)]
pub(crate) fn check_slot_ownership() {
    use enclave_os_common::allocation::AllocationPoolV1;
    let bytes = core::alloc::Layout::array::<(u32, Slot)>(MAX_STREAM_INGRESS_SESSIONS)
        .unwrap()
        .size()
        + crate::ratls::session::cancellation::Queue::<ChargedReceiver>::bytes(
            MAX_STREAM_INGRESS_SESSIONS,
        )
        .unwrap();
    for maximum in [bytes - 1, bytes, bytes + 1] {
        let pool = AllocationPoolV1::new(maximum).unwrap();
        let mut owner = CancellationOwner::default();
        assert_eq!(owner.prepare_from(&pool), maximum >= bytes);
        assert_eq!(pool.used(), if maximum >= bytes { bytes } else { 0 });
        if maximum >= bytes {
            let foreign = AllocationPoolV1::new(bytes).unwrap();
            assert!(!owner.prepare_from(&foreign));
            assert_eq!(foreign.used(), 0);
            // Extracting an empty drain still owns both allocated backings.
            let drained = owner.take_receivers();
            drop(owner);
            assert_eq!(pool.used(), bytes);
            drop(drained);
        } else {
            drop(owner);
        }
        assert_eq!(pool.used(), 0);
    }
    let mut slots = Vec::new();
    for _ in 0..MAX_STREAM_INGRESS_SESSIONS {
        slots.push(SlotCharge::reserve().unwrap());
    }
    assert!(SlotCharge::reserve().is_none());
    // Extraction clones the same charged logical claim. Removing its session
    // marker cannot release credit while outside-STATE work still owns it.
    let work = slots[0].clone();
    drop(slots.remove(0));
    assert!(SlotCharge::reserve().is_none());
    drop(work);
    slots.push(SlotCharge::reserve().unwrap());
    assert!(SlotCharge::reserve().is_none());
    drop(slots);
    let full: Vec<_> = (0..MAX_STREAM_INGRESS_SESSIONS)
        .map(|_| SlotCharge::reserve().unwrap())
        .collect();
    drop(full);
    // Test the actual Work destructor ordering, not only a cloned charge.
    let slots: Vec<_> = (0..MAX_STREAM_INGRESS_SESSIONS - 1)
        .map(|_| SlotCharge::reserve().unwrap())
        .collect();
    let observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let work = Work {
        connection: 1,
        nonce: 1,
        generation: 1,
        binding: [0; 32],
        context: None,
        _context_charge: None,
        header: None,
        receiver: Some(Box::new(ChargedDropCheck(observed.clone()))),
        bytes: vec![0; MAX_STREAM_INGRESS_FRAGMENT],
        length: 1,
        remaining: 1,
        pending: false,
        lease: SlotCharge::reserve().unwrap(),
    };
    drop(work);
    assert!(observed.load(std::sync::atomic::Ordering::Acquire));
    let replacement =
        SlotCharge::reserve().expect("credit released only after receiver destructor");
    drop(replacement);
    // The real invalidation owner and destructor retain the receiver while
    // STATE is held; terminal release and the final logical alias are outside.
    let pool = AllocationPoolV1::new(bytes).unwrap();
    let mut owner = CancellationOwner::default();
    assert!(owner.prepare_from(&pool));
    let lease = SlotCharge::reserve().unwrap();
    let retained = lease.clone();
    observed.store(false, std::sync::atomic::Ordering::Release);
    owner.pending.insert_prepared(
        1,
        Slot {
            nonce: 1,
            generation: 1,
            binding: [0; 32],
            header: None,
            receiver: Some(ChargedReceiver {
                value: Box::new(ChargedDropCheck(observed.clone())),
                _lease: lease.clone(),
            }),
            remaining: 0,
            fragment: Vec::new(),
            parked: false,
            length: 0,
            close: false,
            started: std::time::Instant::now(),
            lease,
        },
    );
    owner.invalidate(1);
    assert_eq!(owner.pending.len(), 0);
    assert_eq!(owner.cancelled.len(), 1);
    owner.invalidate(1);
    assert_eq!(
        owner.cancelled.len(),
        1,
        "same invalidation never duplicates debt"
    );
    assert_eq!(
        pool.used(),
        bytes,
        "invalidation neither reallocates nor releases backing"
    );
    let state = std::sync::Mutex::new(());
    let state_guard = state.lock().unwrap();
    drop(owner);
    assert_eq!(
        pool.used(),
        0,
        "drained metadata dies before its final credit"
    );
    assert!(!observed.load(std::sync::atomic::Ordering::Acquire));
    assert_eq!(terminal_count(), 1);
    assert!(SlotCharge::reserve().is_none());
    drop(state_guard);
    drop(take_terminal().unwrap());
    assert!(observed.load(std::sync::atomic::Ordering::Acquire));
    assert!(
        SlotCharge::reserve().is_none(),
        "outside-STATE retained alias still owns claim"
    );
    drop(retained);
    drop(SlotCharge::reserve().expect("last receiver alias releases original claim"));
    drop(slots);
}

/// Actual adopter phase shared by the control pump and native TLS fixtures.
/// Caller owns this move-only work after releasing transport STATE.
pub(crate) fn run_work(
    begin: HonestStreamIngressBegin,
    work: &mut Work,
) -> Option<HonestIngressResponse> {
    let mut response = None;
    work.pending = false;
    if let Some(context) = work.context.as_ref() {
        if let Some(header) = work.header.take() {
            match begin(&header, work.length, context) {
                Ok(receiver) => work.receiver = Some(receiver),
                Err(refused) => response = Some(refused),
            }
        } else if let Some(mut receiver) = work.receiver.take() {
            match receiver.push_with_backpressure(&work.bytes, context) {
                Err(()) => {
                    response = Some(crate::HonestIngressResponse {
                        status: 403,
                        content_type: "application/octet-stream",
                        body: Vec::new().into(),
                    })
                }
                Ok(HonestStreamIngressPush::Pending) => {
                    work.pending = true;
                    work.receiver = Some(receiver);
                }
                Ok(HonestStreamIngressPush::Consumed) if work.remaining == 0 => {
                    response = Some(receiver.finish(context))
                }
                Ok(HonestStreamIngressPush::Consumed) => work.receiver = Some(receiver),
            }
        }
    }
    response
}

#[cfg(test)]
struct ChargedDropCheck(std::sync::Arc<std::sync::atomic::AtomicBool>);
#[cfg(test)]
impl Drop for ChargedDropCheck {
    fn drop(&mut self) {
        assert!(
            SlotCharge::reserve().is_none(),
            "receiver destruction must precede last Work charge release"
        );
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}
#[cfg(test)]
impl HonestStreamIngressReceiver for ChargedDropCheck {
    fn push(&mut self, _: &[u8], _: &RequestContext) -> Result<(), ()> {
        unreachable!()
    }
    fn finish(self: Box<Self>, _: &RequestContext) -> HonestIngressResponse {
        unreachable!()
    }
}
