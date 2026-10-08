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
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum HonestStreamIngressPush { Consumed,Pending }
pub trait HonestStreamIngressReceiver: Send {
    fn push(&mut self,bytes:&[u8],context:&RequestContext)->Result<(),()>;
    fn push_with_backpressure(&mut self,bytes:&[u8],context:&RequestContext)->Result<HonestStreamIngressPush,()> {
        self.push(bytes,context).map(|()|HonestStreamIngressPush::Consumed)
    }
    fn finish(self:Box<Self>,context:&RequestContext)->HonestIngressResponse;
}
/// Eligibility only: no state access, allocation, I/O, or application authority.
pub type HonestStreamIngressEligible=fn(&HttpRequest,usize)->bool;
/// Called outside STATE after a fixed session marker has been reserved. The
/// adopter must authorize current header/context and charge all body allocations
/// before constructing the receiver. Refusal closes this claimed request.
pub type HonestStreamIngressBegin=fn(&HttpRequest,usize,&RequestContext)->Result<Box<dyn HonestStreamIngressReceiver>,HonestIngressResponse>;
pub(crate) type Hooks=(HonestStreamIngressEligible,HonestStreamIngressBegin);

pub(crate) struct SlotCharge;
static OWNED:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
impl SlotCharge {
    pub(crate) fn reserve()->Option<std::sync::Arc<Self>> {
        OWNED.fetch_update(std::sync::atomic::Ordering::AcqRel,std::sync::atomic::Ordering::Acquire,|n|(n<MAX_STREAM_INGRESS_SESSIONS).then_some(n+1)).ok().map(|_|std::sync::Arc::new(Self))
    }
}
impl Drop for SlotCharge{fn drop(&mut self){OWNED.fetch_sub(1,std::sync::atomic::Ordering::AcqRel);}}
pub(crate) struct ChargedReceiver {pub value:Box<dyn HonestStreamIngressReceiver>,pub lease:std::sync::Arc<SlotCharge>}
pub(crate) struct Slot {
    pub lease:std::sync::Arc<SlotCharge>,
    pub nonce:u64,
    pub generation:u64,
    pub binding:[u8;32],
    pub header:Option<HttpRequest>,
    pub receiver:Option<ChargedReceiver>,
    pub remaining:usize,
    pub fragment:Vec<u8>,
    pub parked:bool,
    pub length:usize,
    pub close:bool,
    pub started:std::time::Instant,
}
/// The fixed session marker remains reserved during this move-only work. The
/// actual TLS context is checked again before committing any completion.
pub(crate) struct Work {
    pub connection:u32,
    pub nonce:u64,
    pub generation:u64,
    pub binding:[u8;32],
    pub context:Option<RequestContext>,
    pub context_charge:Option<crate::deferred_ingress::ContextCharge>,
    pub header:Option<HttpRequest>,
    pub receiver:Option<Box<dyn HonestStreamIngressReceiver>>,
    pub bytes:Vec<u8>,
    pub length:usize,
    pub remaining:usize,
    pub pending:bool,
    // Release the transport charge after receiver/body/context destruction.
    pub lease:std::sync::Arc<SlotCharge>,
}
/// Restore one exact selected fragment after the caller's fresh TLS/nonce join.
/// This private accounting helper performs no application authorization or I/O.
pub(crate) fn retain_work(slot:&mut Slot,work:&mut Work)->Result<(),()> {
    if slot.nonce!=work.nonce || slot.generation!=work.generation || slot.binding!=work.binding || slot.receiver.is_some()
        || !std::sync::Arc::ptr_eq(&slot.lease,&work.lease) || !slot.fragment.is_empty()
        || slot.remaining.checked_sub(work.bytes.len())!=Some(work.remaining)
        || work.bytes.len()>MAX_STREAM_INGRESS_FRAGMENT || (work.pending && work.bytes.is_empty()) {return Err(());}
    let receiver=work.receiver.take().ok_or(())?;
    slot.receiver=Some(ChargedReceiver{value:receiver,lease:work.lease.clone()});
    slot.parked=work.pending;
    if work.pending{slot.fragment=std::mem::take(&mut work.bytes);}else{slot.remaining=work.remaining;}
    Ok(())
}
impl Slot {
    pub(crate) fn credit_ready(&mut self){self.parked=false;}
}
static CREDIT_READY:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
/// Notify after an actual adopter stage-completion/credit/context event. This
/// grants no consumption, authority or lease extension. The caller's existing
/// control wake delivers the event; transport timers never retry parked work.
pub fn notify_honest_stream_ingress(){CREDIT_READY.store(true,std::sync::atomic::Ordering::Release);notify();}
pub(crate) fn take_credit_ready()->bool{CREDIT_READY.swap(false,std::sync::atomic::Ordering::AcqRel)}
static REVISION:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
pub(crate) fn notify(){REVISION.store(true,std::sync::atomic::Ordering::Release);}
pub(crate) fn take_revision()->bool{REVISION.swap(false,std::sync::atomic::Ordering::AcqRel)}
static TERMINAL:std::sync::Mutex<[Option<ChargedReceiver>;MAX_STREAM_INGRESS_SESSIONS]>=std::sync::Mutex::new([const{None};MAX_STREAM_INGRESS_SESSIONS]);
fn handoff_terminal(receiver:ChargedReceiver){
    let mut slots=TERMINAL.lock().unwrap_or_else(|e|e.into_inner());
    *slots.iter_mut().find(|slot|slot.is_none()).expect("fixed input ownership includes terminal debt")=Some(receiver);notify();
}
pub(crate) fn take_terminal()->Option<ChargedReceiver>{TERMINAL.lock().unwrap_or_else(|e|e.into_inner()).iter_mut().find_map(Option::take)}
pub(crate) fn terminal_count()->usize{TERMINAL.lock().unwrap_or_else(|e|e.into_inner()).iter().flatten().count()}
#[derive(Default)]
pub(crate) struct CancellationOwner {
    pub pending:std::collections::BTreeMap<u32,Slot>,
    pub cancelled:std::collections::VecDeque<ChargedReceiver>,
}
impl CancellationOwner{
    pub fn take_receivers(&mut self)->Vec<ChargedReceiver>{
        std::mem::take(&mut self.pending).into_values().filter_map(|s|s.receiver).chain(self.cancelled.drain(..)).collect()
    }
}
impl Drop for CancellationOwner{
    fn drop(&mut self){for receiver in self.take_receivers(){handoff_terminal(receiver);}}
}
#[cfg(test)]
pub(crate) fn check_slot_ownership(){
    let mut slots=Vec::new();for _ in 0..MAX_STREAM_INGRESS_SESSIONS{slots.push(SlotCharge::reserve().unwrap());}
    assert!(SlotCharge::reserve().is_none());
    // Extraction clones the same charged logical claim. Removing its session
    // marker cannot release credit while outside-STATE work still owns it.
    let work=slots[0].clone();drop(slots.remove(0));
    assert!(SlotCharge::reserve().is_none());
    drop(work);slots.push(SlotCharge::reserve().unwrap());
    assert!(SlotCharge::reserve().is_none());drop(slots);
    let full:Vec<_>=(0..MAX_STREAM_INGRESS_SESSIONS).map(|_|SlotCharge::reserve().unwrap()).collect();drop(full);
    // Test the actual Work destructor ordering, not only a cloned charge.
    let slots:Vec<_>=(0..MAX_STREAM_INGRESS_SESSIONS-1).map(|_|SlotCharge::reserve().unwrap()).collect();
    let observed=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let work=Work{connection:1,nonce:1,generation:1,binding:[0;32],context:None,context_charge:None,header:None,receiver:Some(Box::new(ChargedDropCheck(observed.clone()))),bytes:vec![0;MAX_STREAM_INGRESS_FRAGMENT],length:1,remaining:1,pending:false,lease:SlotCharge::reserve().unwrap()};
    drop(work);assert!(observed.load(std::sync::atomic::Ordering::Acquire));
    let replacement=SlotCharge::reserve().expect("credit released only after receiver destructor");drop(replacement);drop(slots);

}

/// Actual adopter phase shared by the control pump and native TLS fixtures.
/// Caller owns this move-only work after releasing transport STATE.
pub(crate) fn run_work(begin:HonestStreamIngressBegin,work:&mut Work)->Option<HonestIngressResponse>{
let mut response=None;work.pending=false;
        if let Some(context)=work.context.as_ref() {
            if let Some(header)=work.header.take() {
                match begin(&header,work.length,context){Ok(receiver)=>work.receiver=Some(receiver),Err(refused)=>response=Some(refused)}
            }else if let Some(mut receiver)=work.receiver.take() {
                match receiver.push_with_backpressure(&work.bytes,context) {
                    Err(())=>response=Some(crate::HonestIngressResponse{status:403,content_type:"application/octet-stream",body:Vec::new().into()}),
                    Ok(HonestStreamIngressPush::Pending)=>{work.pending=true;work.receiver=Some(receiver);},
                    Ok(HonestStreamIngressPush::Consumed) if work.remaining==0=>response=Some(receiver.finish(context)),
                    Ok(HonestStreamIngressPush::Consumed)=>work.receiver=Some(receiver),
                }
            }
        }
    response
}

#[cfg(test)]
struct ChargedDropCheck(std::sync::Arc<std::sync::atomic::AtomicBool>);
#[cfg(test)]
impl Drop for ChargedDropCheck {
    fn drop(&mut self){assert!(SlotCharge::reserve().is_none(),"receiver destruction must precede last Work charge release");self.0.store(true,std::sync::atomic::Ordering::Release);}
}
#[cfg(test)]
impl HonestStreamIngressReceiver for ChargedDropCheck {
    fn push(&mut self,_:&[u8],_:&RequestContext)->Result<(),()>{unreachable!()}
    fn finish(self:Box<Self>,_:&RequestContext)->HonestIngressResponse{unreachable!()}
}
