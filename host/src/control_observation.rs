//! Untrusted SPSC publication brackets, not HTTP request readiness.
use std::sync::atomic::{AtomicU64, Ordering};
static SENT: AtomicU64 = AtomicU64::new(0);
fn now() -> Option<u64> {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) } != 0
        || t.tv_nsec < 0
        || t.tv_nsec >= 1_000_000_000
    {
        return None;
    }
    u64::try_from(t.tv_sec)
        .ok()?
        .checked_mul(1000)?
        .checked_add(u64::try_from(t.tv_nsec).ok()? / 1_000_000)
}
pub struct Publication(Option<u64>);
impl Publication {
    pub fn begin() -> Self {
        Self(now())
    }
    /// The atomic publication occurred within this bracket. Consumption may
    /// precede the upper endpoint; never subtract upper from consumption blindly.
    pub fn sent(self, message: &[u8]) {
        let after_ms = now();
        let sequence = SENT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .ok();
        let decoded = enclave_os_common::channel::decode_channel_msg(message);
        log::info!(
            "HONEST-RECOVERY-TRANSPORT: {}",
            serde_json::json!({
            "event":"published", "sequence":sequence,"connection":decoded.as_ref().map(|v|v.1),
            "kind":decoded.as_ref().map(|v|v.0 as u8),"bytes":message.len(),
            "publication_before_ms":self.0,"publication_after_ms":after_ms,
            "clock":"HOST-CLOCK-MONOTONIC-MS","semantic_readiness":false})
        );
    }
}
