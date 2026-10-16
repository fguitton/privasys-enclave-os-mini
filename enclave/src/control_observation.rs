//! Diagnostic timestamps only. No readiness, time or scheduling authority.
//! TLS parsing and public replay share the control TCS. Parsed-ready excludes
//! residence before parsing. A transport trigger is not an authenticated request.
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

static REQUESTS: AtomicU64 = AtomicU64::new(0);
static TRANSPORTS: AtomicU64 = AtomicU64::new(0);
std::thread_local! {
    static REQUEST: Cell<Option<ParsedRequest>> = const { Cell::new(None) };
    static TRANSPORT: Cell<Option<(u32, u64)>> = const { Cell::new(None) };
}
/// Host CLOCK_MONOTONIC milliseconds, untrusted, rounded down. None is a
/// failed observation, never replaced by zero or a different clock domain.
pub fn now() -> Option<u64> {
    crate::ocall::untrusted_monotonic_millis().ok()
}
fn next(counter: &AtomicU64) -> Option<u64> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .ok()
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedRequest {
    pub sequence: Option<u64>,
    pub connection: u32,
    pub parsed_ready_ms: Option<u64>,
    /// The synchronous feed during which parsing completed, if any. Queued
    /// parser turns have no trigger; absence must not be imputed from another request.
    pub trigger_transport: Option<u64>,
}
/// Stack-scoped diagnostic context; dropped before another parsed request.
/// The adopter must validate route, typed operation and current TLS binding
/// before treating this candidate as part of its signed-operation population.
pub struct ParsedGuard(Option<ParsedRequest>);
impl ParsedGuard {
    pub fn begin(connection: u32) -> Self {
        let parsed_ready_ms = now();
        let trigger_transport =
            TRANSPORT.with(|slot| slot.get().filter(|v| v.0 == connection).map(|v| v.1));
        let value = ParsedRequest {
            sequence: next(&REQUESTS),
            connection,
            parsed_ready_ms,
            trigger_transport,
        };
        Self(REQUEST.with(|slot| slot.replace(Some(value))))
    }
}
impl Drop for ParsedGuard {
    fn drop(&mut self) {
        REQUEST.with(|slot| slot.set(self.0));
    }
}
pub fn current(connection: u32) -> Option<ParsedRequest> {
    REQUEST.with(|slot| slot.get().filter(|value| value.connection == connection))
}
pub struct TransportGuard(Option<(u32, u64)>);
impl TransportGuard {
    /// Called immediately after consuming the original SPSC message. FIFO
    /// sequence joins the host publication bracket; no channel bytes change.
    pub fn consumed(message: &[u8]) -> Self {
        let consumed_ms = now();
        let sequence = next(&TRANSPORTS);
        let decoded = enclave_os_common::channel::decode_channel_msg(message);
        let connection = decoded.as_ref().map(|v| v.1);
        let kind = decoded.as_ref().map(|v| v.0 as u8);
        enclave_os_common::enclave_log_info!(
            "HONEST-RECOVERY-TRANSPORT: {}",
            serde_json::json!({
            "event":"consumed", "sequence":sequence,"connection":connection,"kind":kind,
            "bytes":message.len(),"consumed_ms":consumed_ms,"clock":"HOST-CLOCK-MONOTONIC-MS",
            "semantic_readiness":false})
        );
        let value = connection.zip(sequence);
        Self(TRANSPORT.with(|slot| slot.replace(value)))
    }
}
impl Drop for TransportGuard {
    fn drop(&mut self) {
        TRANSPORT.with(|slot| slot.set(self.0));
    }
}
