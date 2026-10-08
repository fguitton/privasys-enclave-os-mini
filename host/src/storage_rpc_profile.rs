//! Opt-in HOST monotonic metadata; never response/currentness authority.
use enclave_os_common::rpc::HonestRpcIdentity;
use std::{cell::Cell, time::Instant};
const MAX_RECORDS: usize = 16384;
thread_local! {static ACTIVE:Cell<bool>=const{Cell::new(false)};static LOCK_NS:Cell<u128>=const{Cell::new(0)};}
pub(crate) fn lock_start() -> Option<Instant> {
    ACTIVE.with(|x| x.get()).then(Instant::now)
}
pub(crate) fn lock_finish(start: Option<Instant>) {
    if let Some(start) = start {
        LOCK_NS.with(|x| x.set(x.get().saturating_add(start.elapsed().as_nanos())));
    }
}
#[derive(serde::Serialize)]
struct Row {
    node: u64,
    generation: u64,
    operation: u64,
    kind: u8,
    request_frame_bytes: usize,
    response_payload_bytes: usize,
    status: i32,
    handler_ns: u128,
    db_lock_ns: u128,
    publication_ns: u128,
    consumption_observation: Option<&'static str>,
    before_publication_to_observation_upper_ns: Option<u128>,
}
pub(crate) struct Sample {
    pub identity: HonestRpcIdentity,
    pub kind: u8,
    pub request: usize,
    pub response: usize,
    pub status: i32,
    pub handler: (u128, u128),
    pub publish: Instant,
    pub end: u64,
    pub tail: u64,
    pub ok: bool,
}
pub(crate) struct Profile {
    rows: Vec<Row>,
    pending: Option<(usize, Instant, u64)>,
    censored: u64,
    published_failures: u64,
}
impl Profile {
    pub(crate) fn new() -> Self {
        Self {
            rows: Vec::new(),
            pending: None,
            censored: 0,
            published_failures: 0,
        }
    }
    pub(crate) fn observe(&mut self, tail: u64, event: &'static str) {
        if let Some((index, start, end)) = self.pending.take() {
            if tail == end {
                self.rows[index].consumption_observation = Some(event);
                self.rows[index].before_publication_to_observation_upper_ns =
                    Some(start.elapsed().as_nanos());
            }
        }
    }
    pub(crate) fn start(&self) -> Instant {
        ACTIVE.with(|x| x.set(true));
        LOCK_NS.with(|x| x.set(0));
        Instant::now()
    }
    pub(crate) fn handler_done(&self, start: Instant) -> (u128, u128) {
        ACTIVE.with(|x| x.set(false));
        (start.elapsed().as_nanos(), LOCK_NS.with(Cell::get))
    }
    pub(crate) fn record(&mut self, sample: Sample) {
        let Sample {
            identity: id,
            kind,
            request,
            response,
            status,
            handler,
            publish,
            end,
            tail,
            ok,
        } = sample;
        if !ok {
            self.published_failures = self.published_failures.saturating_add(1);
        }
        if self.rows.len() == MAX_RECORDS {
            self.censored = self.censored.saturating_add(1);
            return;
        }
        let index = self.rows.len();
        self.rows.push(Row {
            node: id.node_id,
            generation: id.node_generation,
            operation: id.operation_id,
            kind,
            request_frame_bytes: request,
            response_payload_bytes: response,
            status,
            handler_ns: handler.0,
            db_lock_ns: handler.1,
            publication_ns: publish.elapsed().as_nanos(),
            consumption_observation: if ok && tail == end {
                Some("already-consumed-before-first-probe")
            } else {
                None
            },
            before_publication_to_observation_upper_ns: None,
        });
        if ok && tail != end {
            self.pending = Some((index, publish, end));
        }
    }
    fn chunks(&self) -> Vec<serde_json::Value> {
        let chunks = self.rows.len().div_ceil(32);
        self.rows.chunks(32).enumerate().map(|(index,rows)|serde_json::json!({"chunk":index,"chunks":chunks,"records":rows,"clock":"HOST-MONOTONIC","scope":"REQUEST-BOUND-METADATA-ONLY; no payload or authority"})).collect()
    }
    fn summary(&self) -> serde_json::Value {
        serde_json::json!({"records":self.rows.len(),"chunks":self.rows.len().div_ceil(32),"censored":self.censored,"published_failures":self.published_failures,"limit":MAX_RECORDS,"clock":"HOST-MONOTONIC","scope":"join exact node/generation/op IDs to worker first/last IDs; handler includesDBlock/service; upperbound startsBEFOREencode/ringpublication andincludespublication+interveningworkerwork; next-request/shutdown observation, notexactresume; early/missing bounds UNAVAILABLE"})
    }
    pub(crate) fn report(&self) {
        for chunk in self.chunks() {
            log::info!("HONEST-WORKER-STORAGE-HOST: {}", chunk);
        }
        log::info!("HONEST-WORKER-STORAGE-HOST-SUMMARY: {}", self.summary());
    }
    #[cfg(test)]
    pub(crate) fn check(&mut self) {
        // The caller is the actual framed RocksDB dispatcher fixture.
        assert!(!self.rows.is_empty());
        assert!(self.rows.iter().any(|x| x.status == 0 && x.kind == 4));
        let chunks = self.chunks();
        let mut joined = 0;
        for (index, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk["chunk"], index);
            assert_eq!(chunk["chunks"], chunks.len());
            let rows = chunk["records"].as_array().unwrap();
            assert!(rows.len() <= 32);
            joined += rows.len();
            for row in rows {
                assert_eq!(row["node"], 3);
                assert_eq!(row["generation"], 8);
                assert_eq!(row["operation"], 51);
                assert!(row.get("payload").is_none());
            }
        }
        assert_eq!(joined, self.rows.len());
        let mut bounded = Self::new();
        let id = HonestRpcIdentity {
            role: enclave_os_common::rpc::RpcRole::Execution,
            node_id: 3,
            node_generation: 8,
            operation_id: 1,
            method: enclave_os_common::rpc::RpcMethod::WorkerStorage,
        };
        bounded.record(Sample {
            identity: id,
            kind: 0,
            request: 10,
            response: 20,
            status: 0,
            handler: (1, 1),
            publish: Instant::now(),
            end: 24,
            tail: 0,
            ok: true,
        });
        bounded.observe(0, "next-request");
        assert!(bounded.rows[0]
            .before_publication_to_observation_upper_ns
            .is_none());
        bounded.record(Sample {
            identity: id,
            kind: 0,
            request: 10,
            response: 20,
            status: 0,
            handler: (1, 1),
            publish: Instant::now(),
            end: 24,
            tail: 24,
            ok: true,
        });
        assert_eq!(
            bounded.rows[1].consumption_observation,
            Some("already-consumed-before-first-probe")
        );
        assert!(bounded.rows[1]
            .before_publication_to_observation_upper_ns
            .is_none());
        bounded.record(Sample {
            identity: id,
            kind: 0,
            request: 10,
            response: 20,
            status: 0,
            handler: (1, 1),
            publish: Instant::now(),
            end: 44,
            tail: 0,
            ok: true,
        });
        bounded.observe(44, "shutdown");
        assert_eq!(bounded.rows[2].consumption_observation, Some("shutdown"));
        assert!(bounded.rows[2]
            .before_publication_to_observation_upper_ns
            .is_some());
        bounded.record(Sample {
            identity: id,
            kind: 0,
            request: 10,
            response: 20,
            status: 0,
            handler: (1, 1),
            publish: Instant::now(),
            end: 60,
            tail: 0,
            ok: false,
        });
        assert_eq!(bounded.published_failures, 1);
        for _ in 0..MAX_RECORDS {
            bounded.record(Sample {
                identity: id,
                kind: 0,
                request: 10,
                response: 20,
                status: 0,
                handler: (1, 1),
                publish: Instant::now(),
                end: 60,
                tail: 60,
                ok: true,
            });
        }
        assert_eq!(bounded.rows.len(), MAX_RECORDS);
        assert_eq!(bounded.censored, 4);
        assert_eq!(bounded.summary()["censored"], 4);
        println!("WORKER-STORAGE-HOST-PROFILE: actualframedDB/identity/chunks/cap/missing/early/shutdown/failure PASS");
    }
}
