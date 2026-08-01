// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! RocksDB-backed encrypted KV store with per-app table isolation.
//!
//! Each "table" maps to a RocksDB column family.  Tables are created
//! on first use and persisted across restarts.  The host stores opaque
//! ciphertext – all encryption/decryption happens inside the enclave.

use anyhow::{Context, Result};
use enclave_os_common::rpc::{
    encode_persist_raft_ready_batch, PersistRaftReadyBatch, RaftReadyRecordKind,
};
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, WriteOptions, DB};
use std::sync::{Mutex, OnceLock};

static DB_INSTANCE: OnceLock<Mutex<DB>> = OnceLock::new();

/// Shared options for column families.
fn cf_opts() -> Options {
    let mut opts = Options::default();
    opts.optimize_for_point_lookup(4); // 4 MiB block-cache per CF
    opts
}

/// Open (or create) the RocksDB database at `path`.
///
/// All existing column families are opened automatically so that tables
/// created in previous runs survive restarts.
pub fn init(path: &str) -> Result<()> {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    opts.set_max_open_files(256);
    opts.set_write_buffer_size(16 * 1024 * 1024); // 16 MiB

    // Discover existing column families (returns at least ["default"]).
    let cfs = DB::list_cf(&opts, path).unwrap_or_else(|_| vec!["default".to_string()]);

    let cf_descriptors: Vec<ColumnFamilyDescriptor> = cfs
        .iter()
        .map(|name| ColumnFamilyDescriptor::new(name, cf_opts()))
        .collect();

    let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)
        .with_context(|| format!("Failed to open RocksDB at {}", path))?;

    DB_INSTANCE
        .set(Mutex::new(db))
        .map_err(|_| anyhow::anyhow!("KV store already initialised"))?;
    Ok(())
}

/// Get a lock on the shared DB handle.
fn db() -> std::sync::MutexGuard<'static, DB> {
    DB_INSTANCE
        .get()
        .expect("KV store not initialised")
        .lock()
        .expect("KV store lock poisoned")
}

/// Ensure a column family exists, creating it if necessary.
fn ensure_cf(db: &mut DB, table: &str) {
    if db.cf_handle(table).is_none() {
        let _ = db.create_cf(table, &cf_opts());
    }
}

/// Store an encrypted key-value pair in the given table.
pub fn put(table: &str, enc_key: &[u8], enc_val: &[u8]) -> Result<()> {
    let mut db = db();
    ensure_cf(&mut db, table);
    let cf = db.cf_handle(table).unwrap();
    db.put_cf(&cf, enc_key, enc_val)
        .context("RocksDB put_cf failed")
}

/// Retrieve an encrypted value by encrypted key from the given table.
/// Returns `Ok(None)` if the key is not found.
pub fn get(table: &str, enc_key: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut db = db();
    ensure_cf(&mut db, table);
    let cf = db.cf_handle(table).unwrap();
    db.get_cf(&cf, enc_key).context("RocksDB get_cf failed")
}

/// Delete an entry by encrypted key from the given table.
/// Returns `Ok(true)` if the key existed.
pub fn delete(table: &str, enc_key: &[u8]) -> Result<bool> {
    let mut db = db();
    ensure_cf(&mut db, table);
    let cf = db.cf_handle(table).unwrap();
    let existed = db
        .get_cf(&cf, enc_key)
        .context("RocksDB get_cf (before delete) failed")?
        .is_some();
    if existed {
        db.delete_cf(&cf, enc_key)
            .context("RocksDB delete_cf failed")?;
    }
    Ok(existed)
}

/// Outcome of one predecessor-bound synchronous Ready batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaftReadyPersistenceResult {
    Persisted { batch_id: u64, durable_id: u64 },
    Conflict,
}

fn raft_ready_prefix(node_id: u64, node_generation: u64) -> Vec<u8> {
    let mut key = b"honest-s1/ready/v1/".to_vec();
    key.extend_from_slice(&node_id.to_be_bytes());
    key.extend_from_slice(&node_generation.to_be_bytes());
    key.push(b'/');
    key
}

fn raft_ready_meta_key(prefix: &[u8]) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(b"current");
    key
}

fn raft_ready_batch_key(prefix: &[u8], batch_id: u64) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(b"batch/");
    key.extend_from_slice(&batch_id.to_be_bytes());
    key
}

fn raft_ready_record_key(prefix: &[u8], kind: RaftReadyRecordKind, record_key: &[u8]) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(b"record/");
    key.push(kind as u8);
    key.push(b'/');
    key.extend_from_slice(record_key);
    key
}

fn read_durable_id(db: &DB, key: &[u8]) -> Result<u64> {
    let Some(bytes) = db.get(key).context("RocksDB Ready metadata read failed")? else {
        return Ok(0);
    };
    if bytes.len() != 8 {
        anyhow::bail!("RocksDB Ready metadata has an invalid durable ID");
    }
    Ok(u64::from_be_bytes(bytes.as_slice().try_into().map_err(
        |_| anyhow::anyhow!("invalid Ready durable ID"),
    )?))
}

/// Persist one canonical encrypted/authenticated Ready batch with a single
/// synchronous RocksDB `WriteBatch`.
///
/// A matching replay is accepted only while that batch remains the current
/// durable tip. A changed replay or wrong predecessor writes nothing.
pub fn persist_raft_ready_batch_on_db(
    db: &DB,
    request: &PersistRaftReadyBatch,
) -> Result<RaftReadyPersistenceResult> {
    let canonical = encode_persist_raft_ready_batch(request)
        .map_err(|error| anyhow::anyhow!("invalid Ready batch: {error:?}"))?;
    let prefix = raft_ready_prefix(request.node_id, request.node_generation);
    let meta_key = raft_ready_meta_key(&prefix);
    let batch_key = raft_ready_batch_key(&prefix, request.batch_id);
    let current = read_durable_id(db, &meta_key)?;

    if let Some(previous) = db
        .get(&batch_key)
        .context("RocksDB Ready replay read failed")?
    {
        if previous == canonical && current == request.batch_id {
            return Ok(RaftReadyPersistenceResult::Persisted {
                batch_id: request.batch_id,
                durable_id: request.batch_id,
            });
        }
        return Ok(RaftReadyPersistenceResult::Conflict);
    }
    if current != request.expected_previous_durable_id {
        return Ok(RaftReadyPersistenceResult::Conflict);
    }

    let mut batch = WriteBatch::default();
    for record in &request.records {
        batch.put(
            raft_ready_record_key(&prefix, record.kind, &record.key),
            &record.value,
        );
    }
    batch.put(&batch_key, canonical);
    batch.put(&meta_key, request.batch_id.to_be_bytes());

    let mut options = WriteOptions::default();
    options.set_sync(true);
    db.write_opt(batch, &options)
        .context("synchronous RocksDB Ready WriteBatch failed")?;
    Ok(RaftReadyPersistenceResult::Persisted {
        batch_id: request.batch_id,
        durable_id: request.batch_id,
    })
}

/// Persist through the process-global host database.
pub fn persist_raft_ready_batch(
    request: &PersistRaftReadyBatch,
) -> Result<RaftReadyPersistenceResult> {
    let database = db();
    persist_raft_ready_batch_on_db(&database, request)
}

/// List all keys in a table, optionally filtered by a prefix.
///
/// Returns up to `limit` keys whose raw bytes start with `prefix`.
/// Pass an empty prefix to list all keys.
pub fn list_keys(table: &str, prefix: &[u8], limit: usize) -> Result<Vec<Vec<u8>>> {
    let mut db = db();
    ensure_cf(&mut db, table);
    let cf = db.cf_handle(table).unwrap();

    let iter = db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
    let mut keys = Vec::new();
    for item in iter {
        let (k, _v) = item.context("RocksDB iterator failed")?;
        if prefix.is_empty() || k.starts_with(prefix) {
            keys.push(k.to_vec());
            if keys.len() >= limit {
                break;
            }
        } else if !prefix.is_empty() && &*k > prefix {
            // Keys are sorted — if we're past the prefix, stop early
            // (only works when prefix bytes form a valid range boundary).
            break;
        }
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestDbDirectory(PathBuf);

    impl Drop for TestDbDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Helper: open a fresh RocksDB in a temp dir for one test.
    fn open_tmp() -> (TestDbDirectory, DB) {
        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "honest-mini-rocksdb-test-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = DB::open(&opts, &path).unwrap();
        (TestDbDirectory(path), db)
    }

    #[test]
    fn put_get_delete_default_cf() {
        let (_tmp, db) = open_tmp();

        let key = b"encrypted_key_123";
        let val = b"encrypted_value_456";

        db.put(key, val).unwrap();

        let retrieved = db.get(key).unwrap();
        assert_eq!(retrieved, Some(val.to_vec()));

        db.delete(key).unwrap();

        let after_delete = db.get(key).unwrap();
        assert_eq!(after_delete, None);
    }

    #[test]
    fn get_missing_returns_none() {
        let (_tmp, db) = open_tmp();
        assert_eq!(db.get(b"no_such_key").unwrap(), None);
    }

    #[test]
    fn overwrite_existing_key() {
        let (_tmp, db) = open_tmp();
        db.put(b"k", b"v1").unwrap();
        db.put(b"k", b"v2").unwrap();
        assert_eq!(db.get(b"k").unwrap(), Some(b"v2".to_vec()));
    }

    #[test]
    fn binary_keys_and_values() {
        let (_tmp, db) = open_tmp();
        let key = (0u8..=255).collect::<Vec<u8>>();
        let val = vec![0xFFu8; 64_000];
        db.put(&key, &val).unwrap();
        assert_eq!(db.get(&key).unwrap().unwrap(), val);
    }

    #[test]
    fn column_family_isolation() {
        let (_tmp, mut db) = open_tmp();

        // Create two column families.
        db.create_cf("app:alice", &cf_opts()).unwrap();
        db.create_cf("app:bob", &cf_opts()).unwrap();

        let cf_a = db.cf_handle("app:alice").unwrap();
        let cf_b = db.cf_handle("app:bob").unwrap();

        db.put_cf(&cf_a, b"key", b"alice_value").unwrap();
        db.put_cf(&cf_b, b"key", b"bob_value").unwrap();

        assert_eq!(
            db.get_cf(&cf_a, b"key").unwrap(),
            Some(b"alice_value".to_vec())
        );
        assert_eq!(
            db.get_cf(&cf_b, b"key").unwrap(),
            Some(b"bob_value".to_vec())
        );

        // Default CF should NOT have "key".
        assert_eq!(db.get(b"key").unwrap(), None);
    }

    #[test]
    fn raft_ready_batch_is_atomic_idempotent_and_predecessor_bound() {
        use enclave_os_common::rpc::{PersistRaftReadyBatch, RaftReadyRecord, RaftReadyRecordKind};

        let (_tmp, db) = open_tmp();
        let first = PersistRaftReadyBatch {
            node_id: 3,
            node_generation: 7,
            batch_id: 1,
            expected_previous_durable_id: 0,
            records: vec![
                RaftReadyRecord {
                    kind: RaftReadyRecordKind::HardState,
                    key: b"hard-state".to_vec(),
                    value: b"ciphertext-hs-1".to_vec(),
                },
                RaftReadyRecord {
                    kind: RaftReadyRecordKind::AppliedIndex,
                    key: b"applied-index".to_vec(),
                    value: b"ciphertext-index-1".to_vec(),
                },
            ],
        };

        assert_eq!(
            persist_raft_ready_batch_on_db(&db, &first).unwrap(),
            RaftReadyPersistenceResult::Persisted {
                batch_id: 1,
                durable_id: 1
            }
        );
        assert_eq!(
            persist_raft_ready_batch_on_db(&db, &first).unwrap(),
            RaftReadyPersistenceResult::Persisted {
                batch_id: 1,
                durable_id: 1
            }
        );

        let mut altered_replay = first.clone();
        altered_replay.records[0].value = b"different-ciphertext".to_vec();
        assert_eq!(
            persist_raft_ready_batch_on_db(&db, &altered_replay).unwrap(),
            RaftReadyPersistenceResult::Conflict
        );

        let wrong_predecessor = PersistRaftReadyBatch {
            batch_id: 2,
            expected_previous_durable_id: 0,
            records: vec![RaftReadyRecord {
                kind: RaftReadyRecordKind::AppliedIndex,
                key: b"applied-index".to_vec(),
                value: b"must-not-be-written".to_vec(),
            }],
            ..first.clone()
        };
        assert_eq!(
            persist_raft_ready_batch_on_db(&db, &wrong_predecessor).unwrap(),
            RaftReadyPersistenceResult::Conflict
        );

        let second = PersistRaftReadyBatch {
            expected_previous_durable_id: 1,
            ..wrong_predecessor
        };
        assert_eq!(
            persist_raft_ready_batch_on_db(&db, &second).unwrap(),
            RaftReadyPersistenceResult::Persisted {
                batch_id: 2,
                durable_id: 2
            }
        );
    }
}
