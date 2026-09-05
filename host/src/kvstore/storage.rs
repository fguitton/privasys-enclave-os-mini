// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! RocksDB-backed encrypted KV store with per-app table isolation.
//!
//! Each "table" maps to a RocksDB column family.  Tables are created
//! on first use and persisted across restarts.  The host stores opaque
//! ciphertext – all encryption/decryption happens inside the enclave.

use anyhow::{Context, Result};
use enclave_os_common::rpc::{
    decode_persist_opaque_stream_batch, LoadOpaqueStreamTip, OpaqueStreamTip,
    ValidatedPersistOpaqueStreamBatch,
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

/// Outcome of one predecessor-bound synchronous opaque stream batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpaqueStreamPersistenceResult {
    Persisted { batch_id: u64, durable_id: u64 },
    Conflict,
}

fn opaque_stream_prefix(
    node_id: u64,
    node_generation: u64,
    stream_id: [u8; 32],
    persistence_epoch: u64,
) -> Vec<u8> {
    let mut key = b"honest/opaque-stream/v1/".to_vec();
    key.extend_from_slice(&node_id.to_be_bytes());
    key.extend_from_slice(&node_generation.to_be_bytes());
    key.push(b'/');
    key.extend_from_slice(&stream_id);
    key.push(b'/');
    key.extend_from_slice(&persistence_epoch.to_be_bytes());
    key.push(b'/');
    key
}

fn opaque_stream_meta_key(prefix: &[u8]) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(b"current");
    key
}

fn opaque_stream_batch_key(prefix: &[u8], batch_id: u64) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(b"batch/");
    key.extend_from_slice(&batch_id.to_be_bytes());
    key
}

fn read_durable_id(db: &DB, key: &[u8]) -> Result<u64> {
    let Some(bytes) = db
        .get(key)
        .context("RocksDB opaque-stream metadata read failed")?
    else {
        return Ok(0);
    };
    if bytes.len() != 8 {
        anyhow::bail!("RocksDB opaque-stream metadata has an invalid durable ID");
    }
    Ok(u64::from_be_bytes(bytes.as_slice().try_into().map_err(
        |_| anyhow::anyhow!("invalid opaque-stream durable ID"),
    )?))
}

/// Persist one canonical opaque batch with a single synchronous RocksDB
/// `WriteBatch`.
///
/// A matching replay is accepted only while that batch remains the current
/// durable tip. A changed replay or wrong predecessor writes nothing.
pub fn persist_opaque_stream_batch_on_db(
    db: &DB,
    validated: &ValidatedPersistOpaqueStreamBatch<'_>,
) -> Result<OpaqueStreamPersistenceResult> {
    let request = validated.request();
    let canonical = validated.canonical_bytes();
    let prefix = opaque_stream_prefix(
        request.node_id,
        request.node_generation,
        request.stream_id,
        request.persistence_epoch,
    );
    let meta_key = opaque_stream_meta_key(&prefix);
    let batch_key = opaque_stream_batch_key(&prefix, request.batch_id);
    let current = read_durable_id(db, &meta_key)?;

    if let Some(previous) = db
        .get(&batch_key)
        .context("RocksDB opaque-stream replay read failed")?
    {
        if previous.as_slice() == canonical && current == request.batch_id {
            return Ok(OpaqueStreamPersistenceResult::Persisted {
                batch_id: request.batch_id,
                durable_id: request.batch_id,
            });
        }
        return Ok(OpaqueStreamPersistenceResult::Conflict);
    }
    if current != request.expected_previous_durable_id {
        return Ok(OpaqueStreamPersistenceResult::Conflict);
    }

    let mut batch = WriteBatch::default();
    batch.put(&batch_key, canonical);
    batch.put(&meta_key, request.batch_id.to_be_bytes());

    let mut options = WriteOptions::default();
    options.set_sync(true);
    db.write_opt(batch, &options)
        .context("synchronous RocksDB opaque-stream WriteBatch failed")?;
    Ok(OpaqueStreamPersistenceResult::Persisted {
        batch_id: request.batch_id,
        durable_id: request.batch_id,
    })
}

/// Persist through the process-global host database.
pub fn persist_opaque_stream_batch(
    request: &ValidatedPersistOpaqueStreamBatch<'_>,
) -> Result<OpaqueStreamPersistenceResult> {
    let database = db();
    persist_opaque_stream_batch_on_db(&database, request)
}

/// Load the exact current opaque-stream tip from one database.
pub fn load_opaque_stream_tip_on_db(
    db: &DB,
    request: LoadOpaqueStreamTip,
) -> Result<Option<OpaqueStreamTip>> {
    let prefix = opaque_stream_prefix(
        request.node_id,
        request.node_generation,
        request.stream_id,
        request.persistence_epoch,
    );
    let current = read_durable_id(db, &opaque_stream_meta_key(&prefix))?;
    if current == 0 {
        return Ok(None);
    }
    let canonical = db
        .get(opaque_stream_batch_key(&prefix, current))
        .context("RocksDB opaque-stream tip read failed")?
        .ok_or_else(|| anyhow::anyhow!("opaque-stream metadata points to a missing batch"))?;
    let batch = decode_persist_opaque_stream_batch(&canonical)
        .map_err(|error| anyhow::anyhow!("stored opaque-stream batch is invalid: {error:?}"))?
        .into_request();
    if batch.node_id != request.node_id
        || batch.node_generation != request.node_generation
        || batch.stream_id != request.stream_id
        || batch.persistence_epoch != request.persistence_epoch
        || batch.batch_id != current
    {
        anyhow::bail!("stored opaque-stream tip identity differs");
    }
    Ok(Some(OpaqueStreamTip {
        batch_id: batch.batch_id,
        durable_id: batch.batch_id,
        payload_digest: batch.payload_digest,
        payload: batch.payload,
    }))
}

/// Load through the process-global host database.
pub fn load_opaque_stream_tip(request: LoadOpaqueStreamTip) -> Result<Option<OpaqueStreamTip>> {
    let database = db();
    load_opaque_stream_tip_on_db(&database, request)
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
    use enclave_os_common::rpc::{
        decode_persist_opaque_stream_batch, encode_persist_opaque_stream_batch,
        PersistOpaqueStreamBatch,
    };
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};

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

    fn persist_request_on_db(
        db: &DB,
        request: &PersistOpaqueStreamBatch,
    ) -> Result<OpaqueStreamPersistenceResult> {
        let canonical = encode_persist_opaque_stream_batch(request)
            .map_err(|error| anyhow::anyhow!("invalid opaque-stream batch: {error:?}"))?;
        let validated = decode_persist_opaque_stream_batch(&canonical)
            .map_err(|error| anyhow::anyhow!("invalid opaque-stream batch: {error:?}"))?;
        persist_opaque_stream_batch_on_db(db, &validated)
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
    fn opaque_stream_is_atomic_idempotent_predecessor_bound_and_loadable() {
        use enclave_os_common::rpc::LoadOpaqueStreamTip;

        let (_tmp, db) = open_tmp();
        let first = PersistOpaqueStreamBatch {
            node_id: 3,
            node_generation: 7,
            stream_id: [4; 32],
            persistence_epoch: 11,
            batch_id: 1,
            expected_previous_durable_id: 0,
            payload_digest: [8; 32],
            payload: b"opaque-ciphertext-1".to_vec(),
        };

        let first_canonical = encode_persist_opaque_stream_batch(&first).unwrap();
        let first_validated = decode_persist_opaque_stream_batch(&first_canonical).unwrap();
        assert_eq!(
            persist_opaque_stream_batch_on_db(&db, &first_validated).unwrap(),
            OpaqueStreamPersistenceResult::Persisted {
                batch_id: 1,
                durable_id: 1
            }
        );
        let first_key = opaque_stream_batch_key(
            &opaque_stream_prefix(
                first.node_id,
                first.node_generation,
                first.stream_id,
                first.persistence_epoch,
            ),
            first.batch_id,
        );
        assert_eq!(db.get(first_key).unwrap(), Some(first_canonical.clone()));
        assert_eq!(
            persist_opaque_stream_batch_on_db(&db, &first_validated).unwrap(),
            OpaqueStreamPersistenceResult::Persisted {
                batch_id: 1,
                durable_id: 1
            }
        );

        let mut altered_replay = first.clone();
        altered_replay.payload = b"different-ciphertext".to_vec();
        altered_replay.payload_digest = [9; 32];
        assert_eq!(
            persist_request_on_db(&db, &altered_replay).unwrap(),
            OpaqueStreamPersistenceResult::Conflict
        );

        let wrong_predecessor = PersistOpaqueStreamBatch {
            batch_id: 2,
            expected_previous_durable_id: 0,
            payload_digest: [10; 32],
            payload: b"must-not-be-written".to_vec(),
            ..first.clone()
        };
        assert_eq!(
            persist_request_on_db(&db, &wrong_predecessor)
                .unwrap_err()
                .to_string(),
            "invalid opaque-stream batch: InvalidPredecessor"
        );

        let second = PersistOpaqueStreamBatch {
            expected_previous_durable_id: 1,
            ..wrong_predecessor
        };
        assert_eq!(
            persist_request_on_db(&db, &second).unwrap(),
            OpaqueStreamPersistenceResult::Persisted {
                batch_id: 2,
                durable_id: 2
            }
        );

        let tip = load_opaque_stream_tip_on_db(
            &db,
            LoadOpaqueStreamTip {
                node_id: first.node_id,
                node_generation: first.node_generation,
                stream_id: first.stream_id,
                persistence_epoch: first.persistence_epoch,
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(tip.batch_id, 2);
        assert_eq!(tip.durable_id, 2);
        assert_eq!(tip.payload_digest, second.payload_digest);
        assert_eq!(tip.payload, second.payload);

        assert!(load_opaque_stream_tip_on_db(
            &db,
            LoadOpaqueStreamTip {
                stream_id: [5; 32],
                ..LoadOpaqueStreamTip {
                    node_id: first.node_id,
                    node_generation: first.node_generation,
                    stream_id: first.stream_id,
                    persistence_epoch: first.persistence_epoch,
                }
            },
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn opaque_stream_concurrent_successors_select_one_exact_tip() {
        let (_tmp, db) = open_tmp();
        let db = Arc::new(Mutex::new(db));
        let first = PersistOpaqueStreamBatch {
            node_id: 9,
            node_generation: 2,
            stream_id: [6; 32],
            persistence_epoch: 17,
            batch_id: 1,
            expected_previous_durable_id: 0,
            payload_digest: [1; 32],
            payload: b"first".to_vec(),
        };
        assert!(matches!(
            persist_request_on_db(&db.lock().unwrap(), &first).unwrap(),
            OpaqueStreamPersistenceResult::Persisted { .. }
        ));

        let barrier = Arc::new(Barrier::new(3));
        let contenders = [
            ([2; 32], b"second-a".to_vec()),
            ([3; 32], b"second-b".to_vec()),
        ]
        .into_iter()
        .map(|(payload_digest, payload)| {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);
            let mut request = first.clone();
            request.batch_id = 2;
            request.expected_previous_durable_id = 1;
            request.payload_digest = payload_digest;
            request.payload = payload;
            std::thread::spawn(move || {
                barrier.wait();
                persist_request_on_db(&db.lock().unwrap(), &request).unwrap()
            })
        })
        .collect::<Vec<_>>();
        barrier.wait();
        let results = contenders
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, OpaqueStreamPersistenceResult::Persisted { .. }))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, OpaqueStreamPersistenceResult::Conflict))
                .count(),
            1
        );
    }
}
