// Copyright (c) 2026 Edison Lepiten / AIEONYX

use edisondb::backends::{FjallBackend, StorageBackend};
use edisondb::{AuditAction, AuditEntry, DataTier, EdisonError, Record, Store};
use fjall::{Database as FjallDatabase, KeyspaceCreateOptions};
use redb::{Database as RedbDatabase, TableDefinition};
use std::time::{SystemTime, UNIX_EPOCH};


fn raw_record(id: &str, tier: DataTier, owner_id: &str, payload: Vec<u8>) -> Record {
    let safe_id = if id.is_empty() { "fv3:test-id" } else { id };
    let safe_owner = if owner_id.is_empty() { "fv3:test-owner" } else { owner_id };
    let mut record = Record::new(safe_id, tier, safe_owner, payload, [0u8; 32]).unwrap();
    record.id = id.to_string();
    record.owner_id = owner_id.to_string();
    record.created_at = 1;
    record
}

fn temp_path(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    format!("/tmp/edisondb-fv3-{label}-{}-{nanos}", std::process::id())
}

fn write_raw_redb(path: &str, key: &str, record: &Record) {
    const RECORDS: TableDefinition<&str, &str> = TableDefinition::new("records");

    let db = RedbDatabase::create(path).unwrap();
    let txn = db.begin_write().unwrap();

    {
        let mut table = txn.open_table(RECORDS).unwrap();
        let json = serde_json::to_string(record).unwrap();
        table.insert(key, json.as_str()).unwrap();
    }

    txn.commit().unwrap();
}

#[test]
fn store_rejects_empty_owner_without_mutation() {
    let mut store = Store::new();
    let record = raw_record("rec:empty-owner", DataTier::Personal, "", vec![1]);

    assert_eq!(store.write(record), Err(EdisonError::NoOwner));
    assert_eq!(store.record_count(), 0);
    assert_eq!(store.audit_count(), 0);
}

#[test]
fn store_rejects_empty_record_id_without_mutation() {
    let mut store = Store::new();
    let record = raw_record("", DataTier::Noise, "alice", vec![1]);

    assert!(store.write(record).is_err());
    assert_eq!(store.record_count(), 0);
    assert_eq!(store.audit_count(), 0);
}

#[test]
fn store_rejects_invalid_record_before_save() {
    let path = temp_path("redb-invalid-public-write");
    let mut store = Store::new();

    let record = raw_record("rec:invalid", DataTier::Critical, "", vec![1]);

    assert_eq!(store.write(record), Err(EdisonError::NoOwner));
    assert_eq!(store.record_count(), 0);
    assert_eq!(store.audit_count(), 0);

    store.save(&path).unwrap();

    let loaded = Store::load(&path).unwrap();

    assert_eq!(loaded.record_count(), 0);
    assert_eq!(loaded.audit_count(), 0);

    let _ = std::fs::remove_file(path);
}

#[test]
fn store_load_rejects_invalid_record() {
    let path = temp_path("redb-invalid-load");
    let record = raw_record("rec:invalid", DataTier::Critical, "", vec![1]);

    write_raw_redb(&path, "rec:invalid", &record);

    assert!(matches!(Store::load(&path), Err(EdisonError::NoOwner)));

    let _ = std::fs::remove_file(path);
}

#[test]
fn store_load_rejects_key_id_mismatch() {
    let path = temp_path("redb-key-mismatch");
    let record = raw_record("rec:inside", DataTier::Personal, "alice", vec![1]);

    write_raw_redb(&path, "rec:outside", &record);

    assert!(matches!(Store::load(&path), Err(EdisonError::LoadFailed)));

    let _ = std::fs::remove_file(path);
}

#[test]
fn fjall_rejects_empty_owner_without_mutation() {
    let path = temp_path("fjall-empty-owner");
    let mut backend = FjallBackend::open(&path).unwrap();

    let record = raw_record("rec:empty-owner", DataTier::Personal, "", vec![1]);

    assert_eq!(backend.write(record), Err(EdisonError::NoOwner));
    assert_eq!(backend.audit_count(), 0);

    drop(backend);
    let _ = std::fs::remove_dir_all(path);
}

#[test]
fn fjall_rejects_empty_record_id_without_mutation() {
    let path = temp_path("fjall-empty-id");
    let mut backend = FjallBackend::open(&path).unwrap();

    let record = raw_record("", DataTier::Noise, "alice", vec![1]);

    assert!(backend.write(record).is_err());
    assert_eq!(backend.audit_count(), 0);

    drop(backend);
    let _ = std::fs::remove_dir_all(path);
}

#[test]
fn fjall_enforces_global_id_immutability_across_tiers() {
    let path = temp_path("fjall-global-id");
    let mut backend = FjallBackend::open(&path).unwrap();

    let original = raw_record("rec:global", DataTier::Critical, "alice", vec![1]);
    let replacement = raw_record("rec:global", DataTier::Noise, "alice", vec![2]);

    backend.write(original).unwrap();

    assert_eq!(backend.write(replacement), Err(EdisonError::AlreadyExists));
    assert_eq!(backend.audit_count(), 1);

    let stored = backend.read("rec:global", "alice").unwrap();
    assert_eq!(stored.tier, DataTier::Critical);
    assert_eq!(stored.payload(), &[1]);

    drop(backend);
    let _ = std::fs::remove_dir_all(path);
}

fn write_raw_fjall(path: &str, keyspace_name: &str, key: &str, record: &Record) {
    let db = FjallDatabase::builder(path).open().unwrap();

    let keyspace = db
        .keyspace(keyspace_name, KeyspaceCreateOptions::default)
        .unwrap();

    let audit = db
        .keyspace("audit", KeyspaceCreateOptions::default)
        .unwrap();

    let checkpoint = db
        .keyspace("audit_checkpoint", KeyspaceCreateOptions::default)
        .unwrap();

    let record_json = serde_json::to_vec(record).unwrap();

    let anchor = AuditEntry::new(
        "fv3:fixture-anchor",
        "fixture",
        AuditAction::Write,
        1,
        [0u8; 32],
    );

    let audit_json = serde_json::to_vec(&anchor).unwrap();

    let checkpoint_json = serde_json::to_vec(&serde_json::json!({
        "expected_count": 1u64,
        "expected_head": anchor.entry_hash,
    }))
    .unwrap();

    let mut batch = db.batch();

    batch.insert(&keyspace, key.as_bytes(), record_json);

    batch.insert(&audit, b"00000000000000000000", audit_json);

    batch.insert(&checkpoint, b"current", checkpoint_json);

    batch.commit().unwrap();
}

#[test]
fn fjall_open_rejects_invalid_persisted_record() {
    let path = temp_path("fjall-invalid-load");
    let record = raw_record("rec:invalid", DataTier::Personal, "", vec![1]);

    write_raw_fjall(&path, "records_personal", "rec:invalid", &record);

    assert!(matches!(
        FjallBackend::open(&path),
        Err(EdisonError::NoOwner)
    ));

    let _ = std::fs::remove_dir_all(path);
}

#[test]
fn fjall_open_rejects_key_id_mismatch() {
    let path = temp_path("fjall-key-mismatch");
    let record = raw_record("rec:inside", DataTier::Personal, "alice", vec![1]);

    write_raw_fjall(&path, "records_personal", "rec:outside", &record);

    assert!(matches!(
        FjallBackend::open(&path),
        Err(EdisonError::LoadFailed)
    ));

    let _ = std::fs::remove_dir_all(path);
}

#[test]
fn fjall_open_rejects_tier_keyspace_mismatch() {
    let path = temp_path("fjall-tier-mismatch");
    let record = raw_record("rec:tier", DataTier::Critical, "alice", vec![1]);

    write_raw_fjall(&path, "records_noise", "rec:tier", &record);

    assert!(matches!(
        FjallBackend::open(&path),
        Err(EdisonError::LoadFailed)
    ));

    let _ = std::fs::remove_dir_all(path);
}

#[test]
fn fjall_open_rejects_cross_tier_duplicate_ids() {
    let path = temp_path("fjall-persisted-duplicate");
    let critical = raw_record("rec:duplicate", DataTier::Critical, "alice", vec![1]);
    let noise = raw_record("rec:duplicate", DataTier::Noise, "alice", vec![2]);

    write_raw_fjall(&path, "records_critical", "rec:duplicate", &critical);
    write_raw_fjall(&path, "records_noise", "rec:duplicate", &noise);

    assert!(matches!(
        FjallBackend::open(&path),
        Err(EdisonError::LoadFailed)
    ));

    let _ = std::fs::remove_dir_all(path);
}
