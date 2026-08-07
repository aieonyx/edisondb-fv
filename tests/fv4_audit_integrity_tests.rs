// Copyright (c) 2026 Edison Lepiten / AIEONYX

use edisondb::backends::FjallBackend;
use edisondb::{AuditAction, AuditEntry, DataTier, EdisonError, Record, Store};
use fjall::{Database as FjallDatabase, KeyspaceCreateOptions};
use redb::{Database, ReadableTable, TableDefinition};
use std::time::{SystemTime, UNIX_EPOCH};

const RECORDS: TableDefinition<&str, &str> = TableDefinition::new("records");
const AUDIT: TableDefinition<&str, &str> = TableDefinition::new("audit");

fn temp_path(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    format!(
        "/tmp/edisondb-fv4-{label}-{}-{nanos}.redb",
        std::process::id()
    )
}

fn audit_entry(record_id: &str, timestamp: u64, prev_hash: [u8; 32]) -> AuditEntry {
    AuditEntry::new(record_id, "alice", AuditAction::Write, timestamp, prev_hash)
}

fn write_raw_audit(path: &str, entries: &[(&str, &str)]) {
    let db = Database::create(path).unwrap();
    let txn = db.begin_write().unwrap();

    {
        let _records = txn.open_table(RECORDS).unwrap();
        let mut audit = txn.open_table(AUDIT).unwrap();

        for (key, value) in entries {
            audit.insert(*key, *value).unwrap();
        }
    }

    txn.commit().unwrap();
}

fn write_raw_fjall_audit(path: &str, entries: &[(&str, &str)]) {
    let db = FjallDatabase::builder(path).open().unwrap();
    let audit = db
        .keyspace("audit", KeyspaceCreateOptions::default)
        .unwrap();

    for (key, value) in entries {
        audit.insert(key.as_bytes(), value.as_bytes()).unwrap();
    }
}

#[test]
fn redb_load_rejects_malformed_audit_entry() {
    let path = temp_path("malformed");
    write_raw_audit(&path, &[("00000000000000000000", "{invalid-json")]);

    assert!(matches!(
        Store::load(&path),
        Err(EdisonError::AuditChainBroken)
    ));

    let _ = std::fs::remove_file(path);
}

#[test]
fn redb_load_rejects_broken_audit_chain() {
    let path = temp_path("broken-chain");

    let first = audit_entry("rec:1", 1, [0u8; 32]);
    let second = audit_entry("rec:2", 2, [9u8; 32]);

    let first_json = serde_json::to_string(&first).unwrap();
    let second_json = serde_json::to_string(&second).unwrap();

    write_raw_audit(
        &path,
        &[
            ("00000000000000000000", first_json.as_str()),
            ("00000000000000000001", second_json.as_str()),
        ],
    );

    assert!(matches!(
        Store::load(&path),
        Err(EdisonError::AuditChainBroken)
    ));

    let _ = std::fs::remove_file(path);
}

#[test]
fn redb_save_rejects_tampered_audit_chain() {
    let path = temp_path("tampered-save");
    let mut store = Store::new();

    let record = Record::new(
        "rec:tampered",
        DataTier::Personal,
        "alice",
        vec![1],
        [0u8; 32],
    )
    .unwrap();

    store.write(record).unwrap();
    store.audit_log[0].record_id = "rec:injected".to_string();

    assert_eq!(store.save(&path), Err(EdisonError::AuditChainBroken));

    let _ = std::fs::remove_file(path);
}

#[test]
fn redb_save_removes_stale_audit_rows() {
    let path = temp_path("stale-rows");
    let mut store = Store::new();

    for index in 0..2 {
        let id = format!("rec:{index}");
        let record = Record::new(
            &id,
            DataTier::Personal,
            "alice",
            vec![index as u8],
            [0u8; 32],
        )
        .unwrap();

        store.write(record).unwrap();
    }

    store.save(&path).unwrap();
    store.audit_log.truncate(1);
    store.save(&path).unwrap();

    let loaded = Store::load(&path).unwrap();
    assert_eq!(loaded.audit_count(), 1);

    let _ = std::fs::remove_file(path);
}

#[test]
fn redb_save_uses_canonical_audit_keys() {
    let path = temp_path("canonical-keys");
    let mut store = Store::new();

    for index in 0..12 {
        let id = format!("rec:{index}");
        let record = Record::new(&id, DataTier::Noise, "alice", vec![], [0u8; 32]).unwrap();

        store.write(record).unwrap();
    }

    store.save(&path).unwrap();

    let db = Database::open(&path).unwrap();
    let txn = db.begin_read().unwrap();
    let table = txn.open_table(AUDIT).unwrap();

    let keys: Vec<String> = table
        .iter()
        .unwrap()
        .map(|entry| entry.unwrap().0.value().to_string())
        .collect();

    let expected: Vec<String> = (0..12).map(|index| format!("{index:020}")).collect();

    assert_eq!(keys, expected);

    drop(table);
    drop(txn);
    drop(db);

    let _ = std::fs::remove_file(path);
}

#[test]
fn fjall_open_rejects_malformed_audit_entry() {
    let path = temp_path("fjall-malformed-audit");

    write_raw_fjall_audit(&path, &[("00000000000000000000", "{invalid-json")]);

    assert!(matches!(
        FjallBackend::open(&path),
        Err(EdisonError::AuditChainBroken)
    ));

    let _ = std::fs::remove_dir_all(path);
}

#[test]
fn fjall_open_rejects_broken_audit_chain() {
    let path = temp_path("fjall-broken-chain");

    let first = audit_entry("rec:1", 1, [0u8; 32]);
    let second = audit_entry("rec:2", 2, [9u8; 32]);

    let first_json = serde_json::to_string(&first).unwrap();
    let second_json = serde_json::to_string(&second).unwrap();

    write_raw_fjall_audit(
        &path,
        &[
            ("00000000000000000000", first_json.as_str()),
            ("00000000000000000001", second_json.as_str()),
        ],
    );

    assert!(matches!(
        FjallBackend::open(&path),
        Err(EdisonError::AuditChainBroken)
    ));

    let _ = std::fs::remove_dir_all(path);
}

#[test]
fn fjall_open_rejects_tampered_final_audit_entry() {
    let path = temp_path("fjall-tampered-final");

    let entry = audit_entry("rec:final", 1, [0u8; 32]);
    let mut value = serde_json::to_value(entry).unwrap();

    value["record_id"] = serde_json::Value::String("rec:injected".to_string());

    let tampered_json = serde_json::to_string(&value).unwrap();

    write_raw_fjall_audit(&path, &[("00000000000000000000", tampered_json.as_str())]);

    assert!(matches!(
        FjallBackend::open(&path),
        Err(EdisonError::AuditChainBroken)
    ));

    let _ = std::fs::remove_dir_all(path);
}

#[test]
fn fjall_open_rejects_noncanonical_audit_key() {
    let path = temp_path("fjall-noncanonical-key");

    let entry = audit_entry("rec:1", 1, [0u8; 32]);
    let json = serde_json::to_string(&entry).unwrap();

    write_raw_fjall_audit(&path, &[("0", json.as_str())]);

    assert!(matches!(
        FjallBackend::open(&path),
        Err(EdisonError::AuditChainBroken)
    ));

    let _ = std::fs::remove_dir_all(path);
}

#[test]
fn fjall_open_rejects_audit_sequence_gap() {
    let path = temp_path("fjall-sequence-gap");

    let first = audit_entry("rec:1", 1, [0u8; 32]);
    let second = audit_entry("rec:2", 2, first.entry_hash);

    let first_json = serde_json::to_string(&first).unwrap();
    let second_json = serde_json::to_string(&second).unwrap();

    write_raw_fjall_audit(
        &path,
        &[
            ("00000000000000000000", first_json.as_str()),
            ("00000000000000000002", second_json.as_str()),
        ],
    );

    assert!(matches!(
        FjallBackend::open(&path),
        Err(EdisonError::AuditChainBroken)
    ));

    let _ = std::fs::remove_dir_all(path);
}

#[test]
fn redb_load_rejects_noncanonical_audit_key() {
    let path = temp_path("redb-noncanonical-key");

    let entry = audit_entry("rec:1", 1, [0u8; 32]);
    let json = serde_json::to_string(&entry).unwrap();

    write_raw_audit(&path, &[("0", json.as_str())]);

    assert!(matches!(
        Store::load(&path),
        Err(EdisonError::AuditChainBroken)
    ));

    let _ = std::fs::remove_file(path);
}
