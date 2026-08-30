mod common;
use common::record_new;

// Copyright (c) 2026 Edison Lepiten / AIEONYX

use edisondb::backends::FjallBackend;
use edisondb::{AuditAction, AuditEntry, DataTier, EdisonError, Store};
use fjall::{Database as FjallDatabase, KeyspaceCreateOptions};
use proptest::prelude::*;
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
fn redb_load_rejects_persisted_content_tamper() {
    let path = temp_path("persisted-content-tamper");
    let mut store = Store::new();

    let record = record_new(
        "rec:tampered",
        DataTier::Personal,
        "alice",
        vec![1],
        [0u8; 32],
    )
    .unwrap();

    store.write(record).unwrap();
    store.save(&path).unwrap();

    {
        let db = Database::open(&path).unwrap();
        let txn = db.begin_write().unwrap();

        {
            let mut audit = txn.open_table(AUDIT).unwrap();

            let raw = audit
                .get("00000000000000000000")
                .unwrap()
                .expect("audit entry must exist");

            let mut entry: AuditEntry = serde_json::from_str(raw.value()).unwrap();

            drop(raw);

            entry.record_id = "rec:injected".to_string();

            let json = serde_json::to_string(&entry).unwrap();

            audit.insert("00000000000000000000", json.as_str()).unwrap();
        }

        txn.commit().unwrap();
    }

    assert!(matches!(
        Store::load(&path),
        Err(EdisonError::AuditChainBroken)
    ));

    let _ = std::fs::remove_file(path);
}

#[test]
fn redb_save_rejects_unrelated_history_replacement() {
    let path = temp_path("history-replacement");

    let mut first = Store::new();

    for index in 0..2 {
        let id = format!("rec:{index}");

        let record = record_new(
            &id,
            DataTier::Personal,
            "alice",
            vec![index as u8],
            [0u8; 32],
        )
        .unwrap();

        first.write(record).unwrap();
    }

    first.save(&path).unwrap();

    let mut replacement = Store::new();

    let record = record_new(
        "rec:replacement",
        DataTier::Personal,
        "alice",
        vec![9],
        [0u8; 32],
    )
    .unwrap();

    replacement.write(record).unwrap();

    assert_eq!(replacement.save(&path), Err(EdisonError::AuditChainBroken));

    let loaded = Store::load(&path).unwrap();

    assert_eq!(loaded.audit_count(), 2);
    assert_eq!(loaded.record_count(), 2);
    loaded.verify_audit_chain().unwrap();

    let _ = std::fs::remove_file(path);
}

#[test]
fn redb_save_allows_same_lineage_resave_and_extension() {
    let path = temp_path("lineage-extension");
    let mut store = Store::new();

    let first = record_new("rec:first", DataTier::Personal, "alice", vec![1], [0u8; 32]).unwrap();

    store.write(first).unwrap();
    store.save(&path).unwrap();

    store.save(&path).unwrap();

    let second = record_new(
        "rec:second",
        DataTier::Personal,
        "alice",
        vec![2],
        [0u8; 32],
    )
    .unwrap();

    store.write(second).unwrap();
    store.save(&path).unwrap();

    let loaded = Store::load(&path).unwrap();

    assert_eq!(loaded.audit_count(), 2);
    assert_eq!(loaded.record_count(), 2);
    loaded.verify_audit_chain().unwrap();

    let _ = std::fs::remove_file(path);
}

#[test]
fn redb_save_rejects_stale_snapshot_after_history_extension() {
    let path = temp_path("stale-snapshot");

    let mut seed = Store::new();

    let first = record_new("rec:base", DataTier::Personal, "alice", vec![1], [0u8; 32]).unwrap();

    seed.write(first).unwrap();
    seed.save(&path).unwrap();

    let stale = Store::load(&path).unwrap();
    let mut current = Store::load(&path).unwrap();

    let second = record_new(
        "rec:current",
        DataTier::Personal,
        "alice",
        vec![2],
        [0u8; 32],
    )
    .unwrap();

    current.write(second).unwrap();
    current.save(&path).unwrap();

    assert_eq!(stale.save(&path), Err(EdisonError::AuditChainBroken));

    let loaded = Store::load(&path).unwrap();

    assert_eq!(loaded.audit_count(), 2);
    assert_eq!(loaded.record_count(), 2);
    loaded.verify_audit_chain().unwrap();

    let _ = std::fs::remove_file(path);
}

#[test]
fn redb_save_rejects_divergent_stale_writer() {
    let path = temp_path("divergent-writer");

    let mut seed = Store::new();

    let base = record_new("rec:base", DataTier::Personal, "alice", vec![1], [0u8; 32]).unwrap();

    seed.write(base).unwrap();
    seed.save(&path).unwrap();

    let mut first_writer = Store::load(&path).unwrap();
    let mut second_writer = Store::load(&path).unwrap();

    let left = record_new("rec:left", DataTier::Personal, "alice", vec![2], [0u8; 32]).unwrap();

    let right = record_new("rec:right", DataTier::Personal, "alice", vec![3], [0u8; 32]).unwrap();

    first_writer.write(left).unwrap();
    second_writer.write(right).unwrap();

    first_writer.save(&path).unwrap();

    assert_eq!(
        second_writer.save(&path),
        Err(EdisonError::AuditChainBroken)
    );

    let loaded = Store::load(&path).unwrap();

    assert_eq!(loaded.audit_count(), 2);
    assert_eq!(loaded.record_count(), 2);
    assert_eq!(loaded.list_by_owner("alice").unwrap().len(), 2);
    loaded.verify_audit_chain().unwrap();

    let _ = std::fs::remove_file(path);
}

#[test]
fn redb_save_uses_canonical_audit_keys() {
    let path = temp_path("canonical-keys");
    let mut store = Store::new();

    for index in 0..12 {
        let id = format!("rec:{index}");
        let record = record_new(&id, DataTier::Noise, "alice", vec![], [0u8; 32]).unwrap();

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

#[test]
fn audit_hash_known_answer_v1() {
    let entry = AuditEntry::new("rec:calibration", "owner", AuditAction::Write, 1, [0u8; 32]);

    let expected = [
        0x4d, 0x4f, 0xfe, 0x43, 0x8e, 0x7a, 0xbe, 0x0b, 0x49, 0x59, 0x6f, 0xf8, 0x8f, 0x60, 0x8a,
        0x39, 0xeb, 0x37, 0x8a, 0x12, 0xaf, 0xed, 0x93, 0xd6, 0xc8, 0xe4, 0x88, 0x93, 0x8b, 0x88,
        0x3e, 0x65,
    ];

    assert_eq!(entry.entry_hash, expected);
    assert!(entry.verify_hash());
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4096,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn audit_sha256_timestamp_single_bit_tamper_changes_digest(
        timestamp in any::<u64>(),
        prev_hash in prop::array::uniform32(any::<u8>()),
        bit in 0usize..64,
    ) {
        let original = AuditEntry::new(
            "rec:proptest",
            "owner",
            AuditAction::Write,
            timestamp,
            prev_hash,
        );

        let tampered_timestamp = timestamp ^ (1u64 << bit);

        let tampered = AuditEntry::new(
            "rec:proptest",
            "owner",
            AuditAction::Write,
            tampered_timestamp,
            prev_hash,
        );

        prop_assert_ne!(timestamp, tampered_timestamp);
        prop_assert_ne!(original.entry_hash, tampered.entry_hash);
        prop_assert!(original.verify_hash());
        prop_assert!(tampered.verify_hash());
    }

    #[test]
    fn audit_sha256_prev_hash_single_bit_tamper_changes_digest(
        timestamp in any::<u64>(),
        prev_hash in prop::array::uniform32(any::<u8>()),
        bit in 0usize..256,
    ) {
        let original = AuditEntry::new(
            "rec:proptest",
            "owner",
            AuditAction::Write,
            timestamp,
            prev_hash,
        );

        let mut tampered_prev_hash = prev_hash;
        tampered_prev_hash[bit / 8] ^= 1u8 << (bit % 8);

        let tampered = AuditEntry::new(
            "rec:proptest",
            "owner",
            AuditAction::Write,
            timestamp,
            tampered_prev_hash,
        );

        prop_assert_ne!(prev_hash, tampered_prev_hash);
        prop_assert_ne!(original.entry_hash, tampered.entry_hash);
        prop_assert!(original.verify_hash());
        prop_assert!(tampered.verify_hash());
    }

    #[test]
    fn audit_sha256_distinct_record_identity_separates_entries(
        left_seed in any::<u64>(),
        delta in 1u64..=u64::MAX,
        timestamp in any::<u64>(),
        prev_hash in prop::array::uniform32(any::<u8>()),
    ) {
        let right_seed = left_seed.wrapping_add(delta);

        let left_id = format!("rec:{left_seed:016x}");
        let right_id = format!("rec:{right_seed:016x}");

        let left = AuditEntry::new(
            left_id,
            "owner",
            AuditAction::Write,
            timestamp,
            prev_hash,
        );

        let right = AuditEntry::new(
            right_id,
            "owner",
            AuditAction::Write,
            timestamp,
            prev_hash,
        );

        prop_assert_ne!(
            left.record_id.as_str(),
            right.record_id.as_str()
        );
        prop_assert_ne!(left.entry_hash, right.entry_hash);
        prop_assert!(left.verify_hash());
        prop_assert!(right.verify_hash());
    }
}
