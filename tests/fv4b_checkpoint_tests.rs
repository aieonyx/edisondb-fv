use edisondb::{
    DataTier, EdisonError, Record,
    backends::{FjallBackend, StorageBackend},
};
use fjall::{Database, KeyspaceCreateOptions};

#[test]
fn fjall_fresh_open_persists_genesis_checkpoint() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-genesis-{}-{unique}",
        std::process::id()
    ));

    let _ = std::fs::remove_dir_all(&db_path);

    let path = db_path.to_str().unwrap();

    let backend = FjallBackend::open(path).unwrap();
    drop(backend);

    let db = Database::builder(path).open().unwrap();
    let checkpoint = db
        .keyspace("audit_checkpoint", KeyspaceCreateOptions::default)
        .unwrap();

    let raw = checkpoint
        .get(b"current")
        .unwrap()
        .expect("genesis checkpoint must exist after open");

    let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();

    assert_eq!(value["expected_count"].as_u64(), Some(0));

    let head = value["expected_head"]
        .as_array()
        .expect("expected_head must be an array");

    assert_eq!(head.len(), 32);
    assert!(head.iter().all(|byte| byte.as_u64() == Some(0)));

    drop(checkpoint);
    drop(db);

    std::fs::remove_dir_all(&db_path).unwrap();
}

#[test]
fn fjall_open_rejects_existing_records_without_checkpoint() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-missing-checkpoint-{}-{unique}",
        std::process::id()
    ));

    let _ = std::fs::remove_dir_all(&db_path);

    let path = db_path.to_str().unwrap();

    let db = Database::builder(path).open().unwrap();
    let personal = db
        .keyspace("records_personal", KeyspaceCreateOptions::default)
        .unwrap();

    let record = Record::new(
        "rec:unanchored",
        DataTier::Personal,
        "owner",
        vec![1, 2, 3],
        [0u8; 32],
    )
    .unwrap();

    let json = serde_json::to_vec(&record).unwrap();

    personal.insert(record.id.as_bytes(), json).unwrap();

    drop(personal);
    drop(db);

    let result = FjallBackend::open(path);

    assert!(matches!(result, Err(EdisonError::AuditChainBroken)));

    std::fs::remove_dir_all(&db_path).unwrap();
}

#[test]
fn fjall_open_rejects_unanchored_records_with_valid_checkpoint() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-unanchored-records-{}-{unique}",
        std::process::id()
    ));

    let _ = std::fs::remove_dir_all(&db_path);

    let path = db_path.to_str().unwrap();

    let db = Database::builder(path).open().unwrap();

    let personal = db
        .keyspace("records_personal", KeyspaceCreateOptions::default)
        .unwrap();

    let checkpoint = db
        .keyspace("audit_checkpoint", KeyspaceCreateOptions::default)
        .unwrap();

    let record = Record::new(
        "rec:unanchored-present-checkpoint",
        DataTier::Personal,
        "owner",
        vec![1, 2, 3],
        [0u8; 32],
    )
    .unwrap();

    let record_json = serde_json::to_vec(&record).unwrap();

    personal.insert(record.id.as_bytes(), record_json).unwrap();

    let genesis_checkpoint = serde_json::json!({
        "expected_count": 0,
        "expected_head": vec![0u8; 32],
    });

    let checkpoint_json = serde_json::to_vec(&genesis_checkpoint).unwrap();

    checkpoint.insert(b"current", checkpoint_json).unwrap();

    drop(personal);
    drop(checkpoint);
    drop(db);

    let result = FjallBackend::open(path);

    assert!(matches!(result, Err(EdisonError::AuditChainBroken)));

    std::fs::remove_dir_all(&db_path).unwrap();
}

#[test]
fn fjall_reopen_after_write_preserves_checkpoint_coherence() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-reopen-write-{}-{unique}",
        std::process::id()
    ));

    let _ = std::fs::remove_dir_all(&db_path);

    let path = db_path.to_str().unwrap();

    let mut backend = FjallBackend::open(path).unwrap();

    let record = Record::new(
        "rec:checkpoint-write",
        DataTier::Personal,
        "owner",
        vec![1, 2, 3],
        [0u8; 32],
    )
    .unwrap();

    backend.write(record).unwrap();

    let cached_count = backend.audit_count();
    let cached_head = backend
        .audit_entries()
        .last()
        .expect("write must create an audit entry")
        .entry_hash;

    assert_eq!(cached_count, 1);

    drop(backend);

    let reopened = FjallBackend::open(path).unwrap();

    assert_eq!(reopened.audit_count(), cached_count);

    let reopened_head = reopened
        .audit_entries()
        .last()
        .expect("reopened audit chain must contain write entry")
        .entry_hash;

    assert_eq!(reopened_head, cached_head);

    drop(reopened);

    let db = Database::builder(path).open().unwrap();
    let checkpoint = db
        .keyspace("audit_checkpoint", KeyspaceCreateOptions::default)
        .unwrap();

    let raw = checkpoint
        .get(b"current")
        .unwrap()
        .expect("checkpoint must exist after write");

    let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();

    assert_eq!(value["expected_count"].as_u64(), Some(cached_count as u64));

    let persisted_head = value["expected_head"]
        .as_array()
        .expect("expected_head must be an array");

    let persisted_head: Vec<u8> = persisted_head
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect();

    assert_eq!(persisted_head.as_slice(), cached_head.as_slice());

    drop(checkpoint);
    drop(db);

    std::fs::remove_dir_all(&db_path).unwrap();
}

#[test]
fn fjall_reopen_after_delete_preserves_checkpoint_coherence() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-reopen-delete-{}-{unique}",
        std::process::id()
    ));

    let _ = std::fs::remove_dir_all(&db_path);

    let path = db_path.to_str().unwrap();

    let mut backend = FjallBackend::open(path).unwrap();

    let record = Record::new(
        "rec:checkpoint-delete",
        DataTier::Personal,
        "owner",
        vec![4, 5, 6],
        [0u8; 32],
    )
    .unwrap();

    backend.write(record).unwrap();
    backend.delete("rec:checkpoint-delete", "owner").unwrap();

    let cached_count = backend.audit_count();
    let cached_head = backend
        .audit_entries()
        .last()
        .expect("delete must create an audit entry")
        .entry_hash;

    assert_eq!(cached_count, 2);
    assert!(backend.list_by_owner("owner").unwrap().is_empty());

    drop(backend);

    let reopened = FjallBackend::open(path).unwrap();

    assert_eq!(reopened.audit_count(), cached_count);
    assert!(reopened.list_by_owner("owner").unwrap().is_empty());

    let reopened_head = reopened
        .audit_entries()
        .last()
        .expect("reopened audit chain must contain delete entry")
        .entry_hash;

    assert_eq!(reopened_head, cached_head);

    drop(reopened);

    let db = Database::builder(path).open().unwrap();

    let personal = db
        .keyspace("records_personal", KeyspaceCreateOptions::default)
        .unwrap();

    assert!(personal.get(b"rec:checkpoint-delete").unwrap().is_none());

    let checkpoint = db
        .keyspace("audit_checkpoint", KeyspaceCreateOptions::default)
        .unwrap();

    let raw = checkpoint
        .get(b"current")
        .unwrap()
        .expect("checkpoint must exist after delete");

    let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();

    assert_eq!(value["expected_count"].as_u64(), Some(cached_count as u64));

    let persisted_head = value["expected_head"]
        .as_array()
        .expect("expected_head must be an array");

    let persisted_head: Vec<u8> = persisted_head
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect();

    assert_eq!(persisted_head.as_slice(), cached_head.as_slice());

    drop(checkpoint);
    drop(personal);
    drop(db);

    std::fs::remove_dir_all(&db_path).unwrap();
}

#[test]
fn fjall_reopen_after_read_granted_preserves_checkpoint_coherence() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-reopen-read-granted-{}-{unique}",
        std::process::id()
    ));

    let _ = std::fs::remove_dir_all(&db_path);

    let path = db_path.to_str().unwrap();

    let mut backend = FjallBackend::open(path).unwrap();

    let record = Record::new(
        "rec:checkpoint-read-granted",
        DataTier::Personal,
        "owner",
        vec![7, 8, 9],
        [0u8; 32],
    )
    .unwrap();

    backend.write(record).unwrap();

    let returned = backend
        .read("rec:checkpoint-read-granted", "owner")
        .unwrap();

    assert_eq!(returned.id, "rec:checkpoint-read-granted");

    let cached_count = backend.audit_count();
    let cached_head = backend
        .audit_entries()
        .last()
        .expect("granted read must create an audit entry")
        .entry_hash;

    assert_eq!(cached_count, 2);

    drop(backend);

    let reopened = FjallBackend::open(path).unwrap();

    assert_eq!(reopened.audit_count(), cached_count);

    let records = reopened.list_by_owner("owner").unwrap();

    assert!(
        records
            .iter()
            .any(|record| record.id == "rec:checkpoint-read-granted")
    );

    let reopened_head = reopened
        .audit_entries()
        .last()
        .expect("reopened audit chain must contain granted-read entry")
        .entry_hash;

    assert_eq!(reopened_head, cached_head);

    drop(reopened);

    let db = Database::builder(path).open().unwrap();

    let checkpoint = db
        .keyspace("audit_checkpoint", KeyspaceCreateOptions::default)
        .unwrap();

    let raw = checkpoint
        .get(b"current")
        .unwrap()
        .expect("checkpoint must exist after granted read");

    let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();

    assert_eq!(value["expected_count"].as_u64(), Some(cached_count as u64));

    let persisted_head = value["expected_head"]
        .as_array()
        .expect("expected_head must be an array");

    let persisted_head: Vec<u8> = persisted_head
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect();

    assert_eq!(persisted_head.as_slice(), cached_head.as_slice());

    drop(checkpoint);
    drop(db);

    std::fs::remove_dir_all(&db_path).unwrap();
}

#[test]
fn fjall_reopen_after_read_denied_preserves_checkpoint_coherence() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-reopen-read-denied-{}-{unique}",
        std::process::id()
    ));

    let _ = std::fs::remove_dir_all(&db_path);

    let path = db_path.to_str().unwrap();

    let mut backend = FjallBackend::open(path).unwrap();

    let record = Record::new(
        "rec:checkpoint-read-denied",
        DataTier::Personal,
        "owner",
        vec![10, 11, 12],
        [0u8; 32],
    )
    .unwrap();

    backend.write(record).unwrap();

    let result = backend.read("rec:checkpoint-read-denied", "not-owner");

    assert!(matches!(result, Err(EdisonError::AccessDenied)));

    let cached_count = backend.audit_count();
    let cached_head = backend
        .audit_entries()
        .last()
        .expect("denied read must create an audit entry")
        .entry_hash;

    assert_eq!(cached_count, 2);

    let records = backend.list_by_owner("owner").unwrap();

    assert!(
        records
            .iter()
            .any(|record| record.id == "rec:checkpoint-read-denied")
    );

    drop(backend);

    let reopened = FjallBackend::open(path).unwrap();

    assert_eq!(reopened.audit_count(), cached_count);

    let reopened_records = reopened.list_by_owner("owner").unwrap();

    assert!(
        reopened_records
            .iter()
            .any(|record| record.id == "rec:checkpoint-read-denied")
    );

    let reopened_head = reopened
        .audit_entries()
        .last()
        .expect("reopened audit chain must contain denied-read entry")
        .entry_hash;

    assert_eq!(reopened_head, cached_head);

    drop(reopened);

    let db = Database::builder(path).open().unwrap();

    let checkpoint = db
        .keyspace("audit_checkpoint", KeyspaceCreateOptions::default)
        .unwrap();

    let raw = checkpoint
        .get(b"current")
        .unwrap()
        .expect("checkpoint must exist after denied read");

    let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();

    assert_eq!(value["expected_count"].as_u64(), Some(cached_count as u64));

    let persisted_head = value["expected_head"]
        .as_array()
        .expect("expected_head must be an array");

    let persisted_head: Vec<u8> = persisted_head
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect();

    assert_eq!(persisted_head.as_slice(), cached_head.as_slice());

    drop(checkpoint);
    drop(db);

    std::fs::remove_dir_all(&db_path).unwrap();
}

#[test]
fn redb_fresh_open_persists_genesis_checkpoint() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-redb-genesis-{}-{unique}.redb",
        std::process::id()
    ));

    let _ = std::fs::remove_file(&db_path);

    let path = db_path.to_str().unwrap();

    let backend = edisondb::backends::RedbBackend::open(path).unwrap();

    assert_eq!(backend.audit_count(), 0);

    drop(backend);

    const CHECKPOINT: redb::TableDefinition<&str, &str> =
        redb::TableDefinition::new("audit_checkpoint");

    let db = redb::Database::open(path).unwrap();
    let txn = db.begin_read().unwrap();
    let table = txn.open_table(CHECKPOINT).unwrap();

    let raw = table
        .get("current")
        .unwrap()
        .expect("genesis checkpoint must exist");

    let value: serde_json::Value = serde_json::from_str(raw.value()).unwrap();

    assert_eq!(value["expected_count"].as_u64(), Some(0));

    let persisted_head = value["expected_head"]
        .as_array()
        .expect("expected_head must be an array");

    assert_eq!(persisted_head.len(), 32);

    assert!(persisted_head.iter().all(|byte| byte.as_u64() == Some(0)));

    drop(raw);
    drop(table);
    drop(txn);
    drop(db);

    std::fs::remove_file(&db_path).unwrap();
}

#[test]
fn redb_open_rejects_existing_records_without_checkpoint() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-redb-missing-checkpoint-{}-{unique}.redb",
        std::process::id()
    ));

    let _ = std::fs::remove_file(&db_path);

    let path = db_path.to_str().unwrap();

    let record = Record::new(
        "rec:redb-missing-checkpoint",
        DataTier::Personal,
        "owner",
        vec![1, 2, 3],
        [0u8; 32],
    )
    .unwrap();

    const RECORDS: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("records");

    {
        let db = redb::Database::create(path).unwrap();
        let txn = db.begin_write().unwrap();

        {
            let mut table = txn.open_table(RECORDS).unwrap();

            let json = serde_json::to_string(&record).unwrap();

            table.insert(record.id.as_str(), json.as_str()).unwrap();
        }

        txn.commit().unwrap();
    }

    let result = edisondb::backends::RedbBackend::open(path);

    assert!(matches!(result, Err(EdisonError::AuditChainBroken)));

    std::fs::remove_file(&db_path).unwrap();
}

#[test]
fn redb_open_rejects_unanchored_records_with_valid_checkpoint() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-redb-unanchored-{}-{unique}.redb",
        std::process::id()
    ));

    let _ = std::fs::remove_file(&db_path);

    let path = db_path.to_str().unwrap();

    let record = Record::new(
        "rec:redb-unanchored",
        DataTier::Personal,
        "owner",
        vec![4, 5, 6],
        [0u8; 32],
    )
    .unwrap();

    const RECORDS: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("records");

    const CHECKPOINT: redb::TableDefinition<&str, &str> =
        redb::TableDefinition::new("audit_checkpoint");

    {
        let db = redb::Database::create(path).unwrap();
        let txn = db.begin_write().unwrap();

        {
            let mut table = txn.open_table(RECORDS).unwrap();

            let json = serde_json::to_string(&record).unwrap();

            table.insert(record.id.as_str(), json.as_str()).unwrap();
        }

        {
            let mut table = txn.open_table(CHECKPOINT).unwrap();

            let checkpoint = serde_json::json!({
                "expected_count": 0,
                "expected_head": vec![0u8; 32],
            });

            let json = serde_json::to_string(&checkpoint).unwrap();

            table.insert("current", json.as_str()).unwrap();
        }

        txn.commit().unwrap();
    }

    let result = edisondb::backends::RedbBackend::open(path);

    assert!(matches!(result, Err(EdisonError::AuditChainBroken)));

    std::fs::remove_file(&db_path).unwrap();
}

#[test]
fn redb_reopen_after_write_save_preserves_checkpoint_coherence() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-redb-reopen-write-{}-{unique}.redb",
        std::process::id()
    ));

    let _ = std::fs::remove_file(&db_path);

    let path = db_path.to_str().unwrap();

    let mut backend = edisondb::backends::RedbBackend::open(path).unwrap();

    let record = Record::new(
        "rec:redb-checkpoint-write",
        DataTier::Personal,
        "owner",
        vec![7, 8, 9],
        [0u8; 32],
    )
    .unwrap();

    backend.write(record).unwrap();

    let cached_count = backend.audit_count();

    let audit_entries = backend.audit_entries();

    let cached_head = audit_entries
        .last()
        .expect("write must create an audit entry")
        .entry_hash;

    assert_eq!(cached_count, 1);

    backend.save().unwrap();

    drop(backend);

    let reopened = edisondb::backends::RedbBackend::open(path).unwrap();

    assert_eq!(reopened.audit_count(), cached_count);

    let records = reopened.list_by_owner("owner").unwrap();

    assert!(
        records
            .iter()
            .any(|record| record.id == "rec:redb-checkpoint-write")
    );

    let reopened_entries = reopened.audit_entries();

    let reopened_head = reopened_entries
        .last()
        .expect("reopened audit chain must contain write entry")
        .entry_hash;

    assert_eq!(reopened_head, cached_head);

    drop(reopened);

    const CHECKPOINT: redb::TableDefinition<&str, &str> =
        redb::TableDefinition::new("audit_checkpoint");

    let db = redb::Database::open(path).unwrap();
    let txn = db.begin_read().unwrap();
    let table = txn.open_table(CHECKPOINT).unwrap();

    let raw = table
        .get("current")
        .unwrap()
        .expect("checkpoint must exist after save");

    let value: serde_json::Value = serde_json::from_str(raw.value()).unwrap();

    assert_eq!(value["expected_count"].as_u64(), Some(cached_count as u64));

    let persisted_head = value["expected_head"]
        .as_array()
        .expect("expected_head must be an array");

    let persisted_head: Vec<u8> = persisted_head
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect();

    assert_eq!(persisted_head.as_slice(), cached_head.as_slice());

    drop(raw);
    drop(table);
    drop(txn);
    drop(db);

    std::fs::remove_file(&db_path).unwrap();
}

#[test]
fn redb_reopen_after_delete_save_preserves_checkpoint_coherence() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-redb-reopen-delete-{}-{unique}.redb",
        std::process::id()
    ));

    let _ = std::fs::remove_file(&db_path);

    let path = db_path.to_str().unwrap();

    let mut backend = edisondb::backends::RedbBackend::open(path).unwrap();

    let record = Record::new(
        "rec:redb-checkpoint-delete",
        DataTier::Personal,
        "owner",
        vec![10, 11, 12],
        [0u8; 32],
    )
    .unwrap();

    backend.write(record).unwrap();
    backend
        .delete("rec:redb-checkpoint-delete", "owner")
        .unwrap();

    let cached_count = backend.audit_count();

    let audit_entries = backend.audit_entries();

    let cached_head = audit_entries
        .last()
        .expect("delete must create an audit entry")
        .entry_hash;

    assert_eq!(cached_count, 2);
    assert!(backend.list_by_owner("owner").unwrap().is_empty());

    backend.save().unwrap();

    drop(backend);

    let reopened = edisondb::backends::RedbBackend::open(path).unwrap();

    assert_eq!(reopened.audit_count(), cached_count);
    assert!(reopened.list_by_owner("owner").unwrap().is_empty());

    let reopened_entries = reopened.audit_entries();

    let reopened_head = reopened_entries
        .last()
        .expect("reopened audit chain must contain delete entry")
        .entry_hash;

    assert_eq!(reopened_head, cached_head);

    drop(reopened);

    const RECORDS: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("records");

    const CHECKPOINT: redb::TableDefinition<&str, &str> =
        redb::TableDefinition::new("audit_checkpoint");

    let db = redb::Database::open(path).unwrap();
    let txn = db.begin_read().unwrap();

    {
        let table = txn.open_table(RECORDS).unwrap();

        assert!(table.get("rec:redb-checkpoint-delete").unwrap().is_none());
    }

    {
        let table = txn.open_table(CHECKPOINT).unwrap();

        let raw = table
            .get("current")
            .unwrap()
            .expect("checkpoint must exist after delete save");

        let value: serde_json::Value = serde_json::from_str(raw.value()).unwrap();

        assert_eq!(value["expected_count"].as_u64(), Some(cached_count as u64));

        let persisted_head = value["expected_head"]
            .as_array()
            .expect("expected_head must be an array");

        let persisted_head: Vec<u8> = persisted_head
            .iter()
            .map(|byte| byte.as_u64().unwrap() as u8)
            .collect();

        assert_eq!(persisted_head.as_slice(), cached_head.as_slice());
    }

    drop(txn);
    drop(db);

    std::fs::remove_file(&db_path).unwrap();
}

#[test]
fn redb_reopen_after_read_granted_save_preserves_checkpoint_coherence() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-redb-reopen-read-granted-{}-{unique}.redb",
        std::process::id()
    ));

    let _ = std::fs::remove_file(&db_path);

    let path = db_path.to_str().unwrap();

    let mut backend = edisondb::backends::RedbBackend::open(path).unwrap();

    let record = Record::new(
        "rec:redb-checkpoint-read-granted",
        DataTier::Personal,
        "owner",
        vec![13, 14, 15],
        [0u8; 32],
    )
    .unwrap();

    backend.write(record).unwrap();

    let returned = backend
        .read("rec:redb-checkpoint-read-granted", "owner")
        .unwrap();

    assert_eq!(returned.id, "rec:redb-checkpoint-read-granted");

    let cached_count = backend.audit_count();

    let cached_head = backend
        .audit_entries()
        .last()
        .expect("granted read must create an audit entry")
        .entry_hash;

    assert_eq!(cached_count, 2);

    backend.save().unwrap();

    drop(backend);

    let reopened = edisondb::backends::RedbBackend::open(path).unwrap();

    assert_eq!(reopened.audit_count(), cached_count);

    let records = reopened.list_by_owner("owner").unwrap();

    assert!(
        records
            .iter()
            .any(|record| { record.id == "rec:redb-checkpoint-read-granted" })
    );

    let reopened_head = reopened
        .audit_entries()
        .last()
        .expect("reopened audit chain must contain granted-read entry")
        .entry_hash;

    assert_eq!(reopened_head, cached_head);

    drop(reopened);

    const CHECKPOINT: redb::TableDefinition<&str, &str> =
        redb::TableDefinition::new("audit_checkpoint");

    let db = redb::Database::open(path).unwrap();
    let txn = db.begin_read().unwrap();
    let table = txn.open_table(CHECKPOINT).unwrap();

    let raw = table
        .get("current")
        .unwrap()
        .expect("checkpoint must exist after granted-read save");

    let value: serde_json::Value = serde_json::from_str(raw.value()).unwrap();

    assert_eq!(value["expected_count"].as_u64(), Some(cached_count as u64));

    let persisted_head = value["expected_head"]
        .as_array()
        .expect("expected_head must be an array");

    let persisted_head: Vec<u8> = persisted_head
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect();

    assert_eq!(persisted_head.as_slice(), cached_head.as_slice());

    drop(raw);
    drop(table);
    drop(txn);
    drop(db);

    std::fs::remove_file(&db_path).unwrap();
}

#[test]
fn redb_reopen_after_read_denied_save_preserves_checkpoint_coherence() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-redb-reopen-read-denied-{}-{unique}.redb",
        std::process::id()
    ));

    let _ = std::fs::remove_file(&db_path);

    let path = db_path.to_str().unwrap();

    let mut backend = edisondb::backends::RedbBackend::open(path).unwrap();

    let record = Record::new(
        "rec:redb-checkpoint-read-denied",
        DataTier::Personal,
        "owner",
        vec![16, 17, 18],
        [0u8; 32],
    )
    .unwrap();

    backend.write(record).unwrap();

    let result = backend.read("rec:redb-checkpoint-read-denied", "not-owner");

    assert!(matches!(result, Err(EdisonError::AccessDenied)));

    let cached_count = backend.audit_count();

    let cached_head = backend
        .audit_entries()
        .last()
        .expect("denied read must create an audit entry")
        .entry_hash;

    assert_eq!(cached_count, 2);

    let records = backend.list_by_owner("owner").unwrap();

    assert!(
        records
            .iter()
            .any(|record| { record.id == "rec:redb-checkpoint-read-denied" })
    );

    backend.save().unwrap();

    drop(backend);

    let reopened = edisondb::backends::RedbBackend::open(path).unwrap();

    assert_eq!(reopened.audit_count(), cached_count);

    let reopened_records = reopened.list_by_owner("owner").unwrap();

    assert!(
        reopened_records
            .iter()
            .any(|record| { record.id == "rec:redb-checkpoint-read-denied" })
    );

    let reopened_head = reopened
        .audit_entries()
        .last()
        .expect("reopened audit chain must contain denied-read entry")
        .entry_hash;

    assert_eq!(reopened_head, cached_head);

    drop(reopened);

    const CHECKPOINT: redb::TableDefinition<&str, &str> =
        redb::TableDefinition::new("audit_checkpoint");

    let db = redb::Database::open(path).unwrap();
    let txn = db.begin_read().unwrap();
    let table = txn.open_table(CHECKPOINT).unwrap();

    let raw = table
        .get("current")
        .unwrap()
        .expect("checkpoint must exist after denied-read save");

    let value: serde_json::Value = serde_json::from_str(raw.value()).unwrap();

    assert_eq!(value["expected_count"].as_u64(), Some(cached_count as u64));

    let persisted_head = value["expected_head"]
        .as_array()
        .expect("expected_head must be an array");

    let persisted_head: Vec<u8> = persisted_head
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect();

    assert_eq!(persisted_head.as_slice(), cached_head.as_slice());

    drop(raw);
    drop(table);
    drop(txn);
    drop(db);

    std::fs::remove_file(&db_path).unwrap();
}

#[test]
fn redb_open_rejects_final_audit_row_deletion_against_checkpoint() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-redb-tail-drop-{}-{unique}.redb",
        std::process::id()
    ));

    let _ = std::fs::remove_file(&db_path);

    let path = db_path.to_str().unwrap();

    let mut backend = edisondb::backends::RedbBackend::open(path).unwrap();

    let first = Record::new(
        "rec:redb-tail-drop-1",
        DataTier::Personal,
        "owner",
        vec![19],
        [0u8; 32],
    )
    .unwrap();

    let second = Record::new(
        "rec:redb-tail-drop-2",
        DataTier::Personal,
        "owner",
        vec![20],
        [0u8; 32],
    )
    .unwrap();

    backend.write(first).unwrap();
    backend.write(second).unwrap();

    assert_eq!(backend.audit_count(), 2);

    backend.save().unwrap();

    drop(backend);

    const AUDIT: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("audit");

    {
        let db = redb::Database::open(path).unwrap();
        let txn = db.begin_write().unwrap();

        {
            let mut table = txn.open_table(AUDIT).unwrap();

            let removed = table.remove("00000000000000000001").unwrap();

            assert!(
                removed.is_some(),
                "final persisted audit row must exist before deletion"
            );
        }

        txn.commit().unwrap();
    }

    let result = edisondb::backends::RedbBackend::open(path);

    assert!(matches!(result, Err(EdisonError::AuditChainBroken)));

    std::fs::remove_file(&db_path).unwrap();
}

#[test]
fn fjall_open_rejects_final_audit_row_deletion_against_checkpoint() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-fjall-tail-drop-{}-{unique}",
        std::process::id()
    ));

    let _ = std::fs::remove_dir_all(&db_path);

    let path = db_path.to_str().unwrap();

    let mut backend = FjallBackend::open(path).unwrap();

    let first = Record::new(
        "rec:fjall-tail-drop-1",
        DataTier::Personal,
        "owner",
        vec![21],
        [0u8; 32],
    )
    .unwrap();

    let second = Record::new(
        "rec:fjall-tail-drop-2",
        DataTier::Personal,
        "owner",
        vec![22],
        [0u8; 32],
    )
    .unwrap();

    backend.write(first).unwrap();
    backend.write(second).unwrap();

    assert_eq!(backend.audit_count(), 2);

    drop(backend);

    {
        let db = Database::builder(path).open().unwrap();

        let audit = db
            .keyspace("audit", KeyspaceCreateOptions::default)
            .unwrap();

        let checkpoint = db
            .keyspace("audit_checkpoint", KeyspaceCreateOptions::default)
            .unwrap();

        assert!(
            audit.get(b"00000000000000000001").unwrap().is_some(),
            "final persisted audit row must exist before deletion"
        );

        assert!(
            checkpoint.get(b"current").unwrap().is_some(),
            "checkpoint must remain present during tail deletion"
        );

        audit.remove(b"00000000000000000001").unwrap();

        assert!(
            audit.get(b"00000000000000000001").unwrap().is_none(),
            "final persisted audit row must be removed"
        );

        assert!(
            checkpoint.get(b"current").unwrap().is_some(),
            "checkpoint must remain untouched"
        );

        drop(checkpoint);
        drop(audit);
        drop(db);
    }

    let result = FjallBackend::open(path);

    assert!(matches!(result, Err(EdisonError::AuditChainBroken)));

    std::fs::remove_dir_all(&db_path).unwrap();
}

#[test]
fn redb_open_rejects_malformed_checkpoint() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-redb-malformed-checkpoint-{}-{unique}.redb",
        std::process::id()
    ));

    let _ = std::fs::remove_file(&db_path);

    let path = db_path.to_str().unwrap();

    let backend = edisondb::backends::RedbBackend::open(path).unwrap();

    drop(backend);

    const CHECKPOINT: redb::TableDefinition<&str, &str> =
        redb::TableDefinition::new("audit_checkpoint");

    {
        let db = redb::Database::open(path).unwrap();
        let txn = db.begin_write().unwrap();

        {
            let mut table = txn.open_table(CHECKPOINT).unwrap();

            table.insert("current", "{malformed-checkpoint").unwrap();
        }

        txn.commit().unwrap();
    }

    let result = edisondb::backends::RedbBackend::open(path);

    assert!(matches!(result, Err(EdisonError::AuditChainBroken)));

    std::fs::remove_file(&db_path).unwrap();
}

#[test]
fn redb_open_rejects_checkpoint_count_mismatch() {
    use redb::ReadableTable as _;

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-redb-count-mismatch-{}-{unique}.redb",
        std::process::id()
    ));

    let _ = std::fs::remove_file(&db_path);

    let path = db_path.to_str().unwrap();

    let mut backend = edisondb::backends::RedbBackend::open(path).unwrap();

    let record = Record::new(
        "rec:redb-count-mismatch",
        DataTier::Personal,
        "owner",
        vec![23],
        [0u8; 32],
    )
    .unwrap();

    backend.write(record).unwrap();
    backend.save().unwrap();

    drop(backend);

    const CHECKPOINT: redb::TableDefinition<&str, &str> =
        redb::TableDefinition::new("audit_checkpoint");

    {
        let db = redb::Database::open(path).unwrap();
        let txn = db.begin_write().unwrap();

        {
            let mut table = txn.open_table(CHECKPOINT).unwrap();

            let raw = table
                .get("current")
                .unwrap()
                .expect("checkpoint must exist");

            let mut value: serde_json::Value = serde_json::from_str(raw.value()).unwrap();

            drop(raw);

            value["expected_count"] = serde_json::Value::from(2u64);

            let json = serde_json::to_string(&value).unwrap();

            table.insert("current", json.as_str()).unwrap();
        }

        txn.commit().unwrap();
    }

    let result = edisondb::backends::RedbBackend::open(path);

    assert!(matches!(result, Err(EdisonError::AuditChainBroken)));

    std::fs::remove_file(&db_path).unwrap();
}

#[test]
fn redb_open_rejects_checkpoint_head_mismatch() {
    use redb::ReadableTable as _;

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-redb-head-mismatch-{}-{unique}.redb",
        std::process::id()
    ));

    let _ = std::fs::remove_file(&db_path);

    let path = db_path.to_str().unwrap();

    let mut backend = edisondb::backends::RedbBackend::open(path).unwrap();

    let record = Record::new(
        "rec:redb-head-mismatch",
        DataTier::Personal,
        "owner",
        vec![24],
        [0u8; 32],
    )
    .unwrap();

    backend.write(record).unwrap();
    backend.save().unwrap();

    drop(backend);

    const CHECKPOINT: redb::TableDefinition<&str, &str> =
        redb::TableDefinition::new("audit_checkpoint");

    {
        let db = redb::Database::open(path).unwrap();
        let txn = db.begin_write().unwrap();

        {
            let mut table = txn.open_table(CHECKPOINT).unwrap();

            let raw = table
                .get("current")
                .unwrap()
                .expect("checkpoint must exist");

            let mut value: serde_json::Value = serde_json::from_str(raw.value()).unwrap();

            drop(raw);

            assert_eq!(value["expected_count"].as_u64(), Some(1));

            let head = value["expected_head"]
                .as_array_mut()
                .expect("expected_head must be an array");

            assert_eq!(head.len(), 32);

            let first = head[0].as_u64().expect("head byte must be numeric") as u8;

            head[0] = serde_json::Value::from((first ^ 1) as u64);

            let json = serde_json::to_string(&value).unwrap();

            table.insert("current", json.as_str()).unwrap();
        }

        txn.commit().unwrap();
    }

    let result = edisondb::backends::RedbBackend::open(path);

    assert!(matches!(result, Err(EdisonError::AuditChainBroken)));

    std::fs::remove_file(&db_path).unwrap();
}

#[test]
fn fjall_open_rejects_malformed_checkpoint() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-fjall-malformed-checkpoint-{}-{unique}",
        std::process::id()
    ));

    let _ = std::fs::remove_dir_all(&db_path);

    let path = db_path.to_str().unwrap();

    let backend = FjallBackend::open(path).unwrap();

    drop(backend);

    {
        let db = Database::builder(path).open().unwrap();

        let checkpoint = db
            .keyspace("audit_checkpoint", KeyspaceCreateOptions::default)
            .unwrap();

        let mut batch = db.batch();

        batch.insert(&checkpoint, b"current", b"{malformed-checkpoint");

        batch.commit().unwrap();

        drop(checkpoint);
        drop(db);
    }

    let result = FjallBackend::open(path);

    assert!(matches!(result, Err(EdisonError::AuditChainBroken)));

    std::fs::remove_dir_all(&db_path).unwrap();
}

#[test]
fn fjall_open_rejects_checkpoint_count_mismatch() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-fjall-count-mismatch-{}-{unique}",
        std::process::id()
    ));

    let _ = std::fs::remove_dir_all(&db_path);

    let path = db_path.to_str().unwrap();

    let mut backend = FjallBackend::open(path).unwrap();

    let record = Record::new(
        "rec:fjall-count-mismatch",
        DataTier::Personal,
        "owner",
        vec![25],
        [0u8; 32],
    )
    .unwrap();

    backend.write(record).unwrap();

    assert_eq!(backend.audit_count(), 1);

    drop(backend);

    {
        let db = Database::builder(path).open().unwrap();

        let checkpoint = db
            .keyspace("audit_checkpoint", KeyspaceCreateOptions::default)
            .unwrap();

        let raw = checkpoint
            .get(b"current")
            .unwrap()
            .expect("checkpoint must exist");

        let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();

        assert_eq!(value["expected_count"].as_u64(), Some(1));

        value["expected_count"] = serde_json::Value::from(2u64);

        let json = serde_json::to_vec(&value).unwrap();

        let mut batch = db.batch();

        batch.insert(&checkpoint, b"current", json);

        batch.commit().unwrap();

        drop(checkpoint);
        drop(db);
    }

    let result = FjallBackend::open(path);

    assert!(matches!(result, Err(EdisonError::AuditChainBroken)));

    std::fs::remove_dir_all(&db_path).unwrap();
}

#[test]
fn fjall_open_rejects_checkpoint_head_mismatch() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = std::env::temp_dir().join(format!(
        "edisondb-fv4b-fjall-head-mismatch-{}-{unique}",
        std::process::id()
    ));

    let _ = std::fs::remove_dir_all(&db_path);

    let path = db_path.to_str().unwrap();

    let mut backend = FjallBackend::open(path).unwrap();

    let record = Record::new(
        "rec:fjall-head-mismatch",
        DataTier::Personal,
        "owner",
        vec![26],
        [0u8; 32],
    )
    .unwrap();

    backend.write(record).unwrap();

    assert_eq!(backend.audit_count(), 1);

    drop(backend);

    {
        let db = Database::builder(path).open().unwrap();

        let checkpoint = db
            .keyspace("audit_checkpoint", KeyspaceCreateOptions::default)
            .unwrap();

        let raw = checkpoint
            .get(b"current")
            .unwrap()
            .expect("checkpoint must exist");

        let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();

        assert_eq!(value["expected_count"].as_u64(), Some(1));

        let head = value["expected_head"]
            .as_array_mut()
            .expect("expected_head must be an array");

        assert_eq!(head.len(), 32);

        let first = head[0].as_u64().expect("head byte must be numeric") as u8;

        head[0] = serde_json::Value::from((first ^ 1) as u64);

        let json = serde_json::to_vec(&value).unwrap();

        let mut batch = db.batch();

        batch.insert(&checkpoint, b"current", json);

        batch.commit().unwrap();

        drop(checkpoint);
        drop(db);
    }

    let result = FjallBackend::open(path);

    assert!(matches!(result, Err(EdisonError::AuditChainBroken)));

    std::fs::remove_dir_all(&db_path).unwrap();
}
