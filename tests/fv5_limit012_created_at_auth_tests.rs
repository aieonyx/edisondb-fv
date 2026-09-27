use edisondb::{
    DataTier, EdisonError, Record, Store,
    backends::{StorageBackend, fjall::FjallBackend},
};
use fjall::{Database as FjallDatabase, KeyspaceCreateOptions};
use redb::{Database as RedbDatabase, ReadableTable, TableDefinition};

const REDB_RECORDS: TableDefinition<&str, &str> =
    TableDefinition::new("records");

fn redb_path(label: &str) -> String {
    format!(
        "/tmp/edisondb-fv5-limit012-{label}-{}-{}.redb",
        std::process::id(),
        rand::random::<u64>(),
    )
}

fn fjall_path(label: &str) -> String {
    format!(
        "/tmp/edisondb-fv5-limit012-{label}-{}-{}",
        std::process::id(),
        rand::random::<u64>(),
    )
}

fn record(id: &str) -> Record {
    let mut record = Record::new(
        id,
        DataTier::Personal,
        "alice",
        b"LIMIT-012 created_at authenticity witness",
        &[0x42u8; 32],
        [0x24u8; 32],
    )
    .unwrap();

    // Use deterministic nonzero timestamps so this test is about authenticity,
    // not the separate zero-clock boundary in LIMIT-013.
    record.created_at = 100;
    record
}

#[test]
fn limit012_redb_authenticated_load_rejects_nonzero_created_at_tamper() {
    let path = redb_path("redb");
    let _ = std::fs::remove_file(&path);

    let mut store = Store::new();
    store.write(record("rec:limit012-redb")).unwrap();
    store
        .save_authenticated(&path, "limit012-store-secret")
        .unwrap();
    drop(store);

    let db = RedbDatabase::open(&path).unwrap();
    let txn = db.begin_write().unwrap();

    {
        let mut table = txn.open_table(REDB_RECORDS).unwrap();

        let raw = table
            .get("rec:limit012-redb")
            .unwrap()
            .unwrap()
            .value()
            .to_string();

        let mut value: serde_json::Value =
            serde_json::from_str(&raw).unwrap();

        assert_eq!(value["created_at"].as_u64(), Some(100));

        value["created_at"] = serde_json::Value::from(101u64);

        let tampered = serde_json::to_string(&value).unwrap();

        table
            .insert("rec:limit012-redb", tampered.as_str())
            .unwrap();
    }

    txn.commit().unwrap();
    drop(db);

    assert!(matches!(
        Store::load_authenticated(
            &path,
            "limit012-store-secret",
        ),
        Err(EdisonError::AuditChainBroken)
    ));

    let _ = std::fs::remove_file(path);
}

#[test]
fn limit012_fjall_authenticated_open_rejects_nonzero_created_at_tamper() {
    let path = fjall_path("fjall");
    let _ = std::fs::remove_dir_all(&path);

    let mut backend =
        FjallBackend::open_authenticated(
            &path,
            "limit012-store-secret",
        )
        .unwrap();

    backend.write(record("rec:limit012-fjall")).unwrap();
    drop(backend);

    {
        let db = FjallDatabase::builder(&path).open().unwrap();

        let personal = db
            .keyspace(
                "records_personal",
                KeyspaceCreateOptions::default,
            )
            .unwrap();

        let raw = personal
            .get(b"rec:limit012-fjall")
            .unwrap()
            .unwrap();

        let mut value: serde_json::Value =
            serde_json::from_slice(&raw).unwrap();

        assert_eq!(value["created_at"].as_u64(), Some(100));

        value["created_at"] = serde_json::Value::from(101u64);

        personal
            .insert(
                b"rec:limit012-fjall",
                serde_json::to_vec(&value).unwrap(),
            )
            .unwrap();

        drop(personal);
        drop(db);
    }

    assert!(matches!(
        FjallBackend::open_authenticated(
            &path,
            "limit012-store-secret",
        ),
        Err(EdisonError::AuditChainBroken)
    ));

    let _ = std::fs::remove_dir_all(path);
}
