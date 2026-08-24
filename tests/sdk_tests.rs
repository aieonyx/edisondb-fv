//! EdisonDB SDK integration tests

use edisondb::sdk::EdisonDB;

fn fresh(path: &str) -> EdisonDB {
    let _ = std::fs::remove_file(path);
    EdisonDB::connect(path, "alice", "password").unwrap()
}

#[test]
fn sdk_write_and_read() {
    let mut db = fresh("/tmp/sdk_test_1.redb");
    db.write("user:1", "PERSONAL", "sovereign data").unwrap();
    let rec = db.read("user:1").unwrap().unwrap();
    assert_eq!(rec.payload, "sovereign data");
    assert_eq!(rec.tier, "personal");
}

#[test]
fn sdk_read_nonexistent_returns_none() {
    let mut db = fresh("/tmp/sdk_test_2.redb");
    let rec = db.read("ghost").unwrap();
    assert!(rec.is_none());
}

#[test]
fn sdk_delete_removes_record() {
    let mut db = fresh("/tmp/sdk_test_3.redb");
    db.write("doc:1", "NOISE", "log entry").unwrap();
    db.delete("doc:1").unwrap();
    assert!(db.read("doc:1").unwrap().is_none());
}

#[test]
fn sdk_list_returns_all_records() {
    let mut db = fresh("/tmp/sdk_test_4.redb");
    db.write("a", "CRITICAL", "secret").unwrap();
    db.write("b", "NOISE", "log").unwrap();
    let records = db.list(None).unwrap();
    assert_eq!(records.len(), 2);
}

#[test]
fn sdk_list_tier_filter() {
    let mut db = fresh("/tmp/sdk_test_5.redb");
    db.write("a", "CRITICAL", "secret").unwrap();
    db.write("b", "NOISE", "log").unwrap();
    let critical = db.list(Some("CRITICAL")).unwrap();
    assert_eq!(critical.len(), 1);
    assert_eq!(critical[0].id, "a");
}

#[test]
fn sdk_verify_chain_passes() {
    let mut db = fresh("/tmp/sdk_test_6.redb");
    db.write("x", "PERSONAL", "data").unwrap();
    let _ = db.read("x");
    assert!(db.verify().is_ok());
}

#[test]
fn sdk_status_counts_tiers() {
    let mut db = fresh("/tmp/sdk_test_7.redb");
    db.write("c1", "CRITICAL", "a").unwrap();
    db.write("p1", "PERSONAL", "b").unwrap();
    db.write("p2", "PERSONAL", "c").unwrap();
    db.write("n1", "NOISE",    "d").unwrap();
    let stats = db.status().unwrap();
    assert_eq!(stats.critical_count, 1);
    assert_eq!(stats.personal_count, 2);
    assert_eq!(stats.noise_count,    1);
    assert_eq!(stats.record_count,   4);
}

#[test]
fn sdk_backend_is_redb() {
    let db = fresh("/tmp/sdk_test_8.redb");
    assert_eq!(db.backend(), "redb");
}

#[test]
fn sdk_duplicate_write_fails() {
    let mut db = fresh("/tmp/sdk_test_9.redb");
    db.write("k1", "NOISE", "first").unwrap();
    assert!(db.write("k1", "NOISE", "second").is_err());
}
