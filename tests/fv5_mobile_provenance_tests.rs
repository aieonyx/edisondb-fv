// Copyright (c) 2026 Edison Lepiten / AIEONYX
// License: Apache-2.0

#![cfg(feature = "mobile")]

use edisondb::mobile::{ArpiHeader, DbError, MobileDb};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn header_for(value: &str, tier: u8) -> [u8; ArpiHeader::SIZE] {
    let mut hash = [0u8; 32];
    hash.copy_from_slice(blake3::hash(value.as_bytes()).as_bytes());

    ArpiHeader {
        magic: *b"ARPi",
        write_counter: 0,
        timestamp_us: 1,
        tier,
        reserved: [0u8; 3],
        blake3_hash: hash,
        node_id: [0u8; 22],
    }
    .to_bytes()
}

fn unique_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch")
        .as_nanos();

    std::env::temp_dir().join(format!(
        "edisondb-fv5-limit004-{}-{nonce}-{label}",
        std::process::id()
    ))
}

#[test]
fn limit004_header_requires_exact_length() {
    let valid = header_for("payload", 1);

    assert!(ArpiHeader::from_bytes(&valid).is_some());
    assert!(ArpiHeader::from_bytes(&valid[..77]).is_none());

    let mut long = valid.to_vec();
    long.push(0);
    assert!(ArpiHeader::from_bytes(&long).is_none());
}

#[test]
fn limit004_header_rejects_invalid_tier() {
    let mut header = header_for("payload", 1);
    header[20] = 3;

    assert!(ArpiHeader::from_bytes(&header).is_none());
}

#[test]
fn limit004_header_rejects_nonzero_reserved_bytes() {
    let mut header = header_for("payload", 1);
    header[21] = 1;

    assert!(ArpiHeader::from_bytes(&header).is_none());
}

#[test]
fn limit004_insert_accepts_matching_blake3_content() {
    let path = unique_path("valid");
    let path_str = path.to_str().expect("temporary path must be UTF-8");

    let mut db = MobileDb::open(path_str).expect("mobile database must open");
    let value = "sovereign mobile provenance";
    let header = header_for(value, 0);

    db.insert("record:1", value, &header)
        .expect("matching BLAKE3 provenance must be accepted");

    assert_eq!(
        db.query("record:1")
            .expect("query must succeed")
            .as_deref(),
        Some(value)
    );

    drop(db);
    let _ = std::fs::remove_dir_all(path);
}

#[test]
fn limit004_insert_rejects_mismatched_content_hash() {
    let path = unique_path("hash-mismatch");
    let path_str = path.to_str().expect("temporary path must be UTF-8");

    let mut db = MobileDb::open(path_str).expect("mobile database must open");
    let header = header_for("different payload", 0);

    let result = db.insert("record:1", "actual payload", &header);

    assert!(matches!(result, Err(DbError::InvalidArpi)));
    assert!(
        db.query("record:1")
            .expect("query must succeed")
            .is_none()
    );

    drop(db);
    let _ = std::fs::remove_dir_all(path);
}
