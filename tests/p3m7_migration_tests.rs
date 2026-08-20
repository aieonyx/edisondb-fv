// Copyright (c) 2026 Edison Lepiten / AIEONYX
// EdisonDB P3-M7 — Migration toolkit tests (20 tests)

use std::collections::HashSet;
use edisondb::{Record, DataTier};
use edisondb::migration::{
    export, parse_edm, import, transform, build_manifest, verify_manifests,
    ExportOptions, TransformOptions, ConflictStrategy, EdmRecord, EDM_VERSION,
    MigrationError,
};


fn make_record(id: &str, tier: DataTier, owner: &str, payload: &[u8]) -> Record {
    let mut record = Record::new(id, tier, owner, payload.to_vec(), [0u8; 32]).unwrap();
    record.created_at = 1000;
    record
}

// ── T1: export produces valid .edm ───────────────────────────────────────────
#[test]
fn t1_export_basic() {
    let r = make_record("rec:1", DataTier::Noise, "owner1", b"hello");
    let edm = export(&[&r], &ExportOptions::default()).unwrap();
    assert!(edm.contains("\"edm\":1"));
    assert!(edm.contains("rec:1"));
}

// ── T2: export header record_count correct ────────────────────────────────────
#[test]
fn t2_export_count() {
    let r1 = make_record("rec:1", DataTier::Noise, "owner1", b"a");
    let r2 = make_record("rec:2", DataTier::Noise, "owner1", b"b");
    let edm = export(&[&r1, &r2], &ExportOptions::default()).unwrap();
    let (header, _) = parse_edm(&edm).unwrap();
    assert_eq!(header.record_count, 2);
}

// ── T3: export owner filter ───────────────────────────────────────────────────
#[test]
fn t3_export_owner_filter() {
    let r1 = make_record("rec:1", DataTier::Noise, "alice", b"a");
    let r2 = make_record("rec:2", DataTier::Noise, "bob",   b"b");
    let opts = ExportOptions { owner_filter: Some("alice".into()), tier_filter: None };
    let edm = export(&[&r1, &r2], &opts).unwrap();
    let (header, records) = parse_edm(&edm).unwrap();
    assert_eq!(header.record_count, 1);
    assert_eq!(records[0].id, "rec:1");
}

// ── T4: export tier filter ────────────────────────────────────────────────────
#[test]
fn t4_export_tier_filter() {
    let r1 = make_record("rec:1", DataTier::Critical, "owner1", b"c");
    let r2 = make_record("rec:2", DataTier::Noise,    "owner1", b"n");
    let opts = ExportOptions { owner_filter: None, tier_filter: Some(DataTier::Noise) };
    let edm = export(&[&r1, &r2], &opts).unwrap();
    let (_, records) = parse_edm(&edm).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].tier, "noise");
}

// ── T5: parse_edm roundtrip ───────────────────────────────────────────────────
#[test]
fn t5_parse_edm_roundtrip() {
    let r = make_record("rec:99", DataTier::Personal, "owner1", b"sovereign");
    let edm = export(&[&r], &ExportOptions::default()).unwrap();
    let (header, records) = parse_edm(&edm).unwrap();
    assert_eq!(header.edm, EDM_VERSION);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, "rec:99");
    assert_eq!(records[0].tier, "personal");
    assert_eq!(records[0].owner_id, "owner1");
}

// ── T6: parse_edm wrong version ───────────────────────────────────────────────
#[test]
fn t6_parse_wrong_version() {
    let bad = r#"{"edm":99,"exported_at":0,"record_count":0,"owner_filter":null,"tier_filter":null}"#;
    assert!(matches!(parse_edm(bad), Err(MigrationError::VersionMismatch(99))));
}

// ── T7: parse_edm empty input ─────────────────────────────────────────────────
#[test]
fn t7_parse_empty() {
    assert!(matches!(parse_edm(""), Err(MigrationError::EmptyInput)));
}

// ── T8: EdmRecord to_record roundtrip ────────────────────────────────────────
#[test]
fn t8_edm_record_roundtrip() {
    let r = make_record("rec:1", DataTier::Critical, "owner1", b"data");
    let edm = EdmRecord::from_record(&r);
    let r2 = edm.to_record().unwrap();
    assert_eq!(r2.id, r.id);
    assert_eq!(r2.tier, r.tier);
    assert_eq!(r2.owner_id, r.owner_id);
    assert_eq!(r2.payload(), r.payload());
    assert_eq!(r2.salt(), r.salt());
}

// ── T9: import no conflicts ───────────────────────────────────────────────────
#[test]
fn t9_import_clean() {
    let r = make_record("rec:1", DataTier::Noise, "owner1", b"x");
    let edm = export(&[&r], &ExportOptions::default()).unwrap();
    let (_, edm_records) = parse_edm(&edm).unwrap();
    let (records, result) = import(&edm_records, &HashSet::new(), ConflictStrategy::Skip);
    assert_eq!(result.imported, 1);
    assert_eq!(result.skipped, 0);
    assert!(result.errors.is_empty());
    assert_eq!(records[0].id, "rec:1");
}

// ── T10: import skip conflict ─────────────────────────────────────────────────
#[test]
fn t10_import_skip_conflict() {
    let r = make_record("rec:1", DataTier::Noise, "owner1", b"x");
    let edm = export(&[&r], &ExportOptions::default()).unwrap();
    let (_, edm_records) = parse_edm(&edm).unwrap();
    let mut existing = HashSet::new();
    existing.insert("rec:1".to_string());
    let (records, result) = import(&edm_records, &existing, ConflictStrategy::Skip);
    assert_eq!(result.skipped, 1);
    assert_eq!(result.imported, 0);
    assert!(records.is_empty());
}

// ── T11: import overwrite conflict ───────────────────────────────────────────
#[test]
fn t11_import_overwrite_conflict() {
    let r = make_record("rec:1", DataTier::Noise, "owner1", b"x");
    let edm = export(&[&r], &ExportOptions::default()).unwrap();
    let (_, edm_records) = parse_edm(&edm).unwrap();
    let mut existing = HashSet::new();
    existing.insert("rec:1".to_string());
    let (records, result) = import(&edm_records, &existing, ConflictStrategy::Overwrite);
    assert_eq!(result.imported, 1);
    assert_eq!(result.skipped, 0);
    assert_eq!(records[0].id, "rec:1");
}

// ── T12: import error conflict ────────────────────────────────────────────────
#[test]
fn t12_import_error_conflict() {
    let r = make_record("rec:1", DataTier::Noise, "owner1", b"x");
    let edm = export(&[&r], &ExportOptions::default()).unwrap();
    let (_, edm_records) = parse_edm(&edm).unwrap();
    let mut existing = HashSet::new();
    existing.insert("rec:1".to_string());
    let (_, result) = import(&edm_records, &existing, ConflictStrategy::Error);
    assert!(!result.errors.is_empty());
    assert!(result.errors[0].contains("conflict"));
}

// ── T13: transform new_owner ──────────────────────────────────────────────────
#[test]
fn t13_transform_owner() {
    let r = make_record("rec:1", DataTier::Noise, "old_owner", b"x");
    let edm = export(&[&r], &ExportOptions::default()).unwrap();
    let (_, mut records) = parse_edm(&edm).unwrap();
    transform(&mut records, &TransformOptions {
        new_owner: Some("new_owner".into()), ..Default::default()
    });
    assert_eq!(records[0].owner_id, "new_owner");
}

// ── T14: transform new_tier ───────────────────────────────────────────────────
#[test]
fn t14_transform_tier() {
    let r = make_record("rec:1", DataTier::Noise, "owner1", b"x");
    let edm = export(&[&r], &ExportOptions::default()).unwrap();
    let (_, mut records) = parse_edm(&edm).unwrap();
    transform(&mut records, &TransformOptions {
        new_tier: Some(DataTier::Personal), ..Default::default()
    });
    assert_eq!(records[0].tier, "personal");
}

// ── T15: transform id_prefix ──────────────────────────────────────────────────
#[test]
fn t15_transform_id_prefix() {
    let r = make_record("rec:1", DataTier::Noise, "owner1", b"x");
    let edm = export(&[&r], &ExportOptions::default()).unwrap();
    let (_, mut records) = parse_edm(&edm).unwrap();
    transform(&mut records, &TransformOptions {
        id_prefix: Some("migrated:".into()), ..Default::default()
    });
    assert_eq!(records[0].id, "migrated:rec:1");
}

// ── T16: transform strip_id_prefix ───────────────────────────────────────────
#[test]
fn t16_transform_strip_prefix() {
    let r = make_record("old:rec:1", DataTier::Noise, "owner1", b"x");
    let edm = export(&[&r], &ExportOptions::default()).unwrap();
    let (_, mut records) = parse_edm(&edm).unwrap();
    transform(&mut records, &TransformOptions {
        strip_id_prefix: Some("old:".into()), ..Default::default()
    });
    assert_eq!(records[0].id, "rec:1");
}

// ── T17: build_manifest counts ────────────────────────────────────────────────
#[test]
fn t17_manifest_counts() {
    let r1 = make_record("rec:1", DataTier::Critical, "owner1", b"abc");
    let r2 = make_record("rec:2", DataTier::Noise,    "owner1", b"de");
    let manifest = build_manifest(&[r1, r2]);
    assert_eq!(manifest.record_count, 2);
    assert_eq!(manifest.total_payload_bytes, 5);
    assert_eq!(manifest.tier_counts["critical"], 1);
    assert_eq!(manifest.tier_counts["noise"],    1);
}

// ── T18: verify_manifests match ───────────────────────────────────────────────
#[test]
fn t18_verify_manifests_match() {
    let r1 = make_record("rec:1", DataTier::Noise, "owner1", b"x");
    let r2 = make_record("rec:1", DataTier::Noise, "owner1", b"x");
    let m1 = build_manifest(&[r1]);
    let m2 = build_manifest(&[r2]);
    assert!(verify_manifests(&m1, &m2));
}

// ── T19: verify_manifests mismatch ───────────────────────────────────────────
#[test]
fn t19_verify_manifests_mismatch() {
    let r1 = make_record("rec:1", DataTier::Noise, "owner1", b"x");
    let r2 = make_record("rec:2", DataTier::Noise, "owner1", b"x");
    let m1 = build_manifest(&[r1]);
    let m2 = build_manifest(&[r2]);
    assert!(!verify_manifests(&m1, &m2));
}

// ── T20: full migration pipeline ─────────────────────────────────────────────
#[test]
fn t20_full_pipeline() {
    // Source: 3 records
    let r1 = make_record("src:1", DataTier::Noise,    "alice", b"payload1");
    let r2 = make_record("src:2", DataTier::Personal, "alice", b"payload2");
    let r3 = make_record("src:3", DataTier::Noise,    "bob",   b"payload3");

    // Export all
    let edm = export(&[&r1, &r2, &r3], &ExportOptions::default()).unwrap();

    // Parse
    let (header, mut edm_records) = parse_edm(&edm).unwrap();
    assert_eq!(header.record_count, 3);

    // Transform: re-own to new_owner, add prefix
    transform(&mut edm_records, &TransformOptions {
        new_owner: Some("new_owner".into()),
        id_prefix: Some("migrated:".into()),
        ..Default::default()
    });

    // Import
    let (records, result) = import(&edm_records, &HashSet::new(), ConflictStrategy::Skip);
    assert_eq!(result.imported, 3);
    assert!(result.errors.is_empty());

    // Verify all owners changed
    for r in &records {
        assert_eq!(r.owner_id, "new_owner");
        assert!(r.id.starts_with("migrated:"));
    }

    // Manifest check: payload bytes preserved
    let pre_manifest = build_manifest(&[r1, r2, r3]);
    let post_manifest = build_manifest(&records);
    assert_eq!(pre_manifest.total_payload_bytes, post_manifest.total_payload_bytes);
    assert_eq!(pre_manifest.record_count, post_manifest.record_count);
}
