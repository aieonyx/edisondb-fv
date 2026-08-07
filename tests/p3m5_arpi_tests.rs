// Copyright (c) 2026 Edison Lepiten / AIEONYX
// EdisonDB P3-M5 — ARPi protocol integration tests (20 tests)

use edisondb::arpi::{
    ARPI_VERSION, ArpiError, ArpiHeader, ArpiResponse, ArpiTier, HEADER_SIZE, last_audit_hash,
    sha256, validate,
};
use edisondb::{AuditAction, AuditEntry, DataTier};

fn make_audit_entry(record_id: &str, prev_hash: [u8; 32]) -> AuditEntry {
    AuditEntry::new(record_id, "owner", AuditAction::Write, 1000, prev_hash)
}

// ── T1: ArpiTier from DataTier ────────────────────────────────────────────────
#[test]
fn t1_tier_from_data_tier() {
    assert_eq!(
        ArpiTier::from_data_tier(&DataTier::Critical),
        ArpiTier::Critical
    );
    assert_eq!(
        ArpiTier::from_data_tier(&DataTier::Personal),
        ArpiTier::Personal
    );
    assert_eq!(ArpiTier::from_data_tier(&DataTier::Noise), ArpiTier::Noise);
}

// ── T2: ArpiTier u8 roundtrip ─────────────────────────────────────────────────
#[test]
fn t2_tier_u8_roundtrip() {
    for tier in [ArpiTier::Critical, ArpiTier::Personal, ArpiTier::Noise] {
        let v = tier.as_u8();
        assert_eq!(ArpiTier::from_u8(v).unwrap(), tier);
    }
}

// ── T3: ArpiTier invalid u8 ───────────────────────────────────────────────────
#[test]
fn t3_tier_invalid_u8() {
    assert!(ArpiTier::from_u8(3).is_none());
    assert!(ArpiTier::from_u8(255).is_none());
}

// ── T4: ArpiTier labels ───────────────────────────────────────────────────────
#[test]
fn t4_tier_labels() {
    assert_eq!(ArpiTier::Critical.label(), "critical");
    assert_eq!(ArpiTier::Personal.label(), "personal");
    assert_eq!(ArpiTier::Noise.label(), "noise");
}

// ── T5: ArpiHeader new + verify ───────────────────────────────────────────────
#[test]
fn t5_header_verify() {
    let h = ArpiHeader::new(ArpiTier::Critical, 1000, 5, [0u8; 32]);
    assert!(h.verify(), "fresh header seal must verify");
}

// ── T6: ArpiHeader tamper detection ───────────────────────────────────────────
#[test]
fn t6_header_tamper() {
    let mut h = ArpiHeader::new(ArpiTier::Critical, 1000, 5, [0u8; 32]);
    h.count = 999; // tamper with count
    assert!(!h.verify(), "tampered header must fail verify");
}

// ── T7: ArpiHeader serialization size ─────────────────────────────────────────
#[test]
fn t7_header_size() {
    let h = ArpiHeader::new(ArpiTier::Personal, 2000, 3, [1u8; 32]);
    let bytes = h.to_bytes();
    assert_eq!(bytes.len(), HEADER_SIZE);
    assert_eq!(HEADER_SIZE, 78);
}

// ── T8: ArpiHeader wire roundtrip ────────────────────────────────────────────
#[test]
fn t8_header_roundtrip() {
    let audit = [0xABu8; 32];
    let h = ArpiHeader::new(ArpiTier::Noise, 9999, 42, audit);
    let bytes = h.to_bytes();
    let h2 = ArpiHeader::from_bytes(&bytes).unwrap();
    assert_eq!(h2.version, ARPI_VERSION);
    assert_eq!(h2.tier, ArpiTier::Noise);
    assert_eq!(h2.timestamp, 9999);
    assert_eq!(h2.count, 42);
    assert_eq!(h2.audit_hash, audit);
    assert!(h2.verify());
}

// ── T9: ArpiHeader wrong version rejected ─────────────────────────────────────
#[test]
fn t9_header_wrong_version() {
    let h = ArpiHeader::new(ArpiTier::Critical, 1000, 1, [0u8; 32]);
    let mut bytes = h.to_bytes();
    bytes[0] = 99; // corrupt version
    assert!(ArpiHeader::from_bytes(&bytes).is_none());
}

// ── T10: ArpiHeader invalid tier rejected ────────────────────────────────────
#[test]
fn t10_header_invalid_tier() {
    let h = ArpiHeader::new(ArpiTier::Critical, 1000, 1, [0u8; 32]);
    let mut bytes = h.to_bytes();
    bytes[1] = 5; // invalid tier
    assert!(ArpiHeader::from_bytes(&bytes).is_none());
}

// ── T11: ArpiResponse new + verify ───────────────────────────────────────────
#[test]
fn t11_response_verify() {
    let h = ArpiHeader::new(ArpiTier::Critical, 1000, 1, [0u8; 32]);
    let resp = ArpiResponse::new(h, b"sovereign payload".to_vec());
    assert!(resp.verify());
}

// ── T12: ArpiResponse wire roundtrip ─────────────────────────────────────────
#[test]
fn t12_response_roundtrip() {
    let h = ArpiHeader::new(ArpiTier::Personal, 5000, 2, [0xFFu8; 32]);
    let payload = b"EdisonDB record data".to_vec();
    let resp = ArpiResponse::new(h, payload.clone());
    let bytes = resp.to_bytes();
    let resp2 = ArpiResponse::from_bytes(&bytes).unwrap();
    assert_eq!(resp2.payload, payload);
    assert!(resp2.verify());
}

// ── T13: ArpiResponse truncated rejected ─────────────────────────────────────
#[test]
fn t13_response_truncated() {
    let data = vec![0u8; 10]; // less than HEADER_SIZE
    assert!(ArpiResponse::from_bytes(&data).is_none());
}

// ── T14: requires_auth by tier ───────────────────────────────────────────────
#[test]
fn t14_requires_auth() {
    let critical = ArpiResponse::new(ArpiHeader::new(ArpiTier::Critical, 0, 0, [0u8; 32]), vec![]);
    let noise = ArpiResponse::new(ArpiHeader::new(ArpiTier::Noise, 0, 0, [0u8; 32]), vec![]);
    assert!(critical.requires_auth());
    assert!(!noise.requires_auth());
}

// ── T15: validate clean response ─────────────────────────────────────────────
#[test]
fn t15_validate_ok() {
    let h = ArpiHeader::new(ArpiTier::Critical, 1000, 5, [0u8; 32]);
    let resp = ArpiResponse::new(h, vec![]);
    assert!(validate(&resp).is_ok());
}

// ── T16: validate tampered seal ───────────────────────────────────────────────
#[test]
fn t16_validate_tampered() {
    let mut h = ArpiHeader::new(ArpiTier::Critical, 1000, 5, [0u8; 32]);
    h.seal[0] ^= 0xFF; // corrupt seal
    let resp = ArpiResponse::new(h, vec![]);
    assert_eq!(validate(&resp), Err(ArpiError::InvalidSeal));
}

// ── T17: last_audit_hash empty log ───────────────────────────────────────────
#[test]
fn t17_last_audit_hash_empty() {
    let hash = last_audit_hash(&[]);
    assert_eq!(hash, [0u8; 32]);
}

// ── T18: last_audit_hash uses sealed tail ────────────────────────────────────
#[test]
fn t18_last_audit_hash_entries() {
    let e1 = make_audit_entry("rec:1", [0x11u8; 32]);
    let e2 = make_audit_entry("rec:2", [0x22u8; 32]);
    let expected = e2.entry_hash;

    let hash = last_audit_hash(&[e1, e2]);

    assert_eq!(hash, expected);
}

// ── T19: sha256 known vector ──────────────────────────────────────────────────
#[test]
fn t19_sha256_empty() {
    let h = sha256(b"");
    let hex: String = h.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(
        hex,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

// ── T20: from_audit builds correct header ────────────────────────────────────
#[test]
fn t20_from_audit() {
    let entries = vec![
        make_audit_entry("rec:1", [0xAAu8; 32]),
        make_audit_entry("rec:2", [0xBBu8; 32]),
    ];
    let expected = entries.last().unwrap().entry_hash;
    let h = ArpiHeader::from_audit(&DataTier::Critical, &entries, 2);

    assert_eq!(h.tier, ArpiTier::Critical);
    assert_eq!(h.count, 2);
    assert_eq!(h.audit_hash, expected);
    assert!(h.verify());
}
