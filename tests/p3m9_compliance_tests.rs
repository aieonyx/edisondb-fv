// Copyright (c) 2026 Edison Lepiten / AIEONYX
// EdisonDB P3-M9 — Compliance tooling tests (20 tests)

use edisondb::compliance::*;
use edisondb::{AuditAction, AuditEntry, DataTier, Record};


fn rec(id: &str, tier: DataTier, owner: &str, age_secs: u64) -> Record {
    let safe_owner = if owner.is_empty() { "compliance:test-owner" } else { owner };
    let mut record =
        Record::new(id, tier, safe_owner, b"payload".to_vec(), [0u8; 32]).unwrap();
    record.owner_id = owner.to_string();
    record.created_at = 1000u64.saturating_sub(age_secs);
    record
}

fn audit(ts: u64, action: AuditAction, requester: &str) -> AuditEntry {
    AuditEntry::new("rec:1", requester, action, ts, [0u8; 32])
}

const NOW: u64 = 1000;

// ── T1: RetentionPolicy::sovereign_default ────────────────────────────────────
#[test]
fn t1_retention_sovereign_default() {
    let p = RetentionPolicy::sovereign_default();
    assert!(p.critical_max_age_secs > p.personal_max_age_secs);
    assert!(p.personal_max_age_secs > p.noise_max_age_secs);
}

// ── T2: RetentionPolicy::is_expired — not expired ────────────────────────────
#[test]
fn t2_retention_not_expired() {
    let p = RetentionPolicy::new(1000, 500, 100);
    let r = rec("rec:1", DataTier::Noise, "owner1", 50); // 50s old, limit 100
    assert!(!p.is_expired(&r, NOW));
}

// ── T3: RetentionPolicy::is_expired — expired ────────────────────────────────
#[test]
fn t3_retention_expired() {
    let p = RetentionPolicy::new(1000, 500, 100);
    let r = rec("rec:1", DataTier::Noise, "owner1", 200); // 200s old, limit 100
    assert!(p.is_expired(&r, NOW));
}

// ── T4: RetentionPolicy zero means no limit ───────────────────────────────────
#[test]
fn t4_retention_no_limit() {
    let p = RetentionPolicy::new(0, 0, 0);
    let r = rec("rec:1", DataTier::Critical, "owner1", 999999);
    assert!(!p.is_expired(&r, NOW));
}

// ── T5: TierSummary from records ─────────────────────────────────────────────
#[test]
fn t5_tier_summary() {
    let r1 = rec("r1", DataTier::Critical, "o1", 0);
    let r2 = rec("r2", DataTier::Personal, "o1", 0);
    let r3 = rec("r3", DataTier::Noise, "o1", 0);
    let r4 = rec("r4", DataTier::Noise, "o2", 0);
    let s = TierSummary::from_records(&[&r1, &r2, &r3, &r4]);
    assert_eq!(s.critical_count, 1);
    assert_eq!(s.personal_count, 1);
    assert_eq!(s.noise_count, 2);
    assert_eq!(s.total(), 4);
}

// ── T6: TierSummary payload bytes ────────────────────────────────────────────
#[test]
fn t6_tier_summary_payload() {
    let r1 = rec("r1", DataTier::Noise, "o1", 0);
    let r2 = rec("r2", DataTier::Noise, "o1", 0);
    let s = TierSummary::from_records(&[&r1, &r2]);
    assert_eq!(s.total_payload_bytes, 14); // "payload" * 2 = 7 * 2
}

// ── T7: AuditSummary from entries ────────────────────────────────────────────
#[test]
fn t7_audit_summary() {
    let entries = vec![
        audit(100, AuditAction::Write, "alice"),
        audit(200, AuditAction::ReadGranted, "alice"),
        audit(300, AuditAction::Delete, "bob"),
        audit(400, AuditAction::ReadDenied, "eve"),
    ];
    let s = AuditSummary::from_entries(&entries);
    assert_eq!(s.total_entries, 4);
    assert_eq!(s.write_count, 1);
    assert_eq!(s.read_count, 1);
    assert_eq!(s.delete_count, 1);
    assert_eq!(s.denied_count, 1);
    assert_eq!(s.unique_requesters, 3);
    assert_eq!(s.earliest_timestamp, 100);
    assert_eq!(s.latest_timestamp, 400);
}

// ── T8: AuditSummary empty ────────────────────────────────────────────────────
#[test]
fn t8_audit_summary_empty() {
    let s = AuditSummary::from_entries(&[]);
    assert_eq!(s.total_entries, 0);
    assert_eq!(s.unique_requesters, 0);
}

// ── T9: erasure_report owner records ─────────────────────────────────────────
#[test]
fn t9_erasure_report() {
    let r1 = rec("r1", DataTier::Personal, "alice", 0);
    let r2 = rec("r2", DataTier::Noise, "alice", 0);
    let r3 = rec("r3", DataTier::Noise, "bob", 0);
    let entries = vec![audit(100, AuditAction::Write, "alice")];
    let report = erasure_report(&[&r1, &r2, &r3], &entries, "alice");
    assert_eq!(report.records_found, 2);
    assert_eq!(report.records_erasable, 2);
    assert_eq!(report.audit_entries_found, 1);
    assert!(report.erasable_ids.contains(&"r1".to_string()));
    assert!(report.erasable_ids.contains(&"r2".to_string()));
}

// ── T10: erasure_report unknown owner ────────────────────────────────────────
#[test]
fn t10_erasure_report_unknown() {
    let r1 = rec("r1", DataTier::Noise, "alice", 0);
    let report = erasure_report(&[&r1], &[], "nobody");
    assert_eq!(report.records_found, 0);
    assert_eq!(report.records_erasable, 0);
}

// ── T11: generate_report — compliant ─────────────────────────────────────────
#[test]
fn t11_report_compliant() {
    let r1 = rec("r1", DataTier::Noise, "owner1", 10);
    let policy = RetentionPolicy::new(1000, 1000, 1000);
    let report = generate_report(&[&r1], &[], &policy, NOW, 0);
    assert!(report.is_compliant);
    assert_eq!(report.violation_count(), 0);
}

// ── T12: generate_report — retention violation ───────────────────────────────
#[test]
fn t12_report_retention_violation() {
    let r1 = rec("r1", DataTier::Noise, "owner1", 500);
    let policy = RetentionPolicy::new(1000, 1000, 100); // noise limit 100s
    let report = generate_report(&[&r1], &[], &policy, NOW, 0);
    assert!(!report.is_compliant);
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.violation_type == ViolationType::RetentionExpired)
    );
}

// ── T13: generate_report — missing owner violation ───────────────────────────
#[test]
fn t13_report_missing_owner() {
    let r = rec("r1", DataTier::Noise, "", 0);
    let policy = RetentionPolicy::new(0, 0, 0);
    let report = generate_report(&[&r], &[], &policy, NOW, 0);
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.violation_type == ViolationType::MissingOwner)
    );
}

// ── T14: generate_report — audit gap violation ───────────────────────────────
#[test]
fn t14_report_audit_gap() {
    let entries = vec![
        audit(100, AuditAction::Write, "alice"),
        audit(600, AuditAction::ReadGranted, "alice"), // 500s gap
    ];
    let policy = RetentionPolicy::new(0, 0, 0);
    let report = generate_report(&[], &entries, &policy, NOW, 200); // gap threshold 200s
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.violation_type == ViolationType::AuditGap)
    );
}

// ── T15: generate_report — no audit gap below threshold ──────────────────────
#[test]
fn t15_report_no_audit_gap() {
    let entries = vec![
        audit(100, AuditAction::Write, "alice"),
        audit(150, AuditAction::ReadGranted, "alice"), // 50s gap
    ];
    let policy = RetentionPolicy::new(0, 0, 0);
    let report = generate_report(&[], &entries, &policy, NOW, 200);
    assert!(
        !report
            .violations
            .iter()
            .any(|v| v.violation_type == ViolationType::AuditGap)
    );
}

// ── T16: generate_report — owner record counts ───────────────────────────────
#[test]
fn t16_report_owner_counts() {
    let r1 = rec("r1", DataTier::Noise, "alice", 0);
    let r2 = rec("r2", DataTier::Noise, "alice", 0);
    let r3 = rec("r3", DataTier::Noise, "bob", 0);
    let policy = RetentionPolicy::new(0, 0, 0);
    let report = generate_report(&[&r1, &r2, &r3], &[], &policy, NOW, 0);
    assert_eq!(report.owner_record_counts["alice"], 2);
    assert_eq!(report.owner_record_counts["bob"], 1);
}

// ── T17: generate_report — tier summary in report ────────────────────────────
#[test]
fn t17_report_tier_summary() {
    let r1 = rec("r1", DataTier::Critical, "o1", 0);
    let r2 = rec("r2", DataTier::Noise, "o1", 0);
    let policy = RetentionPolicy::new(0, 0, 0);
    let report = generate_report(&[&r1, &r2], &[], &policy, NOW, 0);
    assert_eq!(report.tier_summary.critical_count, 1);
    assert_eq!(report.tier_summary.noise_count, 1);
    assert_eq!(report.tier_summary.total(), 2);
}

// ── T18: generate_report — audit summary in report ───────────────────────────
#[test]
fn t18_report_audit_summary() {
    let entries = vec![
        audit(100, AuditAction::Write, "alice"),
        audit(200, AuditAction::Write, "alice"),
        audit(300, AuditAction::ReadGranted, "bob"),
    ];
    let policy = RetentionPolicy::new(0, 0, 0);
    let report = generate_report(&[], &entries, &policy, NOW, 0);
    assert_eq!(report.audit_summary.write_count, 2);
    assert_eq!(report.audit_summary.read_count, 1);
    assert_eq!(report.audit_summary.unique_requesters, 2);
}

// ── T19: multiple violations in one report ───────────────────────────────────
#[test]
fn t19_multiple_violations() {
    let r1 = rec("r1", DataTier::Noise, "", 500); // missing owner + expired
    let r2 = rec("r2", DataTier::Noise, "owner1", 500); // expired
    let policy = RetentionPolicy::new(0, 0, 100);
    let report = generate_report(&[&r1, &r2], &[], &policy, NOW, 0);
    assert!(report.violation_count() >= 2);
    assert!(!report.is_compliant);
}

// ── T20: full compliance pipeline ────────────────────────────────────────────
#[test]
fn t20_full_compliance_pipeline() {
    // Build a compliant dataset
    let r1 = rec("r1", DataTier::Critical, "alice", 10);
    let r2 = rec("r2", DataTier::Personal, "alice", 20);
    let r3 = rec("r3", DataTier::Noise, "bob", 5);
    let entries = vec![
        audit(990, AuditAction::Write, "alice"),
        audit(995, AuditAction::Write, "bob"),
        audit(999, AuditAction::ReadGranted, "alice"),
    ];
    let policy = RetentionPolicy::new(7 * 365 * 86400, 3 * 365 * 86400, 90 * 86400);
    let report = generate_report(&[&r1, &r2, &r3], &entries, &policy, NOW, 3600);

    // Compliance checks
    assert!(report.is_compliant);
    assert_eq!(report.tier_summary.total(), 3);
    assert_eq!(report.audit_summary.total_entries, 3);
    assert_eq!(report.audit_summary.unique_requesters, 2);

    // Erasure check for alice
    let erasure = erasure_report(&[&r1, &r2, &r3], &entries, "alice");
    assert_eq!(erasure.records_erasable, 2);
    assert_eq!(erasure.audit_entries_found, 2);
}
