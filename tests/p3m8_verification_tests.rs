mod common;
use common::record_new;

// Copyright (c) 2026 Edison Lepiten / AIEONYX
// EdisonDB P3-M8 — Formal verification hooks tests (20 tests)

use edisondb::policy::PolicyEngine;
use edisondb::verification::*;
use edisondb::{AuditAction, AuditEntry, DataTier, EdisonError, Record, Store};


fn make_record(id: &str, tier: DataTier, owner: &str) -> Record {
    let safe_owner = if owner.is_empty() { "verification:test-owner" } else { owner };
    let mut record =
        record_new(id, tier, safe_owner, b"data".to_vec(), [0u8; 32]).unwrap();
    record.owner_id = owner.to_string();
    record.created_at = 1000;
    record
}

fn make_audit(ts: u64, prev: [u8; 32]) -> AuditEntry {
    AuditEntry::new("rec:1", "owner", AuditAction::Write, ts, prev)
}

// ── T1: owner nonempty invariant — valid record ───────────────────────────────
#[test]
fn t1_owner_nonempty_valid() {
    let r = make_record("rec:1", DataTier::Noise, "owner1");
    assert!(invariant_record_owner_nonempty(&r));
}

// ── T2: owner nonempty invariant — empty owner ───────────────────────────────
#[test]
fn t2_owner_nonempty_empty() {
    let r = make_record("rec:1", DataTier::Noise, "");
    assert!(!invariant_record_owner_nonempty(&r));
}

// ── T3: store owners nonempty — all valid ────────────────────────────────────
#[test]
fn t3_store_owners_nonempty() {
    let mut store = Store::default();
    store
        .write(make_record("rec:1", DataTier::Noise, "owner1"))
        .unwrap();
    store
        .write(make_record("rec:2", DataTier::Personal, "owner2"))
        .unwrap();
    assert!(invariant_store_owners_nonempty(&store));
}

// ── T4: tier gate — Critical owner access ────────────────────────────────────
#[test]
fn t4_tier_gate_critical_owner() {
    let r = make_record("rec:1", DataTier::Critical, "owner1");
    assert!(invariant_tier_gate(&r, "owner1"));
}

// ── T5: tier gate — Critical non-owner blocked ───────────────────────────────
#[test]
fn t5_tier_gate_critical_nonowner() {
    let r = make_record("rec:1", DataTier::Critical, "owner1");
    assert!(!invariant_tier_gate(&r, "stranger"));
}

// ── T6: tier gate — Noise accessible by anyone ───────────────────────────────
#[test]
fn t6_tier_gate_noise_open() {
    let r = make_record("rec:1", DataTier::Noise, "owner1");
    assert!(invariant_tier_gate(&r, "anyone"));
    assert!(invariant_tier_gate(&r, "stranger"));
    assert!(invariant_tier_gate(&r, ""));
}

// ── T7: audit monotonicity — ascending timestamps ────────────────────────────
#[test]
fn t7_audit_monotonic_ok() {
    let entries = vec![
        make_audit(100, [0u8; 32]),
        make_audit(200, [1u8; 32]),
        make_audit(300, [2u8; 32]),
    ];
    assert!(invariant_audit_monotonic(&entries));
}

// ── T8: audit monotonicity — equal timestamps ok ─────────────────────────────
#[test]
fn t8_audit_monotonic_equal() {
    let entries = vec![make_audit(100, [0u8; 32]), make_audit(100, [1u8; 32])];
    assert!(invariant_audit_monotonic(&entries));
}

// ── T9: audit monotonicity — descending fails ────────────────────────────────
#[test]
fn t9_audit_monotonic_fail() {
    let entries = vec![make_audit(200, [0u8; 32]), make_audit(100, [1u8; 32])];
    assert!(!invariant_audit_monotonic(&entries));
}

// ── T10: audit chain integrity ───────────────────────────────────────────────
#[test]
fn t10_audit_chain_noself() {
    let first = make_audit(100, [0u8; 32]);
    let second = make_audit(200, first.entry_hash);
    let entries = vec![first, second];

    assert!(invariant_audit_chain_integrity(&entries));
    assert!(invariant_audit_chain_noself(&entries));
}

// ── T11: owner always permit invariant ───────────────────────────────────────
#[test]
fn t11_owner_always_permit() {
    let engine = PolicyEngine::new();
    assert!(invariant_owner_always_permit(&engine, "owner1"));
}

// ── T12: noise readable invariant ────────────────────────────────────────────
#[test]
fn t12_noise_readable() {
    let engine = PolicyEngine::new();
    assert!(invariant_noise_readable_by_all(&engine, "owner1"));
}

// ── T13: pre_write valid record ───────────────────────────────────────────────
#[test]
fn t13_pre_write_valid() {
    let r = make_record("rec:1", DataTier::Noise, "owner1");
    assert!(pre_write(&r).is_ok());
}

// ── T14: pre_write empty owner fails ─────────────────────────────────────────
#[test]
fn t14_pre_write_empty_owner() {
    let r = make_record("rec:1", DataTier::Noise, "");
    assert!(pre_write(&r).is_err());
}

// ── T15: pre_write empty id fails ────────────────────────────────────────────
#[test]
fn t15_empty_id_rejected_at_record_construction() {
    let result = record_new(
        "",
        DataTier::Noise,
        "owner1",
        b"data".to_vec(),
        [0u8; 32],
    );

    assert_eq!(result, Err(EdisonError::EmptyRecordId));
}

// ── T16: post_write count tracking ───────────────────────────────────────────
#[test]
fn t16_post_write() {
    assert!(post_write(0, 1)); // new record
    assert!(post_write(5, 6)); // append
    assert!(post_write(5, 5)); // overwrite
    assert!(!post_write(5, 7)); // jump of 2 — invalid
}

// ── T17: post_delete count tracking ──────────────────────────────────────────
#[test]
fn t17_post_delete() {
    assert!(post_delete(5, 4, true)); // found and deleted
    assert!(post_delete(5, 5, false)); // not found, no change
    assert!(!post_delete(5, 5, true)); // found but count didn't decrease
}

// ── T18: witness_noise_open ───────────────────────────────────────────────────
#[test]
fn t18_witness_noise_open() {
    let r = make_record("rec:1", DataTier::Noise, "owner1");
    assert!(witness_noise_open(&r).is_ok());
    // Non-noise record — property doesn't apply, still Ok
    let r2 = make_record("rec:2", DataTier::Critical, "owner1");
    assert!(witness_noise_open(&r2).is_ok());
}

// ── T19: witness_critical_owner_only ─────────────────────────────────────────
#[test]
fn t19_witness_critical_owner_only() {
    let r = make_record("rec:1", DataTier::Critical, "owner1");
    assert!(witness_critical_owner_only(&r, "owner1").is_ok());
    assert!(witness_critical_owner_only(&r, "stranger").is_ok()); // returns Ok with correct gate
}

// ── T20: witness_write_read_consistency ──────────────────────────────────────
#[test]
fn t20_write_read_consistency() {
    let mut store = Store::default();
    let r = make_record("rec:verify:1", DataTier::Noise, "owner1");
    assert!(witness_write_read_consistency(&mut store, r, "owner1").is_ok());
}
