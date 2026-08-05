// Copyright (c) 2026 Edison Lepiten / AIEONYX
// EdisonDB P3-M6 — Policy engine tests (22 tests)

use edisondb::policy::{
    Action, Role, Delegation, PolicyRule, PolicyEngine,
};
use edisondb::DataTier;

const NOW: u64 = 1_000_000;

fn engine() -> PolicyEngine { PolicyEngine::new() }

// ── T1: Action from_str roundtrip ────────────────────────────────────────────
#[test]
fn t1_action_from_str() {
    for s in ["read","write","delete","audit","grant","admin"] {
        let a = Action::from_str(s).unwrap();
        assert_eq!(a.as_str(), s);
    }
    assert!(Action::from_str("unknown").is_none());
}

// ── T2: Role from_str roundtrip ───────────────────────────────────────────────
#[test]
fn t2_role_from_str() {
    for s in ["owner","reader","auditor","writer","admin"] {
        let r = Role::from_str(s).unwrap();
        assert_eq!(r.as_str(), s);
    }
    assert!(Role::from_str("superuser").is_none());
}

// ── T3: Owner role permits all actions on all tiers ──────────────────────────
#[test]
fn t3_owner_role_all_actions() {
    for tier in [&DataTier::Critical, &DataTier::Personal, &DataTier::Noise] {
        let actions = Role::Owner.permitted_actions(tier);
        for a in [&Action::Read, &Action::Write, &Action::Delete,
                  &Action::Audit, &Action::Grant, &Action::Admin] {
            assert!(actions.contains(a), "Owner must permit {:?} on {:?}", a, tier);
        }
    }
}

// ── T4: Reader role cannot read Critical ─────────────────────────────────────
#[test]
fn t4_reader_no_critical() {
    let actions = Role::Reader.permitted_actions(&DataTier::Critical);
    assert!(actions.is_empty(), "Reader must have no access to Critical");
}

// ── T5: Reader can read Noise and Personal ────────────────────────────────────
#[test]
fn t5_reader_noise_personal() {
    assert!(Role::Reader.permitted_actions(&DataTier::Noise).contains(&Action::Read));
    assert!(Role::Reader.permitted_actions(&DataTier::Personal).contains(&Action::Read));
}

// ── T6: Auditor only gets Audit action ────────────────────────────────────────
#[test]
fn t6_auditor_only_audit() {
    for tier in [&DataTier::Critical, &DataTier::Personal, &DataTier::Noise] {
        let actions = Role::Auditor.permitted_actions(tier);
        assert_eq!(actions, vec![Action::Audit]);
    }
}

// ── T7: Delegation expiry ─────────────────────────────────────────────────────
#[test]
fn t7_delegation_expiry() {
    let d = Delegation::new("alice", Role::Reader, "owner", NOW - 1);
    assert!(d.is_expired(NOW), "delegation should be expired");
    let d2 = Delegation::permanent("alice", Role::Reader, "owner");
    assert!(!d2.is_expired(NOW), "permanent delegation must not expire");
}

// ── T8: Owner always gets Permit ──────────────────────────────────────────────
#[test]
fn t8_owner_bypass() {
    let e = engine();
    let dec = e.evaluate("owner1", "owner1", "rec:1",
                         &Action::Delete, &DataTier::Critical, NOW);
    assert!(dec.is_permit());
    assert!(dec.reason().contains("owner bypass"));
}

// ── T9: Unknown subject gets default Deny ────────────────────────────────────
#[test]
fn t9_default_deny() {
    let e = engine();
    let dec = e.evaluate("stranger", "owner1", "rec:1",
                         &Action::Read, &DataTier::Noise, NOW);
    assert!(dec.is_deny());
    assert!(dec.reason().contains("default deny"));
}

// ── T10: Delegation grants access ────────────────────────────────────────────
#[test]
fn t10_delegation_grants_access() {
    let mut e = engine();
    e.delegate("owner1", Delegation::permanent("alice", Role::Reader, "owner1"));
    let dec = e.evaluate("alice", "owner1", "rec:1",
                         &Action::Read, &DataTier::Noise, NOW);
    assert!(dec.is_permit(), "alice should have read via Reader role");
    assert!(dec.reason().contains("role:reader"));
}

// ── T11: Delegation does not grant exceeding role ────────────────────────────
#[test]
fn t11_delegation_no_exceed() {
    let mut e = engine();
    e.delegate("owner1", Delegation::permanent("alice", Role::Reader, "owner1"));
    let dec = e.evaluate("alice", "owner1", "rec:1",
                         &Action::Write, &DataTier::Noise, NOW);
    assert!(dec.is_deny(), "Reader must not have Write access");
}

// ── T12: Expired delegation is rejected ──────────────────────────────────────
#[test]
fn t12_expired_delegation() {
    let mut e = engine();
    e.delegate("owner1", Delegation::new("alice", Role::Reader, "owner1", NOW - 1));
    let dec = e.evaluate("alice", "owner1", "rec:1",
                         &Action::Read, &DataTier::Noise, NOW);
    assert!(dec.is_deny(), "expired delegation must not grant access");
}

// ── T13: Explicit allow rule grants access ───────────────────────────────────
#[test]
fn t13_allow_rule() {
    let mut e = engine();
    e.add_rule(PolicyRule::allow("bob", "rec:", Action::Read));
    let dec = e.evaluate("bob", "owner1", "rec:42",
                         &Action::Read, &DataTier::Noise, NOW);
    assert!(dec.is_permit());
    assert!(dec.reason().contains("allow rule"));
}

// ── T14: Explicit deny overrides allow ───────────────────────────────────────
#[test]
fn t14_deny_overrides_allow() {
    let mut e = engine();
    e.add_rule(PolicyRule::allow("eve", "*", Action::Read));
    e.add_rule(PolicyRule::deny("eve", "rec:secret", Action::Read));
    // deny rule evaluates first (order 2 > order 4)
    let dec = e.evaluate("eve", "owner1", "rec:secret",
                         &Action::Read, &DataTier::Noise, NOW);
    assert!(dec.is_deny(), "explicit deny must override allow");
}

// ── T15: Wildcard subject rule matches anyone ─────────────────────────────────
#[test]
fn t15_wildcard_subject() {
    let mut e = engine();
    e.add_rule(PolicyRule::allow("*", "pub:", Action::Read));
    let dec = e.evaluate("anyone", "owner1", "pub:post:1",
                         &Action::Read, &DataTier::Noise, NOW);
    assert!(dec.is_permit());
}

// ── T16: Reader cannot access Critical via delegation ────────────────────────
#[test]
fn t16_reader_no_critical_via_delegation() {
    let mut e = engine();
    e.delegate("owner1", Delegation::permanent("alice", Role::Reader, "owner1"));
    let dec = e.evaluate("alice", "owner1", "rec:secret",
                         &Action::Read, &DataTier::Critical, NOW);
    assert!(dec.is_deny(), "Reader must not access Critical tier");
}

// ── T17: Admin role cannot Grant ─────────────────────────────────────────────
#[test]
fn t17_admin_no_grant() {
    let mut e = engine();
    e.delegate("owner1", Delegation::permanent("sysadmin", Role::Admin, "owner1"));
    let dec = e.evaluate("sysadmin", "owner1", "rec:1",
                         &Action::Grant, &DataTier::Noise, NOW);
    assert!(dec.is_deny(), "Admin role must not include Grant action");
}

// ── T18: Writer can write Personal ───────────────────────────────────────────
#[test]
fn t18_writer_personal_write() {
    let mut e = engine();
    e.delegate("owner1", Delegation::permanent("writer1", Role::Writer, "owner1"));
    let dec = e.evaluate("writer1", "owner1", "rec:1",
                         &Action::Write, &DataTier::Personal, NOW);
    assert!(dec.is_permit());
}

// ── T19: delegation_count and rule_count ─────────────────────────────────────
#[test]
fn t19_counts() {
    let mut e = engine();
    assert_eq!(e.delegation_count("owner1"), 0);
    e.delegate("owner1", Delegation::permanent("a", Role::Reader, "owner1"));
    e.delegate("owner1", Delegation::permanent("b", Role::Auditor, "owner1"));
    assert_eq!(e.delegation_count("owner1"), 2);
    assert_eq!(e.rule_count(), 0);
    e.add_rule(PolicyRule::allow("*", "*", Action::Read));
    assert_eq!(e.rule_count(), 1);
}

// ── T20: different owners' delegations don't cross ───────────────────────────
#[test]
fn t20_delegation_isolation() {
    let mut e = engine();
    // owner2 grants alice Reader — should NOT apply to owner1's resources
    e.delegate("owner2", Delegation::permanent("alice", Role::Reader, "owner2"));
    let dec = e.evaluate("alice", "owner1", "rec:1",
                         &Action::Read, &DataTier::Noise, NOW);
    assert!(dec.is_deny(), "delegation from owner2 must not apply to owner1 resources");
}

#[test]
fn t21_admin_cannot_access_critical() {
    let mut e = engine();
    e.delegate("owner1", Delegation::permanent("sysadmin", Role::Admin, "owner1"));

    let dec = e.evaluate("sysadmin", "owner1", "rec:secret",
                         &Action::Read, &DataTier::Critical, NOW);

    assert!(dec.is_deny());
    assert!(dec.reason().contains("critical tier requires owner"));
}

#[test]
fn t22_allow_rule_cannot_access_critical() {
    let mut e = engine();
    e.add_rule(PolicyRule::allow("alice", "*", Action::Read));

    let dec = e.evaluate("alice", "owner1", "rec:secret",
                         &Action::Read, &DataTier::Critical, NOW);

    assert!(dec.is_deny());
    assert!(dec.reason().contains("critical tier requires owner"));
}
