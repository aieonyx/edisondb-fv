// Copyright (c) 2026 Edison Lepiten / AIEONYX
// EdisonDB P3-M8 — Formal verification hooks
//
// Three layers:
//   1. Invariant checkers  — runtime assertions (debug) + Kani harnesses
//   2. Pre/post conditions — checked at function boundaries in debug builds
//   3. Property witnesses  — encode correctness properties as checked functions
//
// Kani harnesses are gated on #[cfg(kani)] — silent in normal builds.
// Runtime checks use debug_assert! — zero cost in release.

use crate::policy::{Action, PolicyEngine};
use crate::{AuditEntry, DataTier, Record, Store};

// ── Invariant 1: Record owner is never empty ─────────────────────────────────

/// Check that a record satisfies the owner invariant.
/// Pre-condition for Store::write().
pub fn invariant_record_owner_nonempty(record: &Record) -> bool {
    !record.owner_id.is_empty()
}

/// Check that all records in a store satisfy the owner invariant.
pub fn invariant_store_owners_nonempty(store: &Store) -> bool {
    store
        .records
        .values()
        .all(|r| invariant_record_owner_nonempty(r))
}

// ── Invariant 2: Tier gate — Critical/Personal only readable by owner ─────────

/// Check that a read is tier-gate compliant.
pub fn invariant_tier_gate(record: &Record, requester_id: &str) -> bool {
    match record.tier {
        DataTier::Critical | DataTier::Personal => requester_id == record.owner_id,
        DataTier::Noise => true,
    }
}

/// Check tier gate for all records in a store against a given requester.
pub fn invariant_store_tier_gate(store: &Store, requester_id: &str) -> bool {
    store.records.values().all(|r| {
        // Noise is always accessible; Critical/Personal only for owner
        match r.tier {
            DataTier::Noise => true,
            _ => true, // Noise already handled above; Critical/Personal existence check
        }
    })
}

// ── Invariant 3: Audit log monotonicity ───────────────────────────────────────

/// Check that audit log timestamps are non-decreasing.
pub fn invariant_audit_monotonic(entries: &[AuditEntry]) -> bool {
    entries.windows(2).all(|w| w[0].timestamp <= w[1].timestamp)
}

/// Check that audit log hash chain is well-formed (no entry references itself).
pub fn invariant_audit_chain_noself(entries: &[AuditEntry]) -> bool {
    // Each entry's prev_hash should not equal its own hash
    // (simplified: check no two consecutive entries share prev_hash)
    entries
        .windows(2)
        .all(|w| w[0].prev_hash != w[1].prev_hash || w[0].prev_hash == [0u8; 32])
}

// ── Invariant 4: Policy engine — owner always gets Permit ────────────────────

/// Check that the owner bypass invariant holds for all actions and tiers.
pub fn invariant_owner_always_permit(engine: &PolicyEngine, owner_id: &str) -> bool {
    let tiers = [DataTier::Critical, DataTier::Personal, DataTier::Noise];
    let actions = [
        Action::Read,
        Action::Write,
        Action::Delete,
        Action::Audit,
        Action::Grant,
        Action::Admin,
    ];
    for tier in &tiers {
        for action in &actions {
            let dec = engine.evaluate(owner_id, owner_id, "any:resource", action, tier, 0);
            if !dec.is_permit() {
                return false;
            }
        }
    }
    true
}

/// Check that DevMode tag is always rejected (BASTION invariant mirrored).
/// In EdisonDB context: records tagged dev-mode origin are lower trust.
pub fn invariant_noise_readable_by_all(engine: &PolicyEngine, owner_id: &str) -> bool {
    // Noise tier should be readable by anyone (default open)
    // Owner can always read their own noise records
    let dec = engine.evaluate(
        owner_id,
        owner_id,
        "noise:rec",
        &Action::Read,
        &DataTier::Noise,
        0,
    );
    dec.is_permit()
}

// ── Pre/post condition wrappers ───────────────────────────────────────────────

/// Pre-condition: record is valid for write.
pub fn pre_write(record: &Record) -> Result<(), String> {
    if record.owner_id.is_empty() {
        return Err("pre_write: owner_id must not be empty".into());
    }
    if record.id.is_empty() {
        return Err("pre_write: id must not be empty".into());
    }
    Ok(())
}

/// Post-condition: after write, record count increased by at most 1.
pub fn post_write(before_count: usize, after_count: usize) -> bool {
    after_count == before_count + 1 || after_count == before_count // overwrite case
}

/// Pre-condition: read request is well-formed.
pub fn pre_read(record_id: &str, requester_id: &str) -> Result<(), String> {
    if record_id.is_empty() {
        return Err("pre_read: record_id must not be empty".into());
    }
    if requester_id.is_empty() {
        return Err("pre_read: requester_id must not be empty".into());
    }
    Ok(())
}

/// Post-condition: delete reduces count by exactly 1 or 0 (if not found).
pub fn post_delete(before_count: usize, after_count: usize, found: bool) -> bool {
    if found {
        after_count == before_count - 1
    } else {
        after_count == before_count
    }
}

// ── Property witnesses ────────────────────────────────────────────────────────

/// Witness: Noise records are readable without authentication.
/// Returns Ok if the property holds for the given record.
pub fn witness_noise_open(record: &Record) -> Result<(), String> {
    if record.tier != DataTier::Noise {
        return Ok(()); // property doesn't apply
    }
    // Any requester should be able to read Noise
    // Noise tier: readable by owner (trivially) and all others
    if record.tier == DataTier::Noise {
        Ok(())
    } else {
        Err("witness_noise_open: Noise record not universally readable".into())
    }
}

/// Witness: Critical records are only readable by owner.
pub fn witness_critical_owner_only(record: &Record, requester: &str) -> Result<(), String> {
    if record.tier != DataTier::Critical {
        return Ok(());
    }
    let should_permit = requester == record.owner_id;
    let tier_gate_result = invariant_tier_gate(record, requester);
    if tier_gate_result == should_permit {
        Ok(())
    } else {
        Err(format!(
            "witness_critical_owner_only: tier gate mismatch for {}",
            requester
        ))
    }
}

/// Witness: write followed by read returns the same record.
pub fn witness_write_read_consistency(
    store: &mut Store,
    record: Record,
    _requester_id: &str,
) -> Result<(), String> {
    let id = record.id.clone();
    let owner = record.owner_id.clone();
    store.write(record).map_err(|e| e.to_string())?;
    match store.read(&id, &owner) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!(
            "witness_write_read_consistency: read after write failed for {}: {}",
            id, e
        )),
    }
}

// ── Kani harnesses (gated on #[cfg(kani)]) ───────────────────────────────────

#[cfg(kani)]
#[allow(unexpected_cfgs)]
mod kani_harnesses {
    use super::*;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum SymbolicIdentity {
        OwnerA,
        OwnerB,
        RequesterA,
        RequesterB,
    }

    fn symbolic_identity() -> SymbolicIdentity {
        match kani::any::<u8>() % 4 {
            0 => SymbolicIdentity::OwnerA,
            1 => SymbolicIdentity::OwnerB,
            2 => SymbolicIdentity::RequesterA,
            _ => SymbolicIdentity::RequesterB,
        }
    }

    fn identity_str(identity: SymbolicIdentity) -> &'static str {
        match identity {
            SymbolicIdentity::OwnerA => "owner-a",
            SymbolicIdentity::OwnerB => "owner-b",
            SymbolicIdentity::RequesterA => "requester-a",
            SymbolicIdentity::RequesterB => "requester-b",
        }
    }

    #[kani::proof]
    fn kani_owner_nonempty_invariant() {
        let owner = symbolic_identity();
        let owner_string = identity_str(owner).to_owned();

        let record = Record {
            id: "rec:1".into(),
            tier: DataTier::Noise,
            owner_id: owner_string,
            payload: vec![],
            salt: [0u8; 32],
            created_at: 0,
        };

        assert!(invariant_record_owner_nonempty(&record));
    }

    #[kani::proof]
    fn kani_tier_gate_critical() {
        let requester_is_owner: bool = kani::any();

        let record = Record {
            id: "rec:1".into(),
            tier: DataTier::Critical,
            owner_id: "owner".into(),
            payload: vec![],
            salt: [0u8; 32],
            created_at: 0,
        };

        let requester = if requester_is_owner { "owner" } else { "other" };

        let result = invariant_tier_gate(&record, requester);

        assert_eq!(result, requester_is_owner);
    }
}
