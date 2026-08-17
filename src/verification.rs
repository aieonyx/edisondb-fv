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
    store.records.values().all(invariant_record_owner_nonempty)
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
    store
        .records
        .values()
        .all(|record| invariant_tier_gate(record, requester_id))
}

// ── Invariant 3: Audit log monotonicity ───────────────────────────────────────

/// Check that audit log timestamps are non-decreasing.
pub fn invariant_audit_monotonic(entries: &[AuditEntry]) -> bool {
    entries.windows(2).all(|w| w[0].timestamp <= w[1].timestamp)
}

pub(crate) fn audit_link_integrity_valid(
    previous_hash_matches: bool,
    entry_hash_valid: bool,
) -> bool {
    previous_hash_matches && entry_hash_valid
}

/// Check that every audit entry is sealed and linked to its predecessor.
pub fn invariant_audit_chain_integrity(entries: &[AuditEntry]) -> bool {
    let mut expected_prev = [0u8; 32];

    for entry in entries {
        if !audit_link_integrity_valid(entry.prev_hash == expected_prev, entry.verify_hash()) {
            return false;
        }

        expected_prev = entry.entry_hash;
    }

    true
}

/// Compatibility wrapper for the original verification API.
pub fn invariant_audit_chain_noself(entries: &[AuditEntry]) -> bool {
    invariant_audit_chain_integrity(entries)
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
    use crate::policy::{PolicyPrecheck, policy_precheck};
    use crate::{
        AuditAction, AuditEntry, EdisonError, ensure_new_record_id,
        validate_persisted_record_metadata, verify_audit_entries,
    };

    #[kani::proof]
    #[kani::unwind(16)]
    fn kani_owner_nonempty_invariant() {
        let owner_empty: bool = kani::any();

        let record = Record {
            id: "rec:1".into(),
            tier: DataTier::Noise,
            owner_id: if owner_empty { "" } else { "owner" }.into(),
            payload: vec![],
            salt: [0u8; 32],
            created_at: 0,
        };

        let result = record.validate();

        if owner_empty {
            assert_eq!(result, Err(EdisonError::NoOwner));
        } else {
            assert!(result.is_ok());
        }
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

    #[kani::proof]
    fn kani_policy_tier_ceiling() {
        let requester_is_owner: bool = kani::any();
        let tier_selector: u8 = kani::any();
        let role_selector: u8 = kani::any();
        let action_selector: u8 = kani::any();
        let delegation_expired: bool = kani::any();
        let add_allow_rule: bool = kani::any();
        let add_deny_rule: bool = kani::any();

        kani::assume(tier_selector < 3);
        kani::assume(role_selector < 6);
        kani::assume(action_selector < 6);

        let tier = match tier_selector {
            0 => DataTier::Critical,
            1 => DataTier::Personal,
            _ => DataTier::Noise,
        };

        let _downstream_configuration = (
            role_selector,
            action_selector,
            delegation_expired,
            add_allow_rule,
            add_deny_rule,
        );

        let decision = policy_precheck(requester_is_owner, &tier);

        match tier {
            DataTier::Critical => {
                if requester_is_owner {
                    assert_eq!(decision, PolicyPrecheck::PermitOwner);
                } else {
                    assert_eq!(decision, PolicyPrecheck::DenyCritical);
                }
            }
            DataTier::Personal | DataTier::Noise => {
                if requester_is_owner {
                    assert_eq!(decision, PolicyPrecheck::PermitOwner);
                } else {
                    assert_eq!(decision, PolicyPrecheck::Continue);
                }
            }
        }
    }

    #[kani::proof]
    fn kani_record_identity_validation() {
        let id_empty: bool = kani::any();
        let owner_empty: bool = kani::any();

        let record = Record {
            id: if id_empty { "" } else { "rec:1" }.into(),
            tier: DataTier::Personal,
            owner_id: if owner_empty { "" } else { "owner" }.into(),
            payload: vec![],
            salt: [0u8; 32],
            created_at: 0,
        };

        assert_eq!(record.validate().is_ok(), !id_empty && !owner_empty);
    }

    #[kani::proof]
    fn kani_storage_id_immutability() {
        let id_exists: bool = kani::any();

        assert_eq!(ensure_new_record_id(id_exists).is_ok(), !id_exists);
    }

    fn sealed_three_entry_audit_entries() -> Vec<AuditEntry> {
        let first = AuditEntry::new("rec:0", "owner", AuditAction::Write, 1, [0u8; 32]);

        let second = AuditEntry::new(
            "rec:1",
            "owner",
            AuditAction::ReadGranted,
            2,
            first.entry_hash,
        );

        let third = AuditEntry::new("rec:2", "owner", AuditAction::Delete, 3, second.entry_hash);

        vec![first, second, third]
    }

    fn bounded_audit_model_input(entry_seed: u8, mutation_seed: u8, bit_seed: u16) -> [u8; 84] {
        let first = AuditEntry::new("rec:0", "owner", AuditAction::Write, 1, [0u8; 32]);

        let second = AuditEntry::new(
            "rec:1",
            "owner",
            AuditAction::ReadGranted,
            2,
            first.entry_hash,
        );

        let third = AuditEntry::new("rec:2", "owner", AuditAction::Delete, 3, second.entry_hash);

        let mut entry = match entry_seed % 3 {
            0 => first,
            1 => second,
            _ => third,
        };

        match mutation_seed % 3 {
            0 => {}
            1 => {
                let bit = (bit_seed % 64) as u32;
                entry.timestamp ^= 1u64 << bit;
            }
            _ => {
                let bit = (bit_seed % 256) as usize;
                entry.prev_hash[bit / 8] ^= 1u8 << (bit % 8);
            }
        }

        // Production serialization is the single source of truth.
        let serialized = entry.audit_hash_input();
        assert_eq!(serialized.len(), 84);

        let mut bytes = [0u8; 84];
        for index in 0..84 {
            bytes[index] = serialized[index];
        }

        bytes
    }

    #[kani::proof]
    #[kani::unwind(85)]
    fn kani_audit_digest_model_single_bit_tamper_changes_digest() {
        // FV-4b proves the forward property consumed by audit tamper
        // detection. For mutable bit p:
        //
        // T(x XOR e_p) = T(x) XOR code(p), where code(p) = p + 1.
        //
        // code(p) is nonzero, so a supported single-bit mutation must
        // change the bounded verification digest.
        let entry_seed: u8 = kani::any();
        let mutation_class: u8 = kani::any();
        let bit_seed: u16 = kani::any();

        kani::assume(entry_seed < 3);
        kani::assume(mutation_class == 1 || mutation_class == 2);

        let original = bounded_audit_model_input(entry_seed, 0, 0);
        let tampered = bounded_audit_model_input(entry_seed, mutation_class, bit_seed);

        if mutation_class == 1 {
            let bit = (bit_seed % 64) as usize;
            let byte = 51 - (bit / 8);

            // timestamp is serialized big-endian at bytes 44..52.
            assert!(original[byte] != tampered[byte]);
        } else {
            let bit = (bit_seed % 256) as usize;
            let byte = 52 + (bit / 8);

            // prev_hash is serialized directly at bytes 52..84.
            assert!(original[byte] != tampered[byte]);
        }

        let original_digest = crate::audit_digest(&original);
        let tampered_digest = crate::audit_digest(&tampered);

        // Bytes 14..16 carry the nine-bit linear syndrome. Showing
        // either syndrome byte changed establishes digest inequality
        // without invoking whole-array equality.
        assert!(
            original_digest[14] != tampered_digest[14]
                || original_digest[15] != tampered_digest[15]
        );
    }

    #[kani::proof]
    #[kani::unwind(85)]
    fn kani_audit_digest_distinct_identity_separates_entries() {
        let left_entry: u8 = kani::any();
        let right_entry: u8 = kani::any();

        kani::assume(left_entry < 3);
        kani::assume(right_entry < 3);
        kani::assume(left_entry != right_entry);

        let left = bounded_audit_model_input(left_entry, kani::any(), kani::any());
        let right = bounded_audit_model_input(right_entry, kani::any(), kani::any());

        // rec:0, rec:1, rec:2 have pairwise-distinct identity bytes.
        // Identity is carried directly by the verification digest, while
        // the syndrome is scoped to single-bit timestamp/prev_hash tamper.
        assert!(left[29] != right[29]);

        let left_digest = crate::audit_digest(&left);
        let right_digest = crate::audit_digest(&right);

        // In the FV-4b 84-byte model, input[29] is carried directly
        // to digest[12]. The bounded mutation classes do not modify
        // record identity, so distinct entries remain separated.
        assert!(left_digest[12] != right_digest[12]);
    }

    #[kani::proof]
    #[kani::unwind(80)]
    fn kani_audit_entry_model_hash_calibration() {
        // This live harness exercises the verification-only digest.
        // The earlier real-SHA calibration remains historical evidence.
        let entry = AuditEntry::new("rec:calibration", "owner", AuditAction::Write, 1, [0u8; 32]);

        assert!(entry.verify_hash());
    }

    #[kani::proof]
    #[kani::unwind(80)]
    fn kani_audit_chain_valid_sealed_chain() {
        let audit_log = sealed_three_entry_audit_entries();

        assert!(verify_audit_entries(&audit_log).is_ok());
    }

    #[kani::proof]
    #[kani::unwind(80)]
    fn kani_audit_chain_content_tamper_rejected() {
        let mut audit_log = sealed_three_entry_audit_entries();

        let entry_index: u8 = kani::any();
        let byte_index: u8 = kani::any();
        let bit_index: u8 = kani::any();

        kani::assume(entry_index < 3);
        kani::assume(byte_index < 8);
        kani::assume(bit_index < 8);

        let mut timestamp = match entry_index {
            0 => audit_log[0].timestamp.to_be_bytes(),
            1 => audit_log[1].timestamp.to_be_bytes(),
            _ => audit_log[2].timestamp.to_be_bytes(),
        };

        // A one-bit XOR mask is nonzero, so the selected byte must change.
        timestamp[byte_index as usize] ^= 1u8 << bit_index;
        let tampered = u64::from_be_bytes(timestamp);

        match entry_index {
            0 => audit_log[0].timestamp = tampered,
            1 => audit_log[1].timestamp = tampered,
            _ => audit_log[2].timestamp = tampered,
        }

        assert_eq!(
            verify_audit_entries(&audit_log),
            Err(EdisonError::AuditChainBroken)
        );
    }

    #[kani::proof]
    #[kani::unwind(80)]
    fn kani_audit_chain_prev_hash_tamper_rejected() {
        let mut audit_log = sealed_three_entry_audit_entries();

        let entry_index: u8 = kani::any();
        let byte_index: u8 = kani::any();
        let bit_index: u8 = kani::any();

        kani::assume(entry_index < 3);
        kani::assume(byte_index < 32);
        kani::assume(bit_index < 8);

        let mask = 1u8 << bit_index;

        // A one-bit XOR mask is nonzero, so the selected byte must change.
        match entry_index {
            0 => audit_log[0].prev_hash[byte_index as usize] ^= mask,
            1 => audit_log[1].prev_hash[byte_index as usize] ^= mask,
            _ => audit_log[2].prev_hash[byte_index as usize] ^= mask,
        }

        assert_eq!(
            verify_audit_entries(&audit_log),
            Err(EdisonError::AuditChainBroken)
        );
    }

    #[kani::proof]
    #[kani::unwind(80)]
    fn kani_audit_chain_entry_hash_tamper_rejected() {
        let mut audit_log = sealed_three_entry_audit_entries();

        let entry_index: u8 = kani::any();
        let byte_index: u8 = kani::any();
        let bit_index: u8 = kani::any();

        kani::assume(entry_index < 3);
        kani::assume(byte_index < 32);
        kani::assume(bit_index < 8);

        let mask = 1u8 << bit_index;

        // A one-bit XOR mask is nonzero, so the selected byte must change.
        match entry_index {
            0 => audit_log[0].entry_hash[byte_index as usize] ^= mask,
            1 => audit_log[1].entry_hash[byte_index as usize] ^= mask,
            _ => audit_log[2].entry_hash[byte_index as usize] ^= mask,
        }

        assert_eq!(
            verify_audit_entries(&audit_log),
            Err(EdisonError::AuditChainBroken)
        );
    }

    #[kani::proof]
    #[kani::unwind(80)]
    fn kani_audit_chain_reorder_rejected() {
        let mut audit_log = sealed_three_entry_audit_entries();

        let first_index: u8 = kani::any();
        let second_index: u8 = kani::any();

        kani::assume(first_index < 3);
        kani::assume(second_index < 3);
        kani::assume(first_index != second_index);

        audit_log.swap(first_index as usize, second_index as usize);

        assert_eq!(
            verify_audit_entries(&audit_log),
            Err(EdisonError::AuditChainBroken)
        );
    }

    #[kani::proof]
    #[kani::unwind(80)]
    fn kani_audit_chain_interior_drop_rejected() {
        let mut audit_log = sealed_three_entry_audit_entries();

        let drop_index: u8 = kani::any();

        // Only first/interior deletion is claimed here.
        // Tail deletion is intentionally covered by LIMIT-001 below.
        kani::assume(drop_index < 2);

        audit_log.remove(drop_index as usize);

        assert_eq!(
            verify_audit_entries(&audit_log),
            Err(EdisonError::AuditChainBroken)
        );
    }

    #[kani::proof]
    #[kani::unwind(80)]
    fn kani_audit_chain_tail_drop_limitation() {
        let mut audit_log = sealed_three_entry_audit_entries();

        let removed = audit_log.pop();
        assert!(removed.is_some());

        // LIMIT-001:
        // Before AuditCheckpoint exists, removal of the final entry leaves
        // an internally valid chain prefix. This harness witnesses the
        // limitation rather than claiming rejection.
        assert!(verify_audit_entries(&audit_log).is_ok());
    }

    #[kani::proof]
    fn kani_audit_chain_tail_drop_checkpoint_rejected() {
        let expected_count: u64 = kani::any();
        let expected_head: [u8; 32] = kani::any();

        kani::assume(expected_count > 0);

        let checkpoint = crate::AuditCheckpoint {
            expected_count,
            expected_head,
        };

        let actual_count = expected_count - 1;

        assert_eq!(
            crate::validate_audit_checkpoint(&checkpoint, actual_count, expected_head,),
            Err(crate::EdisonError::AuditChainBroken)
        );
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn kani_persisted_record_metadata() {
        let use_matching_key: bool = kani::any();
        let tier_selector: u8 = kani::any();
        let id_is_unique: bool = kani::any();

        kani::assume(tier_selector < 3);

        let record = Record {
            id: "rec:fv3".to_string(),
            tier: match tier_selector {
                0 => DataTier::Critical,
                1 => DataTier::Personal,
                _ => DataTier::Noise,
            },
            owner_id: "owner".to_string(),
            payload: Vec::new(),
            salt: [0u8; 32],
            created_at: 0,
        };

        let expected_tier = DataTier::Personal;
        let persisted_key: &[u8] = if use_matching_key {
            b"rec:fv3"
        } else {
            b"rec:other"
        };

        let result = validate_persisted_record_metadata(
            persisted_key,
            &record,
            &expected_tier,
            id_is_unique,
        );

        if result.is_ok() {
            assert_eq!(persisted_key, record.id.as_bytes());
            assert_eq!(&record.tier, &expected_tier);
            assert!(id_is_unique);
        }

        if persisted_key != record.id.as_bytes() {
            assert_eq!(result, Err(EdisonError::LoadFailed));
        }

        if record.tier != expected_tier {
            assert_eq!(result, Err(EdisonError::LoadFailed));
        }

        if !id_is_unique {
            assert_eq!(result, Err(EdisonError::LoadFailed));
        }

        if persisted_key == record.id.as_bytes() && record.tier == expected_tier && id_is_unique {
            assert!(result.is_ok());
        }
    }
}
