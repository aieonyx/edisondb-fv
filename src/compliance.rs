// Copyright (c) 2026 Edison Lepiten / AIEONYX
// EdisonDB P3-M9 — Compliance tooling
//
// Sovereign compliance layer:
//   1. Audit report generation — structured summary of all data activity
//   2. Retention policy checking — flag records older than policy window
//   3. Right-to-erasure (GDPR Art.17) — verify owner data can be fully removed
//   4. Tier compliance summary — count/validate records by tier
//   5. Policy violation detection — records without owners, wrong tier access

use std::collections::HashMap;
use crate::{Record, DataTier, AuditEntry, AuditAction};

// ── Retention policy ──────────────────────────────────────────────────────────

/// Retention policy: maximum age in seconds per tier.
/// 0 = no limit.
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    pub critical_max_age_secs: u64,
    pub personal_max_age_secs: u64,
    pub noise_max_age_secs: u64,
}

impl RetentionPolicy {
    pub fn new(critical: u64, personal: u64, noise: u64) -> Self {
        Self {
            critical_max_age_secs: critical,
            personal_max_age_secs: personal,
            noise_max_age_secs: noise,
        }
    }

    /// Sovereign default: Critical 7 years, Personal 3 years, Noise 90 days
    pub fn sovereign_default() -> Self {
        Self::new(
            7 * 365 * 86400,
            3 * 365 * 86400,
            90 * 86400,
        )
    }

    pub fn max_age(&self, tier: &DataTier) -> u64 {
        match tier {
            DataTier::Critical => self.critical_max_age_secs,
            DataTier::Personal => self.personal_max_age_secs,
            DataTier::Noise    => self.noise_max_age_secs,
        }
    }

    /// Check if a record violates retention policy given current time.
    pub fn is_expired(&self, record: &Record, now: u64) -> bool {
        let max = self.max_age(&record.tier);
        if max == 0 { return false; }
        now.saturating_sub(record.created_at) > max
    }
}

impl Default for RetentionPolicy {
    fn default() -> Self { Self::sovereign_default() }
}

// ── Tier summary ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct TierSummary {
    pub critical_count: usize,
    pub personal_count: usize,
    pub noise_count: usize,
    pub total_payload_bytes: usize,
}

impl TierSummary {
    pub fn from_records(records: &[&Record]) -> Self {
        let mut s = Self::default();
        for r in records {
            match r.tier {
                DataTier::Critical => s.critical_count += 1,
                DataTier::Personal => s.personal_count += 1,
                DataTier::Noise    => s.noise_count += 1,
            }
            s.total_payload_bytes += r.payload().len();
        }
        s
    }

    pub fn total(&self) -> usize {
        self.critical_count + self.personal_count + self.noise_count
    }
}

// ── Audit summary ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct AuditSummary {
    pub total_entries: usize,
    pub write_count: usize,
    pub read_count: usize,
    pub delete_count: usize,
    pub denied_count: usize,
    pub unique_requesters: usize,
    pub earliest_timestamp: u64,
    pub latest_timestamp: u64,
}

impl AuditSummary {
    pub fn from_entries(entries: &[AuditEntry]) -> Self {
        let mut s = Self::default();
        let mut requesters = std::collections::HashSet::new();
        s.total_entries = entries.len();
        for e in entries {
            match e.action {
                AuditAction::Write       => s.write_count += 1,
                AuditAction::ReadGranted => s.read_count += 1,
                AuditAction::ReadDenied  => s.denied_count += 1,
                AuditAction::Delete      => s.delete_count += 1,
            }
            requesters.insert(e.requester_id.clone());
            if s.earliest_timestamp == 0 || e.timestamp < s.earliest_timestamp {
                s.earliest_timestamp = e.timestamp;
            }
            if e.timestamp > s.latest_timestamp {
                s.latest_timestamp = e.timestamp;
            }
        }
        s.unique_requesters = requesters.len();
        s
    }
}

// ── Compliance violation ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ViolationType {
    RetentionExpired,
    MissingOwner,
    UnauthorizedAccess,
    AuditGap,           // timestamp gap > threshold
    DuplicateRecordId,
}

#[derive(Debug, Clone)]
pub struct ComplianceViolation {
    pub violation_type: ViolationType,
    pub record_id: Option<String>,
    pub detail: String,
}

impl ComplianceViolation {
    pub fn retention(record_id: &str, tier: &DataTier) -> Self {
        Self {
            violation_type: ViolationType::RetentionExpired,
            record_id: Some(record_id.to_string()),
            detail: format!("record {} ({:?}) exceeds retention policy", record_id, tier),
        }
    }
    pub fn missing_owner(record_id: &str) -> Self {
        Self {
            violation_type: ViolationType::MissingOwner,
            record_id: Some(record_id.to_string()),
            detail: format!("record {} has no owner", record_id),
        }
    }
    pub fn audit_gap(from: u64, to: u64, gap_secs: u64) -> Self {
        Self {
            violation_type: ViolationType::AuditGap,
            record_id: None,
            detail: format!("audit gap of {}s between {} and {}", gap_secs, from, to),
        }
    }
}

// ── Right-to-erasure ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ErasureReport {
    pub owner_id: String,
    pub records_found: usize,
    pub records_erasable: usize,
    pub audit_entries_found: usize,
    /// Record IDs that would be erased
    pub erasable_ids: Vec<String>,
}

/// Generate a right-to-erasure report for an owner.
/// Does not actually erase — returns what would be affected.
pub fn erasure_report(
    records: &[&Record],
    audit_entries: &[AuditEntry],
    owner_id: &str,
) -> ErasureReport {
    let owner_records: Vec<&&Record> = records.iter()
        .filter(|r| r.owner_id == owner_id)
        .collect();
    let erasable_ids: Vec<String> = owner_records.iter()
        .map(|r| r.id.clone())
        .collect();
    let audit_count = audit_entries.iter()
        .filter(|e| e.requester_id == owner_id)
        .count();

    ErasureReport {
        owner_id: owner_id.to_string(),
        records_found: owner_records.len(),
        records_erasable: owner_records.len(), // all owner records are erasable
        audit_entries_found: audit_count,
        erasable_ids,
    }
}

// ── Full compliance report ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ComplianceReport {
    pub generated_at: u64,
    pub tier_summary: TierSummary,
    pub audit_summary: AuditSummary,
    pub violations: Vec<ComplianceViolation>,
    pub owner_record_counts: HashMap<String, usize>,
    pub is_compliant: bool,
}

impl ComplianceReport {
    pub fn violation_count(&self) -> usize { self.violations.len() }
    pub fn has_violations(&self) -> bool { !self.violations.is_empty() }
}

/// Generate a full compliance report.
pub fn generate_report(
    records: &[&Record],
    audit_entries: &[AuditEntry],
    policy: &RetentionPolicy,
    now: u64,
    audit_gap_threshold_secs: u64,
) -> ComplianceReport {
    let mut violations = Vec::new();

    // Tier summary
    let tier_summary = TierSummary::from_records(records);

    // Audit summary
    let audit_summary = AuditSummary::from_entries(audit_entries);

    // Owner counts
    let mut owner_counts: HashMap<String, usize> = HashMap::new();
    for r in records {
        *owner_counts.entry(r.owner_id.clone()).or_insert(0) += 1;
    }

    // Check violations
    let mut seen_ids = std::collections::HashSet::new();
    for r in records {
        // Missing owner
        if r.owner_id.is_empty() {
            violations.push(ComplianceViolation::missing_owner(&r.id));
        }
        // Retention
        if policy.is_expired(r, now) {
            violations.push(ComplianceViolation::retention(&r.id, &r.tier));
        }
        // Duplicate IDs
        if !seen_ids.insert(r.id.clone()) {
            violations.push(ComplianceViolation {
                violation_type: ViolationType::DuplicateRecordId,
                record_id: Some(r.id.clone()),
                detail: format!("duplicate record id: {}", r.id),
            });
        }
    }

    // Audit gap check
    for window in audit_entries.windows(2) {
        let gap = window[1].timestamp.saturating_sub(window[0].timestamp);
        if gap > audit_gap_threshold_secs && audit_gap_threshold_secs > 0 {
            violations.push(ComplianceViolation::audit_gap(
                window[0].timestamp, window[1].timestamp, gap,
            ));
        }
    }

    let is_compliant = violations.is_empty();

    ComplianceReport {
        generated_at: now,
        tier_summary,
        audit_summary,
        violations,
        owner_record_counts: owner_counts,
        is_compliant,
    }
}
