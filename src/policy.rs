// Copyright (c) 2026 Edison Lepiten / AIEONYX
// EdisonDB P3-M6 — Sovereign access control + policy engine
//
// Architecture: Inverted Admin Model extended with policy rules.
// The owner always retains supreme authority over Critical/Personal data.
// Roles delegate subsets of that authority to other identities.
// Policies are evaluated after tier gates (DataTier still gates first).

use std::collections::HashMap;
use crate::DataTier;

// ── Action ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Action {
    Read,
    Write,
    Delete,
    Audit,   // read audit log
    Grant,   // delegate roles
    Admin,   // full control (owner-only by default)
}

impl Action {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "read"   => Some(Self::Read),
            "write"  => Some(Self::Write),
            "delete" => Some(Self::Delete),
            "audit"  => Some(Self::Audit),
            "grant"  => Some(Self::Grant),
            "admin"  => Some(Self::Admin),
            _        => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read   => "read",
            Self::Write  => "write",
            Self::Delete => "delete",
            Self::Audit  => "audit",
            Self::Grant  => "grant",
            Self::Admin  => "admin",
        }
    }
}

// ── Role ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Role {
    Owner,    // full control — all actions on all tiers
    Reader,   // read Noise + Personal (not Critical unless owner)
    Auditor,  // read audit log only
    Writer,   // read + write Noise + Personal
    Admin,    // all actions except Grant (cannot create new owners)
}

impl Role {
    /// Actions granted by this role on a given tier.
    pub fn permitted_actions(&self, tier: &DataTier) -> Vec<Action> {
        match self {
            Self::Owner => vec![
                Action::Read, Action::Write, Action::Delete,
                Action::Audit, Action::Grant, Action::Admin,
            ],
            Self::Reader => match tier {
                DataTier::Critical => vec![],
                DataTier::Personal => vec![Action::Read],
                DataTier::Noise    => vec![Action::Read],
            },
            Self::Auditor => vec![Action::Audit],
            Self::Writer => match tier {
                DataTier::Critical => vec![],
                DataTier::Personal => vec![Action::Read, Action::Write],
                DataTier::Noise    => vec![Action::Read, Action::Write],
            },
            Self::Admin => match tier {
                DataTier::Critical => vec![
                    Action::Read, Action::Write, Action::Delete, Action::Audit,
                ],
                DataTier::Personal => vec![
                    Action::Read, Action::Write, Action::Delete, Action::Audit,
                ],
                DataTier::Noise => vec![
                    Action::Read, Action::Write, Action::Delete, Action::Audit,
                ],
            },
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "owner"   => Some(Self::Owner),
            "reader"  => Some(Self::Reader),
            "auditor" => Some(Self::Auditor),
            "writer"  => Some(Self::Writer),
            "admin"   => Some(Self::Admin),
            _         => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Owner   => "owner",
            Self::Reader  => "reader",
            Self::Auditor => "auditor",
            Self::Writer  => "writer",
            Self::Admin   => "admin",
        }
    }
}

// ── Delegation ────────────────────────────────────────────────────────────────

/// A role grant from an owner to a subject identity.
#[derive(Debug, Clone)]
pub struct Delegation {
    /// Identity receiving the role
    pub subject: String,
    /// Role granted
    pub role: Role,
    /// Unix timestamp after which this delegation expires (0 = never)
    pub expires_at: u64,
    /// Granted by (must be owner or Admin)
    pub granted_by: String,
}

impl Delegation {
    pub fn new(subject: &str, role: Role, granted_by: &str, expires_at: u64) -> Self {
        Self {
            subject: subject.to_string(),
            role,
            expires_at,
            granted_by: granted_by.to_string(),
        }
    }

    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at != 0 && now > self.expires_at
    }

    pub fn permanent(subject: &str, role: Role, granted_by: &str) -> Self {
        Self::new(subject, role, granted_by, 0)
    }
}

// ── Policy rule ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum RuleEffect {
    Allow,
    Deny,
}

/// A single policy rule: subject + resource pattern + action → effect.
#[derive(Debug, Clone)]
pub struct PolicyRule {
    /// Subject identity (exact match, or "*" for any)
    pub subject: String,
    /// Resource pattern (prefix match, or "*" for any)
    pub resource: String,
    /// Action this rule applies to
    pub action: Action,
    /// Effect when matched
    pub effect: RuleEffect,
}

impl PolicyRule {
    pub fn allow(subject: &str, resource: &str, action: Action) -> Self {
        Self { subject: subject.into(), resource: resource.into(),
               action, effect: RuleEffect::Allow }
    }
    pub fn deny(subject: &str, resource: &str, action: Action) -> Self {
        Self { subject: subject.into(), resource: resource.into(),
               action, effect: RuleEffect::Deny }
    }

    /// Does this rule match the given request?
    pub fn matches(&self, subject: &str, resource: &str, action: &Action) -> bool {
        let subject_match = self.subject == "*" || self.subject == subject;
        let resource_match = self.resource == "*"
            || resource.starts_with(&self.resource)
            || self.resource == resource;
        let action_match = &self.action == action;
        subject_match && resource_match && action_match
    }
}

// ── Access decision ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum AccessDecision {
    Permit(String),        // reason
    Deny(String),          // reason
    NotApplicable(String), // no matching rule
}

impl AccessDecision {
    pub fn is_permit(&self) -> bool { matches!(self, Self::Permit(_)) }
    pub fn is_deny(&self)   -> bool { matches!(self, Self::Deny(_)) }
    pub fn reason(&self) -> &str {
        match self { Self::Permit(r)|Self::Deny(r)|Self::NotApplicable(r) => r }
    }
}

// ── Policy engine ─────────────────────────────────────────────────────────────

pub fn tier_ceiling_allows(is_owner: bool, tier: &DataTier) -> bool {
    !matches!(tier, DataTier::Critical) || is_owner
}

/// Sovereign policy engine — Inverted Admin Model extended with RBAC + rules.
/// Evaluation order:
///   1. Owner bypass — owner always gets Permit
///   2. Explicit Deny rules (Deny-overrides)
///   3. Delegation roles (role-based Allow)
///   4. Explicit Allow rules
///   5. Default Deny
pub struct PolicyEngine {
    /// owner_id → set of delegations they've issued
    delegations: HashMap<String, Vec<Delegation>>,
    /// Explicit policy rules (evaluated after role check)
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self { delegations: HashMap::new(), rules: vec![] }
    }

    /// Register a delegation (owner grants role to subject).
    pub fn delegate(&mut self, owner_id: &str, delegation: Delegation) {
        self.delegations.entry(owner_id.to_string())
            .or_default()
            .push(delegation);
    }

    /// Add a policy rule.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Evaluate access. `now` is current unix timestamp for expiry checks.
    pub fn evaluate(
        &self,
        subject: &str,
        owner_id: &str,
        resource: &str,
        action: &Action,
        tier: &DataTier,
        now: u64,
    ) -> AccessDecision {
        // 1. Owner bypass
        if subject == owner_id {
            return AccessDecision::Permit("owner bypass".into());
        }

        if !tier_ceiling_allows(subject == owner_id, tier) {
            return AccessDecision::Deny("critical tier requires owner".into());
        }

        // 2. Explicit Deny rules (highest priority after owner)
        for rule in &self.rules {
            if rule.matches(subject, resource, action) {
                if matches!(rule.effect, RuleEffect::Deny) {
                    return AccessDecision::Deny(
                        format!("explicit deny rule: {}/{}", rule.subject, rule.resource)
                    );
                }
            }
        }

        // 3. Delegation roles
        for (del_owner, delegations) in &self.delegations {
            if del_owner != owner_id { continue; }
            for del in delegations {
                if del.subject != subject { continue; }
                if del.is_expired(now) { continue; }
                let permitted = del.role.permitted_actions(tier);
                if permitted.contains(action) {
                    return AccessDecision::Permit(
                        format!("role:{} from:{}", del.role.as_str(), del.granted_by)
                    );
                }
            }
        }

        // 4. Explicit Allow rules
        for rule in &self.rules {
            if rule.matches(subject, resource, action) {
                if matches!(rule.effect, RuleEffect::Allow) {
                    return AccessDecision::Permit(
                        format!("allow rule: {}/{}", rule.subject, rule.resource)
                    );
                }
            }
        }

        // 5. Default Deny
        AccessDecision::Deny(format!(
            "default deny: {}@{} -> {} on {}",
            subject, resource, action.as_str(), tier.as_str()
        ))
    }

    pub fn delegation_count(&self, owner_id: &str) -> usize {
        self.delegations.get(owner_id).map(|v| v.len()).unwrap_or(0)
    }

    pub fn rule_count(&self) -> usize { self.rules.len() }
}

impl Default for PolicyEngine { fn default() -> Self { Self::new() } }
