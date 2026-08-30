// Copyright (c) 2026 Edison Lepiten / AIEONYX
// EdisonDB P3-M7 — Migration toolkit: export, import, transform, verify
//
// Wire format: Edison Migration (.edm) — newline-delimited JSON
// Line 0: header  {"edm":1,"exported_at":N,"record_count":N,"owner_filter":"..|null"}
// Line 1+: record {"id":"..","tier":"..","owner_id":"..","payload_hex":"..","salt_hex":"..","created_at":N}

use crate::{
    DataTier, EncryptedPayload, Record, now_secs,
};
use serde::{Deserialize, Serialize};

// ── .edm format ───────────────────────────────────────────────────────────────

pub const EDM_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdmHeader {
    pub edm: u32,
    pub exported_at: u64,
    pub record_count: usize,
    pub owner_filter: Option<String>,
    pub tier_filter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdmRecord {
    pub id: String,
    pub tier: String,
    pub owner_id: String,
    pub payload_hex: String,
    pub salt_hex: String,
    pub created_at: u64,
}

impl EdmRecord {
    pub fn from_record(r: &Record) -> Self {
        Self {
            id: r.id.clone(),
            tier: r.tier.as_str().to_string(),
            owner_id: r.owner_id.clone(),
            payload_hex: hex(r.payload()),
            salt_hex: hex(r.salt()),
            created_at: r.created_at,
        }
    }


    pub fn to_record(&self) -> Result<Record, MigrationError> {
        let tier = DataTier::from_str(&self.tier)
            .ok_or_else(|| MigrationError::InvalidTier(self.tier.clone()))?;

        let payload = unhex(&self.payload_hex)
            .ok_or_else(|| MigrationError::InvalidHex("payload".into()))?;

        let payload = EncryptedPayload::from_persisted(payload)
            .map_err(|e| MigrationError::InvalidRecordData(e.to_string()))?;

        let salt_bytes = unhex(&self.salt_hex)
            .ok_or_else(|| MigrationError::InvalidHex("salt".into()))?;

        if salt_bytes.len() != 32 {
            return Err(MigrationError::InvalidHex(
                "salt must be 32 bytes".into(),
            ));
        }

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&salt_bytes);

        crate::PersistedRecord::from_parts(
            self.id.clone(),
            tier,
            self.owner_id.clone(),
            payload,
            salt,
            self.created_at,
        )
        .into_validated_record()
        .map_err(|e| MigrationError::InvalidRecordData(e.to_string()))
    }
}

// ── Export ────────────────────────────────────────────────────────────────────

/// Export options
#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    /// Only export records owned by this identity (None = all)
    pub owner_filter: Option<String>,
    /// Only export records of this tier (None = all)
    pub tier_filter: Option<DataTier>,
}

/// Export records to .edm newline-delimited JSON string.
pub fn export(records: &[&Record], opts: &ExportOptions) -> Result<String, MigrationError> {
    // Apply filters
    let filtered: Vec<&&Record> = records.iter()
        .filter(|r| {
            let owner_ok = opts.owner_filter.as_deref()
                .map(|o| r.owner_id == o).unwrap_or(true);
            let tier_ok = opts.tier_filter.as_ref()
                .map(|t| &r.tier == t).unwrap_or(true);
            owner_ok && tier_ok
        })
        .collect();

    let header = EdmHeader {
        edm: EDM_VERSION,
        exported_at: now_secs(),
        record_count: filtered.len(),
        owner_filter: opts.owner_filter.clone(),
        tier_filter: opts.tier_filter.as_ref().map(|t| t.as_str().to_string()),
    };

    let mut lines = Vec::new();
    lines.push(serde_json::to_string(&header)
        .map_err(|e| MigrationError::Serialize(e.to_string()))?);

    for r in &filtered {
        let edm_rec = EdmRecord::from_record(r);
        lines.push(serde_json::to_string(&edm_rec)
            .map_err(|e| MigrationError::Serialize(e.to_string()))?);
    }

    Ok(lines.join("\n"))
}

// ── Import ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ConflictStrategy {
    Skip,       // skip existing records silently
    Overwrite,  // overwrite existing records
    Error,      // return error on conflict
}

#[derive(Debug, Default)]
pub struct ImportResult {
    pub imported: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

/// Parse .edm bytes into (header, records).
pub fn parse_edm(data: &str) -> Result<(EdmHeader, Vec<EdmRecord>), MigrationError> {
    let mut lines = data.lines();

    // Parse header
    let header_line = lines.next()
        .ok_or(MigrationError::EmptyInput)?;
    let header: EdmHeader = serde_json::from_str(header_line)
        .map_err(|e| MigrationError::InvalidHeader(e.to_string()))?;
    if header.edm != EDM_VERSION {
        return Err(MigrationError::VersionMismatch(header.edm));
    }

    // Parse records
    let mut records = Vec::new();
    for (i, line) in lines.enumerate() {
        if line.trim().is_empty() { continue; }
        let rec: EdmRecord = serde_json::from_str(line)
            .map_err(|e| MigrationError::InvalidRecord(i, e.to_string()))?;
        records.push(rec);
    }

    Ok((header, records))
}

/// Import records from parsed EdmRecords into a Vec<Record>.
/// Returns ImportResult with counts.
pub fn import(
    edm_records: &[EdmRecord],
    existing_ids: &std::collections::HashSet<String>,
    strategy: ConflictStrategy,
) -> (Vec<Record>, ImportResult) {
    let mut result = ImportResult::default();
    let mut out = Vec::new();

    for edm in edm_records {
        if existing_ids.contains(&edm.id) {
            match strategy {
                ConflictStrategy::Skip => {
                    result.skipped += 1;
                    continue;
                }
                ConflictStrategy::Error => {
                    result.errors.push(format!("conflict: {}", edm.id));
                    continue;
                }
                ConflictStrategy::Overwrite => {
                    // include anyway — caller handles overwrite
                }
            }
        }
        match edm.to_record() {
            Ok(r) => { out.push(r); result.imported += 1; }
            Err(e) => { result.errors.push(format!("record {}: {}", edm.id, e)); }
        }
    }

    (out, result)
}

// ── Transform ─────────────────────────────────────────────────────────────────

/// Transform options applied during migration
#[derive(Debug, Clone, Default)]
pub struct TransformOptions {
    /// Replace owner_id (re-own all records)
    pub new_owner: Option<String>,
    /// Replace tier for all records
    pub new_tier: Option<DataTier>,
    /// Prepend string to all record IDs
    pub id_prefix: Option<String>,
    /// Strip a prefix from record IDs
    pub strip_id_prefix: Option<String>,
}

/// Apply transforms to a set of EdmRecords in place.
pub fn transform(records: &mut Vec<EdmRecord>, opts: &TransformOptions) {
    for r in records.iter_mut() {
        if let Some(owner) = &opts.new_owner {
            r.owner_id = owner.clone();
        }
        if let Some(tier) = &opts.new_tier {
            r.tier = tier.as_str().to_string();
        }
        if let Some(prefix) = &opts.id_prefix {
            r.id = format!("{}{}", prefix, r.id);
        }
        if let Some(strip) = &opts.strip_id_prefix {
            if r.id.starts_with(strip.as_str()) {
                r.id = r.id[strip.len()..].to_string();
            }
        }
    }
}

// ── Verify ────────────────────────────────────────────────────────────────────

/// Manifest of a set of records — for post-migration integrity verification.
#[derive(Debug, Clone)]
pub struct MigrationManifest {
    pub record_count: usize,
    pub total_payload_bytes: usize,
    pub tier_counts: std::collections::HashMap<String, usize>,
    /// SHA-256 of all record IDs sorted and concatenated
    pub id_hash: [u8; 32],
}

/// Build a manifest from a slice of records.
pub fn build_manifest(records: &[Record]) -> MigrationManifest {
    let mut tier_counts = std::collections::HashMap::new();
    let mut total_payload = 0usize;
    let mut ids: Vec<&str> = records.iter().map(|r| r.id.as_str()).collect();
    ids.sort();

    for r in records {
        *tier_counts.entry(r.tier.as_str().to_string()).or_insert(0) += 1;
        total_payload += r.payload().len();
    }

    // Hash: SHA-256 of sorted IDs concatenated with null bytes
    let id_blob: Vec<u8> = ids.iter()
        .flat_map(|id| id.as_bytes().iter().chain(&[0u8]).copied())
        .collect();
    let id_hash = crate::arpi::sha256(&id_blob);

    MigrationManifest {
        record_count: records.len(),
        total_payload_bytes: total_payload,
        tier_counts,
        id_hash,
    }
}

/// Verify two manifests match (pre/post migration check).
pub fn verify_manifests(pre: &MigrationManifest, post: &MigrationManifest) -> bool {
    pre.record_count == post.record_count
        && pre.id_hash == post.id_hash
        && pre.total_payload_bytes == post.total_payload_bytes
}

// ── MigrationError ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum MigrationError {
    EmptyInput,
    InvalidHeader(String),
    VersionMismatch(u32),
    InvalidRecord(usize, String),
    InvalidRecordData(String),
    InvalidTier(String),
    InvalidHex(String),
    Conflict(String),
    Serialize(String),
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::EmptyInput           => write!(f, "empty .edm input"),
            Self::InvalidHeader(s)     => write!(f, "invalid header: {}", s),
            Self::VersionMismatch(v)   => write!(f, "unsupported .edm version: {}", v),
            Self::InvalidRecord(i, s)  => write!(f, "invalid record at line {}: {}", i, s),
            Self::InvalidRecordData(s) => write!(f, "invalid record data: {}", s),
            Self::InvalidTier(s)       => write!(f, "invalid tier: {}", s),
            Self::InvalidHex(s)        => write!(f, "invalid hex: {}", s),
            Self::Conflict(s)          => write!(f, "conflict: {}", s),
            Self::Serialize(s)         => write!(f, "serialize error: {}", s),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).ok())
        .collect()
}

// ── DataTier helper (needed here) ─────────────────────────────────────────────

impl DataTier {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "critical" => Some(Self::Critical),
            "personal" => Some(Self::Personal),
            "noise"    => Some(Self::Noise),
            _          => None,
        }
    }
}
