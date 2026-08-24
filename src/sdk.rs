//! # EdisonDB Rust SDK
//!
//! The official Rust SDK for EdisonDB — the sovereign, AI-native,
//! multi-model database engine.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use edisondb::sdk::{EdisonDB, SdkRecord};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut db = EdisonDB::connect("myapp.redb", "owner", "password")?;
//!
//!     db.write("user:1", "personal", "Alice sovereign data")?;
//!
//!     if let Some(record) = db.read("user:1")? {
//!         println!("Got: {}", record.payload);
//!     }
//!
//!     Ok(())
//! }
//! ```

use crate::executor::{EqlExecutor, EqlResult, DbStats};
use crate::eql::parse;
use crate::EdisonError;

// ── SdkRecord ─────────────────────────────────────────────────────────────────

/// A record returned by EdisonDB read and list operations.
#[derive(Debug, Clone)]
pub struct SdkRecord {
    /// The unique identifier of the record.
    pub id: String,
    /// The data tier: "critical", "personal", or "noise".
    pub tier: String,
    /// The decrypted payload content.
    pub payload: String,
    /// Unix timestamp of record creation.
    pub created_at: u64,
}

// ── SdkAuditEntry ─────────────────────────────────────────────────────────────

/// A single entry in the audit log.
#[derive(Debug, Clone)]
pub struct SdkAuditEntry {
    /// The record ID this audit entry refers to.
    pub record_id: String,
    /// The identity that performed the action.
    pub requester_id: String,
    /// Human-readable action description.
    pub action: String,
    /// Unix timestamp of the action.
    pub timestamp: u64,
}

// ── EdisonDB ──────────────────────────────────────────────────────────────────

/// The main EdisonDB client.
///
/// Create a client with [`EdisonDB::connect`], then use the methods
/// to read and write sovereign encrypted data.
///
/// All data is encrypted at rest using AES-256-GCM with Argon2id
/// key derivation. The password never leaves the client.
pub struct EdisonDB {
    executor: EqlExecutor,
}

impl EdisonDB {
    /// Open or create an EdisonDB database.
    ///
    /// If the database file does not exist, it is created.
    /// If it exists, it is opened and decrypted using the provided credentials.
    ///
    /// # Arguments
    /// * `path`     — Path to the `.redb` database file.
    /// * `owner_id` — The owner identity string (e.g. `"alice"`).
    /// * `password` — The password used for key derivation.
    ///
    /// # Errors
    /// Returns [`EdisonError`] if the database cannot be opened.
    pub fn connect(path: &str, owner_id: &str, password: &str) -> Result<Self, EdisonError> {
        let executor = EqlExecutor::open(path, owner_id, password)?;
        Ok(Self { executor })
    }

    /// Write a new record to the database.
    ///
    /// # Arguments
    /// * `id`      — Unique record identifier (e.g. `"user:1"`).
    /// * `tier`    — Data tier: `"CRITICAL"`, `"PERSONAL"`, or `"NOISE"`.
    /// * `payload` — The plaintext data to encrypt and store.
    ///
    /// # Errors
    /// Returns [`EdisonError::AlreadyExists`] if the ID is already taken.
    pub fn write(&mut self, id: &str, tier: &str, payload: &str) -> Result<(), EdisonError> {
        let stmt = parse(&format!("WRITE {} TIER {} {}", id, tier.to_uppercase(), payload))
            .map_err(|_| EdisonError::SaveFailed)?;
        self.executor.execute(stmt)?;
        Ok(())
    }

    /// Read a record by ID.
    ///
    /// Returns `None` if the record does not exist.
    /// Returns [`EdisonError::AccessDenied`] if the caller is not the owner.
    pub fn read(&mut self, id: &str) -> Result<Option<SdkRecord>, EdisonError> {
        let stmt = parse(&format!("READ {}", id))
            .map_err(|_| EdisonError::LoadFailed)?;
        match self.executor.execute(stmt) {
            Ok(EqlResult::Read { id, tier, payload }) => Ok(Some(SdkRecord {
                id,
                tier: format!("{:?}", tier).to_lowercase(),
                payload,
                created_at: 0,
            })),
            Err(EdisonError::NotFound) => Ok(None),
            Err(e) => Err(e),
            _ => Ok(None),
        }
    }

    /// List all records owned by this client.
    ///
    /// Optionally filter by tier: `"CRITICAL"`, `"PERSONAL"`, or `"NOISE"`.
    pub fn list(&mut self, tier: Option<&str>) -> Result<Vec<SdkRecord>, EdisonError> {
        let cmd = match tier {
            Some(t) => format!("LIST TIER {}", t.to_uppercase()),
            None    => "LIST".to_string(),
        };
        let stmt = parse(&cmd).map_err(|_| EdisonError::LoadFailed)?;
        match self.executor.execute(stmt)? {
            EqlResult::Listed(records) => Ok(records.into_iter().map(|r| SdkRecord {
                id:         r.string_id,
                tier:       format!("{:?}", r.tier).to_lowercase(),
                payload:    String::new(),
                created_at: r.created_at,
            }).collect()),
            _ => Ok(vec![]),
        }
    }

    /// Delete a record by ID.
    ///
    /// Only the owner can delete their own records.
    pub fn delete(&mut self, id: &str) -> Result<(), EdisonError> {
        let stmt = parse(&format!("DELETE {}", id))
            .map_err(|_| EdisonError::SaveFailed)?;
        self.executor.execute(stmt)?;
        Ok(())
    }

    /// Retrieve the audit log, optionally filtered by record ID.
    pub fn audit(&self, id: Option<&str>) -> Result<Vec<SdkAuditEntry>, EdisonError> {
        let entries = self.executor.audit_log(id);
        Ok(entries.into_iter().map(|e| SdkAuditEntry {
            record_id:    e.record_id,
            requester_id: e.requester_id,
            action:       format!("{:?}", e.action),
            timestamp:    e.timestamp,
        }).collect())
    }

    /// Return database statistics.
    pub fn status(
        &self,
    ) -> Result<DbStats, crate::EdisonError> {
        self.executor.stats()
    }

    /// Verify the audit chain integrity.
    ///
    /// Returns `Ok(())` if the chain is intact.
    /// Returns [`EdisonError::AuditChainBroken`] if tampering is detected.
    pub fn verify(&self) -> Result<(), EdisonError> {
        self.executor.verify_chain()
    }

    /// Persist the current state to disk explicitly.
    pub fn persist(&self) -> Result<(), EdisonError> {
        self.executor.save()
    }

    /// Return the name of the active storage backend.
    pub fn backend(&self) -> &str {
        self.executor.backend_name()
    }

    /// Search for similar vectors by query vector.
    pub fn search_vectors(
        &mut self,
        query: &[f32],
        k: usize,
        min_similarity: Option<f32>,
    ) -> Result<Vec<crate::executor::VectorHit>, EdisonError> {
        use crate::eql::Statement;
        let stmt = Statement::Search {
            query: query.to_vec(),
            k,
            min_similarity,
        };
        match self.executor.execute(stmt)? {
            crate::executor::EqlResult::Found(hits) => Ok(hits),
            _ => Ok(vec![]),
        }
    }
}
