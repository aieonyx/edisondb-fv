pub mod redb;
pub mod fjall;

pub use redb::RedbBackend;
pub use fjall::FjallBackend;

use crate::{Record, AuditEntry, EdisonError};

// ── StorageBackend trait ──────────────────────────────────────────────────────
pub trait StorageBackend: Send {
    fn write(&mut self, record: Record) -> Result<(), EdisonError>;
    fn read(&mut self, id: &str, requester_id: &str) -> Result<Record, EdisonError>;
    fn list_by_owner(&self, owner_id: &str) -> Result<Vec<Record>, EdisonError>;
    fn delete(&mut self, id: &str, requester_id: &str) -> Result<(), EdisonError>;
    fn audit_entries(&self) -> Vec<AuditEntry>;
    fn audit_count(&self) -> usize;
    fn verify_audit_chain(&self) -> Result<(), EdisonError>;
    fn save(&self) -> Result<(), EdisonError>;
    fn backend_name(&self) -> &'static str;
}

// ── Router ────────────────────────────────────────────────────────────────────
pub struct Router {
    backend: Box<dyn StorageBackend>,
}

impl Router {
    pub fn new(backend: Box<dyn StorageBackend>) -> Self {
        Self { backend }
    }
    pub fn backend_name(&self) -> &'static str { self.backend.backend_name() }
    pub fn write(&mut self, record: Record) -> Result<(), EdisonError> { self.backend.write(record) }
    pub fn read(&mut self, id: &str, requester_id: &str) -> Result<Record, EdisonError> { self.backend.read(id, requester_id) }
    pub fn list_by_owner(&self, owner_id: &str) -> Result<Vec<Record>, EdisonError> { self.backend.list_by_owner(owner_id) }
    pub fn delete(&mut self, id: &str, requester_id: &str) -> Result<(), EdisonError> { self.backend.delete(id, requester_id) }
    pub fn audit_entries(&self) -> Vec<AuditEntry> { self.backend.audit_entries() }
    pub fn audit_count(&self) -> usize { self.backend.audit_count() }
    pub fn verify_audit_chain(&self) -> Result<(), EdisonError> { self.backend.verify_audit_chain() }
    pub fn save(&self) -> Result<(), EdisonError> { self.backend.save() }
}
