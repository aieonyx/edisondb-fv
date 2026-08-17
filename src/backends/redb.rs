use super::StorageBackend;
use crate::{AuditEntry, EdisonError, Record, Store};

// ── RedbBackend ───────────────────────────────────────────────────────────────
// Phase 1 backend — wraps Store (redb key-value engine).
pub struct RedbBackend {
    store: Store,
    path: String,
}

impl RedbBackend {
    pub fn open(path: &str) -> Result<Self, EdisonError> {
        let store = if std::path::Path::new(path).exists() {
            Store::load(path)?
        } else {
            let store = Store::new();
            store.save(path)?;
            store
        };
        Ok(Self {
            store,
            path: path.to_string(),
        })
    }
}

impl StorageBackend for RedbBackend {
    fn write(&mut self, record: Record) -> Result<(), EdisonError> {
        self.store.write(record)
    }

    fn read(&mut self, id: &str, requester_id: &str) -> Result<Record, EdisonError> {
        self.store.read(id, requester_id).cloned()
    }

    fn list_by_owner(&self, owner_id: &str) -> Vec<Record> {
        self.store
            .list_by_owner(owner_id)
            .into_iter()
            .cloned()
            .collect()
    }

    fn delete(&mut self, id: &str, requester_id: &str) -> Result<(), EdisonError> {
        self.store.delete(id, requester_id)
    }

    fn audit_entries(&self) -> Vec<AuditEntry> {
        self.store.audit_entries().clone()
    }

    fn audit_count(&self) -> usize {
        self.store.audit_count()
    }

    fn verify_audit_chain(&self) -> Result<(), EdisonError> {
        self.store.verify_audit_chain()
    }

    fn save(&self) -> Result<(), EdisonError> {
        self.store.save(&self.path)
    }

    fn backend_name(&self) -> &'static str {
        "redb"
    }
}

// ── Router ────────────────────────────────────────────────────────────────────
// The router holds the active backend and delegates all operations to it.
// In Phase 1, always routes to RedbBackend.
// In Phase 2+, may route by tier, query type, or config.
pub struct Router {
    backend: Box<dyn StorageBackend>,
}

impl Router {
    pub fn new(backend: Box<dyn StorageBackend>) -> Self {
        Self { backend }
    }

    pub fn backend_name(&self) -> &'static str {
        self.backend.backend_name()
    }

    pub fn write(&mut self, record: Record) -> Result<(), EdisonError> {
        self.backend.write(record)
    }

    pub fn read(&mut self, id: &str, requester_id: &str) -> Result<Record, EdisonError> {
        self.backend.read(id, requester_id)
    }

    pub fn list_by_owner(&self, owner_id: &str) -> Vec<Record> {
        self.backend.list_by_owner(owner_id)
    }

    pub fn delete(&mut self, id: &str, requester_id: &str) -> Result<(), EdisonError> {
        self.backend.delete(id, requester_id)
    }

    pub fn audit_entries(&self) -> Vec<AuditEntry> {
        self.backend.audit_entries()
    }

    pub fn audit_count(&self) -> usize {
        self.backend.audit_count()
    }

    pub fn verify_audit_chain(&self) -> Result<(), EdisonError> {
        self.backend.verify_audit_chain()
    }

    pub fn save(&self) -> Result<(), EdisonError> {
        self.backend.save()
    }
}
