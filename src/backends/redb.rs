use super::StorageBackend;
use crate::{AuditEntry, EdisonError, Record, Store};

// ── RedbBackend ───────────────────────────────────────────────────────────────
// Phase 1 backend — wraps Store (redb key-value engine).
pub struct RedbBackend {
    store: Store,
    path: String,
    // P3.5 authenticated checkpoint mode.
    //
    // The store secret is retained only so the existing keyless
    // StorageBackend `save()` trait method can continue persisting
    // authenticated checkpoints after an authenticated open.
    // FV-5 P4 owns secret zeroization.
    store_secret: Option<String>,
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
            store_secret: None,
        })
    }

    /// Open or create a Redb backend whose audit checkpoint is controlled
    /// by `store_secret`.
    ///
    /// Legacy checkpoints are rejected rather than implicitly upgraded.
    /// Conversely, `open()` rejects authenticated checkpoints because strict
    /// legacy checkpoint parsing does not accept authentication fields.
    pub fn open_authenticated(
        path: &str,
        store_secret: &str,
    ) -> Result<Self, EdisonError> {
        let store = if std::path::Path::new(path).exists() {
            Store::load_authenticated(path, store_secret)?
        } else {
            let store = Store::new();
            store.save_authenticated(path, store_secret)?;
            store
        };

        Ok(Self {
            store,
            path: path.to_string(),
            store_secret: Some(store_secret.to_string()),
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


    fn list_by_owner(
        &self,
        owner_id: &str,
    ) -> Result<Vec<Record>, EdisonError> {
        Ok(self
            .store
            .list_by_owner(owner_id)?
            .into_iter()
            .cloned()
            .collect())
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
        match self.store_secret.as_deref() {
            Some(store_secret) => {
                self.store.save_authenticated(&self.path, store_secret)
            }
            None => self.store.save(&self.path),
        }
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

    pub fn list_by_owner(&self, owner_id: &str) -> Result<Vec<Record>, EdisonError> {
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

#[cfg(test)]
mod p35_authenticated_backend_tests {
    use super::*;

    fn path(label: &str) -> String {
        format!(
            "/tmp/edisondb-p35-redb-{}-{}-{}.redb",
            label,
            std::process::id(),
            rand::random::<u64>(),
        )
    }

    #[test]
    fn p35_redb_authenticated_open_save_and_reopen() {
        let path = path("round-trip");
        let _ = std::fs::remove_file(&path);

        let backend =
            RedbBackend::open_authenticated(&path, "correct-store-secret")
                .unwrap();

        backend.save().unwrap();
        drop(backend);

        let reopened =
            RedbBackend::open_authenticated(&path, "correct-store-secret")
                .unwrap();

        assert_eq!(reopened.backend_name(), "redb");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn p35_redb_authenticated_open_rejects_wrong_store_secret() {
        let path = path("wrong-store-secret");
        let _ = std::fs::remove_file(&path);

        let backend =
            RedbBackend::open_authenticated(&path, "correct-store-secret")
                .unwrap();
        drop(backend);

        assert!(matches!(
            RedbBackend::open_authenticated(&path, "wrong-store-secret"),
            Err(EdisonError::AuditChainBroken)
        ));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn p35_redb_legacy_open_rejects_authenticated_checkpoint() {
        let path = path("legacy-downgrade");
        let _ = std::fs::remove_file(&path);

        let backend =
            RedbBackend::open_authenticated(&path, "correct-store-secret")
                .unwrap();
        drop(backend);

        assert!(matches!(
            RedbBackend::open(&path),
            Err(EdisonError::AuditChainBroken)
        ));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn p35_redb_authenticated_open_rejects_legacy_checkpoint() {
        let path = path("legacy-upgrade");
        let _ = std::fs::remove_file(&path);

        let backend = RedbBackend::open(&path).unwrap();
        drop(backend);

        assert!(matches!(
            RedbBackend::open_authenticated(
                &path,
                "checkpoint-store-secret",
            ),
            Err(EdisonError::AuditChainBroken)
        ));

        let _ = std::fs::remove_file(&path);
    }
}
