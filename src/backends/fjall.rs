use fjall::{Database, KeyspaceCreateOptions};
use crate::{Record, AuditEntry, AuditAction, EdisonError, DataTier, now_secs};
use super::StorageBackend;
use sha2::{Sha256, Digest};
use std::collections::HashSet;

const CRITICAL: &str = "records_critical";
const PERSONAL: &str = "records_personal";
const NOISE:    &str = "records_noise";
const AUDIT:    &str = "audit";

pub struct FjallBackend {
    _db:      Database,
    critical: fjall::Keyspace,
    personal: fjall::Keyspace,
    noise:    fjall::Keyspace,
    audit:    fjall::Keyspace,
}

impl FjallBackend {
    pub fn open(path: &str) -> Result<Self, EdisonError> {
        let db = Database::builder(path)
            .open()
            .map_err(|_| EdisonError::LoadFailed)?;
        let critical = db.keyspace(CRITICAL, KeyspaceCreateOptions::default)
            .map_err(|_| EdisonError::LoadFailed)?;
        let personal = db.keyspace(PERSONAL, KeyspaceCreateOptions::default)
            .map_err(|_| EdisonError::LoadFailed)?;
        let noise = db.keyspace(NOISE, KeyspaceCreateOptions::default)
            .map_err(|_| EdisonError::LoadFailed)?;
        let audit = db.keyspace(AUDIT, KeyspaceCreateOptions::default)
            .map_err(|_| EdisonError::LoadFailed)?;

        let backend = Self { _db: db, critical, personal, noise, audit };
        backend.validate_persisted_records()?;
        Ok(backend)
    }

    fn validate_persisted_records(&self) -> Result<(), EdisonError> {
        let mut record_ids = HashSet::new();

        for (keyspace, expected_tier) in [
            (&self.critical, DataTier::Critical),
            (&self.personal, DataTier::Personal),
            (&self.noise, DataTier::Noise),
        ] {
            for guard in keyspace.iter() {
                let (key, value) = guard.into_inner()
                    .map_err(|_| EdisonError::LoadFailed)?;
                let record: Record = serde_json::from_slice(&value)
                    .map_err(|_| EdisonError::LoadFailed)?;

                record.validate()?;

                let key_matches = &*key == record.id.as_bytes();
                let tier_matches = record.tier == expected_tier;
                let id_is_unique = record_ids.insert(record.id.clone());

                if !crate::persisted_record_metadata_valid(
                    key_matches,
                    tier_matches,
                    id_is_unique,
                ) {
                    return Err(EdisonError::LoadFailed);
                }
            }
        }

        Ok(())
    }

    fn tier_ks(&self, tier: &DataTier) -> &fjall::Keyspace {
        match tier {
            DataTier::Critical => &self.critical,
            DataTier::Personal => &self.personal,
            DataTier::Noise    => &self.noise,
        }
    }

    fn last_chain_hash(&self) -> [u8; 32] {
        let last = self.audit.iter().next_back();
        match last {
            None => [0u8; 32],
            Some(guard) => {
                match guard.into_inner() {
                    Ok((_, v)) => {
                        let mut hasher = Sha256::new();
                        hasher.update(&*v);
                        hasher.finalize().into()
                    }
                    Err(_) => [0u8; 32],
                }
            }
        }
    }

    fn append_audit(
        &self,
        record_id: String,
        requester_id: String,
        action: AuditAction,
    ) -> Result<(), EdisonError> {
        let prev_hash = self.last_chain_hash();
        let entry = AuditEntry {
            record_id,
            requester_id,
            action,
            timestamp: now_secs(),
            prev_hash,
        };
        let json = serde_json::to_string(&entry)
            .map_err(|_| EdisonError::SaveFailed)?;
        let idx = self.audit.len().unwrap_or(0);
        let key = format!("{:016}", idx);
        self.audit.insert(key.as_bytes(), json.as_bytes())
            .map_err(|_| EdisonError::SaveFailed)?;
        Ok(())
    }

    fn all_audit_entries(&self) -> Result<Vec<AuditEntry>, EdisonError> {
        let mut entries = Vec::new();
        for guard in self.audit.iter() {
            let (_, v) = guard.into_inner()
                .map_err(|_| EdisonError::LoadFailed)?;
            let entry: AuditEntry = serde_json::from_slice(&v)
                .map_err(|_| EdisonError::LoadFailed)?;
            entries.push(entry);
        }
        Ok(entries)
    }
}

impl StorageBackend for FjallBackend {
    fn write(&mut self, record: Record) -> Result<(), EdisonError> {
        record.validate()?;

        let mut id_exists = false;
        for ks in [&self.critical, &self.personal, &self.noise] {
            if ks.get(record.id.as_bytes())
                .map_err(|_| EdisonError::LoadFailed)?
                .is_some()
            {
                id_exists = true;
                break;
            }
        }
        crate::ensure_new_record_id(id_exists)?;
        self.append_audit(
            record.id.clone(),
            record.owner_id.clone(),
            AuditAction::Write,
        )?;
        let json = serde_json::to_string(&record)
            .map_err(|_| EdisonError::SaveFailed)?;
        self.tier_ks(&record.tier)
            .insert(record.id.as_bytes(), json.as_bytes())
            .map_err(|_| EdisonError::SaveFailed)?;
        Ok(())
    }

    fn read(&mut self, id: &str, requester_id: &str) -> Result<Record, EdisonError> {
        for tier in [DataTier::Critical, DataTier::Personal, DataTier::Noise] {
            let ks = self.tier_ks(&tier);
            if let Some(v) = ks.get(id.as_bytes())
                .map_err(|_| EdisonError::LoadFailed)? {
                let record: Record = serde_json::from_slice(&v)
                    .map_err(|_| EdisonError::LoadFailed)?;
                if record.is_readable_by(requester_id) {
                    self.append_audit(
                        id.to_string(),
                        requester_id.to_string(),
                        AuditAction::ReadGranted,
                    )?;
                    return Ok(record);
                } else {
                    self.append_audit(
                        id.to_string(),
                        requester_id.to_string(),
                        AuditAction::ReadDenied,
                    )?;
                    return Err(EdisonError::AccessDenied);
                }
            }
        }
        Err(EdisonError::NotFound)
    }

    fn list_by_owner(&self, owner_id: &str) -> Vec<Record> {
        let mut records = Vec::new();
        for ks in [&self.critical, &self.personal, &self.noise] {
            for guard in ks.iter() {
                if let Ok((_, v)) = guard.into_inner()
                    && let Ok(r) = serde_json::from_slice::<Record>(&v)
                    && r.owner_id == owner_id
                {
                    records.push(r);
                }
            }
        }
        records
    }

    fn delete(&mut self, id: &str, requester_id: &str) -> Result<(), EdisonError> {
        for tier in [DataTier::Critical, DataTier::Personal, DataTier::Noise] {
            let ks = self.tier_ks(&tier);
            if let Some(v) = ks.get(id.as_bytes())
                .map_err(|_| EdisonError::LoadFailed)? {
                let record: Record = serde_json::from_slice(&v)
                    .map_err(|_| EdisonError::LoadFailed)?;
                if record.owner_id != requester_id {
                    return Err(EdisonError::AccessDenied);
                }
                self.append_audit(
                    id.to_string(),
                    requester_id.to_string(),
                    AuditAction::Delete,
                )?;
                self.tier_ks(&tier).remove(id.as_bytes())
                    .map_err(|_| EdisonError::SaveFailed)?;
                return Ok(());
            }
        }
        Err(EdisonError::NotFound)
    }

    fn audit_entries(&self) -> Vec<AuditEntry> {
        self.all_audit_entries().unwrap_or_default()
    }

    fn audit_count(&self) -> usize {
        self.audit.len().unwrap_or(0)
    }

    fn verify_audit_chain(&self) -> Result<(), EdisonError> {
        let entries = self.all_audit_entries()?;
        let mut expected_prev = [0u8; 32];
        for entry in &entries {
            if entry.prev_hash != expected_prev {
                return Err(EdisonError::AuditChainBroken);
            }
            let json = serde_json::to_string(entry).unwrap_or_default();
            let mut hasher = Sha256::new();
            hasher.update(json.as_bytes());
            expected_prev = hasher.finalize().into();
        }
        Ok(())
    }

    fn save(&self) -> Result<(), EdisonError> {
        Ok(()) // fjall is always persistent
    }

    fn backend_name(&self) -> &'static str {
        "fjall"
    }
}
