use super::StorageBackend;
use crate::{AuditAction, AuditEntry, DataTier, EdisonError, Record, now_secs};
use fjall::{Database, KeyspaceCreateOptions};
use std::collections::HashSet;

const CRITICAL: &str = "records_critical";
const PERSONAL: &str = "records_personal";
const NOISE: &str = "records_noise";
const AUDIT: &str = "audit";

pub struct FjallBackend {
    _db: Database,
    critical: fjall::Keyspace,
    personal: fjall::Keyspace,
    noise: fjall::Keyspace,
    audit: fjall::Keyspace,
    audit_len: usize,
    audit_tail: [u8; 32],
}

impl FjallBackend {
    pub fn open(path: &str) -> Result<Self, EdisonError> {
        let db = Database::builder(path)
            .open()
            .map_err(|_| EdisonError::LoadFailed)?;
        let critical = db
            .keyspace(CRITICAL, KeyspaceCreateOptions::default)
            .map_err(|_| EdisonError::LoadFailed)?;
        let personal = db
            .keyspace(PERSONAL, KeyspaceCreateOptions::default)
            .map_err(|_| EdisonError::LoadFailed)?;
        let noise = db
            .keyspace(NOISE, KeyspaceCreateOptions::default)
            .map_err(|_| EdisonError::LoadFailed)?;
        let audit = db
            .keyspace(AUDIT, KeyspaceCreateOptions::default)
            .map_err(|_| EdisonError::LoadFailed)?;

        let audit_entries = Self::validated_audit_entries(&audit)?;
        let audit_len = audit_entries.len();
        let audit_tail = audit_entries
            .last()
            .map(|entry| entry.entry_hash)
            .unwrap_or([0u8; 32]);

        let backend = Self {
            _db: db,
            critical,
            personal,
            noise,
            audit,
            audit_len,
            audit_tail,
        };

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
                let (key, value) = guard.into_inner().map_err(|_| EdisonError::LoadFailed)?;
                let record: Record =
                    serde_json::from_slice(&value).map_err(|_| EdisonError::LoadFailed)?;

                record.validate()?;

                let key_matches = &*key == record.id.as_bytes();
                let tier_matches = record.tier == expected_tier;
                let id_is_unique = record_ids.insert(record.id.clone());

                if !crate::persisted_record_metadata_valid(key_matches, tier_matches, id_is_unique)
                {
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
            DataTier::Noise => &self.noise,
        }
    }

    fn validated_audit_entries(audit: &fjall::Keyspace) -> Result<Vec<AuditEntry>, EdisonError> {
        let mut entries = Vec::new();
        let mut expected_prev = [0u8; 32];

        for (expected_index, guard) in audit.iter().enumerate() {
            let (key, value) = guard
                .into_inner()
                .map_err(|_| EdisonError::AuditChainBroken)?;

            let expected_key = format!("{expected_index:020}");
            if &*key != expected_key.as_bytes() {
                return Err(EdisonError::AuditChainBroken);
            }

            let entry: AuditEntry =
                serde_json::from_slice(&value).map_err(|_| EdisonError::AuditChainBroken)?;

            if entry.prev_hash != expected_prev || !entry.verify_hash() {
                return Err(EdisonError::AuditChainBroken);
            }

            expected_prev = entry.entry_hash;
            entries.push(entry);
        }

        Ok(entries)
    }

    fn append_audit(
        &mut self,
        record_id: String,
        requester_id: String,
        action: AuditAction,
    ) -> Result<(), EdisonError> {
        let next_len = self
            .audit_len
            .checked_add(1)
            .ok_or(EdisonError::SaveFailed)?;

        let entry = AuditEntry::new(record_id, requester_id, action, now_secs(), self.audit_tail);

        let json = serde_json::to_string(&entry).map_err(|_| EdisonError::SaveFailed)?;
        let key = format!("{:020}", self.audit_len);

        self.audit
            .insert(key.as_bytes(), json.as_bytes())
            .map_err(|_| EdisonError::SaveFailed)?;

        self.audit_len = next_len;
        self.audit_tail = entry.entry_hash;

        Ok(())
    }

    fn all_audit_entries(&self) -> Result<Vec<AuditEntry>, EdisonError> {
        Self::validated_audit_entries(&self.audit)
    }
}

impl StorageBackend for FjallBackend {
    fn write(&mut self, record: Record) -> Result<(), EdisonError> {
        record.validate()?;

        let mut id_exists = false;
        for ks in [&self.critical, &self.personal, &self.noise] {
            if ks
                .get(record.id.as_bytes())
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
        let json = serde_json::to_string(&record).map_err(|_| EdisonError::SaveFailed)?;
        self.tier_ks(&record.tier)
            .insert(record.id.as_bytes(), json.as_bytes())
            .map_err(|_| EdisonError::SaveFailed)?;
        Ok(())
    }

    fn read(&mut self, id: &str, requester_id: &str) -> Result<Record, EdisonError> {
        for tier in [DataTier::Critical, DataTier::Personal, DataTier::Noise] {
            let ks = self.tier_ks(&tier);
            if let Some(v) = ks.get(id.as_bytes()).map_err(|_| EdisonError::LoadFailed)? {
                let record: Record =
                    serde_json::from_slice(&v).map_err(|_| EdisonError::LoadFailed)?;
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
            if let Some(v) = ks.get(id.as_bytes()).map_err(|_| EdisonError::LoadFailed)? {
                let record: Record =
                    serde_json::from_slice(&v).map_err(|_| EdisonError::LoadFailed)?;
                if record.owner_id != requester_id {
                    return Err(EdisonError::AccessDenied);
                }
                self.append_audit(
                    id.to_string(),
                    requester_id.to_string(),
                    AuditAction::Delete,
                )?;
                self.tier_ks(&tier)
                    .remove(id.as_bytes())
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
        self.audit_len
    }

    fn verify_audit_chain(&self) -> Result<(), EdisonError> {
        Self::validated_audit_entries(&self.audit).map(|_| ())
    }

    fn save(&self) -> Result<(), EdisonError> {
        Ok(()) // fjall is always persistent
    }

    fn backend_name(&self) -> &'static str {
        "fjall"
    }
}
