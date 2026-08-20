use super::StorageBackend;
use crate::{
    AuditAction, AuditCheckpoint, AuditEntry, CheckpointOpenState, DataTier, EdisonError, Record,
    checkpoint_error, classify_checkpoint_state, now_secs,
};
use fjall::{Database, KeyspaceCreateOptions};
use std::collections::HashSet;

const CRITICAL: &str = "records_critical";
const PERSONAL: &str = "records_personal";
const NOISE: &str = "records_noise";
const AUDIT: &str = "audit";
const AUDIT_CHECKPOINT: &str = "audit_checkpoint";
const AUDIT_CHECKPOINT_KEY: &[u8] = b"current";

pub struct FjallBackend {
    _db: Database,
    critical: fjall::Keyspace,
    personal: fjall::Keyspace,
    noise: fjall::Keyspace,
    audit: fjall::Keyspace,
    audit_checkpoint: fjall::Keyspace,
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
        let audit_checkpoint = db
            .keyspace(AUDIT_CHECKPOINT, KeyspaceCreateOptions::default)
            .map_err(|_| EdisonError::LoadFailed)?;

        let audit_entries = Self::validated_audit_entries(&audit)?;
        let audit_len = audit_entries.len();
        let audit_tail = audit_entries
            .last()
            .map(|entry| entry.entry_hash)
            .unwrap_or([0u8; 32]);

        let records_empty = critical.is_empty().map_err(|_| EdisonError::LoadFailed)?
            && personal.is_empty().map_err(|_| EdisonError::LoadFailed)?
            && noise.is_empty().map_err(|_| EdisonError::LoadFailed)?;

        let checkpoint_value = audit_checkpoint
            .get(AUDIT_CHECKPOINT_KEY)
            .map_err(|_| EdisonError::LoadFailed)?;

        let checkpoint_bytes = checkpoint_value.as_deref();

        let actual_count = u64::try_from(audit_len).map_err(|_| EdisonError::AuditChainBroken)?;

        let checkpoint_state = classify_checkpoint_state(
            checkpoint_bytes,
            audit_entries.is_empty(),
            records_empty,
            actual_count,
            audit_tail,
        )
        .map_err(checkpoint_error)?;

        if checkpoint_state == CheckpointOpenState::Genesis {
            let checkpoint = AuditCheckpoint {
                expected_count: 0,
                expected_head: [0u8; 32],
            };

            let checkpoint_json =
                serde_json::to_vec(&checkpoint).map_err(|_| EdisonError::SaveFailed)?;

            let mut batch = db.batch();
            batch.insert(&audit_checkpoint, AUDIT_CHECKPOINT_KEY, checkpoint_json);
            batch.commit().map_err(|_| EdisonError::SaveFailed)?;
        }

        let backend = Self {
            _db: db,
            critical,
            personal,
            noise,
            audit,
            audit_checkpoint,
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

                let id_is_unique = record_ids.insert(record.id.clone());

                crate::validate_persisted_record_metadata(
                    &key,
                    &record,
                    &expected_tier,
                    id_is_unique,
                )?;
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

        let checkpoint_count = u64::try_from(next_len).map_err(|_| EdisonError::SaveFailed)?;

        let checkpoint = AuditCheckpoint {
            expected_count: checkpoint_count,
            expected_head: entry.entry_hash,
        };

        let checkpoint_json =
            serde_json::to_vec(&checkpoint).map_err(|_| EdisonError::SaveFailed)?;

        let key = format!("{:020}", self.audit_len);

        let mut batch = self._db.batch();
        batch.insert(&self.audit, key.as_bytes(), json.as_bytes());
        batch.insert(
            &self.audit_checkpoint,
            AUDIT_CHECKPOINT_KEY,
            checkpoint_json,
        );
        batch.commit().map_err(|_| EdisonError::SaveFailed)?;

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

        let next_len = self
            .audit_len
            .checked_add(1)
            .ok_or(EdisonError::SaveFailed)?;

        let entry = AuditEntry::new(
            record.id.clone(),
            record.owner_id.clone(),
            AuditAction::Write,
            now_secs(),
            self.audit_tail,
        );

        let audit_json = serde_json::to_string(&entry).map_err(|_| EdisonError::SaveFailed)?;
        let record_json = serde_json::to_string(&record).map_err(|_| EdisonError::SaveFailed)?;

        let checkpoint_count = u64::try_from(next_len).map_err(|_| EdisonError::SaveFailed)?;

        let checkpoint = AuditCheckpoint {
            expected_count: checkpoint_count,
            expected_head: entry.entry_hash,
        };

        let checkpoint_json =
            serde_json::to_vec(&checkpoint).map_err(|_| EdisonError::SaveFailed)?;

        let audit_key = format!("{:020}", self.audit_len);
        let record_keyspace = self.tier_ks(&record.tier).clone();

        let mut batch = self._db.batch();
        batch.insert(&self.audit, audit_key.as_bytes(), audit_json.as_bytes());
        batch.insert(
            &record_keyspace,
            record.id.as_bytes(),
            record_json.as_bytes(),
        );
        batch.insert(
            &self.audit_checkpoint,
            AUDIT_CHECKPOINT_KEY,
            checkpoint_json,
        );
        batch.commit().map_err(|_| EdisonError::SaveFailed)?;

        self.audit_len = next_len;
        self.audit_tail = entry.entry_hash;

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
            let record_keyspace = self.tier_ks(&tier).clone();

            if let Some(v) = record_keyspace
                .get(id.as_bytes())
                .map_err(|_| EdisonError::LoadFailed)?
            {
                let record: Record =
                    serde_json::from_slice(&v).map_err(|_| EdisonError::LoadFailed)?;

                if record.owner_id != requester_id {
                    return Err(EdisonError::AccessDenied);
                }

                let next_len = self
                    .audit_len
                    .checked_add(1)
                    .ok_or(EdisonError::SaveFailed)?;

                let entry = AuditEntry::new(
                    id.to_string(),
                    requester_id.to_string(),
                    AuditAction::Delete,
                    now_secs(),
                    self.audit_tail,
                );

                let audit_json =
                    serde_json::to_string(&entry).map_err(|_| EdisonError::SaveFailed)?;

                let checkpoint_count =
                    u64::try_from(next_len).map_err(|_| EdisonError::SaveFailed)?;

                let checkpoint = AuditCheckpoint {
                    expected_count: checkpoint_count,
                    expected_head: entry.entry_hash,
                };

                let checkpoint_json =
                    serde_json::to_vec(&checkpoint).map_err(|_| EdisonError::SaveFailed)?;

                let audit_key = format!("{:020}", self.audit_len);

                let mut batch = self._db.batch();
                batch.insert(&self.audit, audit_key.as_bytes(), audit_json.as_bytes());
                batch.remove(&record_keyspace, id.as_bytes());
                batch.insert(
                    &self.audit_checkpoint,
                    AUDIT_CHECKPOINT_KEY,
                    checkpoint_json,
                );
                batch.commit().map_err(|_| EdisonError::SaveFailed)?;

                self.audit_len = next_len;
                self.audit_tail = entry.entry_hash;

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

#[cfg(test)]
mod checkpoint_state_tests {
    use super::*;
    use crate::CheckpointFailureReason;

    #[test]
    fn checkpoint_state_reports_unanchored_records() {
        let checkpoint = AuditCheckpoint {
            expected_count: 0,
            expected_head: [0u8; 32],
        };

        let bytes = serde_json::to_vec(&checkpoint).unwrap();

        let result = classify_checkpoint_state(Some(&bytes), true, false, 0, [0u8; 32]);

        assert_eq!(result, Err(CheckpointFailureReason::UnanchoredRecords));
    }

    #[test]
    fn checkpoint_state_reports_missing() {
        let result = classify_checkpoint_state(None, false, true, 1, [7u8; 32]);

        assert_eq!(result, Err(CheckpointFailureReason::Missing));
    }

    #[test]
    fn checkpoint_state_reports_malformed() {
        let result = classify_checkpoint_state(Some(b"not-json"), true, true, 0, [0u8; 32]);

        assert_eq!(result, Err(CheckpointFailureReason::Malformed));
    }

    #[test]
    fn checkpoint_state_reports_count_mismatch() {
        let checkpoint = AuditCheckpoint {
            expected_count: 2,
            expected_head: [9u8; 32],
        };

        let bytes = serde_json::to_vec(&checkpoint).unwrap();

        let result = classify_checkpoint_state(Some(&bytes), false, true, 1, [9u8; 32]);

        assert_eq!(result, Err(CheckpointFailureReason::CountMismatch));
    }

    #[test]
    fn checkpoint_state_reports_head_mismatch() {
        let checkpoint = AuditCheckpoint {
            expected_count: 1,
            expected_head: [9u8; 32],
        };

        let bytes = serde_json::to_vec(&checkpoint).unwrap();

        let result = classify_checkpoint_state(Some(&bytes), false, true, 1, [8u8; 32]);

        assert_eq!(result, Err(CheckpointFailureReason::HeadMismatch));
    }
}
