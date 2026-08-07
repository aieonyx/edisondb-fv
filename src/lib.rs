use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use rand::RngCore;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
pub mod backends;
pub mod embedding;
pub mod eql;
pub mod executor;
pub mod sdk;
pub mod vector;

const RECORDS_TABLE: TableDefinition<&str, &str> = TableDefinition::new("records");
const AUDIT_TABLE: TableDefinition<&str, &str> = TableDefinition::new("audit");

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DataTier {
    Critical,
    Personal,
    Noise,
}

impl DataTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            DataTier::Critical => "critical",
            DataTier::Personal => "personal",
            DataTier::Noise => "noise",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub tier: DataTier,
    pub owner_id: String,
    pub payload: Vec<u8>,
    pub salt: [u8; 32],
    pub created_at: u64,
}

impl Record {
    pub fn new(
        id: &str,
        tier: DataTier,
        owner_id: &str,
        payload: Vec<u8>,
        salt: [u8; 32],
    ) -> Result<Self, EdisonError> {
        let record = Record {
            id: id.to_string(),
            tier,
            owner_id: owner_id.to_string(),
            payload,
            salt,
            created_at: now_secs(),
        };
        record.validate()?;
        Ok(record)
    }

    pub(crate) fn validate(&self) -> Result<(), EdisonError> {
        if self.owner_id.is_empty() {
            return Err(EdisonError::NoOwner);
        }
        if self.id.is_empty() {
            return Err(EdisonError::EmptyRecordId);
        }
        Ok(())
    }

    fn is_readable_by(&self, requester_id: &str) -> bool {
        match self.tier {
            DataTier::Critical => requester_id == self.owner_id,
            DataTier::Personal => requester_id == self.owner_id,
            DataTier::Noise => true,
        }
    }
}

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum EdisonError {
    #[error("Record must have an owner")]
    NoOwner,
    #[error("Record ID must not be empty")]
    EmptyRecordId,
    #[error("Access denied — owner only")]
    AccessDenied,
    #[error("Record not found")]
    NotFound,
    #[error("Failed to save database")]
    SaveFailed,
    #[error("Failed to load database")]
    LoadFailed,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed — wrong key or corrupted data")]
    DecryptionFailed,
    #[error("Key derivation failed")]
    KeyDerivationFailed,
    #[error("Record already exists")]
    AlreadyExists,
    #[error("Audit chain integrity violation")]
    AuditChainBroken,
    #[error("Embedding service unavailable — is Ollama running?")]
    EmbeddingUnavailable,
}

pub(crate) fn ensure_new_record_id(id_exists: bool) -> Result<(), EdisonError> {
    if id_exists {
        Err(EdisonError::AlreadyExists)
    } else {
        Ok(())
    }
}

pub(crate) fn persisted_record_metadata_valid(
    key_matches: bool,
    tier_matches: bool,
    id_is_unique: bool,
) -> bool {
    key_matches && tier_matches && id_is_unique
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    Write,
    ReadGranted,
    ReadDenied,
    Delete,
}

impl AuditAction {
    fn code(&self) -> u8 {
        match self {
            Self::Write => 1,
            Self::ReadGranted => 2,
            Self::ReadDenied => 3,
            Self::Delete => 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub record_id: String,
    pub requester_id: String,
    pub action: AuditAction,
    pub timestamp: u64,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

impl AuditEntry {
    pub fn new(
        record_id: impl Into<String>,
        requester_id: impl Into<String>,
        action: AuditAction,
        timestamp: u64,
        prev_hash: [u8; 32],
    ) -> Self {
        let mut entry = Self {
            record_id: record_id.into(),
            requester_id: requester_id.into(),
            action,
            timestamp,
            prev_hash,
            entry_hash: [0u8; 32],
        };

        entry.entry_hash = entry.calculate_hash();
        entry
    }

    pub fn verify_hash(&self) -> bool {
        self.entry_hash == self.calculate_hash()
    }

    fn calculate_hash(&self) -> [u8; 32] {
        fn update_text(hasher: &mut Sha256, value: &str) {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }

        let mut hasher = Sha256::new();
        hasher.update(b"EDISONDB-AUDIT-V1");
        update_text(&mut hasher, &self.record_id);
        update_text(&mut hasher, &self.requester_id);
        hasher.update([self.action.code()]);
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.prev_hash);
        hasher.finalize().into()
    }
}

pub struct Store {
    pub records: HashMap<String, Record>,
    pub audit_log: Vec<AuditEntry>,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    pub fn new() -> Self {
        Store {
            records: HashMap::new(),
            audit_log: Vec::new(),
        }
    }

    fn last_chain_hash(&self) -> [u8; 32] {
        self.audit_log
            .last()
            .map(|entry| entry.entry_hash)
            .unwrap_or([0u8; 32])
    }

    fn append_audit(&mut self, record_id: String, requester_id: String, action: AuditAction) {
        let entry = AuditEntry::new(
            record_id,
            requester_id,
            action,
            now_secs(),
            self.last_chain_hash(),
        );

        self.audit_log.push(entry);
    }

    pub fn verify_audit_chain(&self) -> Result<(), EdisonError> {
        let mut expected_prev = [0u8; 32];

        for entry in &self.audit_log {
            if entry.prev_hash != expected_prev || !entry.verify_hash() {
                return Err(EdisonError::AuditChainBroken);
            }

            expected_prev = entry.entry_hash;
        }

        Ok(())
    }

    pub fn write(&mut self, record: Record) -> Result<(), EdisonError> {
        record.validate()?;
        ensure_new_record_id(self.records.contains_key(&record.id))?;
        self.append_audit(
            record.id.clone(),
            record.owner_id.clone(),
            AuditAction::Write,
        );
        self.records.insert(record.id.clone(), record);
        Ok(())
    }

    pub fn read(&mut self, id: &str, requester_id: &str) -> Result<&Record, EdisonError> {
        let (found, readable) = match self.records.get(id) {
            None => return Err(EdisonError::NotFound),
            Some(record) => (true, record.is_readable_by(requester_id)),
        };
        let _ = found;
        if readable {
            self.append_audit(
                id.to_string(),
                requester_id.to_string(),
                AuditAction::ReadGranted,
            );
            Ok(self.records.get(id).unwrap())
        } else {
            self.append_audit(
                id.to_string(),
                requester_id.to_string(),
                AuditAction::ReadDenied,
            );
            Err(EdisonError::AccessDenied)
        }
    }

    pub fn audit_count(&self) -> usize {
        self.audit_log.len()
    }

    pub fn list_by_owner(&self, owner_id: &str) -> Vec<&Record> {
        self.records
            .values()
            .filter(|r| r.owner_id == owner_id)
            .collect()
    }

    pub fn audit_entries(&self) -> &Vec<AuditEntry> {
        &self.audit_log
    }

    pub fn delete(&mut self, id: &str, requester_id: &str) -> Result<(), EdisonError> {
        match self.records.get(id) {
            None => Err(EdisonError::NotFound),
            Some(record) => {
                if record.owner_id != requester_id {
                    return Err(EdisonError::AccessDenied);
                }
                self.append_audit(
                    id.to_string(),
                    requester_id.to_string(),
                    AuditAction::Delete,
                );
                self.records.remove(id);
                Ok(())
            }
        }
    }

    pub fn save(&self, path: &str) -> Result<(), EdisonError> {
        for (id, record) in &self.records {
            record.validate()?;
            if id != &record.id {
                return Err(EdisonError::SaveFailed);
            }
        }

        self.verify_audit_chain()?;

        let db = Database::create(path).map_err(|_| EdisonError::SaveFailed)?;
        let write_txn = db.begin_write().map_err(|_| EdisonError::SaveFailed)?;
        {
            let mut table = write_txn
                .open_table(RECORDS_TABLE)
                .map_err(|_| EdisonError::SaveFailed)?;
            // Drain all existing entries first so deletes are persisted
            let keys: Vec<String> = table
                .iter()
                .map_err(|_| EdisonError::SaveFailed)?
                .flatten()
                .map(|(k, _)| k.value().to_string())
                .collect();
            for key in keys {
                table
                    .remove(key.as_str())
                    .map_err(|_| EdisonError::SaveFailed)?;
            }
            for (id, record) in &self.records {
                let json = serde_json::to_string(record).map_err(|_| EdisonError::SaveFailed)?;
                table
                    .insert(id.as_str(), json.as_str())
                    .map_err(|_| EdisonError::SaveFailed)?;
            }
        }
        {
            let mut table = write_txn
                .open_table(AUDIT_TABLE)
                .map_err(|_| EdisonError::SaveFailed)?;

            let mut keys = Vec::new();
            for entry in table.iter().map_err(|_| EdisonError::SaveFailed)? {
                let (key, _) = entry.map_err(|_| EdisonError::SaveFailed)?;
                keys.push(key.value().to_string());
            }

            for key in keys {
                table
                    .remove(key.as_str())
                    .map_err(|_| EdisonError::SaveFailed)?;
            }

            for (index, entry) in self.audit_log.iter().enumerate() {
                let json = serde_json::to_string(entry).map_err(|_| EdisonError::SaveFailed)?;
                let key = format!("{index:020}");

                table
                    .insert(key.as_str(), json.as_str())
                    .map_err(|_| EdisonError::SaveFailed)?;
            }
        }
        write_txn.commit().map_err(|_| EdisonError::SaveFailed)?;
        Ok(())
    }

    pub fn load(path: &str) -> Result<Self, EdisonError> {
        let db = Database::open(path).map_err(|_| EdisonError::LoadFailed)?;
        let read_txn = db.begin_read().map_err(|_| EdisonError::LoadFailed)?;
        let mut records = HashMap::new();
        let table = read_txn
            .open_table(RECORDS_TABLE)
            .map_err(|_| EdisonError::LoadFailed)?;
        for entry in table.iter().map_err(|_| EdisonError::LoadFailed)? {
            let (key, value) = entry.map_err(|_| EdisonError::LoadFailed)?;
            let record: Record =
                serde_json::from_str(value.value()).map_err(|_| EdisonError::LoadFailed)?;

            record.validate()?;
            if key.value() != record.id {
                return Err(EdisonError::LoadFailed);
            }

            records.insert(record.id.clone(), record);
        }
        let mut keyed_audit = Vec::new();

        if let Ok(table) = read_txn.open_table(AUDIT_TABLE) {
            let iter = table.iter().map_err(|_| EdisonError::AuditChainBroken)?;

            for entry in iter {
                let (key, value) = entry.map_err(|_| EdisonError::AuditChainBroken)?;
                let key_text = key.value();
                let index = key_text
                    .parse::<usize>()
                    .map_err(|_| EdisonError::AuditChainBroken)?;

                if key_text != format!("{index:020}") {
                    return Err(EdisonError::AuditChainBroken);
                }

                let audit_entry: AuditEntry = serde_json::from_str(value.value())
                    .map_err(|_| EdisonError::AuditChainBroken)?;

                keyed_audit.push((index, audit_entry));
            }
        }

        keyed_audit.sort_by_key(|(index, _)| *index);

        let mut audit_log = Vec::with_capacity(keyed_audit.len());
        for (expected, (index, entry)) in keyed_audit.into_iter().enumerate() {
            if index != expected {
                return Err(EdisonError::AuditChainBroken);
            }

            audit_log.push(entry);
        }

        let store = Store { records, audit_log };
        store.verify_audit_chain()?;
        Ok(store)
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn encrypt_payload(
    data: &[u8],
    key: &[u8; 32],
    record_id: &str,
    tier: &DataTier,
) -> Result<Vec<u8>, EdisonError> {
    let aad = format!("{}:{}", record_id, tier.as_str());
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let payload = Payload {
        msg: data,
        aad: aad.as_bytes(),
    };
    let mut encrypted = cipher
        .encrypt(nonce, payload)
        .map_err(|_| EdisonError::EncryptionFailed)?;
    let mut result = nonce_bytes.to_vec();
    result.append(&mut encrypted);
    Ok(result)
}

pub fn decrypt_payload(
    data: &[u8],
    key: &[u8; 32],
    record_id: &str,
    tier: &DataTier,
) -> Result<Vec<u8>, EdisonError> {
    if data.len() < 12 {
        return Err(EdisonError::DecryptionFailed);
    }
    let aad = format!("{}:{}", record_id, tier.as_str());
    let (nonce_bytes, encrypted) = data.split_at(12);
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let payload = Payload {
        msg: encrypted,
        aad: aad.as_bytes(),
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| EdisonError::DecryptionFailed)
}

pub fn derive_key(password: &str, salt: &[u8; 32]) -> Result<[u8; 32], EdisonError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| EdisonError::KeyDerivationFailed)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_can_read_critical() {
        let r = Record::new(
            "rec:1",
            DataTier::Critical,
            "owner_abc",
            vec![1, 2, 3],
            [0u8; 32],
        )
        .unwrap();
        assert!(r.is_readable_by("owner_abc"));
    }

    #[test]
    fn non_owner_cannot_read_critical() {
        let r = Record::new(
            "rec:2",
            DataTier::Critical,
            "owner_abc",
            vec![1, 2, 3],
            [0u8; 32],
        )
        .unwrap();
        assert!(!r.is_readable_by("attacker"));
    }

    #[test]
    fn admin_cannot_read_critical() {
        let r = Record::new(
            "rec:3",
            DataTier::Critical,
            "owner_abc",
            vec![1, 2, 3],
            [0u8; 32],
        )
        .unwrap();
        assert!(!r.is_readable_by("admin"));
        assert!(!r.is_readable_by("root"));
    }

    #[test]
    fn noise_readable_by_anyone() {
        let r = Record::new(
            "rec:4",
            DataTier::Noise,
            "owner_abc",
            vec![9, 8, 7],
            [0u8; 32],
        )
        .unwrap();
        assert!(r.is_readable_by("anyone"));
    }

    #[test]
    fn record_without_owner_rejected() {
        let result = Record::new("rec:5", DataTier::Personal, "", vec![1], [0u8; 32]);
        assert_eq!(result, Err(EdisonError::NoOwner));
    }

    #[test]
    fn record_has_timestamp() {
        let r = Record::new("rec:6", DataTier::Personal, "owner_abc", vec![], [0u8; 32]).unwrap();
        assert!(r.created_at > 0);
    }

    #[test]
    fn owner_can_read_stored_record() {
        let mut store = Store::new();
        let r = Record::new(
            "rec:10",
            DataTier::Personal,
            "owner_abc",
            vec![1, 2, 3],
            [0u8; 32],
        )
        .unwrap();
        store.write(r).unwrap();
        assert!(store.read("rec:10", "owner_abc").is_ok());
    }

    #[test]
    fn attacker_cannot_read_stored_record() {
        let mut store = Store::new();
        let r = Record::new(
            "rec:11",
            DataTier::Critical,
            "owner_abc",
            vec![1, 2, 3],
            [0u8; 32],
        )
        .unwrap();
        store.write(r).unwrap();
        assert_eq!(
            store.read("rec:11", "attacker"),
            Err(EdisonError::AccessDenied)
        );
    }

    #[test]
    fn write_creates_audit_entry() {
        let mut store = Store::new();
        let r = Record::new(
            "rec:20",
            DataTier::Personal,
            "owner_abc",
            vec![1],
            [0u8; 32],
        )
        .unwrap();
        store.write(r).unwrap();
        assert_eq!(store.audit_count(), 1);
    }

    #[test]
    fn multiple_writes_all_audited() {
        let mut store = Store::new();
        for i in 0..5 {
            let id = format!("rec:{}", i);
            let r = Record::new(&id, DataTier::Noise, "owner_abc", vec![], [0u8; 32]).unwrap();
            store.write(r).unwrap();
        }
        assert_eq!(store.audit_count(), 5);
    }

    #[test]
    fn granted_read_is_audited() {
        let mut store = Store::new();
        let r = Record::new(
            "rec:30",
            DataTier::Personal,
            "owner_abc",
            vec![1],
            [0u8; 32],
        )
        .unwrap();
        store.write(r).unwrap();
        let _ = store.read("rec:30", "owner_abc");
        assert_eq!(store.audit_count(), 2);
    }

    #[test]
    fn denied_read_is_audited() {
        let mut store = Store::new();
        let r = Record::new(
            "rec:31",
            DataTier::Critical,
            "owner_abc",
            vec![1],
            [0u8; 32],
        )
        .unwrap();
        store.write(r).unwrap();
        let _ = store.read("rec:31", "attacker");
        assert_eq!(store.audit_count(), 2);
    }

    #[test]
    fn list_returns_owner_records_only() {
        let mut store = Store::new();
        let r1 = Record::new("rec:60", DataTier::Personal, "alice", vec![1], [0u8; 32]).unwrap();
        let r2 = Record::new("rec:61", DataTier::Noise, "bob", vec![2], [0u8; 32]).unwrap();
        store.write(r1).unwrap();
        store.write(r2).unwrap();
        let alice_records = store.list_by_owner("alice");
        assert_eq!(alice_records.len(), 1);
        assert_eq!(alice_records[0].id, "rec:60");
    }

    #[test]
    fn owner_can_delete_own_record() {
        let mut store = Store::new();
        let r = Record::new("rec:70", DataTier::Personal, "alice", vec![1], [0u8; 32]).unwrap();
        store.write(r).unwrap();
        assert!(store.delete("rec:70", "alice").is_ok());
        assert_eq!(store.list_by_owner("alice").len(), 0);
    }

    #[test]
    fn non_owner_cannot_delete_record() {
        let mut store = Store::new();
        let r = Record::new("rec:71", DataTier::Critical, "alice", vec![1], [0u8; 32]).unwrap();
        store.write(r).unwrap();
        assert_eq!(
            store.delete("rec:71", "attacker"),
            Err(EdisonError::AccessDenied)
        );
    }

    #[test]
    fn payload_encrypts_and_decrypts() {
        let key = [0u8; 32];
        let original = b"sovereign data";
        let encrypted = encrypt_payload(original, &key, "rec:crypto", &DataTier::Personal).unwrap();
        assert_ne!(encrypted, original.to_vec());
        let decrypted =
            decrypt_payload(&encrypted, &key, "rec:crypto", &DataTier::Personal).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn aad_mismatch_fails_decryption() {
        let key = [0u8; 32];
        let original = b"sovereign data";
        let encrypted =
            encrypt_payload(original, &key, "rec:aad-test", &DataTier::Critical).unwrap();
        let result = decrypt_payload(&encrypted, &key, "rec:other", &DataTier::Critical);
        assert_eq!(result, Err(EdisonError::DecryptionFailed));
    }

    #[test]
    fn aad_tier_mismatch_fails_decryption() {
        let key = [0u8; 32];
        let original = b"sovereign data";
        let encrypted =
            encrypt_payload(original, &key, "rec:tier-test", &DataTier::Critical).unwrap();
        let result = decrypt_payload(&encrypted, &key, "rec:tier-test", &DataTier::Personal);
        assert_eq!(result, Err(EdisonError::DecryptionFailed));
    }

    #[test]
    fn store_saves_and_loads() {
        let path = "/tmp/test_edison_m2.redb";
        let _ = std::fs::remove_file(path);
        let mut store = Store::new();
        let r = Record::new(
            "rec:40",
            DataTier::Personal,
            "owner_abc",
            vec![1, 2, 3],
            [0u8; 32],
        )
        .unwrap();
        store.write(r).unwrap();
        store.save(path).unwrap();
        let loaded = Store::load(path).unwrap();
        let record = loaded.records.get("rec:40").unwrap();
        assert_eq!(record.owner_id, "owner_abc");
    }

    #[test]
    fn audit_log_persists() {
        let path = "/tmp/test_audit_m2.redb";
        let _ = std::fs::remove_file(path);
        let mut store = Store::new();
        let r = Record::new(
            "rec:50",
            DataTier::Personal,
            "owner_abc",
            vec![1],
            [0u8; 32],
        )
        .unwrap();
        store.write(r).unwrap();
        let _ = store.read("rec:50", "owner_abc");
        store.save(path).unwrap();
        let loaded = Store::load(path).unwrap();
        assert_eq!(loaded.audit_count(), 2);
    }

    #[test]
    fn same_password_same_key() {
        let salt = [1u8; 32];
        let key1 = derive_key("owner_password", &salt).unwrap();
        let key2 = derive_key("owner_password", &salt).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn different_password_different_key() {
        let salt = [1u8; 32];
        let key1 = derive_key("owner_password", &salt).unwrap();
        let key2 = derive_key("wrong_password", &salt).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn duplicate_id_rejected() {
        let mut store = Store::new();
        let r1 = Record::new("rec:100", DataTier::Personal, "alice", vec![1], [0u8; 32]).unwrap();
        let r2 = Record::new("rec:100", DataTier::Personal, "alice", vec![2], [0u8; 32]).unwrap();
        store.write(r1).unwrap();
        assert_eq!(store.write(r2), Err(EdisonError::AlreadyExists));
    }

    #[test]
    fn audit_chain_is_valid() {
        let mut store = Store::new();
        for i in 0..5 {
            let id = format!("rec:{}", i);
            let r = Record::new(&id, DataTier::Personal, "alice", vec![1], [0u8; 32]).unwrap();
            store.write(r).unwrap();
            let _ = store.read(&id, "alice");
        }
        assert!(store.verify_audit_chain().is_ok());
    }

    #[test]
    fn audit_chain_detects_tampering() {
        let mut store = Store::new();
        let r = Record::new(
            "rec:tamper",
            DataTier::Critical,
            "alice",
            vec![1],
            [0u8; 32],
        )
        .unwrap();
        store.write(r).unwrap();
        let _ = store.read("rec:tamper", "alice");
        // Tamper with the first entry
        store.audit_log[0].record_id = "injected".to_string();
        assert_eq!(
            store.verify_audit_chain(),
            Err(EdisonError::AuditChainBroken)
        );
    }
}
pub mod arpi;
pub mod compliance;
pub mod migration;
pub mod policy;
pub mod sovereign_embed;
pub mod verification;

// Mobile FFI — enabled only under the `mobile` feature flag
#[cfg(feature = "mobile")]
pub mod mobile;
