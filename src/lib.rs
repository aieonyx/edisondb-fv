use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use rand::RngCore;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
#[cfg(not(kani))]
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
const AUDIT_CHECKPOINT_TABLE: TableDefinition<&str, &str> =
    TableDefinition::new("audit_checkpoint");
const AUDIT_CHECKPOINT_KEY: &str = "current";

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


pub const ENCRYPTED_PAYLOAD_MAGIC: [u8; 4] = *b"EDB1";
pub const ENCRYPTED_PAYLOAD_VERSION: u8 = 1;
pub const ENCRYPTED_PAYLOAD_NONCE_LEN: usize = 12;
pub const ENCRYPTED_PAYLOAD_TAG_LEN: usize = 16;

const ENCRYPTED_PAYLOAD_PREFIX_LEN: usize = 5;
const ENCRYPTED_PAYLOAD_CIPHERTEXT_OFFSET: usize =
    ENCRYPTED_PAYLOAD_PREFIX_LEN + ENCRYPTED_PAYLOAD_NONCE_LEN;
const ENCRYPTED_PAYLOAD_MIN_LEN: usize =
    ENCRYPTED_PAYLOAD_CIPHERTEXT_OFFSET + ENCRYPTED_PAYLOAD_TAG_LEN;

/// Structurally validated EdisonDB encrypted payload envelope.
///
/// Structural validity proves only that the framing is recognized and
/// internally well-formed. Cryptographic authenticity is established only
/// when AES-GCM decryption succeeds with the correct key and AAD.
#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedPayload {
    bytes: Vec<u8>,
}

impl EncryptedPayload {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn version(&self) -> u8 {
        self.bytes[4]
    }

    pub(crate) fn from_persisted(
        bytes: Vec<u8>,
    ) -> Result<Self, EdisonError> {
        Self::validate_bytes(&bytes)?;
        Ok(Self { bytes })
    }

    pub(crate) fn from_ciphertext_parts(
        nonce: [u8; ENCRYPTED_PAYLOAD_NONCE_LEN],
        ciphertext: Vec<u8>,
    ) -> Result<Self, EdisonError> {
        if ciphertext.len() < ENCRYPTED_PAYLOAD_TAG_LEN {
            return Err(EdisonError::InvalidEncryptedPayload);
        }

        let mut bytes = Vec::with_capacity(
            ENCRYPTED_PAYLOAD_PREFIX_LEN
                + ENCRYPTED_PAYLOAD_NONCE_LEN
                + ciphertext.len(),
        );

        bytes.extend_from_slice(&ENCRYPTED_PAYLOAD_MAGIC);
        bytes.push(ENCRYPTED_PAYLOAD_VERSION);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);

        Self::from_persisted(bytes)
    }

    fn validate_bytes(
        bytes: &[u8],
    ) -> Result<(), EdisonError> {
        if bytes.len() < ENCRYPTED_PAYLOAD_MAGIC.len()
            || !bytes.starts_with(&ENCRYPTED_PAYLOAD_MAGIC)
        {
            return Err(EdisonError::LegacyPayloadFormat);
        }

        if bytes.len() < ENCRYPTED_PAYLOAD_PREFIX_LEN {
            return Err(EdisonError::InvalidEncryptedPayload);
        }

        let version = bytes[4];

        if version != ENCRYPTED_PAYLOAD_VERSION {
            return Err(
                EdisonError::UnsupportedPayloadVersion(version),
            );
        }

        if bytes.len() < ENCRYPTED_PAYLOAD_MIN_LEN {
            return Err(EdisonError::InvalidEncryptedPayload);
        }

        Ok(())
    }

    pub(crate) fn nonce_and_ciphertext(
        &self,
    ) -> (&[u8], &[u8]) {
        (
            &self.bytes[
                ENCRYPTED_PAYLOAD_PREFIX_LEN
                    ..ENCRYPTED_PAYLOAD_CIPHERTEXT_OFFSET
            ],
            &self.bytes[
                ENCRYPTED_PAYLOAD_CIPHERTEXT_OFFSET..
            ],
        )
    }
}

impl Serialize for EncryptedPayload {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.bytes.serialize(serializer)
    }
}


/// Persisted reconstruction accepts only structurally valid versioned
/// envelopes. This does not establish cryptographic authenticity; that
/// remains the responsibility of authenticated decryption.
impl<'de> Deserialize<'de> for EncryptedPayload {
    fn deserialize<D>(
        deserializer: D,
    ) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;

        Self::from_persisted(bytes)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Record {
    id: String,
    tier: DataTier,
    pub owner_id: String,
    payload: EncryptedPayload,
    salt: [u8; 32],
    pub created_at: u64,
}


#[derive(Debug, Clone, PartialEq, Deserialize)]
pub(crate) struct PersistedRecord {
    id: String,
    tier: DataTier,
    owner_id: String,
    payload: EncryptedPayload,
    salt: [u8; 32],
    created_at: u64,
}

impl PersistedRecord {
    pub(crate) fn from_parts(
        id: String,
        tier: DataTier,
        owner_id: String,
        payload: EncryptedPayload,
        salt: [u8; 32],
        created_at: u64,
    ) -> Self {
        Self {
            id,
            tier,
            owner_id,
            payload,
            salt,
            created_at,
        }
    }

    pub(crate) fn into_validated_record(
        self,
    ) -> Result<Record, EdisonError> {
        if self.created_at == 0 {
            return Err(EdisonError::InvalidCreatedAt);
        }

        let PersistedRecord {
            id,
            tier,
            owner_id,
            payload,
            salt,
            created_at,
        } = self;

        Record::new_with_created_at(
            &id,
            tier,
            &owner_id,
            payload,
            salt,
            created_at,
        )
    }
}

pub(crate) fn validate_record_identity(
    id: &str,
    owner_id: &str,
) -> Result<(), EdisonError> {
    if owner_id.is_empty() {
        return Err(EdisonError::NoOwner);
    }

    if id.is_empty() {
        return Err(EdisonError::EmptyRecordId);
    }

    Ok(())
}

impl Record {
    /// Construct a record from plaintext using the supplied encryption key.
    ///
    /// Encryption is performed inside this constructor so the ciphertext's
    /// AES-GCM associated data is necessarily bound to this record's immutable
    /// identifier and tier.
    pub fn new(
        id: &str,
        tier: DataTier,
        owner_id: &str,
        data: &[u8],
        key: &[u8; 32],
        salt: [u8; 32],
    ) -> Result<Self, EdisonError> {
        let payload = encrypt_payload(data, key, id, &tier)?;

        Self::new_with_created_at(
            id,
            tier,
            owner_id,
            payload,
            salt,
            now_secs(),
        )
    }

    /// Construct a record with an explicit timestamp.
    ///
    /// This is the production-shared construction seam used by `new()` and
    /// verification paths that cannot model the operating-system clock.
    ///
    /// A zero timestamp is permitted during construction because it may
    /// represent a local clock anomaly. Persisted reconstruction is stricter
    /// and rejects a stored zero timestamp before reaching this constructor.
    pub(crate) fn new_with_created_at(
        id: &str,
        tier: DataTier,
        owner_id: &str,
        payload: EncryptedPayload,
        salt: [u8; 32],
        created_at: u64,
    ) -> Result<Self, EdisonError> {
        let record = Self {
            id: id.to_string(),
            tier,
            owner_id: owner_id.to_string(),
            payload,
            salt,
            created_at,
        };

        record.validate()?;
        Ok(record)
    }

    /// Immutable record identifier.
    ///
    /// The identifier is part of the AES-GCM associated-data boundary and
    /// cannot be changed independently of the encrypted payload.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Immutable data tier.
    ///
    /// The tier is part of the AES-GCM associated-data boundary and cannot be
    /// changed independently of the encrypted payload.
    pub fn tier(&self) -> &DataTier {
        &self.tier
    }

    pub fn payload(&self) -> &[u8] {
        self.payload.as_bytes()
    }

    pub(crate) fn encrypted_payload(
        &self,
    ) -> &EncryptedPayload {
        &self.payload
    }

    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }


    pub(crate) fn validate(&self) -> Result<(), EdisonError> {
        validate_record_identity(&self.id, &self.owner_id)
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
    #[error("legacy payload format")]
    LegacyPayloadFormat,
    #[error("unsupported encrypted payload version: {0}")]
    UnsupportedPayloadVersion(u8),
    #[error("invalid encrypted payload envelope")]
    InvalidEncryptedPayload,
    #[error("Key derivation failed")]
    KeyDerivationFailed,
    #[error("Record already exists")]
    AlreadyExists,
    #[error("Persisted record timestamp must be nonzero")]
    InvalidCreatedAt,
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

pub(crate) fn validate_persisted_record_metadata(
    persisted_key: &[u8],
    record: &Record,
    expected_tier: &DataTier,
    id_is_unique: bool,
) -> Result<(), EdisonError> {
    if persisted_key != record.id.as_bytes() || &record.tier != expected_tier || !id_is_unique {
        return Err(EdisonError::LoadFailed);
    }

    Ok(())
}

#[cfg(not(kani))]
pub(crate) fn audit_digest(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[cfg(kani)]
pub(crate) fn audit_digest(input: &[u8]) -> [u8; 32] {
    fn parity(value: u64) -> u16 {
        (value.count_ones() as u16) & 1
    }

    let mut output = [0u8; 32];
    let length = (input.len() as u64).to_be_bytes();

    output[0] = length[0];
    output[1] = length[1];
    output[2] = length[2];
    output[3] = length[3];
    output[4] = length[4];
    output[5] = length[5];
    output[6] = length[6];
    output[7] = length[7];

    if input.len() == 84 {
        // FV-4b bounded domain:
        // record identity is carried directly for cross-entry separation.
        output[8] = input[25];
        output[9] = input[26];
        output[10] = input[27];
        output[11] = input[28];
        output[12] = input[29];
        output[13] = input[43];

        // The 320 mutable bits are timestamp || prev_hash.
        // Bit p uses code(p) = p + 1. Each syndrome output bit is the
        // parity of the input against a fixed mask, producing the
        // zero-relative GF(2)-linear map required by the FV-4b model.
        let w0 = u64::from_le_bytes([
            input[44], input[45], input[46], input[47], input[48], input[49], input[50], input[51],
        ]);
        let w1 = u64::from_le_bytes([
            input[52], input[53], input[54], input[55], input[56], input[57], input[58], input[59],
        ]);
        let w2 = u64::from_le_bytes([
            input[60], input[61], input[62], input[63], input[64], input[65], input[66], input[67],
        ]);
        let w3 = u64::from_le_bytes([
            input[68], input[69], input[70], input[71], input[72], input[73], input[74], input[75],
        ]);
        let w4 = u64::from_le_bytes([
            input[76], input[77], input[78], input[79], input[80], input[81], input[82], input[83],
        ]);

        let s0 = parity(
            (w0 & 0x5555_5555_5555_5555)
                ^ (w1 & 0x5555_5555_5555_5555)
                ^ (w2 & 0x5555_5555_5555_5555)
                ^ (w3 & 0x5555_5555_5555_5555)
                ^ (w4 & 0x5555_5555_5555_5555),
        );

        let s1 = parity(
            (w0 & 0x6666_6666_6666_6666)
                ^ (w1 & 0x6666_6666_6666_6666)
                ^ (w2 & 0x6666_6666_6666_6666)
                ^ (w3 & 0x6666_6666_6666_6666)
                ^ (w4 & 0x6666_6666_6666_6666),
        );

        let s2 = parity(
            (w0 & 0x7878_7878_7878_7878)
                ^ (w1 & 0x7878_7878_7878_7878)
                ^ (w2 & 0x7878_7878_7878_7878)
                ^ (w3 & 0x7878_7878_7878_7878)
                ^ (w4 & 0x7878_7878_7878_7878),
        );

        let s3 = parity(
            (w0 & 0x7f80_7f80_7f80_7f80)
                ^ (w1 & 0x7f80_7f80_7f80_7f80)
                ^ (w2 & 0x7f80_7f80_7f80_7f80)
                ^ (w3 & 0x7f80_7f80_7f80_7f80)
                ^ (w4 & 0x7f80_7f80_7f80_7f80),
        );

        let s4 = parity(
            (w0 & 0x7fff_8000_7fff_8000)
                ^ (w1 & 0x7fff_8000_7fff_8000)
                ^ (w2 & 0x7fff_8000_7fff_8000)
                ^ (w3 & 0x7fff_8000_7fff_8000)
                ^ (w4 & 0x7fff_8000_7fff_8000),
        );

        let s5 = parity(
            (w0 & 0x7fff_ffff_8000_0000)
                ^ (w1 & 0x7fff_ffff_8000_0000)
                ^ (w2 & 0x7fff_ffff_8000_0000)
                ^ (w3 & 0x7fff_ffff_8000_0000)
                ^ (w4 & 0x7fff_ffff_8000_0000),
        );

        let s6 = parity(
            (w0 & 0x8000_0000_0000_0000)
                ^ (w1 & 0x7fff_ffff_ffff_ffff)
                ^ (w2 & 0x8000_0000_0000_0000)
                ^ (w3 & 0x7fff_ffff_ffff_ffff)
                ^ (w4 & 0x8000_0000_0000_0000),
        );

        let s7 = parity(
            (w0 & 0x0000_0000_0000_0000)
                ^ (w1 & 0x8000_0000_0000_0000)
                ^ (w2 & 0xffff_ffff_ffff_ffff)
                ^ (w3 & 0x7fff_ffff_ffff_ffff)
                ^ (w4 & 0x0000_0000_0000_0000),
        );

        let s8 = parity(
            (w0 & 0x0000_0000_0000_0000)
                ^ (w1 & 0x0000_0000_0000_0000)
                ^ (w2 & 0x0000_0000_0000_0000)
                ^ (w3 & 0x8000_0000_0000_0000)
                ^ (w4 & 0xffff_ffff_ffff_ffff),
        );

        let syndrome = s0
            | (s1 << 1)
            | (s2 << 2)
            | (s3 << 3)
            | (s4 << 4)
            | (s5 << 5)
            | (s6 << 6)
            | (s7 << 7)
            | (s8 << 8);

        output[14] = (syndrome >> 8) as u8;
        output[15] = syndrome as u8;
    }

    // Outside the declared 84-byte FV-4b domain the model is
    // deterministic, but no injectivity property is claimed.
    output
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

    // Canonical audit serialization invariant:
    // this is the single preimage construction path consumed by both
    // production SHA-256 and the verification-only digest.
    pub(crate) fn audit_hash_input(&self) -> Vec<u8> {
        fn append_text(input: &mut Vec<u8>, value: &str) {
            input.extend_from_slice(&(value.len() as u64).to_be_bytes());
            input.extend_from_slice(value.as_bytes());
        }

        let mut input = Vec::new();
        input.extend_from_slice(b"EDISONDB-AUDIT-V1");
        append_text(&mut input, &self.record_id);
        append_text(&mut input, &self.requester_id);
        input.push(self.action.code());
        input.extend_from_slice(&self.timestamp.to_be_bytes());
        input.extend_from_slice(&self.prev_hash);
        input
    }

    fn calculate_hash(&self) -> [u8; 32] {
        audit_digest(&self.audit_hash_input())
    }
}

const AUTHENTICATED_AUDIT_CHECKPOINT_VERSION: u8 = 2;
const CHECKPOINT_STORE_SALT_LEN: usize = 32;
const CHECKPOINT_MAC_DOMAIN: &[u8] = b"EDISONDB-AUDIT-CHECKPOINT-V2";
const CHECKPOINT_MAC_KEY_CONTEXT: &str =
    "AIEONYX EdisonDB audit checkpoint MAC key v2";
const RECORD_CREATED_AT_COMMITMENT_DOMAIN: &[u8] =
    b"EDISONDB-RECORD-CREATED-AT-V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditCheckpoint {
    pub(crate) expected_count: u64,
    pub(crate) expected_head: [u8; 32],
}

/// Versioned authenticated audit checkpoint.
///
/// `store_salt` is a database-level KDF salt, distinct from per-record salts.
/// `mac` authenticates the canonical audit count/head plus the deterministic
/// current-record `id -> created_at` commitment under a domain-separated key
/// derived from the store key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthenticatedAuditCheckpoint {
    pub(crate) version: u8,
    pub(crate) expected_count: u64,
    pub(crate) expected_head: [u8; 32],
    pub(crate) record_created_at_commitment: [u8; 32],
    pub(crate) store_salt: [u8; CHECKPOINT_STORE_SALT_LEN],
    pub(crate) mac: [u8; 32],
}

pub(crate) fn record_created_at_commitment<'a, I>(
    records: I,
) -> [u8; 32]
where
    I: IntoIterator<Item = (&'a str, u64)>,
{
    let mut entries: Vec<(Vec<u8>, u64)> = records
        .into_iter()
        .map(|(id, created_at)| (id.as_bytes().to_vec(), created_at))
        .collect();

    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut input = Vec::new();
    input.extend_from_slice(RECORD_CREATED_AT_COMMITMENT_DOMAIN);
    input.extend_from_slice(&(entries.len() as u64).to_be_bytes());

    for (id, created_at) in entries {
        input.extend_from_slice(&(id.len() as u64).to_be_bytes());
        input.extend_from_slice(&id);
        input.extend_from_slice(&created_at.to_be_bytes());
    }

    *blake3::hash(&input).as_bytes()
}

fn checkpoint_mac_input(
    expected_count: u64,
    expected_head: &[u8; 32],
    record_created_at_commitment: &[u8; 32],
) -> Vec<u8> {
    let mut input = Vec::with_capacity(
        CHECKPOINT_MAC_DOMAIN.len()
            + 8
            + expected_head.len()
            + record_created_at_commitment.len(),
    );
    input.extend_from_slice(CHECKPOINT_MAC_DOMAIN);
    input.extend_from_slice(&expected_count.to_be_bytes());
    input.extend_from_slice(expected_head);
    input.extend_from_slice(record_created_at_commitment);
    input
}

fn derive_checkpoint_mac_key(
    store_secret: &str,
    store_salt: &[u8; CHECKPOINT_STORE_SALT_LEN],
) -> Result<[u8; 32], EdisonError> {
    let store_key = derive_key(store_secret, store_salt)?;
    Ok(blake3::derive_key(
        CHECKPOINT_MAC_KEY_CONTEXT,
        &store_key,
    ))
}

fn checkpoint_mac(
    mac_key: &[u8; 32],
    expected_count: u64,
    expected_head: &[u8; 32],
    record_created_at_commitment: &[u8; 32],
) -> [u8; 32] {
    let input = checkpoint_mac_input(
        expected_count,
        expected_head,
        record_created_at_commitment,
    );
    *blake3::keyed_hash(mac_key, &input).as_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckpointAuthContext {
    store_salt: [u8; CHECKPOINT_STORE_SALT_LEN],
    mac_key: [u8; 32],
}

fn checkpoint_auth_context(
    store_secret: &str,
    store_salt: [u8; CHECKPOINT_STORE_SALT_LEN],
) -> Result<CheckpointAuthContext, EdisonError> {
    let mac_key = derive_checkpoint_mac_key(store_secret, &store_salt)?;
    Ok(CheckpointAuthContext {
        store_salt,
        mac_key,
    })
}

pub(crate) fn authenticated_audit_checkpoint_from_context(
    expected_count: u64,
    expected_head: [u8; 32],
    record_created_at_commitment: [u8; 32],
    context: &CheckpointAuthContext,
) -> AuthenticatedAuditCheckpoint {
    let mac = checkpoint_mac(
        &context.mac_key,
        expected_count,
        &expected_head,
        &record_created_at_commitment,
    );

    AuthenticatedAuditCheckpoint {
        version: AUTHENTICATED_AUDIT_CHECKPOINT_VERSION,
        expected_count,
        expected_head,
        record_created_at_commitment,
        store_salt: context.store_salt,
        mac,
    }
}

fn verify_authenticated_audit_checkpoint_with_context(
    checkpoint: &AuthenticatedAuditCheckpoint,
    context: &CheckpointAuthContext,
) -> Result<(), EdisonError> {
    if checkpoint.version != AUTHENTICATED_AUDIT_CHECKPOINT_VERSION
        || checkpoint.store_salt != context.store_salt
    {
        return Err(EdisonError::AuditChainBroken);
    }

    let expected_mac = checkpoint_mac(
        &context.mac_key,
        checkpoint.expected_count,
        &checkpoint.expected_head,
        &checkpoint.record_created_at_commitment,
    );

    // Equality is accumulated over the complete fixed-size MAC. No
    // constant-time execution claim is made here.
    let difference = checkpoint
        .mac
        .iter()
        .zip(expected_mac.iter())
        .fold(0u8, |acc, (left, right)| acc | (left ^ right));

    if difference != 0 {
        return Err(EdisonError::AuditChainBroken);
    }

    Ok(())
}

#[cfg(test)]
pub(crate) fn authenticate_audit_checkpoint(
    expected_count: u64,
    expected_head: [u8; 32],
    record_created_at_commitment: [u8; 32],
    store_secret: &str,
    store_salt: [u8; CHECKPOINT_STORE_SALT_LEN],
) -> Result<AuthenticatedAuditCheckpoint, EdisonError> {
    let context = checkpoint_auth_context(store_secret, store_salt)?;
    Ok(authenticated_audit_checkpoint_from_context(
        expected_count,
        expected_head,
        record_created_at_commitment,
        &context,
    ))
}

#[cfg(test)]
pub(crate) fn verify_authenticated_audit_checkpoint_mac(
    checkpoint: &AuthenticatedAuditCheckpoint,
    store_secret: &str,
) -> Result<(), EdisonError> {
    let context =
        checkpoint_auth_context(store_secret, checkpoint.store_salt)?;
    verify_authenticated_audit_checkpoint_with_context(
        checkpoint,
        &context,
    )
}

pub(crate) fn classify_authenticated_checkpoint_state(
    checkpoint_bytes: Option<&[u8]>,
    audit_empty: bool,
    records_empty: bool,
    actual_count: u64,
    actual_head: [u8; 32],
    actual_record_created_at_commitment: [u8; 32],
    store_secret: &str,
) -> Result<(CheckpointOpenState, CheckpointAuthContext), EdisonError> {
    match checkpoint_bytes {
        Some(bytes) => {
            let checkpoint: AuthenticatedAuditCheckpoint =
                serde_json::from_slice(bytes)
                    .map_err(|_| EdisonError::AuditChainBroken)?;

            let context =
                checkpoint_auth_context(store_secret, checkpoint.store_salt)?;

            verify_authenticated_audit_checkpoint_with_context(
                &checkpoint,
                &context,
            )?;

            validate_audit_checkpoint(
                &AuditCheckpoint {
                    expected_count: checkpoint.expected_count,
                    expected_head: checkpoint.expected_head,
                },
                actual_count,
                actual_head,
            )?;

            if checkpoint.record_created_at_commitment
                != actual_record_created_at_commitment
            {
                return Err(EdisonError::AuditChainBroken);
            }

            if audit_empty && !records_empty {
                return Err(EdisonError::AuditChainBroken);
            }

            Ok((CheckpointOpenState::Existing, context))
        }
        None => {
            if !audit_empty || !records_empty {
                return Err(EdisonError::AuditChainBroken);
            }

            let mut store_salt = [0u8; CHECKPOINT_STORE_SALT_LEN];
            rand::thread_rng().fill_bytes(&mut store_salt);

            let context =
                checkpoint_auth_context(store_secret, store_salt)?;

            Ok((CheckpointOpenState::Genesis, context))
        }
    }
}

pub(crate) fn validate_audit_checkpoint(
    checkpoint: &AuditCheckpoint,
    actual_count: u64,
    actual_head: [u8; 32],
) -> Result<(), EdisonError> {
    if checkpoint.expected_count != actual_count || checkpoint.expected_head != actual_head {
        return Err(EdisonError::AuditChainBroken);
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckpointFailureReason {
    Missing,
    Malformed,
    CountMismatch,
    HeadMismatch,
    UnanchoredRecords,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckpointOpenState {
    Genesis,
    Existing,
}

pub(crate) fn classify_checkpoint_state(
    checkpoint_bytes: Option<&[u8]>,
    audit_empty: bool,
    records_empty: bool,
    actual_count: u64,
    actual_head: [u8; 32],
) -> Result<CheckpointOpenState, CheckpointFailureReason> {
    match checkpoint_bytes {
        Some(bytes) => {
            let checkpoint: AuditCheckpoint =
                serde_json::from_slice(bytes).map_err(|_| CheckpointFailureReason::Malformed)?;

            if validate_audit_checkpoint(&checkpoint, actual_count, actual_head).is_err() {
                if checkpoint.expected_count != actual_count {
                    return Err(CheckpointFailureReason::CountMismatch);
                }

                return Err(CheckpointFailureReason::HeadMismatch);
            }

            if audit_empty && !records_empty {
                return Err(CheckpointFailureReason::UnanchoredRecords);
            }

            Ok(CheckpointOpenState::Existing)
        }
        None => {
            if audit_empty && records_empty {
                Ok(CheckpointOpenState::Genesis)
            } else {
                Err(CheckpointFailureReason::Missing)
            }
        }
    }
}

pub(crate) fn checkpoint_error(_reason: CheckpointFailureReason) -> EdisonError {
    EdisonError::AuditChainBroken
}

pub(crate) fn verify_audit_entries(entries: &[AuditEntry]) -> Result<(), EdisonError> {
    let mut expected_prev = [0u8; 32];

    for entry in entries {
        if entry.prev_hash != expected_prev || !entry.verify_hash() {
            return Err(EdisonError::AuditChainBroken);
        }

        expected_prev = entry.entry_hash;
    }

    Ok(())
}

pub(crate) fn audit_history_is_prefix(persisted: &[AuditEntry], candidate: &[AuditEntry]) -> bool {
    if persisted.len() > candidate.len() {
        return false;
    }

    persisted.iter().zip(candidate.iter()).all(|(left, right)| {
        left.record_id == right.record_id
            && left.requester_id == right.requester_id
            && left.action.code() == right.action.code()
            && left.timestamp == right.timestamp
            && left.prev_hash == right.prev_hash
            && left.entry_hash == right.entry_hash
    })
}

pub struct Store {
    records: HashMap<String, Record>,
    audit_log: Vec<AuditEntry>,
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
        verify_audit_entries(&self.audit_log)
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

    pub fn record_count(&self) -> usize {
        self.records.len()
    }


    pub fn list_by_owner(
        &self,
        owner_id: &str,
    ) -> Result<Vec<&Record>, EdisonError> {
        Ok(self
            .records
            .values()
            .filter(|r| r.owner_id == owner_id)
            .collect())
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
        self.save_impl(path, None)
    }

    /// Persist using an audit checkpoint controlled by `store_secret`.
    ///
    /// Existing legacy checkpoints are rejected rather than automatically
    /// upgraded so authenticated callers cannot silently accept a downgrade.
    pub fn save_authenticated(
        &self,
        path: &str,
        store_secret: &str,
    ) -> Result<(), EdisonError> {
        self.save_impl(path, Some(store_secret))
    }

    fn save_impl(
        &self,
        path: &str,
        store_secret: Option<&str>,
    ) -> Result<(), EdisonError> {
        for (id, record) in &self.records {
            record.validate()?;
            if id != &record.id {
                return Err(EdisonError::SaveFailed);
            }
        }

        self.verify_audit_chain()?;

        let db = Database::create(path).map_err(|_| EdisonError::SaveFailed)?;
        let write_txn = db.begin_write().map_err(|_| EdisonError::SaveFailed)?;

        let persisted_records_empty = {
            let table = write_txn
                .open_table(RECORDS_TABLE)
                .map_err(|_| EdisonError::SaveFailed)?;

            let mut iter = table.iter().map_err(|_| EdisonError::SaveFailed)?;

            match iter.next() {
                None => true,
                Some(entry) => {
                    entry.map_err(|_| EdisonError::SaveFailed)?;
                    false
                }
            }
        };

        let persisted_audit = {
            let table = write_txn
                .open_table(AUDIT_TABLE)
                .map_err(|_| EdisonError::SaveFailed)?;

            let iter = table.iter().map_err(|_| EdisonError::AuditChainBroken)?;

            let mut keyed = Vec::new();

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

                keyed.push((index, audit_entry));
            }

            keyed.sort_by_key(|(index, _)| *index);

            let mut audit = Vec::with_capacity(keyed.len());

            for (expected, (index, entry)) in keyed.into_iter().enumerate() {
                if index != expected {
                    return Err(EdisonError::AuditChainBroken);
                }

                audit.push(entry);
            }

            verify_audit_entries(&audit)?;
            audit
        };

        let persisted_checkpoint = {
            let table = write_txn
                .open_table(AUDIT_CHECKPOINT_TABLE)
                .map_err(|_| EdisonError::SaveFailed)?;

            table
                .get(AUDIT_CHECKPOINT_KEY)
                .map_err(|_| EdisonError::SaveFailed)?
                .map(|value| value.value().to_string())
        };

        let persisted_count =
            u64::try_from(persisted_audit.len()).map_err(|_| EdisonError::AuditChainBroken)?;

        let persisted_head = persisted_audit
            .last()
            .map(|entry| entry.entry_hash)
            .unwrap_or([0u8; 32]);

        let persisted_record_created_at_commitment =
            if store_secret.is_some() {
                let table = write_txn
                    .open_table(RECORDS_TABLE)
                    .map_err(|_| EdisonError::AuditChainBroken)?;

                let mut entries = Vec::new();

                for entry in table
                    .iter()
                    .map_err(|_| EdisonError::AuditChainBroken)?
                {
                    let (key, value) =
                        entry.map_err(|_| EdisonError::AuditChainBroken)?;

                    let persisted: PersistedRecord =
                        serde_json::from_str(value.value())
                            .map_err(|_| EdisonError::AuditChainBroken)?;

                    let record = persisted
                        .into_validated_record()
                        .map_err(|_| EdisonError::AuditChainBroken)?;

                    if key.value() != record.id {
                        return Err(EdisonError::AuditChainBroken);
                    }

                    entries.push((record.id.clone(), record.created_at));
                }

                Some(record_created_at_commitment(
                    entries
                        .iter()
                        .map(|(id, created_at)| {
                            (id.as_str(), *created_at)
                        }),
                ))
            } else {
                None
            };

        let checkpoint_auth = if let Some(store_secret) = store_secret {
            let (_, context) = classify_authenticated_checkpoint_state(
                persisted_checkpoint.as_deref().map(str::as_bytes),
                persisted_audit.is_empty(),
                persisted_records_empty,
                persisted_count,
                persisted_head,
                persisted_record_created_at_commitment
                    .ok_or(EdisonError::AuditChainBroken)?,
                store_secret,
            )?;
            Some(context)
        } else {
            classify_checkpoint_state(
                persisted_checkpoint.as_deref().map(str::as_bytes),
                persisted_audit.is_empty(),
                persisted_records_empty,
                persisted_count,
                persisted_head,
            )
            .map_err(checkpoint_error)?;
            None
        };

        if !audit_history_is_prefix(&persisted_audit, &self.audit_log) {
            return Err(EdisonError::AuditChainBroken);
        }

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
        {
            let checkpoint_count =
                u64::try_from(self.audit_log.len()).map_err(|_| EdisonError::SaveFailed)?;
            let checkpoint_head = self.last_chain_hash();

            let checkpoint_record_created_at_commitment =
                record_created_at_commitment(
                    self.records
                        .iter()
                        .map(|(id, record)| {
                            (id.as_str(), record.created_at)
                        }),
                );

            let checkpoint_json = if let Some(context) = checkpoint_auth.as_ref() {
                let checkpoint =
                    authenticated_audit_checkpoint_from_context(
                        checkpoint_count,
                        checkpoint_head,
                        checkpoint_record_created_at_commitment,
                        context,
                    );
                serde_json::to_string(&checkpoint)
                    .map_err(|_| EdisonError::SaveFailed)?
            } else {
                let checkpoint = AuditCheckpoint {
                    expected_count: checkpoint_count,
                    expected_head: checkpoint_head,
                };
                serde_json::to_string(&checkpoint)
                    .map_err(|_| EdisonError::SaveFailed)?
            };

            let mut table = write_txn
                .open_table(AUDIT_CHECKPOINT_TABLE)
                .map_err(|_| EdisonError::SaveFailed)?;

            table
                .insert(AUDIT_CHECKPOINT_KEY, checkpoint_json.as_str())
                .map_err(|_| EdisonError::SaveFailed)?;
        }

        write_txn.commit().map_err(|_| EdisonError::SaveFailed)?;
        Ok(())
    }

    pub fn load(path: &str) -> Result<Self, EdisonError> {
        Self::load_impl(path, None)
    }

    /// Load a store whose audit checkpoint is controlled by `store_secret`.
    ///
    /// A legacy two-field checkpoint is rejected. Migration into the
    /// authenticated format must be an explicit operation.
    pub fn load_authenticated(
        path: &str,
        store_secret: &str,
    ) -> Result<Self, EdisonError> {
        Self::load_impl(path, Some(store_secret))
    }

    fn load_impl(
        path: &str,
        store_secret: Option<&str>,
    ) -> Result<Self, EdisonError> {
        let db = Database::open(path).map_err(|_| EdisonError::LoadFailed)?;
        let write_txn = db.begin_write().map_err(|_| EdisonError::LoadFailed)?;

        let mut records = HashMap::new();

        {
            let table = write_txn
                .open_table(RECORDS_TABLE)
                .map_err(|_| EdisonError::LoadFailed)?;

            for entry in table.iter().map_err(|_| EdisonError::LoadFailed)? {
                let (key, value) = entry.map_err(|_| EdisonError::LoadFailed)?;

                let persisted: PersistedRecord =
                    serde_json::from_str(value.value()).map_err(|_| EdisonError::LoadFailed)?;
                let record = persisted.into_validated_record()?;

                if key.value() != record.id {
                    return Err(EdisonError::LoadFailed);
                }

                records.insert(record.id.clone(), record);
            }
        }

        let mut keyed_audit = Vec::new();

        {
            let table = write_txn
                .open_table(AUDIT_TABLE)
                .map_err(|_| EdisonError::AuditChainBroken)?;

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

        let actual_count =
            u64::try_from(store.audit_log.len()).map_err(|_| EdisonError::AuditChainBroken)?;

        let actual_head = store.last_chain_hash();
        let records_empty = store.records.is_empty();
        let audit_empty = store.audit_log.is_empty();

        let actual_record_created_at_commitment =
            record_created_at_commitment(
                store
                    .records
                    .iter()
                    .map(|(id, record)| {
                        (id.as_str(), record.created_at)
                    }),
            );

        {
            let mut table = write_txn
                .open_table(AUDIT_CHECKPOINT_TABLE)
                .map_err(|_| EdisonError::AuditChainBroken)?;

            let checkpoint_value = table
                .get(AUDIT_CHECKPOINT_KEY)
                .map_err(|_| EdisonError::AuditChainBroken)?;

            let checkpoint_bytes = checkpoint_value
                .as_ref()
                .map(|value| value.value().as_bytes());

            if let Some(store_secret) = store_secret {
                let (checkpoint_state, context) =
                    classify_authenticated_checkpoint_state(
                        checkpoint_bytes,
                        audit_empty,
                        records_empty,
                        actual_count,
                        actual_head,
                        actual_record_created_at_commitment,
                        store_secret,
                    )?;

                drop(checkpoint_value);

                if checkpoint_state == CheckpointOpenState::Genesis {
                    let checkpoint =
                        authenticated_audit_checkpoint_from_context(
                            0,
                            [0u8; 32],
                            actual_record_created_at_commitment,
                            &context,
                        );

                    let checkpoint_json =
                        serde_json::to_string(&checkpoint)
                            .map_err(|_| EdisonError::LoadFailed)?;

                    table
                        .insert(
                            AUDIT_CHECKPOINT_KEY,
                            checkpoint_json.as_str(),
                        )
                        .map_err(|_| EdisonError::LoadFailed)?;
                }
            } else {
                let checkpoint_state = classify_checkpoint_state(
                    checkpoint_bytes,
                    audit_empty,
                    records_empty,
                    actual_count,
                    actual_head,
                )
                .map_err(checkpoint_error)?;

                drop(checkpoint_value);

                if checkpoint_state == CheckpointOpenState::Genesis {
                    let checkpoint = AuditCheckpoint {
                        expected_count: 0,
                        expected_head: [0u8; 32],
                    };

                    let checkpoint_json =
                        serde_json::to_string(&checkpoint)
                            .map_err(|_| EdisonError::LoadFailed)?;

                    table
                        .insert(
                            AUDIT_CHECKPOINT_KEY,
                            checkpoint_json.as_str(),
                        )
                        .map_err(|_| EdisonError::LoadFailed)?;
                }
            }
        }

        write_txn.commit().map_err(|_| EdisonError::LoadFailed)?;

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
) -> Result<EncryptedPayload, EdisonError> {
    let aad = format!("{}:{}", record_id, tier.as_str());
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; ENCRYPTED_PAYLOAD_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::from_slice(&nonce_bytes);
    let payload = Payload {
        msg: data,
        aad: aad.as_bytes(),
    };

    let encrypted = cipher
        .encrypt(nonce, payload)
        .map_err(|_| EdisonError::EncryptionFailed)?;

    EncryptedPayload::from_ciphertext_parts(
        nonce_bytes,
        encrypted,
    )
}

pub fn decrypt_payload(
    data: &EncryptedPayload,
    key: &[u8; 32],
    record_id: &str,
    tier: &DataTier,
) -> Result<Vec<u8>, EdisonError> {
    let (nonce_bytes, encrypted) =
        data.nonce_and_ciphertext();

    let aad = format!("{}:{}", record_id, tier.as_str());
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

    #[test]
    fn record_identity_both_empty_preserves_no_owner_precedence() {
        assert_eq!(
            super::validate_record_identity("", ""),
            Err(super::EdisonError::NoOwner)
        );
    }

    use super::*;

    fn test_encrypted_payload(
        id: &str,
        tier: &DataTier,
        payload: &[u8],
    ) -> EncryptedPayload {
        let key = [0x5au8; 32];

        encrypt_payload(
            payload,
            &key,
            id,
            tier,
        )
        .unwrap()
    }

    fn record_new(
        id: &str,
        tier: DataTier,
        owner_id: &str,
        payload: Vec<u8>,
        salt: [u8; 32],
    ) -> Result<Record, EdisonError> {
        let key = [0x5au8; 32];

        Record::new(
            id,
            tier,
            owner_id,
            &payload,
            &key,
            salt,
        )
    }


    #[test]
    fn owner_can_read_critical() {
        let r = record_new(
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
        let r = record_new(
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
        let r = record_new(
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
        let r = record_new(
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
        let result = record_new("rec:5", DataTier::Personal, "", vec![1], [0u8; 32]);
        assert_eq!(result, Err(EdisonError::NoOwner));
    }

    #[test]
    fn record_has_timestamp() {
        let r = record_new("rec:6", DataTier::Personal, "owner_abc", vec![], [0u8; 32]).unwrap();
        assert!(r.created_at > 0);
    }

    #[test]
    fn owner_can_read_stored_record() {
        let mut store = Store::new();
        let r = record_new(
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
        let r = record_new(
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
        let r = record_new(
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
            let r = record_new(&id, DataTier::Noise, "owner_abc", vec![], [0u8; 32]).unwrap();
            store.write(r).unwrap();
        }
        assert_eq!(store.audit_count(), 5);
    }

    #[test]
    fn granted_read_is_audited() {
        let mut store = Store::new();
        let r = record_new(
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
        let r = record_new(
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
        let r1 = record_new("rec:60", DataTier::Personal, "alice", vec![1], [0u8; 32]).unwrap();
        let r2 = record_new("rec:61", DataTier::Noise, "bob", vec![2], [0u8; 32]).unwrap();
        store.write(r1).unwrap();
        store.write(r2).unwrap();
        let alice_records = store.list_by_owner("alice").unwrap();
        assert_eq!(alice_records.len(), 1);
        assert_eq!(alice_records[0].id, "rec:60");
    }

    #[test]
    fn owner_can_delete_own_record() {
        let mut store = Store::new();
        let r = record_new("rec:70", DataTier::Personal, "alice", vec![1], [0u8; 32]).unwrap();
        store.write(r).unwrap();
        assert!(store.delete("rec:70", "alice").is_ok());
        assert_eq!(store.list_by_owner("alice").unwrap().len(), 0);
    }

    #[test]
    fn non_owner_cannot_delete_record() {
        let mut store = Store::new();
        let r = record_new("rec:71", DataTier::Critical, "alice", vec![1], [0u8; 32]).unwrap();
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
        assert_ne!(encrypted.as_bytes(), &original[..]);
        let decrypted =
            decrypt_payload(&encrypted, &key, "rec:crypto", &DataTier::Personal).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn p2_record_constructor_binds_payload_to_immutable_id_and_tier() {
        let key = [0x33u8; 32];
        let salt = [0x44u8; 32];
        let plaintext = b"p2 constructor-bound payload";

        let record = Record::new(
            "rec:p2-bound",
            DataTier::Critical,
            "alice",
            plaintext,
            &key,
            salt,
        )
        .unwrap();

        assert_eq!(record.id(), "rec:p2-bound");
        assert_eq!(record.tier(), &DataTier::Critical);

        let decrypted = decrypt_payload(
            record.encrypted_payload(),
            &key,
            record.id(),
            record.tier(),
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);

        assert_eq!(
            decrypt_payload(
                record.encrypted_payload(),
                &key,
                "rec:p2-transplanted",
                record.tier(),
            ),
            Err(EdisonError::DecryptionFailed)
        );

        assert_eq!(
            decrypt_payload(
                record.encrypted_payload(),
                &key,
                record.id(),
                &DataTier::Personal,
            ),
            Err(EdisonError::DecryptionFailed)
        );
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
    fn p1c_encryption_emits_versioned_envelope_and_round_trips() {
        let key = [7u8; 32];
        let plaintext = b"versioned sovereign payload";

        let encrypted = encrypt_payload(
            plaintext,
            &key,
            "rec:p1c-roundtrip",
            &DataTier::Personal,
        )
        .unwrap();

        assert!(encrypted.as_bytes().starts_with(&ENCRYPTED_PAYLOAD_MAGIC));
        assert_eq!(
            encrypted.version(),
            ENCRYPTED_PAYLOAD_VERSION,
        );
        assert!(
            encrypted.len()
                >= 4
                    + 1
                    + ENCRYPTED_PAYLOAD_NONCE_LEN
                    + ENCRYPTED_PAYLOAD_TAG_LEN
        );

        let decrypted = decrypt_payload(
            &encrypted,
            &key,
            "rec:p1c-roundtrip",
            &DataTier::Personal,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn p1c_unmarked_legacy_payload_fails_closed() {
        let legacy = vec![
            0u8;
            ENCRYPTED_PAYLOAD_NONCE_LEN
                + ENCRYPTED_PAYLOAD_TAG_LEN
        ];

        assert!(matches!(
            EncryptedPayload::from_persisted(legacy),
            Err(EdisonError::LegacyPayloadFormat)
        ));
    }

    #[test]
    fn p1c_unknown_payload_version_fails_closed() {
        let mut envelope = Vec::new();

        envelope.extend_from_slice(
            &ENCRYPTED_PAYLOAD_MAGIC,
        );

        envelope.push(
            ENCRYPTED_PAYLOAD_VERSION + 1,
        );

        envelope.extend_from_slice(
            &[0u8; ENCRYPTED_PAYLOAD_NONCE_LEN],
        );

        envelope.extend_from_slice(
            &[0u8; ENCRYPTED_PAYLOAD_TAG_LEN],
        );

        assert!(matches!(
            EncryptedPayload::from_persisted(envelope),
            Err(EdisonError::UnsupportedPayloadVersion(version))
                if version == ENCRYPTED_PAYLOAD_VERSION + 1
        ));
    }

    #[test]
    fn p1c_truncated_current_envelope_fails_closed() {
        let mut envelope = Vec::new();

        envelope.extend_from_slice(
            &ENCRYPTED_PAYLOAD_MAGIC,
        );

        envelope.push(
            ENCRYPTED_PAYLOAD_VERSION,
        );

        envelope.extend_from_slice(
            &[0u8; ENCRYPTED_PAYLOAD_NONCE_LEN],
        );

        envelope.extend_from_slice(
            &[0u8; ENCRYPTED_PAYLOAD_TAG_LEN - 1],
        );

        assert!(matches!(
            EncryptedPayload::from_persisted(envelope),
            Err(EdisonError::InvalidEncryptedPayload)
        ));
    }

    #[test]
    fn store_saves_and_loads() {
        let path = "/tmp/test_edison_m2.redb";
        let _ = std::fs::remove_file(path);
        let mut store = Store::new();
        let r = record_new(
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
        let r = record_new(
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

    fn p35_store_path(label: &str) -> String {
        format!(
            "/tmp/edisondb-p35-{}-{}-{}.redb",
            label,
            std::process::id(),
            rand::random::<u64>(),
        )
    }

    #[test]
    fn p35_store_authenticated_round_trip_and_legacy_load_rejects() {
        let path = p35_store_path("round-trip");
        let _ = std::fs::remove_file(&path);

        let store = Store::new();
        store
            .save_authenticated(&path, "correct-store-secret")
            .unwrap();

        let loaded =
            Store::load_authenticated(&path, "correct-store-secret").unwrap();

        assert_eq!(loaded.record_count(), 0);
        assert_eq!(loaded.audit_count(), 0);
        assert!(matches!(
            Store::load(&path),
            Err(EdisonError::AuditChainBroken)
        ));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn p35_store_authenticated_load_rejects_wrong_store_secret() {
        let path = p35_store_path("wrong-store-secret");
        let _ = std::fs::remove_file(&path);

        Store::new()
            .save_authenticated(&path, "correct-store-secret")
            .unwrap();

        assert!(matches!(
            Store::load_authenticated(&path, "wrong-store-secret"),
            Err(EdisonError::AuditChainBroken)
        ));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn p35_store_authenticated_load_rejects_legacy_checkpoint() {
        let path = p35_store_path("legacy-reject");
        let _ = std::fs::remove_file(&path);

        Store::new().save(&path).unwrap();

        assert!(matches!(
            Store::load_authenticated(&path, "checkpoint-store-secret"),
            Err(EdisonError::AuditChainBroken)
        ));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn p35_checkpoint_mac_round_trips() {
        let salt = [0x35u8; CHECKPOINT_STORE_SALT_LEN];
        let checkpoint = authenticate_audit_checkpoint(
            7,
            [0xA5u8; 32],
            [0xC1u8; 32],
            "checkpoint-store-secret",
            salt,
        )
        .unwrap();

        assert_eq!(
            verify_authenticated_audit_checkpoint_mac(
                &checkpoint,
                "checkpoint-store-secret",
            ),
            Ok(())
        );
    }

    #[test]
    fn p35_checkpoint_mac_rejects_count_head_and_mac_tamper() {
        let salt = [0x51u8; CHECKPOINT_STORE_SALT_LEN];
        let checkpoint = authenticate_audit_checkpoint(
            11,
            [0xB6u8; 32],
            [0xC1u8; 32],
            "checkpoint-store-secret",
            salt,
        )
        .unwrap();

        let mut count_tampered = checkpoint;
        count_tampered.expected_count += 1;
        assert_eq!(
            verify_authenticated_audit_checkpoint_mac(
                &count_tampered,
                "checkpoint-store-secret",
            ),
            Err(EdisonError::AuditChainBroken)
        );

        let mut head_tampered = checkpoint;
        head_tampered.expected_head[0] ^= 1;
        assert_eq!(
            verify_authenticated_audit_checkpoint_mac(
                &head_tampered,
                "checkpoint-store-secret",
            ),
            Err(EdisonError::AuditChainBroken)
        );

        let mut commitment_tampered = checkpoint;
        commitment_tampered.record_created_at_commitment[0] ^= 1;
        assert_eq!(
            verify_authenticated_audit_checkpoint_mac(
                &commitment_tampered,
                "checkpoint-store-secret",
            ),
            Err(EdisonError::AuditChainBroken)
        );

        let mut mac_tampered = checkpoint;
        mac_tampered.mac[31] ^= 1;
        assert_eq!(
            verify_authenticated_audit_checkpoint_mac(
                &mac_tampered,
                "checkpoint-store-secret",
            ),
            Err(EdisonError::AuditChainBroken)
        );
    }

    #[test]
    fn p35_checkpoint_mac_rejects_wrong_store_secret_and_salt_tamper() {
        let salt = [0x62u8; CHECKPOINT_STORE_SALT_LEN];
        let checkpoint = authenticate_audit_checkpoint(
            3,
            [0xC7u8; 32],
            [0xC1u8; 32],
            "correct-store-secret",
            salt,
        )
        .unwrap();

        assert_eq!(
            verify_authenticated_audit_checkpoint_mac(
                &checkpoint,
                "wrong-store-secret",
            ),
            Err(EdisonError::AuditChainBroken)
        );

        let mut salt_tampered = checkpoint;
        salt_tampered.store_salt[0] ^= 1;
        assert_eq!(
            verify_authenticated_audit_checkpoint_mac(
                &salt_tampered,
                "correct-store-secret",
            ),
            Err(EdisonError::AuditChainBroken)
        );
    }

    #[test]
    fn p35_checkpoint_mac_rejects_unknown_version() {
        let mut checkpoint = authenticate_audit_checkpoint(
            1,
            [0xD8u8; 32],
            [0xC1u8; 32],
            "checkpoint-store-secret",
            [0x73u8; CHECKPOINT_STORE_SALT_LEN],
        )
        .unwrap();

        checkpoint.version =
            AUTHENTICATED_AUDIT_CHECKPOINT_VERSION.wrapping_add(1);

        assert_eq!(
            verify_authenticated_audit_checkpoint_mac(
                &checkpoint,
                "checkpoint-store-secret",
            ),
            Err(EdisonError::AuditChainBroken)
        );
    }

    #[test]
    fn limit012_record_created_at_commitment_is_canonical_and_timestamp_sensitive() {
        let first = record_created_at_commitment([
            ("rec:b", 20),
            ("rec:a", 10),
        ]);

        let reordered = record_created_at_commitment([
            ("rec:a", 10),
            ("rec:b", 20),
        ]);

        assert_eq!(
            first, reordered,
            "record iteration order must not change the commitment",
        );

        let timestamp_changed = record_created_at_commitment([
            ("rec:a", 11),
            ("rec:b", 20),
        ]);

        assert_ne!(
            first, timestamp_changed,
            "changing created_at must change the commitment",
        );

        let boundary_left = record_created_at_commitment([
            ("a", 1),
            ("bc", 2),
        ]);

        let boundary_right = record_created_at_commitment([
            ("ab", 1),
            ("c", 2),
        ]);

        assert_ne!(
            boundary_left, boundary_right,
            "length-delimited record ids must remain unambiguous",
        );
    }

    #[test]
    fn limit012_authenticated_checkpoint_v1_shape_fails_closed() {
        let v1_shape = serde_json::json!({
            "version": 1,
            "expected_count": 0,
            "expected_head": vec![0u8; 32],
            "store_salt": vec![0u8; CHECKPOINT_STORE_SALT_LEN],
            "mac": vec![0u8; 32],
        });

        let bytes = serde_json::to_vec(&v1_shape).unwrap();

        let empty_record_commitment =
            record_created_at_commitment(
                std::iter::empty::<(&str, u64)>(),
            );

        assert!(matches!(
            classify_authenticated_checkpoint_state(
                Some(&bytes),
                true,
                true,
                0,
                [0u8; 32],
                empty_record_commitment,
                "limit012-v1-rejection-secret",
            ),
            Err(EdisonError::AuditChainBroken)
        ));
    }

    #[test]
    fn p35_authenticated_checkpoint_cannot_parse_as_legacy() {
        let checkpoint = authenticate_audit_checkpoint(
            5,
            [0xE9u8; 32],
            [0xC1u8; 32],
            "checkpoint-store-secret",
            [0x84u8; CHECKPOINT_STORE_SALT_LEN],
        )
        .unwrap();

        let encoded = serde_json::to_vec(&checkpoint).unwrap();

        assert!(
            serde_json::from_slice::<AuditCheckpoint>(&encoded).is_err(),
            "authenticated checkpoint must not downgrade to legacy parsing"
        );

        let decoded =
            serde_json::from_slice::<AuthenticatedAuditCheckpoint>(&encoded)
                .unwrap();

        assert_eq!(decoded, checkpoint);
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
        let r1 = record_new("rec:100", DataTier::Personal, "alice", vec![1], [0u8; 32]).unwrap();
        let r2 = record_new("rec:100", DataTier::Personal, "alice", vec![2], [0u8; 32]).unwrap();
        store.write(r1).unwrap();
        assert_eq!(store.write(r2), Err(EdisonError::AlreadyExists));
    }

    #[test]
    fn audit_chain_is_valid() {
        let mut store = Store::new();
        for i in 0..5 {
            let id = format!("rec:{}", i);
            let r = record_new(&id, DataTier::Personal, "alice", vec![1], [0u8; 32]).unwrap();
            store.write(r).unwrap();
            let _ = store.read(&id, "alice");
        }
        assert!(store.verify_audit_chain().is_ok());
    }

    #[test]
    fn audit_chain_detects_tampering() {
        let mut store = Store::new();
        let r = record_new(
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

        let path = format!(
            "/tmp/edisondb-fv-internal-tampered-save-{}.redb",
            std::process::id()
        );

        let _ = std::fs::remove_file(&path);

        assert_eq!(store.save(&path), Err(EdisonError::AuditChainBroken));

        let _ = std::fs::remove_file(path);
    }


    // Golden JSON emitted by P1a commit
    // 81782052fb4ad1c73aeb51df0a72973318f4fa7c. This proves that removing public Record
    // deserialization did not alter the persisted Record JSON bytes.
    const P1B_PRE_P1B_RECORD_JSON: &str = r#"{"id":"rec:p1b-compat","tier":"Personal","owner_id":"alice","payload":[1,2,3],"salt":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"created_at":1}"#;

    #[test]
    fn p1c_pre_p1b_record_json_fails_closed_as_legacy() {
        let result =
            serde_json::from_str::<super::PersistedRecord>(
                P1B_PRE_P1B_RECORD_JSON,
            );

        assert!(result.is_err());
    }

    #[test]
    fn p1b_persisted_zero_timestamp_fails_closed() {
        let persisted = super::PersistedRecord::from_parts(
            "rec:p1b-zero-persisted".to_string(),
            super::DataTier::Personal,
            "alice".to_string(),
            test_encrypted_payload(
                "rec:p1b-zero-persisted",
                &super::DataTier::Personal,
                &[1],
            ),
            [0u8; 32],
            0,
        );

        assert_eq!(
            persisted.into_validated_record(),
            Err(super::EdisonError::InvalidCreatedAt)
        );
    }

    #[test]
    fn p1b_construction_zero_timestamp_remains_allowed() {
        let record = super::Record::new_with_created_at(
            "rec:p1b-zero-construction",
            super::DataTier::Noise,
            "alice",
            test_encrypted_payload(
                "rec:p1b-zero-construction",
                &super::DataTier::Noise,
                &[],
            ),
            [0u8; 32],
            0,
        )
        .unwrap();

        assert_eq!(record.created_at, 0);
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
