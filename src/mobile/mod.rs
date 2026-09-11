// Copyright (c) 2026 Edison Lepiten / AIEONYX
// License: Apache-2.0
//
// EdisonDB Mobile — embedded core module
// Feature-gated: `mobile`. Excludes tonic/gRPC server stack.
// Storage: fjall LSM backend. Signing: BLAKE3. Provenance: ARPi header.

pub mod ffi;
pub mod jni_bridge;

use std::path::Path;
use blake3::Hasher;
use fjall::{Database, Keyspace, KeyspaceCreateOptions};

const WRITE_COUNTER_KEY: &[u8] = b"__write_counter__";

/// Return the next monotonic mobile write counter.
///
/// `None` represents counter exhaustion. Wrapping to zero is forbidden.
pub(crate) fn next_write_counter(current: u64) -> Option<u64> {
    current.checked_add(1)
}

/// Errors surfaced across the FFI boundary.
#[derive(Debug)]
pub enum DbError {
    Io(std::io::Error),
    Fjall(fjall::Error),
    KeyExists,
    NotFound,
    InvalidArpi,
    InvalidCounterState,
    CounterExhausted,
    Other(String),
}

impl From<fjall::Error> for DbError {
    fn from(e: fjall::Error) -> Self { DbError::Fjall(e) }
}
impl From<std::io::Error> for DbError {
    fn from(e: std::io::Error) -> Self { DbError::Io(e) }
}

/// Mobile ARPi write-provenance header — 78 bytes fixed.
///
/// This is the mobile storage provenance format. It is distinct from
/// `crate::arpi::ArpiHeader`, which is the ARPi response/protocol header.
///
/// Offset  Size  Field
///  0       4    magic: b"ARPi"
///  4       8    write_counter (u64 LE, monotonic)
/// 12       8    timestamp_us (u64 LE, Unix microseconds)
/// 20       1    tier (0=Critical 1=Personal 2=Noise)
/// 21       3    reserved (zero)
/// 24      32    blake3_content_hash
/// 56      22    node_id (UTF-8, zero-padded)
#[derive(Debug, Clone)]
pub struct ArpiHeader {
    pub magic: [u8; 4],
    pub write_counter: u64,
    pub timestamp_us: u64,
    pub tier: u8,
    pub reserved: [u8; 3],
    pub blake3_hash: [u8; 32],
    pub node_id: [u8; 22],
}

impl ArpiHeader {
    pub const SIZE: usize = 78;

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::SIZE {
            return None;
        }
        if &bytes[0..4] != b"ARPi" {
            return None;
        }

        let tier = bytes[20];
        if !matches!(tier, 0..=2) {
            return None;
        }

        let write_counter =
            u64::from_le_bytes(bytes[4..12].try_into().ok()?);
        let timestamp_us =
            u64::from_le_bytes(bytes[12..20].try_into().ok()?);

        let mut reserved = [0u8; 3];
        reserved.copy_from_slice(&bytes[21..24]);
        if reserved != [0u8; 3] {
            return None;
        }

        let mut blake3_hash = [0u8; 32];
        blake3_hash.copy_from_slice(&bytes[24..56]);

        let mut node_id = [0u8; 22];
        node_id.copy_from_slice(&bytes[56..78]);

        Some(Self {
            magic: *b"ARPi",
            write_counter,
            timestamp_us,
            tier,
            reserved,
            blake3_hash,
            node_id,
        })
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[0..4].copy_from_slice(&self.magic);
        out[4..12].copy_from_slice(&self.write_counter.to_le_bytes());
        out[12..20].copy_from_slice(&self.timestamp_us.to_le_bytes());
        out[20] = self.tier;
        out[21..24].copy_from_slice(&self.reserved);
        out[24..56].copy_from_slice(&self.blake3_hash);
        out[56..78].copy_from_slice(&self.node_id);
        out
    }
}

fn pack_record(arpi: &[u8; 78], value: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(78 + value.len());
    buf.extend_from_slice(arpi);
    buf.extend_from_slice(value);
    buf
}

fn unpack_value(record: &[u8]) -> Option<&[u8]> {
    if record.len() < 78 { return None; }
    Some(&record[78..])
}

/// Embedded EdisonDB instance — no gRPC, no network stack.
pub struct MobileDb {
    _db: Database,
    partition: Keyspace,
    write_counter: u64,
}

impl MobileDb {
    pub fn open(path: &str) -> Result<Self, DbError> {
        let db = Database::builder(Path::new(path))
            .open()
            .map_err(|e| {
                DbError::Fjall(e)
            })?;
        let partition = db
            .keyspace("main", KeyspaceCreateOptions::default)
            .map_err(|e| {
                DbError::Fjall(e)
            })?;

        let counter = match partition.get(WRITE_COUNTER_KEY) {
            Ok(Some(v)) => {
                let arr: [u8; 8] = v
                    .as_ref()
                    .try_into()
                    .map_err(|_| DbError::InvalidCounterState)?;
                u64::from_le_bytes(arr)
            }
            Ok(None) => 0u64,
            Err(e) => return Err(DbError::Fjall(e)),
        };

        Ok(Self { _db: db, partition, write_counter: counter })
    }

    fn next_counter(&mut self) -> Result<u64, DbError> {
        let next =
            next_write_counter(self.write_counter).ok_or(DbError::CounterExhausted)?;
        self.write_counter = next;
        Ok(next)
    }

    fn persist_counter(&self) -> Result<(), DbError> {
        self.partition
            .insert(WRITE_COUNTER_KEY, &self.write_counter.to_le_bytes())
            .map_err(DbError::Fjall)
    }

    pub fn insert(&mut self, key: &str, value: &str, arpi_raw: &[u8]) -> Result<(), DbError> {
        if arpi_raw.len() < 78 { return Err(DbError::InvalidArpi); }
        let header = ArpiHeader::from_bytes(arpi_raw).ok_or(DbError::InvalidArpi)?;

        // Content provenance is fail-closed on every target, including
        // Android. The header must bind the exact UTF-8 value persisted below.
        let mut h = Hasher::new();
        h.update(value.as_bytes());
        let computed: [u8; 32] = h.finalize().into();
        if computed != header.blake3_hash {
            return Err(DbError::InvalidArpi);
        }

        let counter = self.next_counter()?;
        let mut final_header = header.clone();
        final_header.write_counter = counter;
        let header_bytes = final_header.to_bytes();

        let record = pack_record(&header_bytes, value.as_bytes());
        self.partition
            .insert(key.as_bytes(), &record)
            .map_err(DbError::Fjall)?;
        self.persist_counter()?;
        Ok(())
    }

    pub fn query(&self, key: &str) -> Result<Option<String>, DbError> {
        match self.partition.get(key.as_bytes()) {
            Ok(Some(record)) => {
                let value_bytes = unpack_value(record.as_ref()).unwrap_or(&[]);
                Ok(Some(String::from_utf8_lossy(value_bytes).into_owned()))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(DbError::Fjall(e)),
        }
    }

    pub fn delete(&mut self, key: &str) -> Result<bool, DbError> {
        let existed = self.partition.get(key.as_bytes())
            .map(|v| v.is_some())
            .unwrap_or(false);
        self.partition
            .remove(key.as_bytes())
            .map_err(DbError::Fjall)?;
        Ok(existed)
    }
}


#[cfg(test)]
mod p3_counter_tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        std::env::temp_dir().join(format!(
            "edisondb-fv5-p3-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn valid_arpi(value: &str) -> [u8; ArpiHeader::SIZE] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(value.as_bytes());
        let blake3_hash: [u8; 32] = hasher.finalize().into();

        ArpiHeader {
            magic: *b"ARPi",
            write_counter: 0,
            timestamp_us: 1,
            tier: 2,
            reserved: [0u8; 3],
            blake3_hash,
            node_id: [0u8; 22],
        }
        .to_bytes()
    }

    fn seed_counter(path: &Path, value: &[u8]) {
        let db = Database::builder(path).open().unwrap();
        let partition = db
            .keyspace("main", KeyspaceCreateOptions::default)
            .unwrap();

        partition.insert(WRITE_COUNTER_KEY, value).unwrap();

        drop(partition);
        drop(db);
    }

    fn stored_counter(db: &MobileDb, key: &str) -> u64 {
        let raw = db
            .partition
            .get(key.as_bytes())
            .unwrap()
            .expect("record must exist");

        let record = raw.as_ref();
        let header = record
            .get(..ArpiHeader::SIZE)
            .expect("stored record must contain a complete ARPi header");

        ArpiHeader::from_bytes(header)
            .expect("stored ARPi header must decode")
            .write_counter
    }

    #[test]
    fn p3_counter_increments_and_resumes_after_reopen() {
        let path = temp_path("reopen");
        let path_str = path.to_str().unwrap();

        let mut db = MobileDb::open(path_str).unwrap();

        db.insert("rec:1", "alpha", &valid_arpi("alpha"))
            .unwrap();
        db.insert("rec:2", "beta", &valid_arpi("beta"))
            .unwrap();

        assert_eq!(stored_counter(&db, "rec:1"), 1);
        assert_eq!(stored_counter(&db, "rec:2"), 2);
        assert_eq!(db.write_counter, 2);

        drop(db);

        let mut reopened = MobileDb::open(path_str).unwrap();
        assert_eq!(reopened.write_counter, 2);

        reopened
            .insert("rec:3", "gamma", &valid_arpi("gamma"))
            .unwrap();

        assert_eq!(stored_counter(&reopened, "rec:3"), 3);
        assert_eq!(reopened.write_counter, 3);

        drop(reopened);
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn p3_malformed_persisted_counter_fails_closed() {
        let path = temp_path("malformed");
        seed_counter(&path, &[1u8, 2, 3]);

        let result = MobileDb::open(path.to_str().unwrap());

        assert!(matches!(result, Err(DbError::InvalidCounterState)));

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn p3_counter_exhaustion_rejects_write_without_wraparound() {
        let path = temp_path("exhausted");
        seed_counter(&path, &u64::MAX.to_le_bytes());

        let mut db = MobileDb::open(path.to_str().unwrap()).unwrap();
        assert_eq!(db.write_counter, u64::MAX);

        let result =
            db.insert("rec:max", "omega", &valid_arpi("omega"));

        assert!(matches!(result, Err(DbError::CounterExhausted)));
        assert_eq!(db.write_counter, u64::MAX);
        assert!(db.partition.get(b"rec:max").unwrap().is_none());

        drop(db);
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn p3_counter_transition_never_wraps() {
        assert_eq!(next_write_counter(0), Some(1));
        assert_eq!(next_write_counter(41), Some(42));
        assert_eq!(
            next_write_counter(u64::MAX - 1),
            Some(u64::MAX)
        );
        assert_eq!(next_write_counter(u64::MAX), None);
    }
}
