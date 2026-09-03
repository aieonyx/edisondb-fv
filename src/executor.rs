use rand::RngCore;

use crate::{
    DataTier, EdisonError, EncryptedPayload, Record,
    decrypt_payload, derive_key,
};
use crate::backends::{RedbBackend, FjallBackend, Router};
use crate::eql::{Statement, Tier};

// ── Tier conversion ───────────────────────────────────────────────────────────
fn to_data_tier(t: &Tier) -> DataTier {
    match t {
        Tier::Critical => DataTier::Critical,
        Tier::Personal => DataTier::Personal,
        Tier::Noise    => DataTier::Noise,
    }
}

// ── Result types ──────────────────────────────────────────────────────────────
/// A single vector search result.
#[derive(Debug, Clone)]
pub struct VectorHit {
    pub id: String,
    pub score: f32,
}

#[derive(Debug)]
pub enum EqlResult {
    Written  { id: String, tier: Tier },
    Read     { id: String, tier: DataTier, payload: String },
    Listed   (Vec<RecordInfo>),
    Deleted  { id: String },
    Audited  (Vec<String>),
    Embedded { id: String },
    Found    (Vec<VectorHit>),
}

#[derive(Debug)]
pub struct RecordInfo {
    pub string_id:  String,
    pub tier:       DataTier,
    pub created_at: u64,
}

impl std::fmt::Display for EqlResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EqlResult::Written { id, tier } =>
                write!(f, "OK  WROTE   [{tier}] {id}"),
            EqlResult::Read { id, tier, payload } =>
                write!(f, "OK  READ    [{tier:?}] {id}\n    → {payload}"),
            EqlResult::Deleted { id } =>
                write!(f, "OK  DELETED {id}"),
            EqlResult::Listed(records) => {
                writeln!(f, "OK  {} record(s)", records.len())?;
                for r in records {
                    writeln!(f, "    [{:?}]  {}", r.tier, r.string_id)?;
                }
                Ok(())
            }
            EqlResult::Audited(lines) => {
                writeln!(f, "OK  {} audit entry/entries", lines.len())?;
                for l in lines { writeln!(f, "    {l}")?; }
                Ok(())
            }
            EqlResult::Embedded { id } =>
                write!(f, "OK  EMBEDDED {id}"),
            EqlResult::Found(hits) => {
                writeln!(f, "OK  {} hit(s)", hits.len())?;
                for h in hits {
                    writeln!(f, "    {} score={:.4}", h.id, h.score)?;
                }
                Ok(())
            }
        }
    }
}

// ── Executor ──────────────────────────────────────────────────────────────────
pub struct EqlExecutor {
    router:       Router,
    owner_id:     String,
    password:     String,
    vector_index: crate::vector::VectorIndex,
    db_path:      String,
}

impl EqlExecutor {
    pub fn open(path: &str, owner_id: &str, password: &str) -> Result<Self, EdisonError> {
        let backend_type = std::env::var("EDISONDB_BACKEND")
            .unwrap_or_else(|_| "redb".to_string());
        let router = match backend_type.to_lowercase().as_str() {
            "fjall" => Router::new(Box::new(FjallBackend::open(path)?)),
            _       => Router::new(Box::new(RedbBackend::open(path)?)),
        };
        let vector_path = format!("{}.vectors", path);
        let vector_index = if std::path::Path::new(&vector_path).exists() {
            crate::vector::VectorIndex::load(&vector_path)
                .unwrap_or_else(|_| crate::vector::VectorIndex::new())
        } else {
            crate::vector::VectorIndex::new()
        };
        Ok(Self {
            router,
            owner_id: owner_id.to_string(),
            password: password.to_string(),
            vector_index,
            db_path: path.to_string(),
        })
    }

    pub fn execute(&mut self, stmt: Statement) -> Result<EqlResult, EdisonError> {
        match stmt {
            Statement::Write  { id, tier, payload, auto_embed } => self.exec_write(id, tier, payload, auto_embed),
            Statement::Read   { id }                => self.exec_read(id),
            Statement::List   { tier }              => self.exec_list(tier),
            Statement::Delete { id }                => self.exec_delete(id),
            Statement::Audit  { id }                => self.exec_audit(id),
            Statement::Embed  { id, embedding }        => self.exec_embed(id, embedding),
            Statement::Search { query, k, min_similarity } => self.exec_search(query, k, min_similarity),
            Statement::AutoEmbed { id }                       => self.exec_auto_embed(id),
        }
    }

    fn exec_write(
        &mut self,
        id: String,
        tier: Tier,
        payload: String,
        auto_embed: bool,
    ) -> Result<EqlResult, EdisonError> {
        let data_tier = to_data_tier(&tier);
        let mut salt  = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let key       = derive_key(&self.password, &salt)?;
        // Record construction owns encryption so AAD and immutable metadata
        // cannot be supplied independently.
        let record = Record::new(
            &id,
            data_tier,
            &self.owner_id,
            payload.as_bytes(),
            &key,
            salt,
        )?;
        self.router.write(record)?;
        self.router.save()?;
        if auto_embed {
            let client = crate::embedding::EmbeddingClient::default_ollama();
            if let Ok(embedding) = client.embed(&payload) {
                self.vector_index.insert(id.clone(), embedding)?;
            }
        }
        Ok(EqlResult::Written { id, tier })
    }

    fn exec_read(&mut self, id: String) -> Result<EqlResult, EdisonError> {
        let read_result = self.router.read(&id, &self.owner_id);
        self.router.save()?;

        let (salt, payload, tier) = {
            let record = read_result?;
            (
                *record.salt(),
                record.encrypted_payload().clone(),
                record.tier.clone(),
            )
        };
        let key       = derive_key(&self.password, &salt)?;
        // AAD must match — wrong id or tier = decryption failure
        let decrypted = decrypt_payload(&payload, &key, &id, &tier)?;
        let data      = String::from_utf8(decrypted).map_err(|_| EdisonError::DecryptionFailed)?;
        Ok(EqlResult::Read { id, tier, payload: data })
    }

    fn exec_list(&mut self, tier_filter: Option<Tier>) -> Result<EqlResult, EdisonError> {
        // Collect owned snapshots first to release borrow on self.router
        type Snapshot = (
            String,
            [u8; 32],
            EncryptedPayload,
            DataTier,
            u64,
        );
        let snapshots: Vec<Snapshot> = self.router
            .list_by_owner(&self.owner_id)?
            .into_iter()
            .map(|r| {
                (
                    r.id.clone(),
                    *r.salt(),
                    r.encrypted_payload().clone(),
                    r.tier.clone(),
                    r.created_at,
                )
            })
            .collect();

        let mut infos = Vec::new();
        for (id, salt, payload, tier, created_at) in snapshots {
            if tier_filter.as_ref().is_some_and(|tf| to_data_tier(tf) != tier) {
                continue;
            }
            let key = derive_key(&self.password, &salt)?;
            // Verify AAD integrity on list — corrupt/transplanted records surface here
            let _ = decrypt_payload(&payload, &key, &id, &tier)?;
            infos.push(RecordInfo { string_id: id, tier, created_at });
        }
        Ok(EqlResult::Listed(infos))
    }

    fn exec_delete(&mut self, id: String) -> Result<EqlResult, EdisonError> {
        self.router.delete(&id, &self.owner_id)?;
        self.router.save()?;
        Ok(EqlResult::Deleted { id })
    }

    fn exec_audit(&self, id: Option<String>) -> Result<EqlResult, EdisonError> {
        let entries = self.router.audit_entries();
        let lines = entries
            .iter()
            .filter(|e| match &id {
                Some(filter) => &e.record_id == filter,
                None         => true,
            })
            .map(|e| format!(
                "t={:10}  {:12?}  record={}  by={}",
                e.timestamp, e.action, e.record_id, e.requester_id
            ))
            .collect();
        Ok(EqlResult::Audited(lines))
    }

    fn exec_auto_embed(&mut self, id: String) -> Result<EqlResult, EdisonError> {
        // Find the record payload to embed
        let record = self.router.read(&id, &self.owner_id)?;
        let encrypted_payload =
            record.encrypted_payload().clone();
        let salt = *record.salt();
        let tier = record.tier.clone();
        // Decrypt to get plaintext
        let key = crate::derive_key(&self.password, &salt)?;
        let decrypted =
            crate::decrypt_payload(&encrypted_payload, &key, &id, &tier)?;
        let text = String::from_utf8(decrypted).map_err(|_| EdisonError::DecryptionFailed)?;
        // Generate embedding
        let client = crate::embedding::EmbeddingClient::default_ollama();
        let embedding = client.embed(&text)?;
        self.vector_index.insert(id.clone(), embedding)?;
        Ok(EqlResult::Embedded { id })
    }

    fn exec_embed(
        &mut self,
        id: String,
        embedding: Vec<f32>,
    ) -> Result<EqlResult, EdisonError> {
        self.vector_index.insert(id.clone(), embedding)?;
        Ok(EqlResult::Embedded { id })
    }

    fn exec_search(
        &mut self,
        query: Vec<f32>,
        k: usize,
        min_similarity: Option<f32>,
    ) -> Result<EqlResult, EdisonError> {
        let results = self.vector_index.search(&query, k);
        let hits = results
            .into_iter()
            .filter(|r| min_similarity.is_none_or(|min| r.score >= min))
            .map(|r| VectorHit { id: r.id, score: r.score })
            .collect();
        Ok(EqlResult::Found(hits))
    }
}

// ── Stats & verification ─────────────────────────────────────────────────────────
#[derive(Debug)]
pub struct DbStats {
    pub record_count:   usize,
    pub audit_count:    usize,
    pub critical_count: usize,
    pub personal_count: usize,
    pub noise_count:    usize,
    pub chain_valid:    bool,
}

impl EqlExecutor {
    pub fn stats(&self) -> Result<DbStats, EdisonError> {
        let records = self.router.list_by_owner(&self.owner_id)?;
        let critical_count = records
            .iter()
            .filter(|r| r.tier == crate::DataTier::Critical)
            .count();
        let personal_count = records
            .iter()
            .filter(|r| r.tier == crate::DataTier::Personal)
            .count();
        let noise_count = records
            .iter()
            .filter(|r| r.tier == crate::DataTier::Noise)
            .count();
        let chain_valid = self.router.verify_audit_chain().is_ok();

        Ok(DbStats {
            record_count: records.len(),
            audit_count: self.router.audit_count(),
            critical_count,
            personal_count,
            noise_count,
            chain_valid,
        })
    }

    pub fn verify_chain(&self) -> Result<(), crate::EdisonError> {
        self.router.verify_audit_chain()
    }

    pub fn audit_log(&self, id: Option<&str>) -> Vec<crate::AuditEntry> {
        self.router.audit_entries()
            .into_iter()
            .filter(|e| match id {
                Some(filter) => e.record_id == filter,
                None         => true,
            })
            .collect()
    }

    pub fn backend_name(&self) -> &str {
        self.router.backend_name()
    }

    pub fn save(&self) -> Result<(), crate::EdisonError> {
        self.router.save()?;
        self.vector_index.save(&format!("{}.vectors", self.db_path))?;
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::eql::parse;

    fn fresh(path: &str) -> EqlExecutor {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(path);
        EqlExecutor::open(path, "owner", "password").unwrap()
    }

    #[test]
    fn eql_write_and_read_critical() {
        let mut ex = fresh("/tmp/eql_ex_1.redb");
        ex.execute(parse("WRITE k1 TIER CRITICAL top secret").unwrap()).unwrap();
        match ex.execute(parse("READ k1").unwrap()).unwrap() {
            EqlResult::Read { payload, tier, .. } => {
                assert_eq!(payload, "top secret");
                assert_eq!(tier, DataTier::Critical);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn eql_write_and_read_personal() {
        let mut ex = fresh("/tmp/eql_ex_2.redb");
        ex.execute(parse("WRITE note TIER PERSONAL birthday note").unwrap()).unwrap();
        match ex.execute(parse("READ note").unwrap()).unwrap() {
            EqlResult::Read { tier, .. } => assert_eq!(tier, DataTier::Personal),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn eql_write_and_read_noise() {
        let mut ex = fresh("/tmp/eql_ex_3.redb");
        ex.execute(parse("WRITE log1 TIER NOISE server started").unwrap()).unwrap();
        match ex.execute(parse("READ log1").unwrap()).unwrap() {
            EqlResult::Read { payload, tier, .. } => {
                assert_eq!(payload, "server started");
                assert_eq!(tier, DataTier::Noise);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn eql_wrong_password_fails() {
        let path = "/tmp/eql_ex_4.redb";
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(path);
        {
            let mut ex1 = EqlExecutor::open(path, "owner", "correct").unwrap();
            ex1.execute(parse("WRITE k1 TIER CRITICAL secret").unwrap()).unwrap();
        } // ex1 dropped here — releases fjall file lock
        let mut ex2 = EqlExecutor::open(path, "owner", "wrong").unwrap();
        assert!(ex2.execute(parse("READ k1").unwrap()).is_err());
    }

    #[test]
    fn eql_duplicate_id_rejected() {
        let mut ex = fresh("/tmp/eql_ex_5.redb");
        ex.execute(parse("WRITE k1 TIER NOISE foo").unwrap()).unwrap();
        assert!(ex.execute(parse("WRITE k1 TIER NOISE bar").unwrap()).is_err());
    }

    #[test]
    fn eql_delete_removes_record() {
        let mut ex = fresh("/tmp/eql_ex_6.redb");
        ex.execute(parse("WRITE k1 TIER PERSONAL data").unwrap()).unwrap();
        ex.execute(parse("DELETE k1").unwrap()).unwrap();
        assert!(ex.execute(parse("READ k1").unwrap()).is_err());
    }

    #[test]
    fn eql_list_all() {
        let mut ex = fresh("/tmp/eql_ex_7.redb");
        ex.execute(parse("WRITE a TIER CRITICAL x").unwrap()).unwrap();
        ex.execute(parse("WRITE b TIER NOISE y").unwrap()).unwrap();
        match ex.execute(parse("LIST").unwrap()).unwrap() {
            EqlResult::Listed(v) => assert_eq!(v.len(), 2),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn eql_list_tier_filter() {
        let mut ex = fresh("/tmp/eql_ex_8.redb");
        ex.execute(parse("WRITE a TIER CRITICAL x").unwrap()).unwrap();
        ex.execute(parse("WRITE b TIER NOISE y").unwrap()).unwrap();
        match ex.execute(parse("LIST TIER NOISE").unwrap()).unwrap() {
            EqlResult::Listed(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].string_id, "b");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn eql_audit_captures_operations() {
        let mut ex = fresh("/tmp/eql_ex_9.redb");
        ex.execute(parse("WRITE k1 TIER PERSONAL data").unwrap()).unwrap();
        ex.execute(parse("READ k1").unwrap()).unwrap();
        match ex.execute(parse("AUDIT").unwrap()).unwrap() {
            EqlResult::Audited(lines) => assert!(lines.len() >= 2),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn eql_read_nonexistent_fails() {
        let mut ex = fresh("/tmp/eql_ex_10.redb");
        assert!(ex.execute(parse("READ ghost").unwrap()).is_err());
    }

    #[test]
    fn vector_eql_embed_and_search() {
        let mut ex = fresh("/tmp/eql_vec_1.redb");
        ex.execute(parse("EMBED rec:1 [1.0, 0.0, 0.0]").unwrap()).unwrap();
        ex.execute(parse("EMBED rec:2 [0.0, 1.0, 0.0]").unwrap()).unwrap();
        match ex.execute(parse("SEARCH [1.0, 0.0, 0.0] LIMIT 1").unwrap()).unwrap() {
            EqlResult::Found(hits) => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].id, "rec:1");
            }
            _ => panic!("expected Found"),
        }
    }

    #[test]
    fn vector_similarity_threshold() {
        let mut ex = fresh("/tmp/eql_vec_2.redb");
        ex.execute(parse("EMBED a [1.0, 0.0]").unwrap()).unwrap();
        ex.execute(parse("EMBED b [0.0, 1.0]").unwrap()).unwrap();
        match ex.execute(parse("SEARCH [1.0, 0.0] LIMIT 2 SIMILARITY > 0.5").unwrap()).unwrap() {
            EqlResult::Found(hits) => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].id, "a");
            }
            _ => panic!("expected Found"),
        }
    }

    #[test]
    fn vector_empty_returns_empty() {
        let mut ex = fresh("/tmp/eql_vec_3.redb");
        match ex.execute(parse("SEARCH [1.0, 0.0] LIMIT 5").unwrap()).unwrap() {
            EqlResult::Found(hits) => assert!(hits.is_empty()),
            _ => panic!("expected Found"),
        }
    }
}