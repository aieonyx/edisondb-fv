// src/grpc.rs
// Copyright 2026 Edison Lepiten / AIEONYX — Apache 2.0
//
// EdisonDB gRPC server — tonic 0.14
// Mirrors server.rs pattern: EdisonDB::connect() per request via db_path.
// No unsafe blocks in production code.

use tonic::{Request, Response, Status};
use tokio::sync::Mutex;
use zeroize::Zeroizing;
use edisondb::sdk::EdisonDB;
use edisondb::EdisonError;

// ── Proto generated code ─────────────────────────────────────────────────────

pub mod proto {
    tonic::include_proto!("edisondb");
}

use proto::{
    edison_db_server::{EdisonDb, EdisonDbServer},
    AuditResponse, DeleteResponse, EmbedResponse,
    ListResponse, ReadResponse, SearchHit, SearchResponse,
    WriteResponse,
    WriteRequest, ReadRequest, ListRequest, DeleteRequest,
    AuditRequest, EmbedRequest, SearchRequest,
};

// ── Server struct ─────────────────────────────────────────────────────────────

pub struct EdisonDbGrpc {
    db_path: String,
    operation_lock: Mutex<()>,
}

impl EdisonDbGrpc {
    pub fn new(db_path: String) -> Self {
        Self {
            db_path,
            operation_lock: Mutex::new(()),
        }
    }

    fn extract_password(
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<Zeroizing<String>, Status> {
        metadata
            .get("x-password")
            .and_then(|v| v.to_str().ok())
            .map(|s| Zeroizing::new(s.to_string()))
            .ok_or_else(|| Status::unauthenticated("x-password metadata header is required"))
    }

    fn connect(
        &self,
        owner_id: &str,
        password: &str,
    ) -> Result<EdisonDB, Status> {
        EdisonDB::connect(&self.db_path, owner_id, password)
            .map_err(|e| Status::unauthenticated(e.to_string()))
    }
}

// ── Tier helper ───────────────────────────────────────────────────────────────

fn tier_str(tier_int: i32) -> Result<&'static str, Status> {
    match tier_int {
        0 => Ok("CRITICAL"),
        1 => Ok("PERSONAL"),
        2 => Ok("NOISE"),
        _ => Err(Status::invalid_argument(format!(
            "Invalid tier: {}. Expected 0=CRITICAL 1=PERSONAL 2=NOISE", tier_int
        ))),
    }
}

// ── Service implementation ────────────────────────────────────────────────────

#[tonic::async_trait]
impl EdisonDb for EdisonDbGrpc {

    async fn write(
        &self,
        request: Request<WriteRequest>,
    ) -> Result<Response<WriteResponse>, Status> {
        let password = Self::extract_password(request.metadata())?;
        let req = request.into_inner();
        if req.owner_id.is_empty() {
            return Err(Status::unauthenticated("owner_id is required"));
        }
        let tier = tier_str(req.tier)?;
        let payload = String::from_utf8(req.payload)
            .map_err(|_| Status::invalid_argument("payload must be valid UTF-8"))?;

        let _guard = self.operation_lock.lock().await;
        let mut db = self.connect(&req.owner_id, &password)?;
        db.write(&req.record_id, tier, &payload)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(WriteResponse { success: true, message: "ok".into() }))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
    ) -> Result<Response<ReadResponse>, Status> {
        let password = Self::extract_password(request.metadata())?;
        let req = request.into_inner();
        if req.owner_id.is_empty() {
            return Err(Status::unauthenticated("owner_id is required"));
        }

        let _guard = self.operation_lock.lock().await;
        let mut db = self.connect(&req.owner_id, &password)?;
        match db.read(&req.record_id) {
            Ok(Some(record)) => Ok(Response::new(ReadResponse {
                found:   true,
                payload: record.payload.into_bytes(),
                message: "ok".into(),
            })),
            Ok(None) => Ok(Response::new(ReadResponse {
                found:   false,
                payload: vec![],
                message: "not found".into(),
            })),
            Err(EdisonError::AccessDenied) => {
                Err(Status::permission_denied("access denied"))
            }
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn list(
        &self,
        request: Request<ListRequest>,
    ) -> Result<Response<ListResponse>, Status> {
        let password = Self::extract_password(request.metadata())?;
        let req = request.into_inner();
        if req.owner_id.is_empty() {
            return Err(Status::unauthenticated("owner_id is required"));
        }
        let tier = tier_str(req.tier)?;

        let _guard = self.operation_lock.lock().await;
        let mut db = self.connect(&req.owner_id, &password)?;
        let records = db.list(Some(tier))
            .map_err(|e| Status::internal(e.to_string()))?;

        let record_ids = records.into_iter().map(|r| r.id).collect();
        Ok(Response::new(ListResponse { record_ids }))
    }

    async fn delete(
        &self,
        request: Request<DeleteRequest>,
    ) -> Result<Response<DeleteResponse>, Status> {
        let password = Self::extract_password(request.metadata())?;
        let req = request.into_inner();
        if req.owner_id.is_empty() {
            return Err(Status::unauthenticated("owner_id is required"));
        }

        let _guard = self.operation_lock.lock().await;
        let mut db = self.connect(&req.owner_id, &password)?;
        db.delete(&req.record_id)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(DeleteResponse { success: true, message: "ok".into() }))
    }

    async fn audit(
        &self,
        request: Request<AuditRequest>,
    ) -> Result<Response<AuditResponse>, Status> {
        let password = Self::extract_password(request.metadata())?;
        let req = request.into_inner();
        if req.owner_id.is_empty() {
            return Err(Status::unauthenticated("owner_id is required"));
        }

        let _guard = self.operation_lock.lock().await;
        let db = self.connect(&req.owner_id, &password)?;
        let audit_entries = db.audit(Some(&req.record_id))
            .map_err(|e| Status::internal(e.to_string()))?;

        let entries = audit_entries
            .into_iter()
            .map(|e| format!("[{}] {} — {}", e.timestamp, e.action, e.record_id))
            .collect();

        Ok(Response::new(AuditResponse { entries }))
    }

    async fn embed(
        &self,
        request: Request<EmbedRequest>,
    ) -> Result<Response<EmbedResponse>, Status> {
        let password = Self::extract_password(request.metadata())?;
        let req = request.into_inner();
        if req.owner_id.is_empty() {
            return Err(Status::unauthenticated("owner_id is required"));
        }
        let tier = tier_str(req.tier)?;
        let payload = String::from_utf8(req.payload)
            .map_err(|_| Status::invalid_argument("payload must be valid UTF-8"))?;

        let _guard = self.operation_lock.lock().await;
        let mut db = self.connect(&req.owner_id, &password)?;
        db.write(&req.record_id, tier, &payload)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(EmbedResponse { success: true, message: "ok".into() }))
    }

    async fn search(
        &self,
        request: Request<SearchRequest>,
    ) -> Result<Response<SearchResponse>, Status> {
        let password = Self::extract_password(request.metadata())?;
        let req = request.into_inner();
        if req.owner_id.is_empty() {
            return Err(Status::unauthenticated("owner_id is required"));
        }
        if req.query_vec.len() % 4 != 0 {
            return Err(Status::invalid_argument(
                "query_vec must be 4-byte little-endian f32 values",
            ));
        }

        let query: Vec<f32> = req.query_vec
            .chunks_exact(4)
            .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect();

        let top_k = if req.top_k == 0 { 10 } else { req.top_k as usize };

        let _guard = self.operation_lock.lock().await;
        let mut db = self.connect(&req.owner_id, &password)?;
        let hits = db.search_vectors(&query, top_k, None)
            .map_err(|e| Status::internal(e.to_string()))?;

        let grpc_hits = hits.into_iter()
            .map(|h| SearchHit { record_id: h.id, score: h.score })
            .collect();

        Ok(Response::new(SearchResponse { hits: grpc_hits }))
    }
}

// ── Server entrypoint ─────────────────────────────────────────────────────────

pub async fn serve_grpc(db_path: String, port: u16) {
    let addr = format!("0.0.0.0:{}", port)
        .parse()
        .expect("grpc: invalid bind address");

    let svc = EdisonDbGrpc::new(db_path);

    println!("  gRPC     : grpc://0.0.0.0:{}", port);

    tonic::transport::Server::builder()
        .add_service(EdisonDbServer::new(svc))
        .serve(addr)
        .await
        .expect("grpc: server failed");
}
