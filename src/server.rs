//! EdisonDB REST Server
//!
//! Starts an HTTP server exposing EdisonDB over a REST API.
//!
//! Auth: every request must include X-Owner-ID and X-Password headers.
//!
//! Usage:
//!   edisondb-server --db myapp.redb --port 7777

use axum::{
    Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;

use edisondb::sdk::EdisonDB;

mod grpc;

const STUDIO_HTML: &str = include_str!("studio.html");

#[derive(Deserialize)]
struct SearchBody {
    vector:         Vec<f32>,
    k:              usize,
    min_similarity: Option<f32>,
}



// -- State -------------------------------------------------------------------

struct AppState {
    db_path: String,
}

type SharedState = Arc<Mutex<AppState>>;

// -- Auth helper -------------------------------------------------------------

fn extract_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let owner = headers
        .get("x-owner-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())?;
    let password = headers
        .get("x-password")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())?;
    Some((owner, password))
}

fn open_db(state: &AppState, owner: &str, password: &str)
    -> Result<EdisonDB, (StatusCode, Json<ApiError>)>
{
    EdisonDB::connect(&state.db_path, owner, password)
        .map_err(|e| (
            StatusCode::UNAUTHORIZED,
            Json(ApiError { error: e.to_string() })
        ))
}

// -- Response types ----------------------------------------------------------

#[derive(Serialize)]
struct ApiError {
    error: String,
}

#[derive(Serialize)]
struct ApiOk {
    ok: bool,
}

#[derive(Deserialize)]
struct WriteBody {
    id:      String,
    tier:    String,
    payload: String,
}

#[derive(Deserialize)]
struct TierQuery {
    tier: Option<String>,
}

#[derive(Deserialize)]
struct IdQuery {
    id: Option<String>,
}

// -- Handlers ----------------------------------------------------------------

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "engine": "EdisonDB" }))
}

async fn handle_write(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<WriteBody>,
) -> Result<Json<ApiOk>, (StatusCode, Json<ApiError>)> {
    let (owner, password) = extract_auth(&headers).ok_or((
        StatusCode::UNAUTHORIZED,
        Json(ApiError { error: "Missing X-Owner-ID or X-Password header".into() }),
    ))?;
    let state = state.lock().unwrap();
    let mut db = open_db(&state, &owner, &password)?;
    db.write(&body.id, &body.tier, &body.payload)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiError { error: e.to_string() })))?;
    Ok(Json(ApiOk { ok: true }))
}

async fn handle_read(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let (owner, password) = extract_auth(&headers).ok_or((
        StatusCode::UNAUTHORIZED,
        Json(ApiError { error: "Missing X-Owner-ID or X-Password header".into() }),
    ))?;
    let state = state.lock().unwrap();
    let mut db = open_db(&state, &owner, &password)?;
    match db.read(&id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { error: e.to_string() })))?
    {
        Some(rec) => Ok(Json(serde_json::json!({
            "id":         rec.id,
            "tier":       rec.tier,
            "payload":    rec.payload,
            "created_at": rec.created_at,
        }))),
        None => Err((StatusCode::NOT_FOUND, Json(ApiError { error: "Record not found".into() }))),
    }
}

async fn handle_list(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(params): Query<TierQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let (owner, password) = extract_auth(&headers).ok_or((
        StatusCode::UNAUTHORIZED,
        Json(ApiError { error: "Missing X-Owner-ID or X-Password header".into() }),
    ))?;
    let state = state.lock().unwrap();
    let mut db = open_db(&state, &owner, &password)?;
    let records = db.list(params.tier.as_deref())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { error: e.to_string() })))?;
    let json: Vec<_> = records.iter().map(|r| serde_json::json!({
        "id":         r.id,
        "tier":       r.tier,
        "created_at": r.created_at,
    })).collect();
    Ok(Json(serde_json::json!({ "records": json, "count": json.len() })))
}

async fn handle_delete(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ApiOk>, (StatusCode, Json<ApiError>)> {
    let (owner, password) = extract_auth(&headers).ok_or((
        StatusCode::UNAUTHORIZED,
        Json(ApiError { error: "Missing X-Owner-ID or X-Password header".into() }),
    ))?;
    let state = state.lock().unwrap();
    let mut db = open_db(&state, &owner, &password)?;
    db.delete(&id)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiError { error: e.to_string() })))?;
    db.persist()
        .map_err(|e: edisondb::EdisonError| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { error: e.to_string() })))?;
    Ok(Json(ApiOk { ok: true }))
}

async fn handle_audit(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(params): Query<IdQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let (owner, password) = extract_auth(&headers).ok_or((
        StatusCode::UNAUTHORIZED,
        Json(ApiError { error: "Missing X-Owner-ID or X-Password header".into() }),
    ))?;
    let state = state.lock().unwrap();
    let db = open_db(&state, &owner, &password)?;
    let entries = db.audit(params.id.as_deref())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { error: e.to_string() })))?;
    let json: Vec<_> = entries.iter().map(|e| serde_json::json!({
        "record_id":    e.record_id,
        "requester_id": e.requester_id,
        "action":       e.action,
        "timestamp":    e.timestamp,
    })).collect();
    Ok(Json(serde_json::json!({ "entries": json, "count": json.len() })))
}

async fn handle_status(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let (owner, password) = extract_auth(&headers).ok_or((
        StatusCode::UNAUTHORIZED,
        Json(ApiError { error: "Missing X-Owner-ID or X-Password header".into() }),
    ))?;
    let state = state.lock().unwrap();
    let db = open_db(&state, &owner, &password)?;
    let s = db.status().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: e.to_string(),
            }),
        )
    })?;
    Ok(Json(serde_json::json!({
        "record_count":   s.record_count,
        "audit_count":    s.audit_count,
        "critical_count": s.critical_count,
        "personal_count": s.personal_count,
        "noise_count":    s.noise_count,
        "chain_valid":    s.chain_valid,
        "backend":        db.backend(),
    })))
}

async fn handle_verify(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let (owner, password) = extract_auth(&headers).ok_or((
        StatusCode::UNAUTHORIZED,
        Json(ApiError { error: "Missing X-Owner-ID or X-Password header".into() }),
    ))?;
    let state = state.lock().unwrap();
    let db = open_db(&state, &owner, &password)?;
    match db.verify() {
        Ok(())  => Ok(Json(serde_json::json!({ "chain_valid": true }))),
        Err(e)  => Ok(Json(serde_json::json!({ "chain_valid": false, "error": e.to_string() }))),
    }
}

async fn handle_studio() -> axum::response::Html<&'static str> {
    axum::response::Html(STUDIO_HTML)
}

async fn handle_search(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<SearchBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let (owner, password) = extract_auth(&headers).ok_or((
        StatusCode::UNAUTHORIZED,
        Json(ApiError { error: "Missing X-Owner-ID or X-Password header".into() }),
    ))?;
    let state = state.lock().unwrap();
    let mut db = open_db(&state, &owner, &password)?;
    let results = db.search_vectors(&body.vector, body.k, body.min_similarity)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { error: e.to_string() })))?;
    let hits: Vec<_> = results.iter().map(|h| serde_json::json!({
        "id":    h.id,
        "score": h.score,
    })).collect();
    Ok(Json(serde_json::json!({ "hits": hits, "count": hits.len() })))
}

// -- Main --------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let db_path = args.iter()
        .position(|a| a == "--db")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "edison.redb".to_string());
    let port = args.iter()
        .position(|a| a == "--port")
        .and_then(|i| args.get(i + 1))
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(7777);

    let state = Arc::new(Mutex::new(AppState { db_path: db_path.clone() }));

    let app = Router::new()
        .route("/health",          get(health))
        .route("/api/write",       post(handle_write))
        .route("/api/read/{id}",    get(handle_read))
        .route("/api/list",        get(handle_list))
        .route("/api/delete/{id}",  delete(handle_delete))
        .route("/api/audit",       get(handle_audit))
        .route("/api/status",      get(handle_status))
        .route("/api/verify",      get(handle_verify))
        .route("/api/search",      post(handle_search))
        .route("/studio",          get(handle_studio))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    println!("╔══════════════════════════════════════╗");
    println!("║     EdisonDB REST Server             ║");
    println!("║  Sovereign. Encrypted. Yours.        ║");
    println!("╚══════════════════════════════════════╝");
    println!("  Database : {db_path}");
    println!("  Listening: http://{addr}");
    println!("  Press Ctrl-C to stop.\n");

    // Spawn gRPC server on port 50051 alongside REST
    let grpc_db_path = db_path.clone();
    tokio::spawn(async move {
        grpc::serve_grpc(grpc_db_path, 50051).await;
    });

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
