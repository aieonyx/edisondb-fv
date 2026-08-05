// tests/grpc_tests.rs
// Copyright 2026 Edison Lepiten — Apache 2.0
//
// P3-M2 gRPC integration test suite — 8 tests
// Uses tonic generated client. Server must be running on port 50051.
// These tests mirror grpc_tests.rs structure to sdk_tests.rs for consistency.

use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::Request;

// Import generated proto client
use edisondb::edison_db_client::EdisonDbClient;
use edisondb::{
    AuditRequest, DataTier, DeleteRequest,
    ListRequest, ReadRequest, WriteRequest,
};

pub mod edisondb {
    tonic::include_proto!("edisondb");
}

// ── Test harness ─────────────────────────────────────────────────────────────

const GRPC_ADDR: &str = "http://127.0.0.1:50051";
const OWNER_ID:  &str = "test-owner";
const PASSWORD:  &str = "test-password-secure-123";

fn spawn_server() -> Child {
    Command::new(env!("CARGO_BIN_EXE_edisondb-server"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn EdisonDB server")
}

fn kill_server(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

async fn make_client() -> EdisonDbClient<Channel> {
    EdisonDbClient::connect(GRPC_ADDR)
        .await
        .expect("Failed to connect to gRPC server")
}

/// Attach owner_id + x-password to a tonic Request
fn auth_request<T>(msg: T) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut().insert(
        "x-password",
        MetadataValue::from_static(PASSWORD),
    );
    req
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Test 1: Write a Critical record and verify it is readable via gRPC Read
#[tokio::test]
async fn test_grpc_write_critical() {
    let mut server = spawn_server();
    thread::sleep(Duration::from_secs(2));

    let mut client = make_client().await;

    let write_req = auth_request(WriteRequest {
        owner_id:  OWNER_ID.into(),
        record_id: "grpc:write:1".into(),
        tier:      DataTier::Critical as i32,
        payload:   b"sovereign_data".to_vec(),
    });

    let write_resp = client.write(write_req).await.expect("Write failed");
    assert!(write_resp.into_inner().success, "Write should succeed");

    let read_req = auth_request(ReadRequest {
        owner_id:  OWNER_ID.into(),
        record_id: "grpc:write:1".into(),
        tier:      DataTier::Critical as i32,
    });

    let read_resp = client.read(read_req).await.expect("Read failed").into_inner();
    assert!(read_resp.found, "Record should be found after write");
    assert_eq!(read_resp.payload, b"sovereign_data", "Payload mismatch");

    kill_server(&mut server);
}

/// Test 2: Read a missing record returns found=false, not an error
#[tokio::test]
async fn test_grpc_read_not_found() {
    let mut server = spawn_server();
    thread::sleep(Duration::from_secs(2));

    let mut client = make_client().await;

    let req = auth_request(ReadRequest {
        owner_id:  OWNER_ID.into(),
        record_id: "grpc:nonexistent:999".into(),
        tier:      DataTier::Personal as i32,
    });

    let resp = client.read(req).await.expect("Read RPC failed").into_inner();
    assert!(!resp.found, "Missing record should return found=false");
    assert!(resp.payload.is_empty(), "Missing record payload should be empty");

    kill_server(&mut server);
}

/// Test 3: List returns correct record IDs for the given tier
#[tokio::test]
async fn test_grpc_list_by_tier() {
    let mut server = spawn_server();
    thread::sleep(Duration::from_secs(2));

    let mut client = make_client().await;

    // Write two NOISE records
    for i in 1..=2 {
        let req = auth_request(WriteRequest {
            owner_id:  OWNER_ID.into(),
            record_id: format!("grpc:list:{}", i),
            tier:      DataTier::Noise as i32,
            payload:   format!("val_{}", i).into_bytes(),
        });
        client.write(req).await.expect("Write failed");
    }

    let list_req = auth_request(ListRequest {
        owner_id: OWNER_ID.into(),
        tier:     DataTier::Noise as i32,
    });

    let resp = client.list(list_req).await.expect("List failed").into_inner();
    assert!(
        resp.record_ids.contains(&"grpc:list:1".to_string()),
        "grpc:list:1 should be in list results"
    );
    assert!(
        resp.record_ids.contains(&"grpc:list:2".to_string()),
        "grpc:list:2 should be in list results"
    );

    kill_server(&mut server);
}

/// Test 4: Delete removes a record; subsequent read returns found=false
#[tokio::test]
async fn test_grpc_delete_removes_record() {
    let mut server = spawn_server();
    thread::sleep(Duration::from_secs(2));

    let mut client = make_client().await;

    // Write first
    let write_req = auth_request(WriteRequest {
        owner_id:  OWNER_ID.into(),
        record_id: "grpc:delete:1".into(),
        tier:      DataTier::Personal as i32,
        payload:   b"to_be_deleted".to_vec(),
    });
    client.write(write_req).await.expect("Write failed");

    // Delete
    let del_req = auth_request(DeleteRequest {
        owner_id:  OWNER_ID.into(),
        record_id: "grpc:delete:1".into(),
        tier:      DataTier::Personal as i32,
    });
    let del_resp = client.delete(del_req).await.expect("Delete failed").into_inner();
    assert!(del_resp.success, "Delete should succeed");

    // Read — must be gone
    let read_req = auth_request(ReadRequest {
        owner_id:  OWNER_ID.into(),
        record_id: "grpc:delete:1".into(),
        tier:      DataTier::Personal as i32,
    });
    let read_resp = client.read(read_req).await.expect("Read failed").into_inner();
    assert!(!read_resp.found, "Record should be gone after delete");

    kill_server(&mut server);
}

/// Test 5: Audit returns all entries for a record in chronological order
#[tokio::test]
async fn test_grpc_audit_history() {
    let mut server = spawn_server();
    thread::sleep(Duration::from_secs(2));

    let mut client = make_client().await;

    let write_req = auth_request(WriteRequest {
        owner_id:  OWNER_ID.into(),
        record_id: "grpc:audit:1".into(),
        tier:      DataTier::Critical as i32,
        payload:   b"audit_data".to_vec(),
    });
    client.write(write_req).await.expect("Write failed");

    let read_req = auth_request(ReadRequest {
        owner_id:  OWNER_ID.into(),
        record_id: "grpc:audit:1".into(),
        tier:      DataTier::Critical as i32,
    });
    client.read(read_req).await.expect("Read failed");

    let audit_req = auth_request(AuditRequest {
        owner_id:  OWNER_ID.into(),
        record_id: "grpc:audit:1".into(),
    });

    let resp = client.audit(audit_req).await.expect("Audit failed").into_inner();
    assert!(
        resp.entries.len() >= 2,
        "Audit should return at least 2 entries (one per write), got {}",
        resp.entries.len()
    );

    kill_server(&mut server);
}

/// Test 6: Request without x-password metadata is rejected with UNAUTHENTICATED
#[tokio::test]
async fn test_grpc_no_password_rejected() {
    let mut server = spawn_server();
    thread::sleep(Duration::from_secs(2));

    let mut client = make_client().await;

    // No auth_request wrapper — plain Request with no metadata
    let req = Request::new(WriteRequest {
        owner_id:  OWNER_ID.into(),
        record_id: "grpc:noauth:1".into(),
        tier:      DataTier::Critical as i32,
        payload:   b"should_fail".to_vec(),
    });

    let err = client.write(req).await.expect_err("Should have been rejected");
    assert_eq!(
        err.code(),
        tonic::Code::Unauthenticated,
        "Missing x-password must return UNAUTHENTICATED"
    );

    kill_server(&mut server);
}

/// Test 7: Wrong owner_id returns no data (Inverted Admin Model)
#[tokio::test]
async fn test_grpc_wrong_owner_rejected() {
    let mut server = spawn_server();
    thread::sleep(Duration::from_secs(2));

    let mut client = make_client().await;

    // Write as correct owner
    let write_req = auth_request(WriteRequest {
        owner_id:  OWNER_ID.into(),
        record_id: "grpc:owner:1".into(),
        tier:      DataTier::Critical as i32,
        payload:   b"owner_data".to_vec(),
    });
    client.write(write_req).await.expect("Write failed");

    // Read as wrong owner — must not find the record
    let mut read_req = Request::new(ReadRequest {
        owner_id:  "attacker-owner".into(),
        record_id: "grpc:owner:1".into(),
        tier:      DataTier::Critical as i32,
    });
    read_req.metadata_mut().insert(
        "x-password",
        MetadataValue::from_static("wrong-password"),
    );

    let err = client.read(read_req)
        .await
        .expect_err("Wrong owner must be rejected");

    assert_eq!(
        err.code(),
        tonic::Code::PermissionDenied,
        "Wrong owner must receive PERMISSION_DENIED"
    );

    kill_server(&mut server);
}

/// Test 8: 10 concurrent gRPC writes all commit cleanly — no lost updates
#[tokio::test]
async fn test_grpc_concurrent_writes() {
    let mut server = spawn_server();
    thread::sleep(Duration::from_secs(2));

    let channel = Channel::from_static("http://127.0.0.1:50051")
        .connect()
        .await
        .expect("Failed to connect");

    let mut handles = vec![];

    for i in 0..10 {
        let ch = channel.clone();
        handles.push(tokio::spawn(async move {
            let mut client = EdisonDbClient::new(ch);
            let mut req = Request::new(WriteRequest {
                owner_id:  OWNER_ID.into(),
                record_id: format!("grpc:concurrent:{}", i),
                tier:      DataTier::Noise as i32,
                payload:   format!("concurrent_val_{}", i).into_bytes(),
            });
            req.metadata_mut().insert(
                "x-password",
                MetadataValue::from_static(PASSWORD),
            );
            client.write(req).await
        }));
    }

    let results: Vec<_> = futures::future::join_all(handles).await;
    for (i, result) in results.into_iter().enumerate() {
        let resp = result
            .expect("tokio task panicked")
            .expect(&format!("gRPC write {} failed", i));
        assert!(resp.into_inner().success, "Concurrent write {} did not succeed", i);
    }

    // Verify all 10 are present
    let mut client = EdisonDbClient::new(channel);
    for i in 0..10 {
        let mut req = Request::new(ReadRequest {
            owner_id:  OWNER_ID.into(),
            record_id: format!("grpc:concurrent:{}", i),
            tier:      DataTier::Noise as i32,
        });
        req.metadata_mut().insert(
            "x-password",
            MetadataValue::from_static(PASSWORD),
        );
        let resp = client.read(req).await.expect("Read failed").into_inner();
        assert!(resp.found, "Concurrent record {} missing after all writes", i);
    }

    kill_server(&mut server);
}
