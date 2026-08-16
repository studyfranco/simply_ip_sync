//! Inter-vault delta replication: tombstone propagation and `last_sync_at` advancing only on
//! full success across every configured target.

mod common;

use chrono::Utc;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use simply_ip_sync::entities::{vault_endpoint, vault_sync_task, vault_sync_task_target};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn insert_vault(conn: &sea_orm::DatabaseConnection, name: &str, target_url: &str) -> Uuid {
    let id = Uuid::new_v4();
    let now = Utc::now();
    let sealed = simply_ip_sync::crypto::SecretCipher::Plaintext.seal("shared-secret").unwrap();
    let model = vault_endpoint::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        target_url: Set(target_url.to_owned()),
        api_key: Set("remote-key".to_owned()),
        signing_secret: Set(sealed),
        description: Set(None),
        owner_key_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    model.insert(conn).await.expect("insert vault endpoint");
    id
}

async fn insert_task(
    conn: &sea_orm::DatabaseConnection,
    source_vault_id: Uuid,
    target_vault_id: Uuid,
) -> Uuid {
    let id = Uuid::new_v4();
    let now = Utc::now();
    let task = vault_sync_task::ActiveModel {
        id: Set(id),
        name: Set("test-task".to_owned()),
        source_vault_id: Set(source_vault_id),
        source_group_name: Set("source-group".to_owned()),
        target_group_name: Set("target-group".to_owned()),
        cron_schedule: Set("0 0 * * *".to_owned()),
        last_sync_at: Set(None),
        mode: Set("upsert".to_owned()),
        is_active: Set(true),
        owner_key_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    task.insert(conn).await.expect("insert task");
    let target = vault_sync_task_target::ActiveModel {
        vault_sync_task_id: Set(id),
        target_vault_id: Set(target_vault_id),
        target_group_name: Set(None),
    };
    target.insert(conn).await.expect("insert task target");
    id
}

/// Like [`insert_task`] but wires the task to every vault in `target_vault_ids`, for
/// multi-vault fan-out scenarios.
async fn insert_task_multi(
    conn: &sea_orm::DatabaseConnection,
    source_vault_id: Uuid,
    target_vault_ids: &[Uuid],
) -> Uuid {
    let id = Uuid::new_v4();
    let now = Utc::now();
    let task = vault_sync_task::ActiveModel {
        id: Set(id),
        name: Set(format!("multi-target-task-{id}")),
        source_vault_id: Set(source_vault_id),
        source_group_name: Set("source-group".to_owned()),
        target_group_name: Set("target-group".to_owned()),
        cron_schedule: Set("0 0 * * *".to_owned()),
        last_sync_at: Set(None),
        mode: Set("upsert".to_owned()),
        is_active: Set(true),
        owner_key_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    task.insert(conn).await.expect("insert task");
    for target_vault_id in target_vault_ids {
        let target = vault_sync_task_target::ActiveModel {
            vault_sync_task_id: Set(id),
            target_vault_id: Set(*target_vault_id),
            target_group_name: Set(None),
        };
        target.insert(conn).await.expect("insert task target");
    }
    id
}

fn single_delta_record_response() -> serde_json::Value {
    serde_json::json!([{
        "id": Uuid::new_v4(),
        "target_address": "198.51.100.1",
        "group_name": "source-group",
        "is_deleted": false,
        "created_at": "2026-01-01T00:00:00",
        "updated_at": "2026-01-01T00:00:00",
        "last_seen_at": "2026-01-01T00:00:00"
    }])
}

/// Successful multi-vault sync: a delta fetched from one source vault must be pushed to **every**
/// configured target, and `last_sync_at` only advances once all of them have accepted the batch.
#[tokio::test]
async fn multi_vault_sync_pushes_to_every_target_on_success() {
    let (conn, state, _master) = common::setup().await;

    let source_mock = MockServer::start().await;
    let target1_mock = MockServer::start().await;
    let target2_mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/ips"))
        .respond_with(ResponseTemplate::new(200).set_body_json(single_delta_record_response()))
        .mount(&source_mock)
        .await;

    for target in [&target1_mock, &target2_mock] {
        Mock::given(method("POST"))
            .and(path("/api/records/batch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "created": 1, "updated": 0, "restored": 0, "locked_skipped": 0, "soft_deleted": 0, "linked": 1
            })))
            .mount(target)
            .await;
    }

    let source_id = insert_vault(&conn, "source", &source_mock.uri()).await;
    let target1_id = insert_vault(&conn, "target1", &target1_mock.uri()).await;
    let target2_id = insert_vault(&conn, "target2", &target2_mock.uri()).await;
    let task_id = insert_task_multi(&conn, source_id, &[target1_id, target2_id]).await;

    let before = vault_sync_task::Entity::find_by_id(task_id).one(&conn).await.unwrap().unwrap();
    assert!(before.last_sync_at.is_none());
    let job_start = Utc::now();

    let summary = simply_ip_sync::jobs::vault_sync::run(&state, task_id).await.expect("job runs");
    assert_eq!(summary.status, "SUCCESS");
    assert_eq!(summary.chunks_sent, 2, "one chunk must be sent to each of the two targets");

    let target1_received = target1_mock.received_requests().await.expect("recording enabled");
    let target2_received = target2_mock.received_requests().await.expect("recording enabled");
    assert_eq!(target1_received.len(), 1, "target 1 must receive exactly one batch");
    assert_eq!(target2_received.len(), 1, "target 2 must receive exactly one batch");

    for received in [&target1_received[0], &target2_received[0]] {
        let signature = received.headers.get("X-Signature-256").expect("signature header present");
        assert!(signature.to_str().expect("utf8").starts_with("sha256="), "must carry a CANONICAL_V1 signature");
        let body: serde_json::Value = serde_json::from_slice(&received.body).expect("json body");
        assert_eq!(body["group_name"], serde_json::json!("target-group"));
    }

    let after = vault_sync_task::Entity::find_by_id(task_id).one(&conn).await.unwrap().unwrap();
    let last_sync_at = after.last_sync_at.expect("last_sync_at must advance once every target succeeds");
    assert!(last_sync_at >= job_start, "last_sync_at must be set to (at least) the job's own start time");
}

/// Partial failure across multiple targets: one target accepting the batch while another fails
/// must be recorded as `PARTIAL` (not `SUCCESS`, not silently dropped), and `last_sync_at` must
/// not advance — a subsequent run has to retry the full delta against the failed target, and
/// advancing the high-water mark here would permanently lose the records that never arrived.
#[tokio::test]
async fn multi_vault_sync_reports_partial_and_withholds_last_sync_at_when_one_target_fails() {
    let (conn, state, _master) = common::setup().await;

    let source_mock = MockServer::start().await;
    let healthy_target_mock = MockServer::start().await;
    let failing_target_mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/ips"))
        .respond_with(ResponseTemplate::new(200).set_body_json(single_delta_record_response()))
        .mount(&source_mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/records/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "created": 1, "updated": 0, "restored": 0, "locked_skipped": 0, "soft_deleted": 0, "linked": 1
        })))
        .mount(&healthy_target_mock)
        .await;
    // Simulate one target being unreachable / overloaded (HTTP 413, "payload too large" — a
    // realistic failure mode for a batch endpoint, distinct from a generic 500).
    Mock::given(method("POST"))
        .and(path("/api/records/batch"))
        .respond_with(ResponseTemplate::new(413))
        .mount(&failing_target_mock)
        .await;

    let source_id = insert_vault(&conn, "source", &source_mock.uri()).await;
    let healthy_id = insert_vault(&conn, "healthy-target", &healthy_target_mock.uri()).await;
    let failing_id = insert_vault(&conn, "failing-target", &failing_target_mock.uri()).await;
    let task_id = insert_task_multi(&conn, source_id, &[healthy_id, failing_id]).await;

    let summary = simply_ip_sync::jobs::vault_sync::run(&state, task_id).await.expect("job runs");
    assert_eq!(summary.status, "PARTIAL", "one success + one failure must report PARTIAL, not SUCCESS or FAILED");
    assert!(summary.error_message.is_some(), "the failing target's error must be captured");

    // Persisted to sync_logs, not just returned in the trigger response.
    let logs = simply_ip_sync::entities::sync_log::Entity::find().all(&conn).await.expect("query logs");
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].status, "PARTIAL");
    assert_eq!(logs[0].job_id, task_id);

    let after = vault_sync_task::Entity::find_by_id(task_id).one(&conn).await.unwrap().unwrap();
    assert!(after.last_sync_at.is_none(), "a partial delivery must not advance the high-water mark either");

    // The healthy target still received its batch even though its sibling failed — a partial
    // failure on one target must not prevent delivery to the others.
    let healthy_received = healthy_target_mock.received_requests().await.expect("recording enabled");
    assert_eq!(healthy_received.len(), 1, "the healthy target must still have received its batch");
}

#[tokio::test]
async fn tombstones_propagate_and_last_sync_at_advances_on_success() {
    let (conn, state, _master) = common::setup().await;

    let source_mock = MockServer::start().await;
    let target_mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/ips"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "id": Uuid::new_v4(),
                "target_address": "198.51.100.1",
                "group_name": "source-group",
                "is_deleted": false,
                "created_at": "2026-01-01T00:00:00",
                "updated_at": "2026-01-01T00:00:00",
                "last_seen_at": "2026-01-01T00:00:00"
            },
            {
                "id": Uuid::new_v4(),
                "target_address": "198.51.100.2",
                "group_name": "source-group",
                "is_deleted": true,
                "deleted_at": "2026-01-02T00:00:00",
                "created_at": "2026-01-01T00:00:00",
                "updated_at": "2026-01-02T00:00:00",
                "last_seen_at": "2026-01-01T00:00:00"
            }
        ])))
        .mount(&source_mock)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/records/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "created": 1, "updated": 0, "restored": 0, "locked_skipped": 0, "soft_deleted": 1, "linked": 2
        })))
        .mount(&target_mock)
        .await;

    let source_id = insert_vault(&conn, "source", &source_mock.uri()).await;
    let target_id = insert_vault(&conn, "target", &target_mock.uri()).await;
    let task_id = insert_task(&conn, source_id, target_id).await;

    let summary = simply_ip_sync::jobs::vault_sync::run(&state, task_id).await.expect("job runs");
    assert_eq!(summary.status, "SUCCESS");
    assert_eq!(summary.items_processed, 2);
    assert_eq!(summary.chunks_sent, 1);

    // The pushed batch must carry the tombstone through: is_deleted / deleted_at preserved.
    let received = target_mock.received_requests().await.expect("recording enabled");
    assert_eq!(received.len(), 1);
    let sent_body: serde_json::Value = serde_json::from_slice(&received[0].body).expect("json body");
    let records = sent_body["records"].as_array().expect("records array");
    assert_eq!(records.len(), 2);
    let tombstone = records.iter().find(|r| r["target_address"] == "198.51.100.2").expect("tombstone present");
    assert_eq!(tombstone["is_deleted"], serde_json::json!(true));
    assert!(tombstone["deleted_at"].is_string(), "deleted_at must survive replication");

    // last_sync_at only advances once every target has succeeded.
    let updated_task = vault_sync_task::Entity::find_by_id(task_id).one(&conn).await.unwrap().unwrap();
    assert!(updated_task.last_sync_at.is_some());
}

#[tokio::test]
async fn last_sync_at_does_not_advance_when_a_target_fails() {
    let (conn, state, _master) = common::setup().await;

    let source_mock = MockServer::start().await;
    let target_mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/ips"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([{
            "id": Uuid::new_v4(),
            "target_address": "198.51.100.1",
            "group_name": "source-group",
            "is_deleted": false,
            "created_at": "2026-01-01T00:00:00",
            "updated_at": "2026-01-01T00:00:00",
            "last_seen_at": "2026-01-01T00:00:00"
        }])))
        .mount(&source_mock)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/records/batch"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&target_mock)
        .await;

    let source_id = insert_vault(&conn, "source", &source_mock.uri()).await;
    let target_id = insert_vault(&conn, "target", &target_mock.uri()).await;
    let task_id = insert_task(&conn, source_id, target_id).await;

    let summary = simply_ip_sync::jobs::vault_sync::run(&state, task_id).await.expect("job runs");
    assert_eq!(summary.status, "FAILED");

    let updated_task = vault_sync_task::Entity::find_by_id(task_id).one(&conn).await.unwrap().unwrap();
    assert!(updated_task.last_sync_at.is_none(), "a failed delivery must not advance the high-water mark");
}
