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

/// A task-target with an explicit `target_group_name` override (`vault_sync_task_targets`, per
/// `SCHEMA.MD`'s junction table) must receive the batch under that group, while a sibling target
/// with no override falls back to the task's own `target_group_name`.
#[tokio::test]
async fn per_target_group_name_override_is_honored_independently_of_the_default() {
    let (conn, state, _master) = common::setup().await;

    let source_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/ips"))
        .respond_with(ResponseTemplate::new(200).set_body_json(single_delta_record_response()))
        .mount(&source_mock)
        .await;

    let default_target_mock = MockServer::start().await;
    let override_target_mock = MockServer::start().await;
    for mock in [&default_target_mock, &override_target_mock] {
        Mock::given(method("POST"))
            .and(path("/api/records/batch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "created": 1, "updated": 0, "restored": 0, "locked_skipped": 0, "soft_deleted": 0, "linked": 1
            })))
            .mount(mock)
            .await;
    }

    let source_id = insert_vault(&conn, "source", &source_mock.uri()).await;
    let default_target_id = insert_vault(&conn, "default-target", &default_target_mock.uri()).await;
    let override_target_id = insert_vault(&conn, "override-target", &override_target_mock.uri()).await;

    let task_id = Uuid::new_v4();
    let now = Utc::now();
    let task = vault_sync_task::ActiveModel {
        id: Set(task_id),
        name: Set(format!("override-task-{task_id}")),
        source_vault_id: Set(source_id),
        source_group_name: Set("source-group".to_owned()),
        target_group_name: Set("DEFAULT_GROUP".to_owned()),
        cron_schedule: Set("0 0 * * *".to_owned()),
        last_sync_at: Set(None),
        mode: Set("upsert".to_owned()),
        is_active: Set(true),
        owner_key_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    task.insert(&conn).await.expect("insert task");
    vault_sync_task_target::ActiveModel {
        vault_sync_task_id: Set(task_id),
        target_vault_id: Set(default_target_id),
        target_group_name: Set(None),
    }
    .insert(&conn)
    .await
    .expect("insert default target");
    vault_sync_task_target::ActiveModel {
        vault_sync_task_id: Set(task_id),
        target_vault_id: Set(override_target_id),
        target_group_name: Set(Some("OVERRIDDEN_GROUP".to_owned())),
    }
    .insert(&conn)
    .await
    .expect("insert override target");

    let summary = simply_ip_sync::jobs::vault_sync::run(&state, task_id).await.expect("job runs");
    assert_eq!(summary.status, "SUCCESS");

    let default_received = default_target_mock.received_requests().await.expect("recording enabled");
    let default_body: serde_json::Value = serde_json::from_slice(&default_received[0].body).expect("json");
    assert_eq!(default_body["group_name"], serde_json::json!("DEFAULT_GROUP"), "no override falls back to the task's default target_group_name");

    let override_received = override_target_mock.received_requests().await.expect("recording enabled");
    let override_body: serde_json::Value = serde_json::from_slice(&override_received[0].body).expect("json");
    assert_eq!(
        override_body["group_name"],
        serde_json::json!("OVERRIDDEN_GROUP"),
        "an explicit per-target override must win over the task's default target_group_name"
    );
}

/// Task 3: a target vault that accepts the connection but never responds (or responds far slower
/// than the configured timeout) to `POST /api/records/batch` must be aborted on the client's own
/// schedule, not left to hang a Tokio worker — the job must complete quickly and report `FAILED`,
/// and `last_sync_at` must not advance. Mirrors
/// `external_ingestion_tests.rs::slow_target_vault_is_aborted_by_the_client_timeout_not_left_hanging`
/// for the inter-vault push path specifically (the two pipelines share `client::post_batch`, but
/// each has its own job-level status/`sync_logs`/high-water-mark bookkeeping worth pinning).
#[tokio::test]
async fn slow_target_vault_is_aborted_and_last_sync_at_is_withheld() {
    let (conn, mut state, _master) = common::setup().await;

    let source_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/ips"))
        .respond_with(ResponseTemplate::new(200).set_body_json(single_delta_record_response()))
        .mount(&source_mock)
        .await;

    let slow_target_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/records/batch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "created": 1, "updated": 0, "restored": 0, "locked_skipped": 0, "soft_deleted": 0, "linked": 1
                }))
                .set_delay(std::time::Duration::from_secs(5)),
        )
        .mount(&slow_target_mock)
        .await;

    // Hermetic short timeout on this test's own client — see client::build_http_client's doc
    // comment for why this overrides AppState.http directly rather than the env-var-backed cache.
    state.http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_millis(300))
        .build()
        .expect("client builds");

    let source_id = insert_vault(&conn, "source", &source_mock.uri()).await;
    let target_id = insert_vault(&conn, "slow-target", &slow_target_mock.uri()).await;
    let task_id = insert_task(&conn, source_id, target_id).await;

    let start = std::time::Instant::now();
    let summary = simply_ip_sync::jobs::vault_sync::run(&state, task_id).await.expect("job completes rather than hanging");
    let elapsed = start.elapsed();

    assert_eq!(summary.status, "FAILED");
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "the job must abort on the client's own timeout, not wait out the mock's 5s delay; took {elapsed:?}"
    );

    let updated_task = vault_sync_task::Entity::find_by_id(task_id).one(&conn).await.unwrap().unwrap();
    assert!(updated_task.last_sync_at.is_none(), "a timed-out delivery must not advance the high-water mark");
}

/// Synthesizes a deterministic, valid IPv4 address for delta-record index `i`, staying within
/// `10.0.0.0/8` (comfortably covers the tens-of-thousands of addresses these pagination tests
/// need without colliding).
fn synth_ip(i: u32) -> String {
    format!("10.0.{}.{}", (i / 256) % 256, i % 256)
}

/// Task 1: a source vault holding more delta records than a single page must be paged through
/// completely (`limit`/`offset`) before delivery — not just the first page silently accepted as
/// "the whole delta". 15,001 records spans exactly 4 pages at the client's 5,000-record page size
/// (5000 + 5000 + 5000 + 1), chosen so the boundary itself (a final short page) is exercised, not
/// just a round multiple.
#[tokio::test]
async fn source_vault_delta_spanning_multiple_pages_is_fetched_completely() {
    let (conn, state, _master) = common::setup().await;

    const TOTAL_RECORDS: u32 = 15_001;

    let source_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/ips"))
        .respond_with(move |req: &wiremock::Request| {
            let offset: u32 = req
                .url
                .query_pairs()
                .find(|(k, _)| k == "offset")
                .and_then(|(_, v)| v.parse().ok())
                .unwrap_or(0);
            let limit: u32 = req
                .url
                .query_pairs()
                .find(|(k, _)| k == "limit")
                .and_then(|(_, v)| v.parse().ok())
                .unwrap_or(5000);
            let page_len = limit.min(TOTAL_RECORDS.saturating_sub(offset));
            let page: Vec<serde_json::Value> = (0..page_len)
                .map(|i| {
                    let idx = offset + i;
                    serde_json::json!({
                        "id": uuid::Uuid::new_v4(),
                        "target_address": synth_ip(idx),
                        "group_name": "source-group",
                        "is_deleted": false,
                        "created_at": "2026-01-01T00:00:00",
                        "updated_at": "2026-01-01T00:00:00",
                        "last_seen_at": "2026-01-01T00:00:00"
                    })
                })
                .collect();
            ResponseTemplate::new(200).set_body_json(page)
        })
        .mount(&source_mock)
        .await;

    let target_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/records/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "created": 1, "updated": 0, "restored": 0, "locked_skipped": 0, "soft_deleted": 0, "linked": 1
        })))
        .mount(&target_mock)
        .await;

    let source_id = insert_vault(&conn, "paginated-source", &source_mock.uri()).await;
    let target_id = insert_vault(&conn, "target", &target_mock.uri()).await;
    let task_id = insert_task(&conn, source_id, target_id).await;

    let summary = simply_ip_sync::jobs::vault_sync::run(&state, task_id).await.expect("job runs");

    assert_eq!(summary.status, "SUCCESS");
    assert_eq!(
        summary.items_processed, TOTAL_RECORDS as i32,
        "every record across every page must be fetched, not just the first page"
    );
    assert_eq!(summary.chunks_sent, 4, "15,001 records at a 5,000-record push chunk size means 4 batch requests");

    let source_requests = source_mock.received_requests().await.expect("recording enabled");
    assert_eq!(source_requests.len(), 4, "4 pages of 5000+5000+5000+1 means exactly 4 GET /api/ips calls");

    let target_requests = target_mock.received_requests().await.expect("recording enabled");
    assert_eq!(target_requests.len(), 4, "the fetched delta must be pushed in the same 4 chunks it was assembled from");
    let total_pushed: usize = target_requests
        .iter()
        .map(|req| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).expect("json body");
            body["records"].as_array().expect("records array").len()
        })
        .sum();
    assert_eq!(total_pushed, TOTAL_RECORDS as usize, "the full paginated delta, not just one page, must reach the target");

    let updated_task = vault_sync_task::Entity::find_by_id(task_id).one(&conn).await.unwrap().unwrap();
    assert!(updated_task.last_sync_at.is_some(), "a fully successful multi-page sync must still advance last_sync_at");
}
