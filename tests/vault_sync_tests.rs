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

/// Task 2: a failure on chunk 2 of a target's own 3-chunk push sequence — *after* chunk 1 already
/// landed — must stop that target's sequence immediately (chunk 3 is never attempted), the overall
/// job must report `PARTIAL` (one target, `good_target`, fully succeeds; the other,
/// `bad_target`, partially fails), and `last_sync_at` must remain withheld so the next scheduled
/// run re-fetches and re-pushes the *entire* delta rather than skipping what `bad_target` already
/// (partially) received. `vault_sync_tasks` only ever pushes in `upsert` mode (see
/// `AGENT.MD` §3.B and `SCHEMA.MD`'s `vault_sync_tasks.mode` column) — a `full_replace` variant of
/// this exact scenario lives in `tests/external_ingestion_tests.rs`, the pipeline that actually
/// supports that mode.
#[tokio::test]
async fn mid_run_chunk_failure_stops_further_chunks_and_withholds_last_sync_at() {
    let (conn, state, _master) = common::setup().await;

    const TOTAL_RECORDS: u32 = 12_000;

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

    let good_target_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/records/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "created": 1, "updated": 0, "restored": 0, "locked_skipped": 0, "soft_deleted": 0, "linked": 1
        })))
        .mount(&good_target_mock)
        .await;

    let bad_post_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = bad_post_count.clone();
    let bad_target_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/records/batch"))
        .respond_with(move |_req: &wiremock::Request| {
            let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                // Chunk 1: succeeds, same as every request to good_target_mock.
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "created": 1, "updated": 0, "restored": 0, "locked_skipped": 0, "soft_deleted": 0, "linked": 1
                }))
            } else {
                // Chunk 2: a fatal server error. If chunk 3 were ever sent it would land here too
                // (still failing) — the request-count assertion below is what actually proves
                // chunk 3 was never attempted, not just that it would have failed if it had been.
                ResponseTemplate::new(500)
            }
        })
        .mount(&bad_target_mock)
        .await;

    let source_id = insert_vault(&conn, "source", &source_mock.uri()).await;
    let good_target_id = insert_vault(&conn, "good-target", &good_target_mock.uri()).await;
    let bad_target_id = insert_vault(&conn, "bad-target", &bad_target_mock.uri()).await;
    let task_id = insert_task_multi(&conn, source_id, &[good_target_id, bad_target_id]).await;

    let summary = simply_ip_sync::jobs::vault_sync::run(&state, task_id).await.expect("job runs");

    assert_eq!(
        summary.status, "PARTIAL",
        "one target fully succeeding and the other partially failing must report PARTIAL, not SUCCESS or FAILED"
    );
    assert_eq!(
        summary.chunks_sent, 4,
        "good_target's 3 successful chunks + bad_target's 1 successful chunk (before it failed on chunk 2) = 4"
    );

    let good_requests = good_target_mock.received_requests().await.expect("recording enabled");
    assert_eq!(good_requests.len(), 3, "good_target must still receive its full 3-chunk sequence regardless of bad_target's failure");

    let bad_requests = bad_target_mock.received_requests().await.expect("recording enabled");
    assert_eq!(
        bad_requests.len(), 2,
        "bad_target must receive exactly chunk 1 (succeeded) + chunk 2 (failed) — chunk 3 must never be attempted once chunk 2 failed"
    );

    let task = vault_sync_task::Entity::find_by_id(task_id).one(&conn).await.expect("query").expect("task exists");
    assert!(
        task.last_sync_at.is_none(),
        "last_sync_at must remain withheld after a mid-run failure, so the next scheduled run re-fetches and \
         re-pushes the entire delta rather than skipping what bad_target only partially received"
    );
}

// =============================================================================================
// High-volume, two-vault convergence scenario
//
// Everything above this line drives *stateless* `wiremock` stubs: every response is a fixture, so
// those tests can prove what the engine asked for (page count, chunk count, query string) but not
// what the target ended up holding. The tests below drive `common::MockVault`, which keeps a real
// record store behind the same two endpoints, so the assertions are about **convergence** —
// distinct record counts, dedup on the canonical address, tombstone flags, and an untouched
// sibling group.
// =============================================================================================

/// Deterministic address for `index` inside `10.<block>.0.0/16`: `10.<block>.<index/256>.<index%256>`.
///
/// Index 1 → `10.<block>.0.1`, index 1000 → `10.<block>.3.232`, index 1524 → `10.<block>.5.244`.
fn block_ip(block: u32, index: u32) -> String {
    format!("10.{block}.{}.{}", index / 256, index % 256)
}

/// Inclusive index range as addresses in `10.<block>.0.0/16`.
fn block_range(block: u32, from: u32, to: u32) -> Vec<String> {
    (from..=to).map(|i| block_ip(block, i)).collect()
}

const ALPHA_BLOCK: u32 = 0;
const BETA_BLOCK: u32 = 1;

/// Vault A holds indices 1..=1000 in each group.
const A_FIRST: u32 = 1;
const A_LAST: u32 = 1_000;
/// Vault B's overlap with A: indices 501..=1000 (`10.x.1.245` … `10.x.3.232`), 500 addresses.
const OVERLAP_FIRST: u32 = 501;
const OVERLAP_LAST: u32 = 1_000;
/// Vault B's own unique block: indices 1025..=1524 (`10.x.4.1` … `10.x.5.244`), 500 addresses.
const B_UNIQUE_FIRST: u32 = 1_025;
const B_UNIQUE_LAST: u32 = 1_524;
/// Records added to Vault A between the two sync passes: indices 1525..=1624, 100 addresses,
/// deliberately past B's unique block so they are genuinely new to the target.
const ADDED_FIRST: u32 = 1_525;
const ADDED_LAST: u32 = 1_624;
/// Records soft-deleted on Vault A between the two passes: indices 1..=200, all of which reached
/// Vault B in the first pass, so the tombstones have something to land on.
const DELETED_FIRST: u32 = 1;
const DELETED_LAST: u32 = 200;

/// Builds the two-vault fixture described above and returns `(vault_a, vault_b, seeded_at)`.
///
/// `seeded_at` is deliberately an hour in the past: the second sync pass filters on
/// `since = last_sync_at`, so the untouched bulk of the dataset has to sit clearly *outside* that
/// window for "only the changed records come back" to mean anything. Seeded at "now", every record
/// would land on the boundary and the differential assertion would pass for the wrong reason.
async fn build_two_vault_fixture() -> (common::MockVault, common::MockVault, chrono::DateTime<Utc>) {
    let vault_a = common::MockVault::start().await;
    let vault_b = common::MockVault::start().await;
    let seeded_at = Utc::now() - chrono::Duration::hours(1);

    // Vault A: 1,000 records in each of two groups.
    vault_a.seed("group_alpha", block_range(ALPHA_BLOCK, A_FIRST, A_LAST), seeded_at);
    vault_a.seed("group_beta", block_range(BETA_BLOCK, A_FIRST, A_LAST), seeded_at);

    // Vault B: 1,000 records in each group — half overlapping A, half unique to B.
    for (group, block) in [("group_alpha", ALPHA_BLOCK), ("group_beta", BETA_BLOCK)] {
        vault_b.seed(group, block_range(block, OVERLAP_FIRST, OVERLAP_LAST), seeded_at);
        vault_b.seed(group, block_range(block, B_UNIQUE_FIRST, B_UNIQUE_LAST), seeded_at);
    }

    assert_eq!(vault_a.record_count("group_alpha"), 1_000, "fixture: Vault A group_alpha");
    assert_eq!(vault_a.record_count("group_beta"), 1_000, "fixture: Vault A group_beta");
    assert_eq!(vault_b.record_count("group_alpha"), 1_000, "fixture: Vault B group_alpha");
    assert_eq!(vault_b.record_count("group_beta"), 1_000, "fixture: Vault B group_beta");

    (vault_a, vault_b, seeded_at)
}

/// Wires a sync task replicating `group_alpha` from `source` to `target`, same group name on both
/// sides.
async fn insert_alpha_task(conn: &sea_orm::DatabaseConnection, source_vault_id: Uuid, target_vault_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let now = Utc::now();
    vault_sync_task::ActiveModel {
        id: Set(id),
        name: Set("alpha-replication".to_owned()),
        source_vault_id: Set(source_vault_id),
        source_group_name: Set("group_alpha".to_owned()),
        target_group_name: Set("group_alpha".to_owned()),
        cron_schedule: Set("0 0 * * *".to_owned()),
        last_sync_at: Set(None),
        mode: Set("upsert".to_owned()),
        is_active: Set(true),
        owner_key_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(conn)
    .await
    .expect("insert task");
    vault_sync_task_target::ActiveModel {
        vault_sync_task_id: Set(id),
        target_vault_id: Set(target_vault_id),
        target_group_name: Set(None),
    }
    .insert(conn)
    .await
    .expect("insert task target");
    id
}

/// High-volume replication between two vaults holding partially overlapping datasets, then an
/// incremental second pass carrying additions and tombstones.
///
/// # Pass 1 — full replication into a partially-populated target
///
/// Vault A's `group_alpha` (1,000 records) replicates into Vault B's `group_alpha`, which already
/// holds 1,000 records of its own: 500 shared with A and 500 A has never seen. The target must
/// converge on **1,500 distinct records** — the 500 overlapping addresses updating in place rather
/// than doubling — and B's `group_beta` must be untouched throughout.
///
/// # Pass 2 — differential delivery
///
/// 200 of A's `group_alpha` records are soft-deleted and 100 new ones appear. The second run filters
/// on `since = last_sync_at`, so exactly those 300 must come back — not the 800 that did not change,
/// and not the full 1,100. The 200 tombstones must propagate as `is_deleted = true` onto rows that
/// already exist in B.
///
/// # On pagination
///
/// At 1,000 records the client's 5,000-record page size means the delta is one page, and this test
/// asserts exactly that — one `GET /api/ips` carrying `limit=5000&offset=0`, correct
/// `group_name`/`include_deleted`, and a fetch loop that consumed the whole result. Multi-page
/// paging (15,001 records across 4 pages, including the short final page) is exercised separately
/// by `source_vault_delta_spanning_multiple_pages_is_fetched_completely` above; asserting a page
/// boundary here that the engine does not actually cross would be asserting a fiction.
#[tokio::test]
async fn test_inter_vault_sync_high_volume_partial_overlap() {
    let (conn, state, _master) = common::setup().await;
    let (vault_a, vault_b, seeded_at) = build_two_vault_fixture().await;

    let source_id = insert_vault(&conn, "vault-a", &vault_a.uri()).await;
    let target_id = insert_vault(&conn, "vault-b", &vault_b.uri()).await;
    let task_id = insert_alpha_task(&conn, source_id, target_id).await;

    // ── Pass 1 ────────────────────────────────────────────────────────────────────────────────
    let summary = simply_ip_sync::jobs::vault_sync::run(&state, task_id).await.expect("first pass runs");

    assert_eq!(summary.status, "SUCCESS", "error: {:?}", summary.error_message);
    assert_eq!(summary.items_processed, 1_000, "the full source group must be fetched");
    assert_eq!(summary.chunks_sent, 1, "1,000 records at a 5,000-record chunk size is a single batch");

    // The fetch side: one correctly-parameterised page (see the doc comment on why one).
    let gets = vault_a.gets();
    assert_eq!(gets.len(), 1, "1,000 records fits in one 5,000-record page, so exactly one GET is correct");
    let first_get = &gets[0];
    assert_eq!(first_get.group_name.as_deref(), Some("group_alpha"));
    assert_eq!(first_get.include_deleted.as_deref(), Some("true"), "tombstones must be requested every run");
    assert_eq!(first_get.limit, Some(5_000), "the client must page with an explicit limit");
    assert_eq!(first_get.offset, Some(0));
    assert_eq!(first_get.since, None, "the first run has no high-water mark yet, so it must fetch everything");
    assert_eq!(first_get.returned, 1_000);

    // The push side: one upsert batch carrying the whole delta, with no address sent twice.
    let batches = vault_b.batches();
    assert_eq!(batches.len(), 1, "one fetched chunk means one batch request");
    assert_eq!(batches[0].group_name, "group_alpha");
    assert_eq!(batches[0].mode, "upsert", "inter-vault sync must never send full_replace — a delta is not a full set");
    assert_eq!(batches[0].records, 1_000);
    let mut pushed_sorted = batches[0].addresses.clone();
    pushed_sorted.sort();
    let mut pushed_unique = pushed_sorted.clone();
    pushed_unique.dedup();
    assert_eq!(
        pushed_sorted.len(),
        pushed_unique.len(),
        "the engine must not send the same canonical address twice within a batch"
    );

    // ── Convergence ───────────────────────────────────────────────────────────────────────────
    assert_eq!(
        vault_b.record_count("group_alpha"),
        1_500,
        "500 pre-existing B-only + 500 overlapping (updated in place, not duplicated) + 500 newly \
         pushed from A = 1,500 distinct records"
    );
    assert!(
        vault_b.deleted_addresses("group_alpha").is_empty(),
        "an upsert pass must never tombstone anything"
    );

    // Every address from either side is present exactly once, and nothing else is.
    let converged = vault_b.records("group_alpha");
    let mut expected: Vec<String> = block_range(ALPHA_BLOCK, A_FIRST, A_LAST);
    expected.extend(block_range(ALPHA_BLOCK, B_UNIQUE_FIRST, B_UNIQUE_LAST));
    expected.sort();
    expected.dedup();
    assert_eq!(expected.len(), 1_500, "fixture arithmetic: the union of both datasets is 1,500 addresses");
    let mut actual: Vec<String> = converged.keys().cloned().collect();
    actual.sort();
    assert_eq!(actual, expected, "the target must hold exactly the union of both datasets");

    // The 500 addresses both vaults already had must have been *updated*, not re-created: their
    // `created_at` still carries B's original seeding stamp.
    let seeded_naive = seeded_at.naive_utc();
    for address in block_range(ALPHA_BLOCK, OVERLAP_FIRST, OVERLAP_LAST) {
        let record = converged.get(&address).unwrap_or_else(|| panic!("{address} missing from the target"));
        assert_eq!(
            record.created_at, seeded_naive,
            "{address} existed on B before the sync; an upsert must update it in place, not replace the row"
        );
    }

    // The group nobody asked to replicate must be byte-for-byte untouched.
    assert_eq!(vault_b.record_count("group_beta"), 1_000, "group_beta must not gain records from an alpha-only task");
    assert!(vault_b.deleted_addresses("group_beta").is_empty(), "group_beta must not gain tombstones either");
    assert!(
        vault_b.batches().iter().all(|b| b.group_name == "group_alpha"),
        "no batch may be addressed to any group other than the task's target group"
    );

    let after_pass_one = vault_sync_task::Entity::find_by_id(task_id).one(&conn).await.unwrap().unwrap();
    let first_high_water = after_pass_one.last_sync_at.expect("a fully successful pass must advance last_sync_at");

    // ── Pass 2: mutate the source, then sync differentially ───────────────────────────────────
    let mutated_at = Utc::now();
    let deleted = block_range(ALPHA_BLOCK, DELETED_FIRST, DELETED_LAST);
    vault_a.soft_delete("group_alpha", &deleted, mutated_at);
    vault_a.seed("group_alpha", block_range(ALPHA_BLOCK, ADDED_FIRST, ADDED_LAST), mutated_at);

    let summary2 = simply_ip_sync::jobs::vault_sync::run(&state, task_id).await.expect("second pass runs");

    assert_eq!(summary2.status, "SUCCESS", "error: {:?}", summary2.error_message);
    assert_eq!(
        summary2.items_processed, 300,
        "the differential pass must fetch exactly the 200 tombstoned + 100 added records — not the \
         800 that did not change, and not all 1,100"
    );

    let gets2 = vault_a.gets();
    assert_eq!(gets2.len(), 2, "the second pass adds exactly one more paged fetch");
    let second_get = &gets2[1];
    assert_eq!(
        second_get.since.as_deref(),
        Some(first_high_water.timestamp().to_string().as_str()),
        "the second pass must filter on the high-water mark the first pass recorded"
    );
    assert_eq!(
        second_get.include_deleted.as_deref(),
        Some("true"),
        "without include_deleted the 200 tombstones would be invisible and the deletions would never replicate"
    );
    assert_eq!(second_get.returned, 300);

    // Tombstone delivery: the second batch must carry all 200 deletions, flagged.
    let batches2 = vault_b.batches();
    assert_eq!(batches2.len(), 2, "one delta chunk per pass");
    let delta_batch = &batches2[1];
    assert_eq!(delta_batch.records, 300);
    let tombstoned_in_batch: Vec<&String> = delta_batch
        .addresses
        .iter()
        .zip(&delta_batch.tombstones)
        .filter(|(_, is_deleted)| **is_deleted)
        .map(|(address, _)| address)
        .collect();
    assert_eq!(tombstoned_in_batch.len(), 200, "all 200 deletions must be pushed as tombstones, not silently dropped");

    // ── Convergence, second pass ──────────────────────────────────────────────────────────────
    assert_eq!(
        vault_b.record_count("group_alpha"),
        1_600,
        "1,500 after the first pass + 100 newly added on the source = 1,600 distinct records; the 200 \
         deletions tombstone existing rows rather than removing them"
    );

    let mut b_deleted = vault_b.deleted_addresses("group_alpha");
    b_deleted.sort();
    let mut expected_deleted = deleted.clone();
    expected_deleted.sort();
    assert_eq!(b_deleted, expected_deleted, "exactly the 200 addresses deleted on the source must be tombstoned on the target");

    for address in block_range(ALPHA_BLOCK, ADDED_FIRST, ADDED_LAST) {
        let records = vault_b.records("group_alpha");
        let record = records.get(&address).unwrap_or_else(|| panic!("newly added {address} never reached the target"));
        assert!(!record.is_deleted, "{address} was added, not deleted");
    }

    assert_eq!(
        vault_b.live_addresses("group_alpha").len(),
        1_400,
        "1,600 total less the 200 tombstoned leaves 1,400 live records"
    );

    // Still untouched, two passes in.
    assert_eq!(vault_b.record_count("group_beta"), 1_000, "group_beta must survive both passes unchanged");
    assert!(vault_b.deleted_addresses("group_beta").is_empty());

    let after_pass_two = vault_sync_task::Entity::find_by_id(task_id).one(&conn).await.unwrap().unwrap();
    let second_high_water = after_pass_two.last_sync_at.expect("the second pass must also advance last_sync_at");
    assert!(
        second_high_water > first_high_water,
        "last_sync_at must move forward to this execution's start ({second_high_water} vs {first_high_water})"
    );
}
