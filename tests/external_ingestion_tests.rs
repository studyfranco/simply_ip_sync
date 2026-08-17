//! `jobs::external_ingestion` behavior beyond plain fetch→parse→push: per-target
//! `target_group_name` overrides, zero-item feeds masquerading as a successful fetch (an HTML
//! error/captive-portal page served with `200 OK`), transparent response decompression, slow/hung
//! remote handling, and the concurrent-trigger guard.

mod common;

use std::io::Write;
use std::time::Duration;

use chrono::Utc;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use simply_ip_sync::entities::{external_source, external_source_vault_target, vault_endpoint};
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

async fn insert_source(conn: &sea_orm::DatabaseConnection, source_url: &str, default_group: &str) -> Uuid {
    insert_source_with_mode(conn, source_url, default_group, "upsert").await
}

async fn insert_source_with_mode(
    conn: &sea_orm::DatabaseConnection,
    source_url: &str,
    default_group: &str,
    mode: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let now = Utc::now();
    let model = external_source::ActiveModel {
        id: Set(id),
        name: Set(format!("source-{id}")),
        source_url: Set(source_url.to_owned()),
        parser_type: Set("REGEX_LINE".to_owned()),
        parser_config_json: Set(None),
        cron_schedule: Set("0 0 * * *".to_owned()),
        target_group_name: Set(default_group.to_owned()),
        mode: Set(mode.to_owned()),
        is_active: Set(true),
        last_run_at: Set(None),
        owner_key_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    model.insert(conn).await.expect("insert source");
    id
}

async fn insert_target(
    conn: &sea_orm::DatabaseConnection,
    source_id: Uuid,
    vault_id: Uuid,
    group_override: Option<&str>,
) {
    let row = external_source_vault_target::ActiveModel {
        external_source_id: Set(source_id),
        vault_endpoint_id: Set(vault_id),
        target_group_name: Set(group_override.map(str::to_owned)),
    };
    row.insert(conn).await.expect("insert target");
}

fn batch_response() -> serde_json::Value {
    serde_json::json!({"created": 1, "updated": 0, "restored": 0, "locked_skipped": 0, "soft_deleted": 0, "linked": 1})
}

/// Task 1: a target with an explicit `target_group_name` override must receive the batch under
/// that group, while a sibling target with no override falls back to the source's own default.
#[tokio::test]
async fn per_target_group_name_override_is_honored_independently_of_the_default() {
    let (conn, state, _master) = common::setup().await;

    let feed_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/feed.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string("203.0.113.9\n"))
        .mount(&feed_mock)
        .await;

    let default_target_mock = MockServer::start().await;
    let override_target_mock = MockServer::start().await;
    for mock in [&default_target_mock, &override_target_mock] {
        Mock::given(method("POST"))
            .and(path("/api/records/batch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(batch_response()))
            .mount(mock)
            .await;
    }

    let source_id = insert_source(&conn, &format!("{}/feed.txt", feed_mock.uri()), "DEFAULT_GROUP").await;
    let default_vault_id = insert_vault(&conn, "default-target", &default_target_mock.uri()).await;
    let override_vault_id = insert_vault(&conn, "override-target", &override_target_mock.uri()).await;
    insert_target(&conn, source_id, default_vault_id, None).await;
    insert_target(&conn, source_id, override_vault_id, Some("OVERRIDDEN_GROUP")).await;

    let summary = simply_ip_sync::jobs::external_ingestion::run(&state, source_id).await.expect("job runs");
    assert_eq!(summary.status, "SUCCESS");

    let default_received = default_target_mock.received_requests().await.expect("recording enabled");
    assert_eq!(default_received.len(), 1);
    let default_body: serde_json::Value = serde_json::from_slice(&default_received[0].body).expect("json");
    assert_eq!(default_body["group_name"], serde_json::json!("DEFAULT_GROUP"), "no override falls back to the source's default group");

    let override_received = override_target_mock.received_requests().await.expect("recording enabled");
    assert_eq!(override_received.len(), 1);
    let override_body: serde_json::Value = serde_json::from_slice(&override_received[0].body).expect("json");
    assert_eq!(
        override_body["group_name"],
        serde_json::json!("OVERRIDDEN_GROUP"),
        "an explicit per-target override must win over the source's default group"
    );
}

fn synth_ip(i: u32) -> String {
    format!("10.{}.{}.{}", (i / 65536) % 256, (i / 256) % 256, i % 256)
}

/// Task 4: a `full_replace` source whose feed is large enough to need multiple chunks (12,000
/// records / `MAX_BATCH_SIZE` 5,000 = 3 chunks of 5000/5000/2000) must only mark the *first* chunk
/// as `full_replace` on the wire — chunks 2 and 3 of the same run must arrive as `upsert`, or
/// chunk 2 would read on the receiving vault as "delete everything chunk 2 didn't mention",
/// wiping out chunk 1's just-delivered records before chunk 3 even lands.
#[tokio::test]
async fn full_replace_source_only_marks_the_first_of_several_chunks_as_full_replace() {
    let (conn, state, _master) = common::setup().await;

    const TOTAL_RECORDS: u32 = 12_000;
    let feed_body: String = (0..TOTAL_RECORDS).map(synth_ip).collect::<Vec<_>>().join("\n");

    let feed_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/feed.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string(feed_body))
        .mount(&feed_mock)
        .await;

    let target_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/records/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(batch_response()))
        .mount(&target_mock)
        .await;

    let source_id = insert_source_with_mode(&conn, &format!("{}/feed.txt", feed_mock.uri()), "group", "full_replace").await;
    let vault_id = insert_vault(&conn, "full-replace-target", &target_mock.uri()).await;
    insert_target(&conn, source_id, vault_id, None).await;

    let summary = simply_ip_sync::jobs::external_ingestion::run(&state, source_id).await.expect("job runs");
    assert_eq!(summary.status, "SUCCESS");
    assert_eq!(summary.items_processed, TOTAL_RECORDS as i32, "every record from the feed must be processed, none dropped mid-chunking");
    assert_eq!(summary.chunks_sent, 3, "12,000 records at MAX_BATCH_SIZE=5,000 must split into exactly 3 chunks (5000/5000/2000)");

    let received = target_mock.received_requests().await.expect("recording enabled");
    assert_eq!(received.len(), 3);

    let mut total_delivered = 0usize;
    let mut modes = Vec::with_capacity(3);
    for req in &received {
        let body: serde_json::Value = serde_json::from_slice(&req.body).expect("json body");
        total_delivered += body["records"].as_array().expect("records array").len();
        modes.push(body["mode"].as_str().expect("mode field").to_owned());
    }
    assert_eq!(total_delivered, TOTAL_RECORDS as usize, "all 12,000 records must land on the target, none lost across chunks");
    assert_eq!(modes[0], "full_replace", "only the first chunk of the run may carry full_replace");
    assert_eq!(modes[1], "upsert", "chunk 2 must already be downgraded to upsert");
    assert_eq!(modes[2], "upsert", "chunk 3 must also be upsert, not just chunk 2");
}

/// Task 4: an HTTP `200 OK` carrying an HTML body (Cloudflare/WAF error page, captive portal,
/// a 404 page some hosts serve with a 200 status) must not panic `REGEX_LINE`, must extract zero
/// entries (HTML tags and prose are not IP-shaped), and must surface as `PARTIAL` in `sync_logs`
/// rather than a silent `SUCCESS` — see `jobs::external_ingestion`'s zero-items handling.
#[tokio::test]
async fn html_response_masquerading_as_200_yields_zero_items_and_partial_status_no_panic() {
    let (conn, state, _master) = common::setup().await;

    let html_body = r#"<!DOCTYPE html>
<html>
<head><title>Attention Required! | Cloudflare</title></head>
<body>
<div class="cf-error-details">
  <h1>Sorry, you have been blocked</h1>
  <p>You are unable to access this site.</p>
  <p>Ray ID: 8f2a1c9d4b3e7f10</p>
</div>
</body>
</html>"#;

    let feed_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/feed.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html_body))
        .mount(&feed_mock)
        .await;

    let source_id = insert_source(&conn, &format!("{}/feed.txt", feed_mock.uri()), "group").await;

    // No panic across the full pipeline is the primary assertion here — a panicking job would
    // unwind through `.await` and this test would fail with a panic message, not a clean assert.
    let summary = simply_ip_sync::jobs::external_ingestion::run(&state, source_id).await.expect("job runs without panicking");

    assert_eq!(summary.items_processed, 0, "an HTML error page must yield zero IP-shaped matches");
    assert_eq!(summary.status, "PARTIAL", "a zero-item successful fetch must be flagged, not silently SUCCESS");
    assert!(summary.error_message.is_some(), "the zero-items case must explain itself in sync_logs");

    let logs = simply_ip_sync::entities::sync_log::Entity::find().all(&conn).await.expect("query logs");
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].status, "PARTIAL");
    assert_eq!(logs[0].items_processed, 0);
}

/// The same HTML-masquerade scenario through `JSON_PATH` takes the *other* failure path: HTML is
/// not valid JSON, so this must be a hard parse error (`FAILED`), not a silent zero-item success —
/// confirming the two parser types fail in the way each one's own contract predicts.
#[tokio::test]
async fn html_response_via_json_path_parser_is_a_hard_parse_failure() {
    let (conn, state, _master) = common::setup().await;

    let feed_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/feed.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html><body>404 Not Found</body></html>"))
        .mount(&feed_mock)
        .await;

    let id = Uuid::new_v4();
    let now = Utc::now();
    let source = external_source::ActiveModel {
        id: Set(id),
        name: Set(format!("json-source-{id}")),
        source_url: Set(format!("{}/feed.json", feed_mock.uri())),
        parser_type: Set("JSON_PATH".to_owned()),
        parser_config_json: Set(Some(r#"{"ip_field":"ip"}"#.to_owned())),
        cron_schedule: Set("0 0 * * *".to_owned()),
        target_group_name: Set("group".to_owned()),
        mode: Set("upsert".to_owned()),
        is_active: Set(true),
        last_run_at: Set(None),
        owner_key_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    source.insert(&conn).await.expect("insert source");

    let summary = simply_ip_sync::jobs::external_ingestion::run(&state, id).await.expect("job runs without panicking");
    assert_eq!(summary.status, "FAILED");
    assert_eq!(summary.items_processed, 0);
    assert!(summary.error_message.is_some());
}

/// A feed server that gzip-compresses its response (common for CDN-fronted feeds) must be
/// transparently decompressed before parsing — without response decompression enabled, the
/// parser would receive opaque compressed bytes and (for `REGEX_LINE`) silently extract zero
/// entries, indistinguishable from a genuinely empty feed.
#[tokio::test]
async fn gzip_compressed_feed_response_is_transparently_decompressed() {
    let (conn, state, _master) = common::setup().await;

    let plain = b"198.51.100.20\n198.51.100.21\n";
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(plain).expect("write to gzip encoder");
    let compressed = encoder.finish().expect("finish gzip stream");

    let feed_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/feed.txt"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Encoding", "gzip")
                .set_body_bytes(compressed),
        )
        .mount(&feed_mock)
        .await;

    let source_id = insert_source(&conn, &format!("{}/feed.txt", feed_mock.uri()), "group").await;
    let summary = simply_ip_sync::jobs::external_ingestion::run(&state, source_id).await.expect("job runs");

    assert_eq!(summary.status, "SUCCESS");
    assert_eq!(summary.items_processed, 2, "both addresses must survive gzip decompression before parsing");
}

/// Task 3: a remote target that accepts the TCP connection but never responds (or responds far
/// slower than the configured timeout) must be aborted, not left to hang a Tokio worker
/// indefinitely — the job must complete (bounded by the client's own timeout, not the mock's
/// artificial delay) and report `FAILED` with an explanatory message.
#[tokio::test]
async fn slow_target_vault_is_aborted_by_the_client_timeout_not_left_hanging() {
    let (conn, mut state, _master) = common::setup().await;

    let feed_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/feed.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string("203.0.113.50\n"))
        .mount(&feed_mock)
        .await;

    let slow_target_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/records/batch"))
        // Responds, but only after a delay several times longer than the client's own timeout
        // below — proving the client gives up on its own schedule rather than waiting it out.
        .respond_with(ResponseTemplate::new(200).set_body_json(batch_response()).set_delay(Duration::from_secs(5)))
        .mount(&slow_target_mock)
        .await;

    // A short, test-local timeout — overriding `AppState.http` directly rather than the
    // process-wide `OUTBOUND_HTTP_TIMEOUT_SECS` cache, so this stays hermetic against other tests
    // running in the same process (see `client::build_http_client`'s doc comment).
    state.http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(300))
        .build()
        .expect("client builds");

    let source_id = insert_source(&conn, &format!("{}/feed.txt", feed_mock.uri()), "group").await;
    let target_vault_id = insert_vault(&conn, "slow-target", &slow_target_mock.uri()).await;
    insert_target(&conn, source_id, target_vault_id, None).await;

    let start = std::time::Instant::now();
    let summary = simply_ip_sync::jobs::external_ingestion::run(&state, source_id)
        .await
        .expect("job completes rather than hanging");
    let elapsed = start.elapsed();

    assert_eq!(summary.status, "FAILED", "a target that never responds in time must fail the job, not hang it");
    assert!(summary.error_message.is_some());
    assert!(
        elapsed < Duration::from_secs(2),
        "the job must abort on the client's own timeout (300ms), not wait out the mock's 5s delay; took {elapsed:?}"
    );
}

/// Task 6 (unit-level): [`simply_ip_sync::jobs::try_start_job`] refuses a second concurrent claim
/// on the same resource id, and releases the slot once the first guard drops — exercised directly
/// rather than through HTTP so the assertion is about the primitive itself, not timing-sensitive
/// concurrent request scheduling (covered separately, end-to-end, by `scripts/test_e2e.sh`).
#[test]
fn job_guard_refuses_concurrent_claims_on_the_same_id_and_releases_on_drop() {
    let running_jobs: simply_ip_sync::jobs::RunningJobs =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    let id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    let first = simply_ip_sync::jobs::try_start_job(&running_jobs, id);
    assert!(first.is_some(), "the first claim on a free id must succeed");

    let second = simply_ip_sync::jobs::try_start_job(&running_jobs, id);
    assert!(second.is_none(), "a second concurrent claim on the same id must be refused");

    let unrelated = simply_ip_sync::jobs::try_start_job(&running_jobs, other_id);
    assert!(unrelated.is_some(), "a different id must never be blocked by an unrelated in-flight job");

    drop(first);
    let after_release = simply_ip_sync::jobs::try_start_job(&running_jobs, id);
    assert!(after_release.is_some(), "dropping the guard must release the slot for a subsequent claim");
}
