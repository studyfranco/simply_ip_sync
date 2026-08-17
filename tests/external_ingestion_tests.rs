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

/// Prompted by a bug audited in `example/simply_ip_vault`'s own test suite this session
/// (2026-08-17 cross-project test audit — see `AGENT_NOTES.MD`): its `POST /api/records/batch`
/// rejects a whole batch containing two entries that are the *same* address in different notation
/// (`203.0.113.60` and `203.0.113.60/32`). A feed mixing bare-IP and CIDR-singleton notation for
/// the same address would trip that rejection unless deduplication happens on *canonical* form,
/// not raw string equality. `jobs::external_ingestion::execute`'s dedup (`seen.insert(r.clone())`)
/// operates on whatever each `FeedParser` already returned — and every parser already normalizes
/// through `parsers::normalize_ip_or_cidr` before returning a candidate (collapsing `/32`→bare,
/// `/128`→bare, and any equivalent IPv6 spelling to its canonical form) — so this is, by
/// construction, already correct upstream of the job-layer dedup. This test pins that property
/// end to end rather than leaving it as an unverified inference from reading two files together.
#[tokio::test]
async fn mixed_notation_duplicate_addresses_canonicalize_and_dedupe_to_one_record() {
    let (conn, state, _master) = common::setup().await;

    // Three notations of two addresses: a bare IPv4 and its /32 CIDR-singleton form (equal), and
    // an unabbreviated vs. abbreviated IPv6 spelling of the same address (also equal).
    let feed_body = "203.0.113.60\n203.0.113.60/32\n2001:0db8::0001\n2001:db8::1\n";

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

    let source_id = insert_source(&conn, &format!("{}/feed.txt", feed_mock.uri()), "group").await;
    let vault_id = insert_vault(&conn, "target", &target_mock.uri()).await;
    insert_target(&conn, source_id, vault_id, None).await;

    let summary = simply_ip_sync::jobs::external_ingestion::run(&state, source_id).await.expect("job runs");
    assert_eq!(summary.status, "SUCCESS");
    assert_eq!(summary.items_processed, 2, "four lines naming only two distinct addresses (in different notations) must dedupe to 2, not 4");

    let received = target_mock.received_requests().await.expect("recording enabled");
    assert_eq!(received.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&received[0].body).expect("json body");
    let addresses: Vec<String> = body["records"]
        .as_array()
        .expect("records array")
        .iter()
        .map(|r| r["target_address"].as_str().expect("target_address").to_owned())
        .collect();
    assert_eq!(addresses, vec!["203.0.113.60".to_owned(), "2001:db8::1".to_owned()], "each pair must collapse to its single canonical form");
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

/// Task 2: the literal scenario this task describes — chunk 1 of a `full_replace` run (which
/// already cleared-and-set the target's authoritative content) succeeds, chunk 2 then hits a fatal
/// error. Chunk 3 must never be attempted against that target, and the overall job must report
/// `PARTIAL` (a sibling target that completes all 3 chunks keeps this from being a hard `FAILED`).
/// Unlike `vault_sync` (see `mid_run_chunk_failure_stops_further_chunks_and_withholds_last_sync_at`
/// in `tests/vault_sync_tests.rs`), `external_ingestion` has no `last_sync_at`-style high-water
/// mark to withhold: it re-fetches the feed's *entire* current content on every run regardless of
/// the previous run's outcome, so "the next scheduled run performs a complete re-sync" — the
/// safety property Task 2 asks for — already holds structurally here. `last_run_at` is still
/// recorded unconditionally, since it only ever means "the job executed", not "the job succeeded".
#[tokio::test]
async fn full_replace_mid_run_chunk_failure_stops_further_chunks_and_reports_partial() {
    let (conn, state, _master) = common::setup().await;

    const TOTAL_RECORDS: u32 = 12_000;
    let feed_body: String = (0..TOTAL_RECORDS).map(synth_ip).collect::<Vec<_>>().join("\n");

    let feed_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/feed.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string(feed_body))
        .mount(&feed_mock)
        .await;

    let good_target_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/records/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(batch_response()))
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
                // Chunk 1: succeeds, carrying full_replace — the target's authoritative content
                // has now legitimately been cleared-and-set to chunk 1's records.
                ResponseTemplate::new(200).set_body_json(batch_response())
            } else {
                // Chunk 2: a fatal server error. If chunk 3 were ever sent it would land here too
                // — the request-count assertion below proves it was never attempted at all.
                ResponseTemplate::new(500)
            }
        })
        .mount(&bad_target_mock)
        .await;

    let source_id = insert_source_with_mode(&conn, &format!("{}/feed.txt", feed_mock.uri()), "group", "full_replace").await;
    let good_vault_id = insert_vault(&conn, "good-target", &good_target_mock.uri()).await;
    let bad_vault_id = insert_vault(&conn, "bad-target", &bad_target_mock.uri()).await;
    insert_target(&conn, source_id, good_vault_id, None).await;
    insert_target(&conn, source_id, bad_vault_id, None).await;

    let summary = simply_ip_sync::jobs::external_ingestion::run(&state, source_id).await.expect("job runs");

    assert_eq!(
        summary.status, "PARTIAL",
        "one target fully succeeding and the other partially failing must report PARTIAL, not SUCCESS or FAILED"
    );
    assert_eq!(
        summary.chunks_sent, 4,
        "good_target's 3 successful chunks + bad_target's 1 successful chunk (before failing on chunk 2) = 4"
    );

    let good_requests = good_target_mock.received_requests().await.expect("recording enabled");
    assert_eq!(good_requests.len(), 3, "good_target must still receive its full 3-chunk sequence regardless of bad_target's failure");
    let good_modes: Vec<String> = good_requests
        .iter()
        .map(|r| {
            let body: serde_json::Value = serde_json::from_slice(&r.body).expect("json");
            body["mode"].as_str().expect("mode field").to_owned()
        })
        .collect();
    assert_eq!(good_modes, vec!["full_replace", "upsert", "upsert"], "good_target's own chunk sequence still follows the chunk-0-only rule");

    let bad_requests = bad_target_mock.received_requests().await.expect("recording enabled");
    assert_eq!(
        bad_requests.len(), 2,
        "bad_target must receive exactly chunk 1 (succeeded) + chunk 2 (failed) — chunk 3 must never be attempted once chunk 2 failed"
    );
    let bad_chunk1_body: serde_json::Value = serde_json::from_slice(&bad_requests[0].body).expect("json");
    assert_eq!(
        bad_chunk1_body["mode"], serde_json::json!("full_replace"),
        "bad_target's own chunk 1 legitimately carried full_replace before the run failed on chunk 2"
    );

    let source = external_source::Entity::find_by_id(source_id).one(&conn).await.expect("query").expect("source exists");
    assert!(
        source.last_run_at.is_some(),
        "last_run_at is unconditional by design — it means 'the job executed', not 'the job succeeded'; \
         there is no incremental cursor here for a partial failure to corrupt"
    );
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

/// Task 1: a `Content-Encoding: gzip` response that decompresses to well over
/// `DEFAULT_MAX_DECOMPRESSED_BYTES` (50 MiB) — a classic decompression bomb, since highly
/// repetitive data compresses to almost nothing on the wire — must abort the job as `FAILED`
/// rather than let `reqwest`'s transparent gzip decoder buffer the whole decompressed payload in
/// memory first. The compressed body wiremock actually serves is tiny; only the *decompressed*
/// size exceeds the limit, which is exactly the shape this defense exists for.
#[tokio::test]
async fn oversized_gzip_response_is_rejected_as_a_decompression_bomb_without_buffering_it_fully() {
    let (conn, state, _master) = common::setup().await;

    let oversized = vec![b'a'; simply_ip_sync::config::DEFAULT_MAX_DECOMPRESSED_BYTES as usize + 1024];
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&oversized).expect("write to gzip encoder");
    let compressed = encoder.finish().expect("finish gzip stream");
    assert!(
        compressed.len() < oversized.len() / 100,
        "the compressed bomb should be far smaller than its decompressed size (got {} compressed vs {} decompressed)",
        compressed.len(),
        oversized.len()
    );

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
    let summary = simply_ip_sync::jobs::external_ingestion::run(&state, source_id).await.expect("job runs without panicking");

    assert_eq!(summary.status, "FAILED", "an oversized decompressed body must fail the job, not succeed with truncated data");
    assert_eq!(summary.items_processed, 0);
    let message = summary.error_message.expect("must explain the failure");
    assert!(
        message.contains("MAX_DECOMPRESSED_BYTES") || message.contains("decompress"),
        "error message should explain this is the decompression-bomb guard, got: {message}"
    );

    let logs = simply_ip_sync::entities::sync_log::Entity::find().all(&conn).await.expect("query logs");
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].status, "FAILED");
}

/// The same defense, at the second (independent) expansion point: a `.zip` archive whose single
/// member decompresses to well over the configured limit. The archive itself is tiny on the wire —
/// `read_capped_body`'s outer cap never trips — so this specifically exercises
/// `decompress_if_zip`'s own per-member streaming cap.
#[tokio::test]
async fn oversized_zip_member_is_rejected_as_a_decompression_bomb() {
    let (conn, state, _master) = common::setup().await;

    let oversized = vec![b'a'; simply_ip_sync::config::DEFAULT_MAX_DECOMPRESSED_BYTES as usize + 1024];
    let mut zip_buf = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut zip_buf);
        let options: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        writer.start_file("bomb.txt", options).expect("start_file");
        writer.write_all(&oversized).expect("write member contents");
        writer.finish().expect("finish archive");
    }
    let zip_bytes = zip_buf.into_inner();
    assert!(
        zip_bytes.len() < oversized.len() / 100,
        "the zip bomb should be far smaller than its decompressed size (got {} compressed vs {} decompressed)",
        zip_bytes.len(),
        oversized.len()
    );

    let feed_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/feed.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes))
        .mount(&feed_mock)
        .await;

    let source_id = insert_source(&conn, &format!("{}/feed.zip", feed_mock.uri()), "group").await;
    let summary = simply_ip_sync::jobs::external_ingestion::run(&state, source_id).await.expect("job runs without panicking");

    assert_eq!(summary.status, "FAILED", "a zip member that decompresses past the limit must fail the job");
    assert_eq!(summary.items_processed, 0);
    let message = summary.error_message.expect("must explain the failure");
    assert!(
        message.contains("MAX_DECOMPRESSED_BYTES") || message.contains("decompress"),
        "error message should explain this is the decompression-bomb guard, got: {message}"
    );
}

/// Task 3: a feed host serving Latin-1 (ISO-8859-1)/raw-binary bytes rather than UTF-8 must not
/// crash the job — the full fetch→decompress→parse→push pipeline must complete, extracting
/// whatever IP-shaped tokens survive lossy decoding (see `parsers::regex_line`'s doc comment) and
/// pushing exactly those, rather than the whole run failing over one feed host's encoding choice.
#[tokio::test]
async fn non_utf8_feed_body_does_not_crash_the_job_and_extracts_the_valid_ips() {
    let (conn, state, _master) = common::setup().await;

    let mut body = Vec::new();
    body.extend_from_slice(b"# Liste \xE9 jour (Latin-1, pas UTF-8)\n"); // raw Latin-1 'é'
    body.extend_from_slice(b"203.0.113.44\n");
    body.extend_from_slice(b"; commentaire avec un caract\xE8re \xE9trange\n"); // raw Latin-1 'è'/'é'
    body.extend_from_slice(b"2001:db8::44\n");

    let feed_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/feed.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&feed_mock)
        .await;

    let target_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/records/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(batch_response()))
        .mount(&target_mock)
        .await;

    let source_id = insert_source(&conn, &format!("{}/feed.txt", feed_mock.uri()), "group").await;
    let vault_id = insert_vault(&conn, "target", &target_mock.uri()).await;
    insert_target(&conn, source_id, vault_id, None).await;

    let summary = simply_ip_sync::jobs::external_ingestion::run(&state, source_id).await.expect("job runs without panicking");

    assert_eq!(summary.status, "SUCCESS");
    assert_eq!(summary.items_processed, 2, "both valid IPs must survive despite the Latin-1 bytes elsewhere in the body");

    let received = target_mock.received_requests().await.expect("recording enabled");
    assert_eq!(received.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&received[0].body).expect("json body");
    let addresses: Vec<String> = body["records"]
        .as_array()
        .expect("records array")
        .iter()
        .map(|r| r["target_address"].as_str().expect("target_address").to_owned())
        .collect();
    assert_eq!(addresses, vec!["203.0.113.44".to_owned(), "2001:db8::44".to_owned()]);
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
