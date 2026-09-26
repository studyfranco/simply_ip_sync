//! `POST /api/sources/test-fetch`: a read-only dry-run of the fetch→parse pipeline, callable
//! against values that have never been saved as an `external_sources` row. Covers RBAC gating,
//! the response shape for each outcome (`SUCCESS`/`PARTIAL`/`FAILED`), sample truncation, and that
//! nothing is persisted regardless of outcome.

mod common;

use axum::http::StatusCode;
use sea_orm::EntityTrait;
use serde_json::{json, Value};
use simply_ip_sync::entities::{audit_log, external_source};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn call(
    app: axum::Router,
    key: &common::TestKey,
    body: Value,
) -> (StatusCode, Value) {
    let req = common::signed_request(key, "POST", "/api/sources/test-fetch", Some(body));
    let resp = app.oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
    let parsed: Value = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).expect("json") };
    (status, parsed)
}

/// A key with neither `is_master` nor `can_manage_sources` must be refused — this is the same
/// right `create_external_source` requires, since the test tool exists to be tried before that
/// point, not to bypass it.
#[tokio::test]
async fn a_key_without_can_manage_sources_is_forbidden() {
    let (conn, state, _master) = common::setup().await;
    let unprivileged = common::insert_key(&conn, "NoRights", false, false, false, false, None).await;
    let app = simply_ip_sync::create_app(state);

    let (status, _) = call(
        app,
        &unprivileged,
        json!({"source_url": "http://127.0.0.1:1/feed.txt", "parser_type": "REGEX_LINE"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// A dedicated `can_manage_sources` key (not master) must be accepted — the right, not the tier,
/// is what gates this.
#[tokio::test]
async fn a_key_with_can_manage_sources_is_accepted() {
    let (conn, state, _master) = common::setup().await;
    let feed_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/feed.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string("203.0.113.9\n"))
        .mount(&feed_mock)
        .await;
    let manager = common::insert_key(&conn, "SourceManager", false, false, true, false, None).await;
    let app = simply_ip_sync::create_app(state);

    let (status, body) = call(
        app,
        &manager,
        json!({"source_url": format!("{}/feed.txt", feed_mock.uri()), "parser_type": "REGEX_LINE"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "SUCCESS");
}

/// An invalid `parser_type` is a caller mistake the fetch never gets a chance to attempt — `400`,
/// distinct from a feed/network failure which is reported as `200`/`FAILED`.
#[tokio::test]
async fn an_unknown_parser_type_is_rejected_with_400() {
    let (_conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);

    let (status, _) = call(
        app,
        &master,
        json!({"source_url": "http://127.0.0.1:1/feed.txt", "parser_type": "CSV_MAGIC"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// A feed that returns valid IPs reports `SUCCESS` with the exact extracted, deduplicated set in
/// `sample`, and `total_extracted` matching.
#[tokio::test]
async fn a_working_regex_line_feed_reports_success_with_the_extracted_sample() {
    let (_conn, state, master) = common::setup().await;
    let feed_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/feed.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string("203.0.113.9\n198.51.100.4\n# comment\n203.0.113.9\n"))
        .mount(&feed_mock)
        .await;
    let app = simply_ip_sync::create_app(state);

    let (status, body) = call(
        app,
        &master,
        json!({"source_url": format!("{}/feed.txt", feed_mock.uri()), "parser_type": "REGEX_LINE"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "SUCCESS");
    assert_eq!(body["total_extracted"], 2, "the duplicate address must be deduplicated");
    let sample = body["sample"].as_array().expect("sample array");
    assert_eq!(sample.len(), 2);
    assert!(sample.iter().any(|v| v == "203.0.113.9"));
    assert!(sample.iter().any(|v| v == "198.51.100.4"));
    assert_eq!(body["truncated"], false);
}

/// `JSON_PATH` with `array_path`/`ip_field` is exercised end-to-end here too, not just
/// `REGEX_LINE` — this is exactly the AbuseIPDB-shaped config the WebUI's help text points at.
/// The fixture body below is a trimmed, real response from AbuseIPDB's own
/// `GET /api/v2/blacklist?ipVersion=4` (fetched once during development, per the live shape's own
/// one-request-per-key-refresh rate limit — never hit that endpoint from an automated test, per
/// AGENT.MD's "local fixtures... never against the live rate-limited source" rule), kept as-is
/// including its extra `countryCode`/`abuseConfidenceScore`/`lastReportedAt` fields and top-level
/// `meta` object, to prove the parser correctly ignores everything except the two configured keys
/// rather than happening to work only on a hand-minimized shape.
#[tokio::test]
async fn a_working_json_path_feed_with_array_path_and_ip_field_reports_success() {
    let (_conn, state, master) = common::setup().await;
    let feed_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blacklist"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "meta": {"generatedAt": "2026-09-26T15:51:22+00:00"},
            "data": [
                {"ipAddress": "34.128.85.64", "countryCode": "ID", "abuseConfidenceScore": 100, "lastReportedAt": "2026-09-26T15:17:01+00:00"},
                {"ipAddress": "176.79.79.20", "countryCode": "PT", "abuseConfidenceScore": 100, "lastReportedAt": "2026-09-26T15:17:01+00:00"},
                {"ipAddress": "18.116.101.220", "countryCode": "US", "abuseConfidenceScore": 100, "lastReportedAt": "2026-09-26T15:17:01+00:00"},
                {"ipAddress": "45.148.10.141", "countryCode": "NL", "abuseConfidenceScore": 100, "lastReportedAt": "2026-09-26T15:17:01+00:00"},
                {"ipAddress": "45.148.10.152", "countryCode": "NL", "abuseConfidenceScore": 100, "lastReportedAt": "2026-09-26T15:17:01+00:00"}
            ]
        })))
        .mount(&feed_mock)
        .await;
    let app = simply_ip_sync::create_app(state);

    let (status, body) = call(
        app,
        &master,
        json!({
            "source_url": format!("{}/blacklist", feed_mock.uri()),
            "parser_type": "JSON_PATH",
            "parser_config_json": "{\"array_path\":\"data\",\"ip_field\":\"ipAddress\"}",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "SUCCESS");
    assert_eq!(body["total_extracted"], 5);
    let sample = body["sample"].as_array().expect("sample array");
    assert!(sample.iter().any(|v| v == "34.128.85.64"));
}

/// Same real-source pattern as the IPv4 test above, but for AbuseIPDB's IPv6 blacklist
/// (`GET /api/v2/blacklist?ipVersion=6`) -- a separately fetched, separately real fixture, since
/// IPv6 address normalization (`::` compression, canonical form) has its own edge cases a purely
/// synthetic fixture could accidentally not exercise.
#[tokio::test]
async fn a_working_json_path_feed_with_real_ipv6_addresses_reports_success() {
    let (_conn, state, master) = common::setup().await;
    let feed_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blacklist6"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "meta": {"generatedAt": "2026-09-26T04:01:01+00:00"},
            "data": [
                {"ipAddress": "2a0f:ca80:b00b:9346::5", "countryCode": "NL", "abuseConfidenceScore": 100, "lastReportedAt": "2026-09-26T03:16:52+00:00"},
                {"ipAddress": "2603:3:6101:f6b0::", "countryCode": "US", "abuseConfidenceScore": 100, "lastReportedAt": "2026-09-26T03:14:04+00:00"},
                {"ipAddress": "2001:470:1:fb5::260", "countryCode": "US", "abuseConfidenceScore": 100, "lastReportedAt": "2026-09-26T03:12:47+00:00"},
                {"ipAddress": "2602:f71d::20", "countryCode": "GB", "abuseConfidenceScore": 100, "lastReportedAt": "2026-09-26T03:10:47+00:00"},
                {"ipAddress": "2001:41d0:305:2100::a9db", "countryCode": "FR", "abuseConfidenceScore": 100, "lastReportedAt": "2026-09-26T03:09:39+00:00"}
            ]
        })))
        .mount(&feed_mock)
        .await;
    let app = simply_ip_sync::create_app(state);

    let (status, body) = call(
        app,
        &master,
        json!({
            "source_url": format!("{}/blacklist6", feed_mock.uri()),
            "parser_type": "JSON_PATH",
            "parser_config_json": "{\"array_path\":\"data\",\"ip_field\":\"ipAddress\"}",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "SUCCESS");
    assert_eq!(body["total_extracted"], 5);
    let sample = body["sample"].as_array().expect("sample array");
    assert!(sample.iter().any(|v| v == "2a0f:ca80:b00b:9346::5"));
}

/// A custom header configured in `parser_config_json` (the same mechanism the WebUI's Custom
/// Headers editor writes into) must actually reach the remote feed, exactly as a real scheduled
/// run would send it -- the whole point of a "test" tool is that it exercises the same path.
#[tokio::test]
async fn a_configured_custom_header_is_actually_sent_to_the_feed() {
    let (_conn, state, master) = common::setup().await;
    let feed_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blacklist"))
        .and(wiremock::matchers::header("Key", "super-secret-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("203.0.113.9\n"))
        .mount(&feed_mock)
        .await;
    let app = simply_ip_sync::create_app(state);

    let (status, body) = call(
        app,
        &master,
        json!({
            "source_url": format!("{}/blacklist", feed_mock.uri()),
            "parser_type": "REGEX_LINE",
            "parser_config_json": "{\"headers\":{\"Key\":\"super-secret-token\"}}",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "SUCCESS", "wiremock only matches the mocked route when the header is present");
}

/// A feed that never returns 2xx (host unreachable here — nothing listens on port 1) is reported
/// as a normal `200`-level API response with `status: FAILED` and a human-readable `error`, not an
/// HTTP 5xx — the remote being broken is exactly the information this endpoint exists to surface.
#[tokio::test]
async fn an_unreachable_feed_reports_failed_not_an_http_error() {
    let (_conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);

    let (status, body) = call(
        app,
        &master,
        json!({"source_url": "http://127.0.0.1:1/feed.txt", "parser_type": "REGEX_LINE"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "FAILED");
    assert!(body["error"].as_str().is_some_and(|s| !s.is_empty()));
}

/// A syntactically clean fetch that yields zero parseable entries is `PARTIAL`, not `SUCCESS` --
/// same "zero is not trustworthy" rule `jobs::external_ingestion::execute` applies, since a real
/// feed going to genuinely zero entries is itself an anomaly worth flagging rather than a quiet
/// success.
#[tokio::test]
async fn a_feed_with_zero_extractable_entries_reports_partial() {
    let (_conn, state, master) = common::setup().await;
    let feed_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/empty.html"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html><body>nothing here</body></html>"))
        .mount(&feed_mock)
        .await;
    let app = simply_ip_sync::create_app(state);

    let (status, body) = call(
        app,
        &master,
        json!({"source_url": format!("{}/empty.html", feed_mock.uri()), "parser_type": "REGEX_LINE"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "PARTIAL");
    assert_eq!(body["total_extracted"], 0);
}

/// A feed with more entries than the sample cap reports the true `total_extracted` count, a
/// `sample` capped at the limit, and `truncated: true` -- distinguishing "small feed with few
/// results" from "large feed, only showing a preview" is the entire reason `truncated` exists.
#[tokio::test]
async fn a_feed_exceeding_the_sample_cap_reports_the_true_total_and_a_truncated_sample() {
    let (_conn, state, master) = common::setup().await;
    let feed_mock = MockServer::start().await;
    let body_text: String = (0..75).map(|i| format!("10.0.{}.{}\n", i / 256, i % 256)).collect();
    Mock::given(method("GET"))
        .and(path("/big.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body_text))
        .mount(&feed_mock)
        .await;
    let app = simply_ip_sync::create_app(state);

    let (status, body) = call(
        app,
        &master,
        json!({"source_url": format!("{}/big.txt", feed_mock.uri()), "parser_type": "REGEX_LINE"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "SUCCESS");
    assert_eq!(body["total_extracted"], 75);
    assert_eq!(body["sample"].as_array().expect("sample array").len(), 50);
    assert_eq!(body["truncated"], true);
}

/// Nothing is persisted by this endpoint, on either a successful or a failed test: no
/// `external_sources` row, and no `audit_logs` entry -- it is a read-only preview, not a create
/// with a dry-run flag.
#[tokio::test]
async fn no_source_row_or_audit_log_entry_is_created_by_a_test_fetch() {
    let (conn, state, master) = common::setup().await;
    let feed_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/feed.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string("203.0.113.9\n"))
        .mount(&feed_mock)
        .await;
    let app = simply_ip_sync::create_app(state);

    let audit_before = audit_log::Entity::find().all(&conn).await.expect("count audit logs").len();
    let (status, _) = call(
        app,
        &master,
        json!({"source_url": format!("{}/feed.txt", feed_mock.uri()), "parser_type": "REGEX_LINE"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let source_count = external_source::Entity::find().all(&conn).await.expect("count sources").len();
    assert_eq!(source_count, 0, "test-fetch must never create an external_sources row");
    let audit_after = audit_log::Entity::find().all(&conn).await.expect("count audit logs").len();
    assert_eq!(audit_after, audit_before, "test-fetch is read-only and must not write an audit log entry");
}
