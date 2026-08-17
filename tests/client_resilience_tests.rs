//! `client.rs` resilience: transient-failure retry with exponential backoff (Task 2) and adaptive
//! batch splitting on `413 Payload Too Large` (Task 3). Exercised directly against
//! `client::post_batch`/`client::get_ips_delta` — no database, no full job pipeline — since the
//! property under test belongs entirely to the HTTP client layer.
//!
//! Tests that need a specific `OUTBOUND_MAX_RETRIES`/`OUTBOUND_RETRY_BACKOFF_MS` value mutate
//! those process-wide env vars (by design — see `config::outbound_max_retries`'s doc comment) and
//! must not run concurrently with each other or they'd observe one another's value mid-flight;
//! [`env_lock`] serializes exactly those tests against each other. Tests relying on the untouched
//! defaults don't need it: the defaults (3 retries, 500ms backoff) are what they're testing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use chrono::Utc;
use simply_ip_sync::client::{self, BatchMode, BatchRecordInput};
use simply_ip_sync::crypto::SecretCipher;
use simply_ip_sync::entities::vault_endpoint;
use tokio::sync::Mutex;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Async-aware (not `std::sync::Mutex`, whose guard clippy flags as unsound to hold across an
/// `.await`) lock serializing the handful of tests below that mutate the process-wide
/// `OUTBOUND_MAX_RETRIES`/`OUTBOUND_RETRY_BACKOFF_MS` env vars against each other.
fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn mock_endpoint(cipher: &SecretCipher, target_url: &str) -> vault_endpoint::Model {
    let now = Utc::now();
    vault_endpoint::Model {
        id: Uuid::new_v4(),
        name: "resilience-test-vault".to_owned(),
        target_url: target_url.to_owned(),
        api_key: "remote-key".to_owned(),
        signing_secret: cipher.seal("shared-secret").expect("seal"),
        description: None,
        owner_key_id: None,
        created_at: now,
        updated_at: now,
    }
}

fn records(n: usize) -> Vec<BatchRecordInput> {
    (0..n)
        .map(|i| BatchRecordInput {
            target_address: format!("10.0.{}.{}", (i / 256) % 256, i % 256),
            cause: None,
            is_deleted: None,
            created_at: None,
            updated_at: None,
            last_seen_at: None,
            deleted_at: None,
        })
        .collect()
}

fn batch_response_with_created(created: u64) -> serde_json::Value {
    serde_json::json!({"created": created, "updated": 0, "restored": 0, "locked_skipped": 0, "soft_deleted": 0, "linked": created})
}

/// Task 2: two consecutive transient failures (429 then 503, the exact pair the task names)
/// followed by a 200 on the third attempt must be transparently recovered — the caller sees a
/// plain `Ok`, never learns retries happened at all except via logs.
#[tokio::test]
async fn retry_recovers_after_two_transient_failures_then_succeeds() {
    let _guard = env_lock().lock().await;
    unsafe {
        std::env::set_var("OUTBOUND_RETRY_BACKOFF_MS", "20");
    }

    let mock_server = MockServer::start().await;
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = call_count.clone();
    Mock::given(method("POST"))
        .and(path("/api/records/batch"))
        .respond_with(move |_req: &wiremock::Request| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            match n {
                0 => ResponseTemplate::new(429),
                1 => ResponseTemplate::new(503),
                _ => ResponseTemplate::new(200).set_body_json(batch_response_with_created(3)),
            }
        })
        .mount(&mock_server)
        .await;

    let cipher = SecretCipher::Plaintext;
    let endpoint = mock_endpoint(&cipher, &mock_server.uri());
    let http = client::build_http_client().expect("client builds");

    let result = client::post_batch(&http, &cipher, &endpoint, "group", &records(3), BatchMode::Upsert).await;

    unsafe {
        std::env::remove_var("OUTBOUND_RETRY_BACKOFF_MS");
    }

    let response = result.expect("must succeed after recovering from two transient failures");
    assert_eq!(response.created, 3);
    assert_eq!(call_count.load(Ordering::SeqCst), 3, "exactly 2 failed attempts + 1 successful attempt");
}

/// The retry budget is finite: once `OUTBOUND_MAX_RETRIES` is exhausted against a target that
/// never recovers, the call must fail — not retry forever.
#[tokio::test]
async fn retry_gives_up_after_exceeding_max_retries() {
    let _guard = env_lock().lock().await;
    unsafe {
        std::env::set_var("OUTBOUND_RETRY_BACKOFF_MS", "10");
        std::env::set_var("OUTBOUND_MAX_RETRIES", "2");
    }

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/records/batch"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&mock_server)
        .await;

    let cipher = SecretCipher::Plaintext;
    let endpoint = mock_endpoint(&cipher, &mock_server.uri());
    let http = client::build_http_client().expect("client builds");

    let result = client::post_batch(&http, &cipher, &endpoint, "group", &records(1), BatchMode::Upsert).await;

    unsafe {
        std::env::remove_var("OUTBOUND_RETRY_BACKOFF_MS");
        std::env::remove_var("OUTBOUND_MAX_RETRIES");
    }

    assert!(result.is_err(), "a target that never recovers must eventually fail, not retry indefinitely");
    let received = mock_server.received_requests().await.expect("recording enabled");
    assert_eq!(received.len(), 3, "1 initial attempt + 2 retries (OUTBOUND_MAX_RETRIES=2), then give up");
}

/// A non-transient error (plain `400 Bad Request` — a malformed request, not a server hiccup)
/// must fail immediately. Retrying it would waste the retry budget on something no amount of
/// waiting will fix.
#[tokio::test]
async fn non_transient_error_is_not_retried() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/records/batch"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&mock_server)
        .await;

    let cipher = SecretCipher::Plaintext;
    let endpoint = mock_endpoint(&cipher, &mock_server.uri());
    let http = client::build_http_client().expect("client builds");

    let result = client::post_batch(&http, &cipher, &endpoint, "group", &records(1), BatchMode::Upsert).await;
    assert!(result.is_err());

    let received = mock_server.received_requests().await.expect("recording enabled");
    assert_eq!(received.len(), 1, "a 400 must fail on the first attempt, never retried");
}

/// Task 3: a target rejecting an oversized batch with `413` must have that batch transparently
/// split in half (recursively, if still too large) and each half delivered — the caller sees one
/// successful, aggregated response, never a 413 bubbling up for a batch smaller than what it
/// actually sent.
#[tokio::test]
async fn adaptive_413_splitting_completes_delivery() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/records/batch"))
        .respond_with(|req: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).expect("json body");
            let count = body["records"].as_array().expect("records array").len() as u64;
            if count > 2000 {
                ResponseTemplate::new(413)
            } else {
                ResponseTemplate::new(200).set_body_json(batch_response_with_created(count))
            }
        })
        .mount(&mock_server)
        .await;

    let cipher = SecretCipher::Plaintext;
    let endpoint = mock_endpoint(&cipher, &mock_server.uri());
    let http = client::build_http_client().expect("client builds");

    let result = client::post_batch(&http, &cipher, &endpoint, "group", &records(5000), BatchMode::Upsert).await;

    let response = result.expect("splitting must eventually deliver the whole batch");
    assert_eq!(response.created, 5000, "the aggregated response must reflect all 5000 records, not just the last sub-chunk");

    // `received_requests` includes every attempt, not just the ones that were ultimately
    // accepted: the oversized attempts that provoked a 413 are recorded too (5000, then
    // 2500+2500, each of which is itself still >2000 and gets split again). Only the ≤2000
    // sub-batches represent records actually delivered.
    let received = mock_server.received_requests().await.expect("recording enabled");
    let mut delivered_total = 0usize;
    let mut delivered_count = 0usize;
    for req in &received {
        let body: serde_json::Value = serde_json::from_slice(&req.body).expect("json body");
        let count = body["records"].as_array().expect("records array").len();
        if count <= 2000 {
            delivered_total += count;
            delivered_count += 1;
        }
    }
    assert_eq!(delivered_count, 4, "5000 records split down to four delivered ≤2000-record sub-batches");
    assert_eq!(delivered_total, 5000, "the delivered sub-batches must together cover every record exactly once");
}

/// Task 4 (client-layer half): when a `413` forces a `full_replace` batch to split, only the
/// first resulting sub-chunk may keep `full_replace` — the second must already be `upsert`, or it
/// would erase what the first sub-chunk just delivered to the same target.
#[tokio::test]
async fn adaptive_413_splitting_preserves_full_replace_only_on_first_subchunk() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/records/batch"))
        .respond_with(|req: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).expect("json body");
            let count = body["records"].as_array().expect("records array").len() as u64;
            if count > 2000 {
                ResponseTemplate::new(413)
            } else {
                ResponseTemplate::new(200).set_body_json(batch_response_with_created(count))
            }
        })
        .mount(&mock_server)
        .await;

    let cipher = SecretCipher::Plaintext;
    let endpoint = mock_endpoint(&cipher, &mock_server.uri());
    let http = client::build_http_client().expect("client builds");

    // 3000 > 2000 triggers exactly one split into 1500 + 1500, both under the limit.
    let result = client::post_batch(&http, &cipher, &endpoint, "group", &records(3000), BatchMode::FullReplace).await;
    assert!(result.is_ok());

    // As above: the initial 3000-record attempt is recorded too even though it was rejected with
    // a 413. Only the two ≤2000 sub-batches were actually delivered; their arrival order is what
    // matters for the full_replace-only-on-first-subchunk rule.
    let received = mock_server.received_requests().await.expect("recording enabled");
    let modes: Vec<String> = received
        .iter()
        .filter_map(|req| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).expect("json body");
            let count = body["records"].as_array().expect("records array").len();
            (count <= 2000).then(|| body["mode"].as_str().expect("mode field").to_owned())
        })
        .collect();
    assert_eq!(modes.len(), 2, "3000 records split into exactly two delivered ≤2000-record sub-batches");
    assert_eq!(modes[0], "full_replace", "the first delivered sub-chunk keeps the original full_replace mode");
    assert_eq!(modes[1], "upsert", "the second sub-chunk must be downgraded to upsert, or it would erase the first");
}

/// A single record that still triggers `413` (an individual record itself too large, not a batch
/// sizing problem) cannot be split further and must surface as an error rather than looping
/// forever.
#[tokio::test]
async fn a_413_on_a_single_record_cannot_be_split_further_and_fails() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST")).and(path("/api/records/batch")).respond_with(ResponseTemplate::new(413)).mount(&mock_server).await;

    let cipher = SecretCipher::Plaintext;
    let endpoint = mock_endpoint(&cipher, &mock_server.uri());
    let http = client::build_http_client().expect("client builds");

    let result = client::post_batch(&http, &cipher, &endpoint, "group", &records(1), BatchMode::Upsert).await;
    assert!(result.is_err(), "a single record that is itself too large must fail, not split infinitely");
}

/// Task 2, applied to the delta-fetch side: a transient failure on one page of `GET /api/ips`
/// must be retried for that page alone, and the overall fetch still succeeds.
#[tokio::test]
async fn get_ips_delta_retries_a_transient_failure_per_page() {
    let _guard = env_lock().lock().await;
    unsafe {
        std::env::set_var("OUTBOUND_RETRY_BACKOFF_MS", "20");
    }

    let mock_server = MockServer::start().await;
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = call_count.clone();
    Mock::given(method("GET"))
        .and(path("/api/ips"))
        .respond_with(move |_req: &wiremock::Request| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                ResponseTemplate::new(503)
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id": Uuid::new_v4(),
                    "target_address": "198.51.100.1",
                    "group_name": "g",
                    "is_deleted": false,
                    "created_at": "2026-01-01T00:00:00",
                    "updated_at": "2026-01-01T00:00:00",
                    "last_seen_at": "2026-01-01T00:00:00"
                }]))
            }
        })
        .mount(&mock_server)
        .await;

    let cipher = SecretCipher::Plaintext;
    let endpoint = mock_endpoint(&cipher, &mock_server.uri());
    let http = client::build_http_client().expect("client builds");

    let result = client::get_ips_delta(&http, &cipher, &endpoint, "g", None, true).await;

    unsafe {
        std::env::remove_var("OUTBOUND_RETRY_BACKOFF_MS");
    }

    let records = result.expect("must succeed after retrying the transient failure");
    assert_eq!(records.len(), 1);
    assert_eq!(call_count.load(Ordering::SeqCst), 2, "1 failed attempt + 1 successful retry");
}
