//! Named-attack tests: inbound HMAC verification, anti-replay, and outbound signature generation
//! against a mock `simply_ip_vault` endpoint.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sea_orm::EntityTrait;
use tower::ServiceExt;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn valid_signed_request_is_accepted() {
    let (_conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);
    let req = common::signed_request(&master, "GET", "/api/auth/me", None);
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn missing_signature_header_is_rejected() {
    let (_conn, state, _master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);
    let mut req = Request::builder()
        .method("GET")
        .uri("/api/auth/me")
        .header("X-API-Key", "whatever")
        .header("X-Timestamp", "1700000000")
        .body(Body::empty())
        .expect("build");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 55555))));
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn tampered_signature_is_rejected() {
    let (_conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);
    let mut req = common::signed_request(&master, "GET", "/api/auth/me", None);
    req.headers_mut().insert("X-Signature-256", "sha256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".parse().unwrap());
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn stale_timestamp_outside_skew_window_is_rejected() {
    let (_conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);

    let stale_ts = (chrono::Utc::now().timestamp() - 3600).to_string();
    let signature =
        simply_ip_sync::crypto::compute_signature(&master.signing_secret, "GET", "/api/auth/me", &stale_ts, b"")
            .expect("sign");
    let mut req = Request::builder()
        .method("GET")
        .uri("/api/auth/me")
        .header("X-API-Key", master.plaintext_key.clone())
        .header("X-Timestamp", stale_ts)
        .header("X-Signature-256", signature)
        .body(Body::empty())
        .expect("build");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 55555))));
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn replayed_signature_is_rejected_on_second_use() {
    let (_conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);

    // One signature, computed once, sent twice — the second use must be rejected even though it
    // is byte-identical to the first (a genuinely fresh request would carry a new timestamp).
    let target = "/api/keys";
    let ts = chrono::Utc::now().timestamp().to_string();
    let sig = simply_ip_sync::crypto::compute_signature(&master.signing_secret, "GET", target, &ts, b"").unwrap();
    let build = || {
        let mut req = Request::builder()
            .method("GET")
            .uri(target)
            .header("X-API-Key", master.plaintext_key.clone())
            .header("X-Timestamp", ts.clone())
            .header("X-Signature-256", sig.clone())
            .body(Body::empty())
            .expect("build");
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 55555))));
        req
    };

    let resp_first = app.clone().oneshot(build()).await.expect("response");
    assert_eq!(resp_first.status(), StatusCode::OK, "first use of a signature must be accepted");
    let resp_second = app.oneshot(build()).await.expect("response");
    assert_eq!(resp_second.status(), StatusCode::UNAUTHORIZED, "a replayed signature must be rejected");
}

#[tokio::test]
async fn bound_ips_restricts_access_to_permitted_cidr() {
    use sea_orm::{ActiveModelTrait, IntoActiveModel};
    let (conn, state, master) = common::setup().await;

    // A daughter key bound to a CIDR that excludes the test harness's fixed loopback source.
    let daughter = common::insert_key(&conn, "Restricted", false, false, false, false, Some(master.id)).await;
    let key_row = simply_ip_sync::entities::prelude::ApiKey::find_by_id(daughter.id)
        .one(&conn)
        .await
        .unwrap()
        .unwrap();
    let mut active = key_row.into_active_model();
    active.bound_ips = sea_orm::Set(Some("10.0.0.0/8".to_owned()));
    active.update(&conn).await.unwrap();

    let app = simply_ip_sync::create_app(state);
    let req = common::signed_request(&daughter, "GET", "/api/auth/me", None);
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// Builds a signed `GET /api/auth/me` request from `peer`, optionally carrying an
/// `X-Forwarded-For` header — used by the trusted-proxy tests below, which need control over the
/// TCP peer address that `common::signed_request` always fixes at `127.0.0.1:55555`.
fn signed_request_from_peer(
    key: &common::TestKey,
    peer: std::net::IpAddr,
    forwarded_for: Option<&str>,
) -> Request<Body> {
    let target = "/api/auth/me";
    let (api_key, timestamp, signature) = common::sign(key, "GET", target, b"");
    let mut builder = Request::builder()
        .method("GET")
        .uri(target)
        .header("X-API-Key", api_key)
        .header("X-Timestamp", timestamp)
        .header("X-Signature-256", signature);
    if let Some(xff) = forwarded_for {
        builder = builder.header("X-Forwarded-For", xff);
    }
    let mut req = builder.body(Body::empty()).expect("build");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::new(peer, 55555)));
    req
}

/// A caller reaching the service through a proxy address listed in `TRUSTED_PROXIES` may supply
/// `X-Forwarded-For`, and the resolved client IP (the *forwarded* address, not the proxy's own) is
/// what `bound_ips` is checked against — this is what lets a key be scoped to real end-client
/// ranges sitting behind a load balancer.
#[tokio::test]
async fn trusted_proxy_forwarded_client_ip_is_checked_against_bound_ips() {
    use sea_orm::{ActiveModelTrait, IntoActiveModel};
    let (conn, mut state, master) = common::setup().await;

    let daughter = common::insert_key(&conn, "ProxiedCaller", false, false, false, false, Some(master.id)).await;
    let key_row = simply_ip_sync::entities::prelude::ApiKey::find_by_id(daughter.id).one(&conn).await.unwrap().unwrap();
    let mut active = key_row.into_active_model();
    active.bound_ips = sea_orm::Set(Some("203.0.113.0/24".to_owned()));
    active.update(&conn).await.unwrap();

    // The peer (127.0.0.1) is a trusted load balancer; the real client sits behind it.
    state.trusted_proxies = std::sync::Arc::new(vec!["127.0.0.1/32".parse().unwrap()]);

    let app = simply_ip_sync::create_app(state);
    let peer: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let req = signed_request_from_peer(&daughter, peer, Some("203.0.113.7"));
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a forwarded client IP inside bound_ips, relayed through a trusted proxy, must be permitted"
    );
}

/// The zero-trust counterpart of the test above: a caller connecting from an **untrusted** peer
/// cannot use `X-Forwarded-For` to spoof its way past `bound_ips` by simply claiming to be an
/// address the key is scoped to — `resolve_client_ip` must ignore the header entirely unless the
/// TCP peer itself is a trusted proxy, falling back to the (here, disallowed) peer address.
#[tokio::test]
async fn spoofed_forwarded_for_from_an_untrusted_peer_does_not_bypass_bound_ips() {
    use sea_orm::{ActiveModelTrait, IntoActiveModel};
    let (conn, mut state, master) = common::setup().await;

    let daughter = common::insert_key(&conn, "SpoofAttempt", false, false, false, false, Some(master.id)).await;
    let key_row = simply_ip_sync::entities::prelude::ApiKey::find_by_id(daughter.id).one(&conn).await.unwrap().unwrap();
    let mut active = key_row.into_active_model();
    active.bound_ips = sea_orm::Set(Some("203.0.113.0/24".to_owned()));
    active.update(&conn).await.unwrap();

    // Nothing is trusted — the peer below must be evaluated on its own address, never on a
    // header it supplies about itself.
    state.trusted_proxies = std::sync::Arc::new(Vec::new());

    let app = simply_ip_sync::create_app(state);
    let peer: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    // Forges an X-Forwarded-For claiming to be an address inside bound_ips.
    let req = signed_request_from_peer(&daughter, peer, Some("203.0.113.7"));
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a forged X-Forwarded-For from an untrusted peer must never widen bound_ips access"
    );
}

/// Outbound signature generation: `client::post_batch` must sign requests to a remote vault with
/// a `CANONICAL_V1` HMAC the remote side can verify with the shared secret.
#[tokio::test]
async fn outbound_post_batch_signs_correctly() {
    let mock_server = MockServer::start().await;
    let shared_secret = "outbound-test-secret";

    Mock::given(method("POST"))
        .and(path("/api/records/batch"))
        .and(header("X-API-Key", "remote-key"))
        .respond_with(move |req: &wiremock::Request| {
            let sig_header = req.headers.get("X-Signature-256").expect("signature header present").to_str().expect("utf8");
            let ts_header = req.headers.get("X-Timestamp").expect("timestamp header present").to_str().expect("utf8");
            let target = "/api/records/batch";
            let digest = simply_ip_sync::crypto::verify_signature(
                shared_secret,
                "POST",
                target,
                ts_header,
                &req.body,
                sig_header,
            );
            assert!(digest.is_some(), "remote side must be able to verify the outbound signature");
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "created": 1, "updated": 0, "restored": 0, "locked_skipped": 0, "soft_deleted": 0, "linked": 1
            }))
        })
        .mount(&mock_server)
        .await;

    let cipher = simply_ip_sync::crypto::SecretCipher::Plaintext;
    let sealed_secret = cipher.seal(shared_secret).expect("seal");
    let endpoint = simply_ip_sync::entities::vault_endpoint::Model {
        id: uuid::Uuid::new_v4(),
        name: "MockVault".to_owned(),
        target_url: mock_server.uri(),
        api_key: "remote-key".to_owned(),
        signing_secret: sealed_secret,
        description: None,
        owner_key_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let http = simply_ip_sync::client::build_http_client().expect("http client");
    let records = vec![simply_ip_sync::client::BatchRecordInput {
        target_address: "1.2.3.4".to_owned(),
        cause: None,
        is_deleted: None,
        created_at: None,
        updated_at: None,
        last_seen_at: None,
        deleted_at: None,
    }];
    let result = simply_ip_sync::client::post_batch(&http, &cipher, &endpoint, "test-group", &records, simply_ip_sync::client::BatchMode::Upsert)
        .await
        .expect("post_batch succeeds");
    assert_eq!(result.created, 1);
}

/// Outbound signature generation for the *delta-fetch* side: `client::get_ips_delta` must sign
/// `GET {target_url}/api/ips?...` with the query string included in the signed target (matching
/// `simply_ip_vault`'s own rule that `CANONICAL_V1`'s target is path *plus* query — a signature
/// computed over the bare path alone would let a tampered query string, e.g. flipping
/// `include_deleted=true` to `false`, sail through unnoticed). Also pins the exact query parameter
/// names/values a correct request must carry, since a peer project's vault fixed a real bug this
/// session where `since` filtering silently excluded records deleted after their last-seen
/// timestamp (`example/simply_ip_vault` 2026-08-17) — the client side of that contract is "always
/// ask with `include_deleted=true`", and this test is what would catch a regression on our side of
/// that assumption.
#[tokio::test]
async fn outbound_get_ips_delta_signs_correctly_with_since_and_include_deleted() {
    let mock_server = MockServer::start().await;
    let shared_secret = "outbound-delta-test-secret";
    let since = chrono::Utc::now() - chrono::Duration::hours(1);

    Mock::given(method("GET"))
        .and(path("/api/ips"))
        .respond_with(move |req: &wiremock::Request| {
            let sig_header = req.headers.get("X-Signature-256").expect("signature header present").to_str().expect("utf8");
            let ts_header = req.headers.get("X-Timestamp").expect("timestamp header present").to_str().expect("utf8");
            let target = format!("{}?{}", req.url.path(), req.url.query().expect("query string present"));
            let digest = simply_ip_sync::crypto::verify_signature(shared_secret, "GET", &target, ts_header, b"", sig_header);
            assert!(digest.is_some(), "remote side must be able to verify the outbound signature, including the query string");

            let params: std::collections::HashMap<_, _> = req.url.query_pairs().into_owned().collect();
            assert_eq!(params.get("group_name"), Some(&"delta-group".to_owned()));
            assert_eq!(params.get("include_deleted"), Some(&"true".to_owned()), "the client must always request tombstones");
            assert_eq!(params.get("since"), Some(&since.timestamp().to_string()));
            assert!(params.contains_key("limit"));
            assert!(params.contains_key("offset"));

            ResponseTemplate::new(200).set_body_json(Vec::<serde_json::Value>::new())
        })
        .mount(&mock_server)
        .await;

    let cipher = simply_ip_sync::crypto::SecretCipher::Plaintext;
    let sealed_secret = cipher.seal(shared_secret).expect("seal");
    let endpoint = simply_ip_sync::entities::vault_endpoint::Model {
        id: uuid::Uuid::new_v4(),
        name: "MockSourceVault".to_owned(),
        target_url: mock_server.uri(),
        api_key: "remote-key".to_owned(),
        signing_secret: sealed_secret,
        description: None,
        owner_key_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let http = simply_ip_sync::client::build_http_client().expect("http client");
    let records = simply_ip_sync::client::get_ips_delta(&http, &cipher, &endpoint, "delta-group", Some(since), true)
        .await
        .expect("get_ips_delta succeeds");
    assert!(records.is_empty());
}

/// A tamper test on a large body must flip a byte in the *middle* of the payload, not just
/// truncate or prefix it — a signature scheme covering only a prefix (e.g. a buggy streaming-HMAC
/// implementation that stops reading early) would still catch a truncated/prepended tamper but
/// miss one buried deep in an otherwise-untouched body. Adapted from a pattern audited in
/// `example/simply_hook_executor/scripts/test_e2e.sh` (§25) — reproduced here as a fast in-process
/// Rust test rather than a real-socket E2E curl round-trip, since the property under test
/// (`middleware.rs`'s inbound verification covers the whole buffered body) doesn't need a real
/// socket to prove.
#[tokio::test]
async fn tampering_a_single_byte_deep_in_a_large_body_is_still_detected() {
    let (_conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);

    let targets: Vec<serde_json::Value> = (0..2000)
        .map(|i| serde_json::json!({"vault_endpoint_id": uuid::Uuid::new_v4(), "target_group_name": format!("group-{i}")}))
        .collect();
    let payload = serde_json::json!({
        "name": format!("large-payload-source-{}", uuid::Uuid::new_v4()),
        "source_url": "http://127.0.0.1:1/feed.txt",
        "cron_schedule": "0 0 * * *",
        "target_group_name": "g",
        "targets": targets,
    });
    let body_bytes = serde_json::to_vec(&payload).expect("serialize");
    assert!(body_bytes.len() > 100_000, "the payload must be large enough that a prefix-only signature bug wouldn't be caught by chance");

    let timestamp = chrono::Utc::now().timestamp().to_string();
    let valid_signature =
        simply_ip_sync::crypto::compute_signature(&master.signing_secret, "POST", "/api/sources", &timestamp, &body_bytes).expect("sign");

    // Flip one byte at the exact midpoint of the body — deliberately far from both the start and
    // end, where a partial-coverage bug would be most likely to still (wrongly) verify.
    let mut tampered_body = body_bytes.clone();
    let midpoint = tampered_body.len() / 2;
    tampered_body[midpoint] ^= 0xFF;

    let mut req = Request::builder()
        .method("POST")
        .uri("/api/sources")
        .header("X-API-Key", master.plaintext_key.clone())
        .header("X-Timestamp", timestamp)
        .header("X-Signature-256", valid_signature)
        .header("Content-Type", "application/json")
        .body(Body::from(tampered_body))
        .expect("build");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 55555))));

    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "a signature computed over the untampered body must not verify a body mutated deep in its middle");
}

/// Two genuinely concurrent, distinctly-signed requests replaying the exact same
/// `(key, digest)` pair — proves `ReplayGuard::check_and_record`'s check-then-insert is atomic
/// under real concurrent access, not merely under the sequential reuse
/// `replayed_signature_is_rejected_on_second_use` above exercises. Adapted from a pattern audited
/// in `example/simply_ip_exporter/tests/integration.rs`
/// (`two_concurrent_identical_signed_requests_only_one_succeeds`, 2026-08-17 cross-project test
/// audit — see `AGENT_NOTES.MD`): fire both through `tokio::join!` against the same shared-state
/// router (cloning `Router` clones a handle to the same `Arc`-backed state, not a private copy).
#[tokio::test]
async fn two_concurrent_replays_of_the_same_signature_only_one_succeeds() {
    let (_conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);

    let target = "/api/auth/me";
    let ts = chrono::Utc::now().timestamp().to_string();
    let sig = simply_ip_sync::crypto::compute_signature(&master.signing_secret, "GET", target, &ts, b"").expect("sign");
    let build = || {
        let mut req = Request::builder()
            .method("GET")
            .uri(target)
            .header("X-API-Key", master.plaintext_key.clone())
            .header("X-Timestamp", ts.clone())
            .header("X-Signature-256", sig.clone())
            .body(Body::empty())
            .expect("build");
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 55555))));
        req
    };

    let app_a = app.clone();
    let app_b = app.clone();
    let (resp_a, resp_b) = tokio::join!(app_a.oneshot(build()), app_b.oneshot(build()));
    let status_a = resp_a.expect("response a").status();
    let status_b = resp_b.expect("response b").status();

    let mut statuses = vec![status_a, status_b];
    statuses.sort_by_key(|s| s.as_u16());
    assert_eq!(
        statuses,
        vec![StatusCode::OK, StatusCode::UNAUTHORIZED],
        "exactly one of two genuinely concurrent requests carrying the identical signature must succeed, the other rejected as a replay"
    );
}
