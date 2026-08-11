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
