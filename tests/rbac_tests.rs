//! RBAC compliance: manual trigger permissions (`can_sync` vs unauthorized `403`), R4 scope
//! elevation, §5 Master immutability, and §3 resource lifecycle (owner-only delete).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, Set};
use serde_json::json;
use simply_ip_sync::entities::{api_key_sync_permission, external_source};
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn to_body(bytes: axum::body::Bytes) -> serde_json::Value {
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
    to_body(bytes)
}

async fn insert_source(conn: &sea_orm::DatabaseConnection, source_url: &str, owner_key_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let now = Utc::now();
    let model = external_source::ActiveModel {
        id: Set(id),
        name: Set(format!("source-{id}")),
        source_url: Set(source_url.to_owned()),
        parser_type: Set("REGEX_LINE".to_owned()),
        parser_config_json: Set(None),
        cron_schedule: Set("0 0 * * *".to_owned()),
        target_group_name: Set("group".to_owned()),
        mode: Set("upsert".to_owned()),
        is_active: Set(true),
        last_run_at: Set(None),
        owner_key_id: Set(Some(owner_key_id)),
        created_at: Set(now),
        updated_at: Set(now),
    };
    model.insert(conn).await.expect("insert source");
    id
}

#[tokio::test]
async fn trigger_without_can_sync_is_forbidden() {
    let (conn, state, master) = common::setup().await;
    let daughter = common::insert_key(&conn, "Daughter", false, false, false, false, Some(master.id)).await;
    let source_id = insert_source(&conn, "http://127.0.0.1:1/unused", master.id).await;

    let app = simply_ip_sync::create_app(state);
    let req = common::signed_request(&daughter, "POST", &format!("/api/sources/{source_id}/trigger"), None);
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn trigger_with_granted_can_sync_succeeds() {
    let (conn, state, master) = common::setup().await;
    let daughter = common::insert_key(&conn, "Daughter", false, false, false, false, Some(master.id)).await;

    let feed_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/feed.txt"))
        // A genuinely non-empty body: a comment-only feed would parse to zero entries and report
        // PARTIAL (see jobs::external_ingestion's zero-items handling), which would make this
        // test's final assertion ambiguous between "the RBAC gate worked" (what it actually
        // checks) and "the trigger reported SUCCESS" (a fact about feed content, not permissions).
        .respond_with(ResponseTemplate::new(200).set_body_string("# comment\n203.0.113.5\n"))
        .mount(&feed_mock)
        .await;
    let source_id = insert_source(&conn, &format!("{}/feed.txt", feed_mock.uri()), master.id).await;

    let permission = api_key_sync_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(daughter.id),
        resource_type: Set("external_source".to_owned()),
        resource_id: Set(source_id),
        can_sync: Set(true),
        can_manage: Set(false),
        can_view_logs: Set(true),
        created_at: Set(Utc::now()),
    };
    permission.insert(&conn).await.expect("grant can_sync");

    let app = simply_ip_sync::create_app(state);
    let req = common::signed_request(&daughter, "POST", &format!("/api/sources/{source_id}/trigger"), None);
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["status"], json!("SUCCESS"));
}

#[tokio::test]
async fn only_master_may_grant_scope_elevation() {
    let (conn, state, master) = common::setup().await;
    // A Parent-tier key: can_manage_keys=true, but not Master, so RBAC R4 must still block it
    // from minting a resource-creation right on a new key.
    let parent = common::insert_key(&conn, "Parent", false, true, false, false, Some(master.id)).await;

    let app = simply_ip_sync::create_app(state);
    let payload = json!({ "name": "attempted-escalation", "can_manage_sources": true });
    let req = common::signed_request(&parent, "POST", "/api/keys", Some(payload));
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "R4: only Master may grant a resource-creation right");
}

#[tokio::test]
async fn master_key_rejects_edits_beyond_bound_ips() {
    let (conn, state, master) = common::setup().await;
    let _ = &conn;
    let app = simply_ip_sync::create_app(state);
    let payload = json!({ "name": "Renamed Master" });
    let req = common::signed_request(&master, "PATCH", &format!("/api/keys/{}", master.id), Some(payload));
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "§5: the Master key is immutable except its own bound_ips");
}

#[tokio::test]
async fn master_key_rotation_is_always_refused() {
    let (_conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);
    let req = common::signed_request(&master, "POST", &format!("/api/keys/{}/rotate", master.id), None);
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "§5: rotation is refused for the Master key");
}

#[tokio::test]
async fn resource_lifecycle_delete_requires_owner_or_master() {
    let (conn, state, master) = common::setup().await;
    let owner = common::insert_key(&conn, "Owner", false, true, true, true, Some(master.id)).await;
    let other_parent = common::insert_key(&conn, "OtherParent", false, true, true, true, Some(master.id)).await;
    let source_id = insert_source(&conn, "http://127.0.0.1:1/unused", owner.id).await;

    // Grant `other_parent` full manage rights (R2 conjunct) on the resource, but they are not the
    // owner — §3 says manage rights confer no lifecycle authority.
    let permission = api_key_sync_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(other_parent.id),
        resource_type: Set("external_source".to_owned()),
        resource_id: Set(source_id),
        can_sync: Set(true),
        can_manage: Set(true),
        can_view_logs: Set(true),
        created_at: Set(Utc::now()),
    };
    permission.insert(&conn).await.expect("grant manage");

    let app = simply_ip_sync::create_app(state);
    let req = common::signed_request(&other_parent, "DELETE", &format!("/api/sources/{source_id}"), None);
    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "§3: manage rights alone do not confer lifecycle authority");

    let req_owner = common::signed_request(&owner, "DELETE", &format!("/api/sources/{source_id}"), None);
    let resp_owner = app.oneshot(req_owner).await.expect("response");
    assert_eq!(resp_owner.status(), StatusCode::NO_CONTENT, "the owner may always delete their own resource");
}

#[tokio::test]
async fn unauthenticated_request_never_reaches_a_handler() {
    let (_conn, state, _master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);
    let mut req = Request::builder().method("GET").uri("/api/keys").body(Body::empty()).expect("build");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 55555))));
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
