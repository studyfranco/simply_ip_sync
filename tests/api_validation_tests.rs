//! Request-body validation that must reject before touching the database: malformed
//! `cron_schedule` strings on `POST /api/sources` and `POST /api/sync-tasks`.
//!
//! A source or task that can never be scheduled is not a degraded source or task — it is silent
//! data corruption that surfaces only when nobody notices a cron tick that never fires. These
//! tests assert the `400` happens *and* that nothing was persisted, so a future change that moves
//! the validation after the insert (rejecting the HTTP response but leaving the row behind) would
//! be caught.

mod common;

use axum::http::StatusCode;
use sea_orm::EntityTrait;
use serde_json::json;
use simply_ip_sync::entities::{external_source, vault_sync_task};
use tower::ServiceExt;
use uuid::Uuid;

async fn insert_vault_for_task(conn: &sea_orm::DatabaseConnection) -> Uuid {
    use chrono::Utc;
    use sea_orm::{ActiveModelTrait, Set};
    use simply_ip_sync::entities::vault_endpoint;

    let id = Uuid::new_v4();
    let now = Utc::now();
    let sealed = simply_ip_sync::crypto::SecretCipher::Plaintext.seal("shared-secret").unwrap();
    let model = vault_endpoint::ActiveModel {
        id: Set(id),
        name: Set(format!("vault-{id}")),
        target_url: Set("http://127.0.0.1:1".to_owned()),
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

#[tokio::test]
async fn invalid_cron_on_source_creation_is_rejected_with_400_and_not_persisted() {
    let (conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);

    for bad_cron in ["invalid_cron", "* * *", "", "99 99 99 * *"] {
        let payload = json!({
            "name": format!("source-{bad_cron}-{}", Uuid::new_v4()),
            "source_url": "http://127.0.0.1:1/feed.txt",
            "cron_schedule": bad_cron,
            "target_group_name": "group",
        });
        let req = common::signed_request(&master, "POST", "/api/sources", Some(payload));
        let resp = app.clone().oneshot(req).await.expect("response");
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "cron_schedule '{bad_cron}' must be rejected with 400"
        );
    }

    let count = external_source::Entity::find().all(&conn).await.expect("query sources").len();
    assert_eq!(count, 0, "no source may be persisted when cron validation rejects the request");
}

#[tokio::test]
async fn valid_cron_on_source_creation_is_accepted() {
    let (_conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);

    for good_cron in ["0 0 * * *", "*/15 * * * *", "0 */5 * * * *"] {
        let payload = json!({
            "name": format!("source-{}", Uuid::new_v4()),
            "source_url": "http://127.0.0.1:1/feed.txt",
            "cron_schedule": good_cron,
            "target_group_name": "group",
        });
        let req = common::signed_request(&master, "POST", "/api/sources", Some(payload));
        let resp = app.clone().oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK, "cron_schedule '{good_cron}' should be accepted");
    }
}

#[tokio::test]
async fn invalid_cron_on_sync_task_creation_is_rejected_with_400_and_not_persisted() {
    let (conn, state, master) = common::setup().await;
    let source_vault_id = insert_vault_for_task(&conn).await;
    let app = simply_ip_sync::create_app(state);

    for bad_cron in ["invalid_cron", "* * *", "not-a-cron-at-all"] {
        let payload = json!({
            "name": format!("task-{}", Uuid::new_v4()),
            "source_vault_id": source_vault_id,
            "source_group_name": "source-group",
            "target_group_name": "target-group",
            "cron_schedule": bad_cron,
        });
        let req = common::signed_request(&master, "POST", "/api/sync-tasks", Some(payload));
        let resp = app.clone().oneshot(req).await.expect("response");
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "cron_schedule '{bad_cron}' must be rejected with 400"
        );
    }

    let count = vault_sync_task::Entity::find().all(&conn).await.expect("query tasks").len();
    assert_eq!(count, 0, "no sync task may be persisted when cron validation rejects the request");
}

#[tokio::test]
async fn invalid_cron_on_source_update_is_rejected_without_mutating_existing_row() {
    let (conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);

    let create_payload = json!({
        "name": "existing-source",
        "source_url": "http://127.0.0.1:1/feed.txt",
        "cron_schedule": "0 0 * * *",
        "target_group_name": "group",
    });
    let create_req = common::signed_request(&master, "POST", "/api/sources", Some(create_payload));
    let create_resp = app.clone().oneshot(create_req).await.expect("response");
    assert_eq!(create_resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(create_resp.into_body(), usize::MAX).await.expect("body");
    let created: serde_json::Value = serde_json::from_slice(&body).expect("json");
    let id = created["id"].as_str().expect("id field");

    let update_payload = json!({ "cron_schedule": "not a cron" });
    let update_req = common::signed_request(&master, "PATCH", &format!("/api/sources/{id}"), Some(update_payload));
    let update_resp = app.oneshot(update_req).await.expect("response");
    assert_eq!(update_resp.status(), StatusCode::BAD_REQUEST);

    let stored = external_source::Entity::find_by_id(Uuid::parse_str(id).unwrap())
        .one(&conn)
        .await
        .expect("query")
        .expect("row exists");
    assert_eq!(stored.cron_schedule, "0 0 * * *", "the original valid cron_schedule must be unchanged");
}

/// `mode` must be one of the two values `client::BatchMode::parse` recognizes — a typo here would
/// otherwise silently fall back to upsert deep inside the job (see `external_ingestion::run`'s
/// `BatchMode::parse(...).unwrap_or_else(...)` warning path) instead of being caught at the door.
#[tokio::test]
async fn invalid_mode_on_source_creation_is_rejected_with_400_and_not_persisted() {
    let (conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);

    for bad_mode in ["replace", "FULL_REPLACE", "upsert ", ""] {
        let payload = json!({
            "name": format!("source-{}", Uuid::new_v4()),
            "source_url": "http://127.0.0.1:1/feed.txt",
            "cron_schedule": "0 0 * * *",
            "target_group_name": "group",
            "mode": bad_mode,
        });
        let req = common::signed_request(&master, "POST", "/api/sources", Some(payload));
        let resp = app.clone().oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "mode '{bad_mode}' must be rejected with 400");
    }

    let count = external_source::Entity::find().all(&conn).await.expect("query sources").len();
    assert_eq!(count, 0, "no source may be persisted when mode validation rejects the request");
}

/// Both recognized `mode` values must be accepted, and a request that omits `mode` entirely must
/// default to `"upsert"` rather than requiring every caller to specify it.
#[tokio::test]
async fn valid_mode_on_source_creation_is_accepted_and_omission_defaults_to_upsert() {
    let (_conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);

    for good_mode in ["upsert", "full_replace"] {
        let payload = json!({
            "name": format!("source-{}", Uuid::new_v4()),
            "source_url": "http://127.0.0.1:1/feed.txt",
            "cron_schedule": "0 0 * * *",
            "target_group_name": "group",
            "mode": good_mode,
        });
        let req = common::signed_request(&master, "POST", "/api/sources", Some(payload));
        let resp = app.clone().oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK, "mode '{good_mode}' should be accepted");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        let created: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(created["mode"], json!(good_mode));
    }

    let payload = json!({
        "name": format!("source-{}", Uuid::new_v4()),
        "source_url": "http://127.0.0.1:1/feed.txt",
        "cron_schedule": "0 0 * * *",
        "target_group_name": "group",
    });
    let req = common::signed_request(&master, "POST", "/api/sources", Some(payload));
    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let created: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(created["mode"], json!("upsert"), "omitting mode must default to upsert");
}

/// An update that tries to set an invalid `mode` must be rejected without mutating the existing
/// row — mirrors `invalid_cron_on_source_update_is_rejected_without_mutating_existing_row` above.
#[tokio::test]
async fn invalid_mode_on_source_update_is_rejected_without_mutating_existing_row() {
    let (conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);

    let create_payload = json!({
        "name": "existing-source-mode",
        "source_url": "http://127.0.0.1:1/feed.txt",
        "cron_schedule": "0 0 * * *",
        "target_group_name": "group",
        "mode": "upsert",
    });
    let create_req = common::signed_request(&master, "POST", "/api/sources", Some(create_payload));
    let create_resp = app.clone().oneshot(create_req).await.expect("response");
    assert_eq!(create_resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(create_resp.into_body(), usize::MAX).await.expect("body");
    let created: serde_json::Value = serde_json::from_slice(&body).expect("json");
    let id = created["id"].as_str().expect("id field");

    let update_payload = json!({ "mode": "not_a_real_mode" });
    let update_req = common::signed_request(&master, "PATCH", &format!("/api/sources/{id}"), Some(update_payload));
    let update_resp = app.oneshot(update_req).await.expect("response");
    assert_eq!(update_resp.status(), StatusCode::BAD_REQUEST);

    let stored = external_source::Entity::find_by_id(Uuid::parse_str(id).unwrap())
        .one(&conn)
        .await
        .expect("query")
        .expect("row exists");
    assert_eq!(stored.mode, "upsert", "the original valid mode must be unchanged");
}
