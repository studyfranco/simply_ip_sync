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

/// R1 (non-amplification): a caller may only grant a verb it currently holds itself on the same
/// resource. A Parent holding `can_manage=true` but not `can_sync` on a source must be refused
/// when attempting to grant `can_sync` to a daughter key, even though it otherwise satisfies R2
/// (manage rights on the resource).
#[tokio::test]
async fn cannot_grant_can_sync_without_holding_it_yourself_r1() {
    let (conn, state, master) = common::setup().await;
    let granter = common::insert_key(&conn, "Granter", false, true, false, false, Some(master.id)).await;
    let grantee = common::insert_key(&conn, "Grantee", false, false, false, false, Some(master.id)).await;
    let source_id = insert_source(&conn, "http://127.0.0.1:1/unused", master.id).await;

    let granter_permission = api_key_sync_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(granter.id),
        resource_type: Set("external_source".to_owned()),
        resource_id: Set(source_id),
        can_sync: Set(false),
        can_manage: Set(true),
        can_view_logs: Set(false),
        created_at: Set(Utc::now()),
    };
    granter_permission.insert(&conn).await.expect("grant manage-only to granter");

    let app = simply_ip_sync::create_app(state);
    let payload = json!({ "resource_type": "external_source", "resource_id": source_id, "can_sync": true });
    let req = common::signed_request(&granter, "PUT", &format!("/api/keys/{}/permissions", grantee.id), Some(payload));
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "R1: cannot grant can_sync without holding it yourself on the resource");
}

/// R6 (revocation is never escalation): revoking a permission requires only R2 (manage rights on
/// the resource) — the revoker need not hold the verb being removed. A Parent with `can_manage`
/// but not `can_sync` must still be able to revoke someone else's `can_sync` grant.
#[tokio::test]
async fn revocation_requires_only_manage_not_the_verb_itself_r6() {
    let (conn, state, master) = common::setup().await;
    let revoker = common::insert_key(&conn, "Revoker", false, true, false, false, Some(master.id)).await;
    let grantee = common::insert_key(&conn, "Grantee", false, false, false, false, Some(master.id)).await;
    let source_id = insert_source(&conn, "http://127.0.0.1:1/unused", master.id).await;

    let revoker_permission = api_key_sync_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(revoker.id),
        resource_type: Set("external_source".to_owned()),
        resource_id: Set(source_id),
        can_sync: Set(false),
        can_manage: Set(true),
        can_view_logs: Set(false),
        created_at: Set(Utc::now()),
    };
    revoker_permission.insert(&conn).await.expect("grant manage-only to revoker");

    let grantee_permission_id = Uuid::new_v4();
    let grantee_permission = api_key_sync_permission::ActiveModel {
        id: Set(grantee_permission_id),
        api_key_id: Set(grantee.id),
        resource_type: Set("external_source".to_owned()),
        resource_id: Set(source_id),
        can_sync: Set(true),
        can_manage: Set(false),
        can_view_logs: Set(false),
        created_at: Set(Utc::now()),
    };
    grantee_permission.insert(&conn).await.expect("grant can_sync to grantee");

    let app = simply_ip_sync::create_app(state);
    let req = common::signed_request(
        &revoker,
        "DELETE",
        &format!("/api/keys/{}/permissions/{}", grantee.id, grantee_permission_id),
        None,
    );
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "R6: revocation needs only manage rights, not the verb being removed");
}

/// A key that still owns a resource cannot be deleted — `delete_api_key` returns `409` with the
/// resource inventory, rather than deleting the key and leaving `owner_key_id` dangling (this is
/// precisely why `owner_key_id` carries no FK constraint — see
/// `tests/referential_integrity.rs::owner_key_id_is_deliberately_unconstrained_by_design` — the
/// safety here is enforced by this guard, not by the schema).
#[tokio::test]
async fn deleting_a_key_that_still_owns_resources_is_blocked_with_inventory() {
    let (conn, state, master) = common::setup().await;
    let owner = common::insert_key(&conn, "Owner", false, false, true, false, Some(master.id)).await;
    let source_id = insert_source(&conn, "http://127.0.0.1:1/unused", owner.id).await;

    let app = simply_ip_sync::create_app(state);
    let req = common::signed_request(&master, "DELETE", &format!("/api/keys/{}", owner.id), None);
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = body_json(resp).await;
    let owned = body["owned_resources"].as_array().expect("owned_resources array");
    assert_eq!(owned.len(), 1);
    assert_eq!(owned[0]["id"], json!(source_id));
}

/// The mirror case: a key that owns nothing deletes cleanly.
#[tokio::test]
async fn deleting_a_key_with_no_owned_resources_succeeds() {
    let (conn, state, master) = common::setup().await;
    let empty_handed = common::insert_key(&conn, "EmptyHanded", false, false, false, false, Some(master.id)).await;

    let app = simply_ip_sync::create_app(state);
    let req = common::signed_request(&master, "DELETE", &format!("/api/keys/{}", empty_handed.id), None);
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

/// Enumeration resistance (oracle discipline): a vault endpoint that exists but is out of the
/// caller's visibility scope, and a vault endpoint id that does not exist at all, must be
/// byte-for-byte indistinguishable — same status, same body. If they differed, an unauthorized
/// caller could enumerate real resource ids by noticing which ids get a *different* 404 shape than
/// obviously-random ones.
#[tokio::test]
async fn out_of_scope_and_nonexistent_vaults_are_indistinguishable() {
    let (conn, state, master) = common::setup().await;
    let stranger = common::insert_key(&conn, "Stranger", false, false, false, false, Some(master.id)).await;
    let out_of_scope_id = {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let sealed = simply_ip_sync::crypto::SecretCipher::Plaintext.seal("secret").unwrap();
        let model = simply_ip_sync::entities::vault_endpoint::ActiveModel {
            id: Set(id),
            name: Set("owned-by-master".to_owned()),
            target_url: Set("http://127.0.0.1:1".to_owned()),
            api_key: Set("k".to_owned()),
            signing_secret: Set(sealed),
            description: Set(None),
            owner_key_id: Set(Some(master.id)),
            created_at: Set(now),
            updated_at: Set(now),
        };
        model.insert(&conn).await.expect("insert vault owned by someone else");
        id
    };
    let nonexistent_id = Uuid::new_v4();

    let app = simply_ip_sync::create_app(state);
    let req_out_of_scope = common::signed_request(&stranger, "GET", &format!("/api/vaults/{out_of_scope_id}"), None);
    let resp_out_of_scope = app.clone().oneshot(req_out_of_scope).await.expect("response");
    let status_out_of_scope = resp_out_of_scope.status();
    let body_out_of_scope = body_json(resp_out_of_scope).await;

    let req_nonexistent = common::signed_request(&stranger, "GET", &format!("/api/vaults/{nonexistent_id}"), None);
    let resp_nonexistent = app.oneshot(req_nonexistent).await.expect("response");
    let status_nonexistent = resp_nonexistent.status();
    let body_nonexistent = body_json(resp_nonexistent).await;

    assert_eq!(status_out_of_scope, StatusCode::NOT_FOUND);
    assert_eq!(status_out_of_scope, status_nonexistent, "an out-of-scope resource must return the same status as one that doesn't exist");
    assert_eq!(body_out_of_scope, body_nonexistent, "an out-of-scope resource must return the same body as one that doesn't exist");
}

/// Builds a signed request like `common::signed_request`, but with an explicit timestamp rather
/// than always "now" — needed so two requests built back-to-back in the same wall-clock second
/// don't collide into byte-identical `CANONICAL_V1` signatures, which the anti-replay guard would
/// then (correctly) reject the second of as a replay, an artifact that has nothing to do with
/// whatever property the test actually wants to exercise concurrently.
fn signed_request_at(key: &common::TestKey, method: &str, target: &str, timestamp: i64) -> axum::http::Request<Body> {
    let ts = timestamp.to_string();
    let signature = simply_ip_sync::crypto::compute_signature(&key.signing_secret, method, target, &ts, b"").expect("sign");
    let mut req = Request::builder()
        .method(method)
        .uri(target)
        .header("X-API-Key", key.plaintext_key.clone())
        .header("X-Timestamp", ts)
        .header("X-Signature-256", signature)
        .body(Body::empty())
        .expect("build");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 55555))));
    req
}

/// Two genuinely concurrent `DELETE` requests for the same resource, fired via `tokio::join!`
/// against the same shared-state router rather than sequentially — proves the
/// find-then-delete sequence in `delete_external_source` doesn't let both requests observe the row
/// as present and both report success. `simply_ip_sync`'s SQLite pool is pinned to a single
/// connection (`db::SQLITE_MAX_CONNECTIONS`), which serializes the two requests' actual queries
/// regardless — this test proves the *outcome* end to end (exactly one `204`, exactly one `404`)
/// rather than assuming that serialization is sufficient from reading the pool config alone.
#[tokio::test]
async fn concurrent_deletes_of_the_same_resource_do_not_both_succeed() {
    let (conn, state, master) = common::setup().await;
    let source_id = insert_source(&conn, "http://127.0.0.1:1/unused", master.id).await;

    let app = simply_ip_sync::create_app(state);
    let now = Utc::now().timestamp();
    // Distinct timestamps (not distinct in any way that matters to the property under test — see
    // this helper's doc comment) so both requests carry distinct, individually-valid signatures.
    let target = format!("/api/sources/{source_id}");
    let req_a = signed_request_at(&master, "DELETE", &target, now);
    let req_b = signed_request_at(&master, "DELETE", &target, now + 1);

    let app_a = app.clone();
    let app_b = app.clone();
    let (resp_a, resp_b) = tokio::join!(app_a.oneshot(req_a), app_b.oneshot(req_b));
    let status_a = resp_a.expect("response a").status();
    let status_b = resp_b.expect("response b").status();

    let statuses = {
        let mut s = vec![status_a, status_b];
        s.sort_by_key(|s| s.as_u16());
        s
    };
    assert_eq!(
        statuses,
        vec![StatusCode::NO_CONTENT, StatusCode::NOT_FOUND],
        "exactly one concurrent delete must succeed (204) and the other must find nothing left to delete (404), never both 204"
    );
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
