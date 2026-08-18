//! Compliance suite indexed by `RBAC_MODEL.md` rule/section: one test named `r1_`…`r7_`,
//! `s3_`…`s7_` per governance rule and normative section, so a rule with no test shows up as a
//! missing prefix in `scripts/verify_convergence.sh` rather than in an incident. Five sections
//! (§5, §7) additionally carry a test marked `ADVERSARIAL(§N)` in its doc comment — proof the
//! guarantee holds against a writer that goes around the application entirely (raw SQL), not only
//! against a cooperative one that goes through it. See `verify_convergence.sh`'s own comments for
//! why that distinction matters: a test that supplies the very safeguard it is meant to prove
//! exists only ever proves the application's own habits.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ConnectionTrait, DbErr, Set};
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

async fn grant_permission(
    conn: &sea_orm::DatabaseConnection,
    api_key_id: Uuid,
    resource_id: Uuid,
    can_sync: bool,
    can_manage: bool,
    can_view_logs: bool,
) {
    api_key_sync_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(api_key_id),
        resource_type: Set("external_source".to_owned()),
        resource_id: Set(resource_id),
        can_sync: Set(can_sync),
        can_manage: Set(can_manage),
        can_view_logs: Set(can_view_logs),
        created_at: Set(Utc::now()),
    }
    .insert(conn)
    .await
    .expect("grant permission");
}

// ---------------------------------------------------------------------------------------------
// §2 Core Governance Rules — R1 through R7
// ---------------------------------------------------------------------------------------------

/// R1 (non-amplification): a caller may only grant a verb it currently holds itself on the same
/// resource. A Parent holding `can_manage=true` but not `can_sync` on a source must be refused
/// when attempting to grant `can_sync` to a daughter key, even though it otherwise satisfies R2
/// (manage rights on the resource).
#[tokio::test]
async fn r1_cannot_grant_can_sync_without_holding_it_yourself() {
    let (conn, state, master) = common::setup().await;
    let granter = common::insert_key(&conn, "Granter", false, true, false, false, Some(master.id)).await;
    let grantee = common::insert_key(&conn, "Grantee", false, false, false, false, Some(master.id)).await;
    let source_id = insert_source(&conn, "http://127.0.0.1:1/unused", master.id).await;
    grant_permission(&conn, granter.id, source_id, false, true, false).await;

    let app = simply_ip_sync::create_app(state);
    let payload = json!({ "resource_type": "external_source", "resource_id": source_id, "can_sync": true });
    let req = common::signed_request(&granter, "PUT", &format!("/api/keys/{}/permissions", grantee.id), Some(payload));
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "R1: cannot grant can_sync without holding it yourself on the resource");
}

/// R2 (manage is a conjunction): managing a resource — here, delegating a permission on it —
/// requires **both** global `can_manage_keys` **and** a per-resource `can_manage = true` row.
/// Neither alone is sufficient. Proven both directions in one test: the global flag without the
/// per-resource row fails, and the per-resource row without the global flag also fails, even
/// though each half individually looks like it should be enough.
#[tokio::test]
async fn r2_manage_requires_both_the_global_flag_and_the_per_resource_row() {
    let (conn, state, master) = common::setup().await;
    let source_id = insert_source(&conn, "http://127.0.0.1:1/unused", master.id).await;
    let grantee = common::insert_key(&conn, "Grantee", false, false, false, false, Some(master.id)).await;

    // Half A: global can_manage_keys=true, but no permission row on the resource at all.
    let global_only = common::insert_key(&conn, "GlobalOnly", false, true, false, false, Some(master.id)).await;
    let app = simply_ip_sync::create_app(state.clone());
    let payload = json!({ "resource_type": "external_source", "resource_id": source_id, "can_view_logs": true });
    let req = common::signed_request(&global_only, "PUT", &format!("/api/keys/{}/permissions", grantee.id), Some(payload.clone()));
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "R2: can_manage_keys alone, with no per-resource can_manage row, must not suffice");

    // Half B: a per-resource can_manage=true row, but can_manage_keys=false globally.
    let per_resource_only = common::insert_key(&conn, "PerResourceOnly", false, false, false, false, Some(master.id)).await;
    grant_permission(&conn, per_resource_only.id, source_id, false, true, false).await;
    let app = simply_ip_sync::create_app(state);
    let req = common::signed_request(&per_resource_only, "PUT", &format!("/api/keys/{}/permissions", grantee.id), Some(payload));
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "R2: a per-resource can_manage row alone, without global can_manage_keys, must not suffice");
}

/// R3 (parentage confers no authority): `parent_key_id` exists solely for cascade/visibility
/// scoping. Two daughter keys with identical explicit rights but different parents — one a
/// daughter of Master, the other a daughter of an ordinary Parent key — must be refused an
/// R4-gated action identically. If lineage conferred authority, the Master's direct daughter
/// might be treated as more privileged than the Parent's daughter; R3 says it must not be.
#[tokio::test]
async fn r3_parentage_confers_no_special_authority() {
    let (conn, state, master) = common::setup().await;
    let parent = common::insert_key(&conn, "Parent", false, true, false, false, Some(master.id)).await;
    let daughter_of_master = common::insert_key(&conn, "DaughterOfMaster", false, false, false, false, Some(master.id)).await;
    let daughter_of_parent = common::insert_key(&conn, "DaughterOfParent", false, false, false, false, Some(parent.id)).await;

    let app = simply_ip_sync::create_app(state);
    let payload = json!({ "name": "attempted-escalation", "can_manage_sources": true });

    let req_a = common::signed_request(&daughter_of_master, "POST", "/api/keys", Some(payload.clone()));
    let resp_a = app.clone().oneshot(req_a).await.expect("response");
    let req_b = common::signed_request(&daughter_of_parent, "POST", "/api/keys", Some(payload));
    let resp_b = app.oneshot(req_b).await.expect("response");

    assert_eq!(resp_a.status(), StatusCode::FORBIDDEN, "R3: being a direct daughter of Master confers no extra authority");
    assert_eq!(resp_b.status(), StatusCode::FORBIDDEN, "R3: being a daughter of an ordinary Parent is refused identically");
    assert_eq!(resp_a.status(), resp_b.status(), "R3: lineage must not change the outcome of an otherwise-identical request");
}

/// R4 (only Master creates parents): only the Master key may grant `can_manage_keys`,
/// `can_manage_sources`, or `can_manage_vaults`. A Parent-tier key (`can_manage_keys=true`, but
/// not Master) must still be blocked from minting a resource-creation right on a new key.
#[tokio::test]
async fn r4_only_master_may_grant_scope_elevation() {
    let (conn, state, master) = common::setup().await;
    let parent = common::insert_key(&conn, "Parent", false, true, false, false, Some(master.id)).await;

    let app = simply_ip_sync::create_app(state);
    let payload = json!({ "name": "attempted-escalation", "can_manage_sources": true });
    let req = common::signed_request(&parent, "POST", "/api/keys", Some(payload));
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "R4: only Master may grant a resource-creation right");
}

/// R5 (manage may propagate sideways): a Parent holding manage rights on a resource may grant
/// manage rights on that same resource to *another existing Parent key* — this is not the
/// Parent's own tier expanding (parent_b already holds `can_manage_keys` from its own creation,
/// independent of this grant), only the resource-level permission propagating between two peers.
#[tokio::test]
async fn r5_manage_may_propagate_sideways_between_parents() {
    let (conn, state, master) = common::setup().await;
    let parent_a = common::insert_key(&conn, "ParentA", false, true, false, false, Some(master.id)).await;
    let parent_b = common::insert_key(&conn, "ParentB", false, true, false, false, Some(master.id)).await;
    let source_id = insert_source(&conn, "http://127.0.0.1:1/unused", master.id).await;
    grant_permission(&conn, parent_a.id, source_id, false, true, false).await;

    let app = simply_ip_sync::create_app(state);
    let payload = json!({ "resource_type": "external_source", "resource_id": source_id, "can_manage": true });
    let req = common::signed_request(&parent_a, "PUT", &format!("/api/keys/{}/permissions", parent_b.id), Some(payload));
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK, "R5: manage rights may propagate sideways between two Parent-tier keys");
}

/// R6 (revocation is never escalation): revoking a permission requires only R2 (manage rights on
/// the resource) — the revoker need not hold the verb being removed. A Parent with `can_manage`
/// but not `can_sync` must still be able to revoke someone else's `can_sync` grant.
#[tokio::test]
async fn r6_revocation_requires_only_manage_not_the_verb_itself() {
    let (conn, state, master) = common::setup().await;
    let revoker = common::insert_key(&conn, "Revoker", false, true, false, false, Some(master.id)).await;
    let grantee = common::insert_key(&conn, "Grantee", false, false, false, false, Some(master.id)).await;
    let source_id = insert_source(&conn, "http://127.0.0.1:1/unused", master.id).await;
    grant_permission(&conn, revoker.id, source_id, false, true, false).await;

    let grantee_permission_id = Uuid::new_v4();
    api_key_sync_permission::ActiveModel {
        id: Set(grantee_permission_id),
        api_key_id: Set(grantee.id),
        resource_type: Set("external_source".to_owned()),
        resource_id: Set(source_id),
        can_sync: Set(true),
        can_manage: Set(false),
        can_view_logs: Set(false),
        created_at: Set(Utc::now()),
    }
    .insert(&conn)
    .await
    .expect("grant can_sync to grantee");

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

/// R7 (granting is bounded by R1 and R2 together): the positive complement to `r1_`'s negative
/// case. A granter who satisfies **both** halves — R2's conjunction (`can_manage_keys` and a
/// per-resource `can_manage` row) and R1 (holding `can_sync` itself on that resource) — must
/// succeed in granting `can_sync` to another key.
#[tokio::test]
async fn r7_granting_succeeds_only_when_r1_and_r2_both_hold() {
    let (conn, state, master) = common::setup().await;
    let granter = common::insert_key(&conn, "Granter", false, true, false, false, Some(master.id)).await;
    let grantee = common::insert_key(&conn, "Grantee", false, false, false, false, Some(master.id)).await;
    let source_id = insert_source(&conn, "http://127.0.0.1:1/unused", master.id).await;
    // R2: can_manage_keys (via insert_key above) + a can_manage=true row. R1: also holds can_sync.
    grant_permission(&conn, granter.id, source_id, true, true, false).await;

    let app = simply_ip_sync::create_app(state);
    let payload = json!({ "resource_type": "external_source", "resource_id": source_id, "can_sync": true });
    let req = common::signed_request(&granter, "PUT", &format!("/api/keys/{}/permissions", grantee.id), Some(payload));
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK, "R7: granting succeeds once both R1 and R2 hold simultaneously");
}

// ---------------------------------------------------------------------------------------------
// §3 Resource Lifecycle & Ownership
// ---------------------------------------------------------------------------------------------

/// §3: lifecycle actions (delete, rename) are restricted to Master and the resource's designated
/// `owner_key_id`. Holding `can_manage` (R2) confers no lifecycle authority — a Parent that
/// merely manages a resource's configuration must not be able to delete it.
#[tokio::test]
async fn s3_resource_lifecycle_delete_requires_owner_or_master() {
    let (conn, state, master) = common::setup().await;
    let owner = common::insert_key(&conn, "Owner", false, true, true, true, Some(master.id)).await;
    let other_parent = common::insert_key(&conn, "OtherParent", false, true, true, true, Some(master.id)).await;
    let source_id = insert_source(&conn, "http://127.0.0.1:1/unused", owner.id).await;

    // Grant `other_parent` full manage rights (R2 conjunct) on the resource, but they are not the
    // owner — §3 says manage rights confer no lifecycle authority.
    grant_permission(&conn, other_parent.id, source_id, true, true, true).await;

    let app = simply_ip_sync::create_app(state);
    let req = common::signed_request(&other_parent, "DELETE", &format!("/api/sources/{source_id}"), None);
    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "§3: manage rights alone do not confer lifecycle authority");

    let req_owner = common::signed_request(&owner, "DELETE", &format!("/api/sources/{source_id}"), None);
    let resp_owner = app.oneshot(req_owner).await.expect("response");
    assert_eq!(resp_owner.status(), StatusCode::NO_CONTENT, "the owner may always delete their own resource");
}

// ---------------------------------------------------------------------------------------------
// §4 Visibility & Oracle Discipline
// ---------------------------------------------------------------------------------------------

/// §4 (oracle discipline): a vault endpoint that exists but is out of the caller's visibility
/// scope, and a vault endpoint id that does not exist at all, must be byte-for-byte
/// indistinguishable — same status, same body. If they differed, an unauthorized caller could
/// enumerate real resource ids by noticing which ids get a *different* 404 shape than
/// obviously-random ones.
#[tokio::test]
async fn s4_out_of_scope_and_nonexistent_vaults_are_indistinguishable() {
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

// ---------------------------------------------------------------------------------------------
// §5 Master Key Guarantees
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn s5_master_key_rejects_edits_beyond_bound_ips() {
    let (conn, state, master) = common::setup().await;
    let _ = &conn;
    let app = simply_ip_sync::create_app(state);
    let payload = json!({ "name": "Renamed Master" });
    let req = common::signed_request(&master, "PATCH", &format!("/api/keys/{}", master.id), Some(payload));
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "§5: the Master key is immutable except its own bound_ips");
}

#[tokio::test]
async fn s5_master_key_rotation_is_always_refused() {
    let (_conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);
    let req = common::signed_request(&master, "POST", &format!("/api/keys/{}/rotate", master.id), None);
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "§5: rotation is refused for the Master key");
}

/// ADVERSARIAL(§5): a direct raw-SQL insert setting `is_master=1` with the generated
/// `master_marker` column absent from the insert list (it cannot be named — it is
/// engine-generated) — proving the single-Master constraint holds against a hostile writer that
/// bypasses the application entirely, not merely against a cooperative one going through
/// `bootstrap_master_key`, which is the only application code path that ever writes
/// `is_master = true`.
#[tokio::test]
async fn s5_adversarial_second_master_rejected_by_generated_column() {
    let (conn, _state, _master) = common::setup().await;
    let insert_master = |id: &str| {
        format!(
            "INSERT INTO api_keys (id, name, key_hash, prefix, is_master, can_manage_keys, can_manage_sources, can_manage_vaults, created_at, updated_at) \
             VALUES ('{id}', 'adversarial', '{id}-hash', '{id}pfx', 1, 0, 0, 0, '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
        )
    };
    // `common::setup()` already bootstrapped one Master; this is the second.
    let second: Result<_, DbErr> = conn.execute_unprepared(&insert_master("22222222-2222-2222-2222-222222222222")).await;
    assert!(second.is_err(), "§5 ADVERSARIAL: a second is_master=true row must be rejected by the DB itself, not merely refused by application logic");
}

// ---------------------------------------------------------------------------------------------
// §6 Cascade Deletion & Pre-flight Inventory
// ---------------------------------------------------------------------------------------------

/// A key that still owns a resource cannot be deleted — `delete_api_key` returns `409` with the
/// resource inventory, rather than deleting the key and leaving `owner_key_id` dangling (this is
/// precisely why `owner_key_id` carries no FK constraint — see
/// `tests/referential_integrity.rs::owner_key_id_is_deliberately_unconstrained_by_design` — the
/// safety here is enforced by this guard, not by the schema).
#[tokio::test]
async fn s6_deleting_a_key_that_still_owns_resources_is_blocked_with_inventory() {
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
async fn s6_deleting_a_key_with_no_owned_resources_succeeds() {
    let (conn, state, master) = common::setup().await;
    let empty_handed = common::insert_key(&conn, "EmptyHanded", false, false, false, false, Some(master.id)).await;

    let app = simply_ip_sync::create_app(state);
    let req = common::signed_request(&master, "DELETE", &format!("/api/keys/{}", empty_handed.id), None);
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

// ---------------------------------------------------------------------------------------------
// §7 Database Constraints & Indexing
// ---------------------------------------------------------------------------------------------

/// §7: every index the specification names must actually exist after migration — checked against
/// the database's own catalog (`db::has_index`), not against the migration source, so a migration
/// that silently fails to apply an index would still be caught here.
#[tokio::test]
async fn s7_mandatory_indexes_exist() {
    let (conn, _state, _master) = common::setup().await;
    for (table, index) in [
        ("api_keys", "idx-api_keys-master_marker"),
        ("api_keys", "idx-api_keys-parent_key_id"),
        ("api_keys", "idx-api_keys-prefix"),
        ("vault_endpoints", "idx-vault_endpoints-owner_key_id"),
        ("external_sources", "idx-external_sources-owner_key_id"),
        ("vault_sync_tasks", "idx-vault_sync_tasks-owner_key_id"),
        ("api_key_sync_permissions", "idx-api_key_sync_permissions-unique"),
        ("sync_logs", "idx-sync_logs-job_type_job_id"),
        ("sync_logs", "idx-sync_logs-timestamp"),
        ("audit_logs", "idx-audit_logs-action_timestamp"),
    ] {
        let present = simply_ip_sync::db::has_index(&conn, table, index).await.expect("has_index query");
        assert!(present, "§7: {table}.{index} must exist after migration");
    }
}

/// ADVERSARIAL(§7): `api_keys.key_hash` carries a `UNIQUE` constraint (RBAC_MODEL.md §7's
/// "fast key lookup" index doubles as the collision guard — two keys must never hash-collide
/// to the same lookup value). Proven with a direct raw-SQL insert bypassing the application's own
/// (nonexistent, here) duplicate-check logic, so the guarantee is shown to hold at the engine
/// level rather than merely because nothing in the app currently tries to violate it.
#[tokio::test]
async fn s7_adversarial_duplicate_key_hash_rejected_by_unique_constraint() {
    let (conn, _state, _master) = common::setup().await;
    let insert_daughter = |id: &str, hash: &str| {
        format!(
            "INSERT INTO api_keys (id, name, key_hash, prefix, is_master, can_manage_keys, can_manage_sources, can_manage_vaults, created_at, updated_at) \
             VALUES ('{id}', 'dup-test', '{hash}', '{id}pfx', 0, 0, 0, 0, '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
        )
    };
    conn.execute_unprepared(&insert_daughter("33333333-3333-3333-3333-333333333333", "collide-me"))
        .await
        .expect("first insert with this hash succeeds");

    let second: Result<_, DbErr> = conn
        .execute_unprepared(&insert_daughter("44444444-4444-4444-4444-444444444444", "collide-me"))
        .await;
    assert!(second.is_err(), "§7 ADVERSARIAL: a duplicate key_hash must be rejected by the DB's own UNIQUE constraint");
}

// ---------------------------------------------------------------------------------------------
// Manual-trigger permission gate (`can_sync`), and a targeted TOCTOU regression not tied to a
// single numbered rule — kept here rather than split into a separate file since both are RBAC
// enforcement properties this suite already has the fixtures for.
// ---------------------------------------------------------------------------------------------

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
    grant_permission(&conn, daughter.id, source_id, true, false, true).await;

    let app = simply_ip_sync::create_app(state);
    let req = common::signed_request(&daughter, "POST", &format!("/api/sources/{source_id}/trigger"), None);
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["status"], json!("SUCCESS"));
}

/// Builds a signed request like `common::signed_request`, but with an explicit timestamp rather
/// than always "now" — needed so two requests built back-to-back in the same wall-clock second
/// don't collide into byte-identical `CANONICAL_V1` signatures, which the anti-replay guard would
/// then (correctly) reject the second of as a replay, an artifact that has nothing to do with
/// whatever property the test actually wants to exercise concurrently.
fn signed_request_at(key: &common::TestKey, method: &str, target: &str, timestamp: i64) -> Request<Body> {
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
