//! Shared test harness: an in-memory database, a pinned Master key, helpers to mint additional
//! keys directly against the database, and a `CANONICAL_V1` request signer matching what a real
//! client computes.

#![allow(dead_code)]

use chrono::Utc;
use sea_orm::{ActiveModelTrait, Database, DatabaseConnection, Set};
use simply_ip_sync::crypto::SecretCipher;
use simply_ip_sync::entities::api_key;
use simply_ip_sync::state::AppState;
use simply_ip_sync::{api, crypto, db};
use uuid::Uuid;

/// A freshly minted key plus its plaintext credentials, kept around only for the test that
/// created it (never persisted anywhere the way a real client's secrets would be).
pub struct TestKey {
    pub id: Uuid,
    pub plaintext_key: String,
    pub signing_secret: String,
}

/// Builds an in-memory database with migrations applied, a pinned Master key, and `AppState`
/// wired to a `Plaintext` cipher (so `insert_key`'s sealed secrets round-trip without needing a
/// real `SYNC_ENCRYPTION_KEY`).
pub async fn setup() -> (DatabaseConnection, AppState, TestKey) {
    let conn = Database::connect("sqlite::memory:").await.expect("connect");
    db::run_migrations(&conn).await.expect("migrate");
    let master = insert_key(&conn, "Master", true, true, true, true, None).await;
    let state = AppState::for_tests(conn.clone(), master.id).await;
    (conn, state, master)
}

/// Inserts a key directly against the database (bypassing the HTTP API, the way an integration
/// suite is expected to mint credentials for its scenarios).
#[allow(clippy::too_many_arguments)]
pub async fn insert_key(
    conn: &DatabaseConnection,
    name: &str,
    is_master: bool,
    can_manage_keys: bool,
    can_manage_sources: bool,
    can_manage_vaults: bool,
    parent_key_id: Option<Uuid>,
) -> TestKey {
    let plaintext_key = api::generate_random_key();
    let signing_secret = crypto::generate_signing_secret();
    let id = Uuid::new_v4();
    let now = Utc::now();
    let sealed = SecretCipher::Plaintext.seal(&signing_secret).expect("seal");

    let model = api_key::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        key_hash: Set(api::hash_key(&plaintext_key)),
        signing_secret: Set(Some(sealed)),
        prefix: Set(api::key_prefix(&plaintext_key)),
        is_master: Set(is_master),
        can_manage_keys: Set(can_manage_keys),
        can_manage_sources: Set(can_manage_sources),
        can_manage_vaults: Set(can_manage_vaults),
        parent_key_id: Set(parent_key_id),
        bound_ips: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    model.insert(conn).await.expect("insert key");

    TestKey { id, plaintext_key, signing_secret }
}

/// Computes the three `CANONICAL_V1` headers a real client would send for `method`/`target`/`body`.
pub fn sign(key: &TestKey, method: &str, target: &str, body: &[u8]) -> (String, String, String) {
    let timestamp = Utc::now().timestamp().to_string();
    let signature =
        crypto::compute_signature(&key.signing_secret, method, target, &timestamp, body).expect("sign");
    (key.plaintext_key.clone(), timestamp, signature)
}

/// Builds a fully signed request against `target` (path plus query string), ready for
/// `tower::ServiceExt::oneshot` against the real router. Manually inserts a `ConnectInfo`
/// extension since the test harness never binds a real listener.
pub fn signed_request(key: &TestKey, method: &str, target: &str, body: Option<serde_json::Value>) -> axum::http::Request<axum::body::Body> {
    let body_bytes = match &body {
        Some(v) => serde_json::to_vec(v).expect("serialize body"),
        None => Vec::new(),
    };
    let (api_key, timestamp, signature) = sign(key, method, target, &body_bytes);

    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(target)
        .header("X-API-Key", api_key)
        .header("X-Timestamp", timestamp)
        .header("X-Signature-256", signature);
    if body.is_some() {
        builder = builder.header("Content-Type", "application/json");
    }
    let mut req = builder.body(axum::body::Body::from(body_bytes)).expect("build request");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 55555))));
    req
}
