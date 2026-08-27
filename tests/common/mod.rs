//! Shared test harness: an in-memory database, a pinned Master key, helpers to mint additional
//! keys directly against the database, a `CANONICAL_V1` request signer matching what a real
//! client computes, and [`MockVault`] — a *stateful* stand-in for a remote `simply_ip_vault`.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, NaiveDateTime, Utc};
use sea_orm::{ActiveModelTrait, Database, DatabaseConnection, Set};
use simply_ip_sync::crypto::SecretCipher;
use simply_ip_sync::entities::api_key;
use simply_ip_sync::state::AppState;
use simply_ip_sync::{api, crypto, db};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

// =============================================================================================
// MockVault — a stateful stand-in for a remote `simply_ip_vault`
// =============================================================================================

/// One stored record inside a [`MockVault`] group.
#[derive(Debug, Clone)]
pub struct StoredRecord {
    /// The address exactly as the vault canonicalised and stored it.
    pub target_address: String,
    /// Free-text cause. An omitted `cause` on an upsert leaves the existing value untouched
    /// (never clears it), matching the real vault's documented `BatchRecordInput` contract.
    pub cause: Option<String>,
    /// Tombstone flag.
    pub is_deleted: bool,
    /// When the tombstone was set. `None` while the record is live.
    pub deleted_at: Option<NaiveDateTime>,
    /// Creation timestamp. Never overwritten by a later upsert.
    pub created_at: NaiveDateTime,
    /// Last modification timestamp.
    pub updated_at: NaiveDateTime,
    /// Last time the record was observed. **A soft delete deliberately does not touch this** —
    /// see [`MockVault::soft_delete`].
    pub last_seen_at: NaiveDateTime,
}

/// A `GET /api/ips` call as the vault received it, for asserting what the sync engine actually
/// asked for rather than only what it did with the answer.
#[derive(Debug, Clone)]
pub struct RecordedGet {
    /// `group_name` query parameter.
    pub group_name: Option<String>,
    /// `since` query parameter, as the raw Unix-seconds string the client sent.
    pub since: Option<String>,
    /// `include_deleted` query parameter.
    pub include_deleted: Option<String>,
    /// `limit` query parameter.
    pub limit: Option<u64>,
    /// `offset` query parameter.
    pub offset: Option<u64>,
    /// How many records this call returned.
    pub returned: usize,
}

/// A `POST /api/records/batch` call as the vault received it.
#[derive(Debug, Clone)]
pub struct RecordedBatch {
    /// `group_name` from the request body.
    pub group_name: String,
    /// `mode` from the request body (`"upsert"` / `"full_replace"`).
    pub mode: String,
    /// How many records the batch carried.
    pub records: usize,
    /// Canonicalised addresses the batch carried, in wire order. Captured so a test can assert the
    /// engine did not *send* a duplicate — an assertion the stored map alone cannot make, since it
    /// is keyed by address and would silently absorb one.
    pub addresses: Vec<String>,
    /// The `is_deleted` flag each record carried, positionally aligned with [`Self::addresses`].
    pub tombstones: Vec<bool>,
}

#[derive(Debug, Default)]
struct VaultData {
    /// `group_name` → (canonical address → record). `BTreeMap` so pagination order is
    /// deterministic across runs, which is what makes `limit`/`offset` assertions meaningful.
    groups: HashMap<String, BTreeMap<String, StoredRecord>>,
    gets: Vec<RecordedGet>,
    batches: Vec<RecordedBatch>,
}

/// Canonicalises an address the way `simply_ip_vault` does before keying storage on it: a bare
/// address is normalised through `IpAddr` (so alternate spellings of the same IPv6 address collapse
/// to one key), and a CIDR has its host bits masked off. Anything unparseable is stored verbatim —
/// the mock's job is to mirror the real vault's dedup key, not to re-validate input the sync engine
/// already forwarded.
///
/// For the plain IPv4 host addresses these tests use this is the identity function; it exists so
/// the "no duplicates after canonicalisation" assertion is genuinely testing a canonical key rather
/// than raw string equality.
pub fn canonicalize_address(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Ok(ip) = IpAddr::from_str(trimmed) {
        return ip.to_string();
    }
    if let Ok(net) = ipnetwork::IpNetwork::from_str(trimmed) {
        return format!("{}/{}", net.network(), net.prefix());
    }
    trimmed.to_owned()
}

/// An in-process, **stateful** stand-in for a remote `simply_ip_vault`.
///
/// # Why this exists alongside the plain `wiremock` stubs
///
/// The canned-response stubs elsewhere in this suite can prove *what the sync engine asked for*
/// (how many pages, how many chunks, which query string) but not *what the target ended up
/// holding* — every response is a fixture, so "the target now has 1,500 distinct records" is not a
/// question they can answer. This mock keeps a real record store behind the same two endpoints the
/// engine actually calls, so a test can assert **convergence** — record counts, dedup on the
/// canonical address, tombstone flags, and that an unrelated group was left alone.
///
/// # Fidelity to the real contract
///
/// Two behaviours are mirrored deliberately because the tests turn on them:
///
/// - **`since` is an OR across two columns.** A record is in scope when `last_seen_at >= since`,
///   **or** — only when `include_deleted=true` — when it is a tombstone whose `deleted_at >= since`.
///   The second arm is load-bearing: a soft delete does not touch `last_seen_at`, so without it a
///   record last seen before the cutoff and deleted after it would be invisible to every subsequent
///   differential sync and the deletion would never replicate.
/// - **Upsert never implicitly deletes.** `mode: "upsert"` adds and updates only. `full_replace` is
///   also implemented (it soft-deletes group members the batch omits) so a test can assert the
///   inter-vault pipeline never sends it — `vault_sync_tasks.mode` is always `upsert`.
///
/// # Binding
///
/// Backed by `wiremock::MockServer`, which binds `127.0.0.1:0` and lets the OS assign a free
/// ephemeral port. That is strictly stronger than scanning a fixed range such as `3000..=3100`:
/// there is no window between "found free" and "bound" for another process to take the port, so
/// suites run in parallel under `cargo test` without collisions.
pub struct MockVault {
    server: MockServer,
    data: Arc<Mutex<VaultData>>,
}

impl MockVault {
    /// Starts a vault on an OS-assigned loopback port with both endpoints mounted.
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        let data = Arc::new(Mutex::new(VaultData::default()));

        let get_data = Arc::clone(&data);
        Mock::given(method("GET"))
            .and(path("/api/ips"))
            .respond_with(move |req: &wiremock::Request| Self::handle_get(&get_data, req))
            .mount(&server)
            .await;

        let post_data = Arc::clone(&data);
        Mock::given(method("POST"))
            .and(path("/api/records/batch"))
            .respond_with(move |req: &wiremock::Request| Self::handle_batch(&post_data, req))
            .mount(&server)
            .await;

        Self { server, data }
    }

    /// Base URL to store in a `vault_endpoints.target_url`.
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VaultData> {
        self.data.lock().expect("mock vault state lock is never held across a panic")
    }

    /// Inserts (or refreshes) `addresses` in `group`, stamped `seen_at`. Used both for initial
    /// seeding and for "new records appeared on the source" mutations.
    pub fn seed(&self, group: &str, addresses: impl IntoIterator<Item = String>, seen_at: DateTime<Utc>) {
        let stamp = seen_at.naive_utc();
        let mut data = self.lock();
        let entries = data.groups.entry(group.to_owned()).or_default();
        for address in addresses {
            let key = canonicalize_address(&address);
            entries
                .entry(key.clone())
                .and_modify(|existing| {
                    existing.updated_at = stamp;
                    existing.last_seen_at = stamp;
                })
                .or_insert(StoredRecord {
                    target_address: key,
                    cause: None,
                    is_deleted: false,
                    deleted_at: None,
                    created_at: stamp,
                    updated_at: stamp,
                    last_seen_at: stamp,
                });
        }
    }

    /// Soft-deletes `addresses` in `group`, stamping `deleted_at`.
    ///
    /// **`last_seen_at` is deliberately left untouched**, mirroring the real vault: a deletion is
    /// not a sighting. This is precisely why the `since` filter needs its tombstone arm, and it is
    /// what makes the differential-sync test's "only the changed records come back" assertion
    /// meaningful rather than accidental.
    ///
    /// Panics if an address is not present — a test that soft-deletes a record it never seeded is
    /// asserting against a fixture that does not exist, and should fail loudly at setup.
    pub fn soft_delete(&self, group: &str, addresses: &[String], deleted_at: DateTime<Utc>) {
        let stamp = deleted_at.naive_utc();
        let mut data = self.lock();
        let entries = data
            .groups
            .get_mut(group)
            .unwrap_or_else(|| panic!("group '{group}' has not been seeded"));
        for address in addresses {
            let key = canonicalize_address(address);
            let record = entries
                .get_mut(&key)
                .unwrap_or_else(|| panic!("'{key}' is not present in group '{group}'"));
            record.is_deleted = true;
            record.deleted_at = Some(stamp);
            record.updated_at = stamp;
        }
    }

    /// Every record in `group`, live and tombstoned, keyed by canonical address.
    pub fn records(&self, group: &str) -> BTreeMap<String, StoredRecord> {
        self.lock().groups.get(group).cloned().unwrap_or_default()
    }

    /// Total distinct records in `group` (tombstones included — a tombstone is still a row).
    pub fn record_count(&self, group: &str) -> usize {
        self.lock().groups.get(group).map_or(0, BTreeMap::len)
    }

    /// Canonical addresses in `group` that are currently tombstoned.
    pub fn deleted_addresses(&self, group: &str) -> Vec<String> {
        self.lock()
            .groups
            .get(group)
            .map(|g| g.values().filter(|r| r.is_deleted).map(|r| r.target_address.clone()).collect())
            .unwrap_or_default()
    }

    /// Canonical addresses in `group` that are currently live.
    pub fn live_addresses(&self, group: &str) -> Vec<String> {
        self.lock()
            .groups
            .get(group)
            .map(|g| g.values().filter(|r| !r.is_deleted).map(|r| r.target_address.clone()).collect())
            .unwrap_or_default()
    }

    /// Every `GET /api/ips` this vault has served, in order.
    pub fn gets(&self) -> Vec<RecordedGet> {
        self.lock().gets.clone()
    }

    /// Every `POST /api/records/batch` this vault has served, in order.
    pub fn batches(&self) -> Vec<RecordedBatch> {
        self.lock().batches.clone()
    }

    fn handle_get(data: &Arc<Mutex<VaultData>>, req: &wiremock::Request) -> ResponseTemplate {
        let param = |name: &str| {
            req.url
                .query_pairs()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.into_owned())
        };
        let group_name = param("group_name");
        let since_raw = param("since");
        let include_deleted_raw = param("include_deleted");
        let limit = param("limit").and_then(|v| v.parse::<u64>().ok());
        let offset = param("offset").and_then(|v| v.parse::<u64>().ok());

        let include_deleted = include_deleted_raw.as_deref() == Some("true");
        let since = since_raw
            .as_deref()
            .and_then(|v| v.parse::<i64>().ok())
            .and_then(|secs| DateTime::from_timestamp(secs, 0))
            .map(|dt| dt.naive_utc());

        let mut guard = data.lock().expect("mock vault state lock");
        let mut matched: Vec<serde_json::Value> = Vec::new();

        if let Some(group) = group_name.as_deref()
            && let Some(entries) = guard.groups.get(group)
        {
            for record in entries.values() {
                if record.is_deleted && !include_deleted {
                    continue;
                }
                let in_window = match since {
                    None => true,
                    // The OR the module header calls out: a sighting since the cutoff, or a
                    // tombstone raised since the cutoff. A record can qualify on the second arm
                    // alone, which is the whole reason deletions replicate at all.
                    Some(cutoff) => {
                        record.last_seen_at >= cutoff
                            || (include_deleted
                                && record.is_deleted
                                && record.deleted_at.is_some_and(|d| d >= cutoff))
                    }
                };
                if !in_window {
                    continue;
                }
                matched.push(serde_json::json!({
                    "id": Uuid::new_v4(),
                    "target_address": record.target_address,
                    "group_name": group,
                    "cause": record.cause,
                    "is_deleted": record.is_deleted,
                    "deleted_at": record.deleted_at,
                    "created_at": record.created_at,
                    "updated_at": record.updated_at,
                    "last_seen_at": record.last_seen_at,
                }));
            }
        }

        let start = offset.unwrap_or(0) as usize;
        let end = match limit {
            Some(l) => start.saturating_add(l as usize).min(matched.len()),
            None => matched.len(),
        };
        let page: Vec<serde_json::Value> =
            if start >= matched.len() { Vec::new() } else { matched[start..end].to_vec() };

        guard.gets.push(RecordedGet {
            group_name,
            since: since_raw,
            include_deleted: include_deleted_raw,
            limit,
            offset,
            returned: page.len(),
        });

        ResponseTemplate::new(200).set_body_json(page)
    }

    fn handle_batch(data: &Arc<Mutex<VaultData>>, req: &wiremock::Request) -> ResponseTemplate {
        #[derive(serde::Deserialize)]
        struct BatchPayload {
            group_name: String,
            #[serde(default)]
            mode: Option<String>,
            records: Vec<BatchRecord>,
        }
        #[derive(serde::Deserialize)]
        struct BatchRecord {
            target_address: String,
            #[serde(default)]
            cause: Option<String>,
            #[serde(default)]
            is_deleted: Option<bool>,
            #[serde(default)]
            created_at: Option<NaiveDateTime>,
            #[serde(default)]
            updated_at: Option<NaiveDateTime>,
            #[serde(default)]
            last_seen_at: Option<NaiveDateTime>,
            #[serde(default)]
            deleted_at: Option<NaiveDateTime>,
        }

        let Ok(payload) = req.body_json::<BatchPayload>() else {
            return ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "malformed batch payload"
            }));
        };

        let mode = payload.mode.unwrap_or_else(|| "upsert".to_owned());
        let now = Utc::now().naive_utc();

        let mut guard = data.lock().expect("mock vault state lock");
        guard.batches.push(RecordedBatch {
            group_name: payload.group_name.clone(),
            mode: mode.clone(),
            records: payload.records.len(),
            addresses: payload.records.iter().map(|r| canonicalize_address(&r.target_address)).collect(),
            tombstones: payload.records.iter().map(|r| r.is_deleted.unwrap_or(false)).collect(),
        });

        let entries = guard.groups.entry(payload.group_name.clone()).or_default();
        let mut created = 0u64;
        let mut updated = 0u64;
        let mut restored = 0u64;
        let mut soft_deleted = 0u64;
        let mut present: Vec<String> = Vec::with_capacity(payload.records.len());

        for record in payload.records {
            let key = canonicalize_address(&record.target_address);
            present.push(key.clone());
            let is_deleted = record.is_deleted.unwrap_or(false);

            match entries.get_mut(&key) {
                Some(existing) => {
                    if existing.is_deleted && !is_deleted {
                        restored += 1;
                    }
                    if !existing.is_deleted && is_deleted {
                        soft_deleted += 1;
                    }
                    // An omitted `cause` leaves the stored value alone rather than clearing it.
                    if record.cause.is_some() {
                        existing.cause = record.cause;
                    }
                    existing.is_deleted = is_deleted;
                    existing.deleted_at = if is_deleted { record.deleted_at.or(Some(now)) } else { None };
                    existing.updated_at = record.updated_at.unwrap_or(now);
                    existing.last_seen_at = record.last_seen_at.unwrap_or(existing.last_seen_at);
                    updated += 1;
                }
                None => {
                    entries.insert(
                        key.clone(),
                        StoredRecord {
                            target_address: key,
                            cause: record.cause,
                            is_deleted,
                            deleted_at: if is_deleted { record.deleted_at.or(Some(now)) } else { None },
                            // `created_at` is honoured only for genuinely new rows.
                            created_at: record.created_at.unwrap_or(now),
                            updated_at: record.updated_at.unwrap_or(now),
                            last_seen_at: record.last_seen_at.unwrap_or(now),
                        },
                    );
                    created += 1;
                }
            }
        }

        if mode == "full_replace" {
            let omitted: Vec<String> = entries
                .keys()
                .filter(|k| !present.contains(k))
                .cloned()
                .collect();
            for key in omitted {
                if let Some(record) = entries.get_mut(&key)
                    && !record.is_deleted
                {
                    record.is_deleted = true;
                    record.deleted_at = Some(now);
                    record.updated_at = now;
                    soft_deleted += 1;
                }
            }
        }

        let linked = created + updated;
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "created": created,
            "updated": updated,
            "restored": restored,
            "locked_skipped": 0,
            "soft_deleted": soft_deleted,
            "linked": linked,
        }))
    }
}
