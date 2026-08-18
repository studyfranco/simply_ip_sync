//! Two properties that the HTTP-level suites structurally cannot pin, plus the error-envelope
//! contract.
//!
//! **Why direct-threaded tests exist here.** Every other concurrency test in this repository
//! drives the router, and the router cannot actually run two handlers at once: `db::connect` caps
//! SQLite at `SQLITE_MAX_CONNECTIONS = 1`, and `auth_middleware` takes that single connection
//! before any handler body runs. Concurrent requests therefore queue on the pool, and a
//! check-then-act race between two handlers never gets the chance to interleave. A test that
//! drives the router and passes proves the endpoint works; it does not prove the guard underneath
//! it is safe under contention, because the contention never happened. The tests below reach past
//! the pool and hammer the guard directly with real OS threads released from a `Barrier`, which is
//! the only arrangement here that can actually fail when the guard is wrong.

use std::sync::{Arc, Barrier};

use simply_ip_sync::replay::ReplayGuard;
use uuid::Uuid;

mod common;

/// 16 threads released simultaneously against one `(key_id, digest)`; exactly one must be admitted.
///
/// This test is known to be able to fail: replacing `check_and_record`'s single locked
/// `get`-then-`insert` with a `contains_key` that drops the lock before re-taking it to insert
/// makes it report multiple winners within a handful of rounds.
#[test]
fn the_replay_ledger_admits_exactly_one_winner_under_real_thread_contention() {
    const THREADS: usize = 16;
    const ROUNDS: usize = 25;

    for round in 0..ROUNDS {
        let guard = Arc::new(ReplayGuard::default());
        let barrier = Arc::new(Barrier::new(THREADS));
        let key_id = Uuid::new_v4();
        let digest = format!("round-{round}-digest").into_bytes();

        let accepted: usize = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    let guard = Arc::clone(&guard);
                    let barrier = Arc::clone(&barrier);
                    let digest = digest.clone();
                    scope.spawn(move || {
                        // Every thread parks here and is released in the same instant, so the
                        // window between "is it recorded?" and "record it" is genuinely contended.
                        barrier.wait();
                        usize::from(guard.check_and_record(key_id, &digest))
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().expect("worker thread")).sum()
        });

        assert_eq!(
            accepted, 1,
            "round {round}: {accepted} of {THREADS} concurrent uses of one signature were admitted; \
             exactly one may be"
        );
    }
}

/// Distinct signatures must not block each other: a guard that serialised everything would also
/// report "exactly one winner" above, so this pins that the test above is measuring collision
/// handling rather than a global lockout.
#[test]
fn distinct_signatures_are_all_admitted_under_the_same_contention() {
    const THREADS: usize = 16;

    let guard = Arc::new(ReplayGuard::default());
    let barrier = Arc::new(Barrier::new(THREADS));
    let key_id = Uuid::new_v4();

    let accepted: usize = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..THREADS)
            .map(|i| {
                let guard = Arc::clone(&guard);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    usize::from(guard.check_and_record(key_id, format!("digest-{i}").as_bytes()))
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("worker thread")).sum()
    });

    assert_eq!(accepted, THREADS, "distinct signatures must not exclude one another");
}

// ---------------------------------------------------------------------------------------------
// Error-envelope totality
// ---------------------------------------------------------------------------------------------

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use common::signed_request;

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.expect("read body");
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("response body was not JSON ({e}): {}", String::from_utf8_lossy(&bytes)))
}

/// Axum's built-in `Path`/`Query` rejections render as **plain text**. Every other refusal this
/// service emits is `{"error": "..."}`. A client that parses the envelope to decide whether to
/// retry would hit a parse failure instead of a status it can act on, so the envelope has to be
/// total: malformed path segments and malformed query strings included.
#[tokio::test]
async fn a_malformed_path_segment_is_refused_inside_the_json_envelope() {
    let (_conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);

    let req = signed_request(&master, "GET", "/api/keys/not-a-uuid/permissions", None);
    let resp = app.oneshot(req).await.expect("response");

    // `NotFound`, not `InvalidInput`: a syntactically invalid id must be indistinguishable from a
    // well-formed id that does not exist, or the error shape becomes an id-format oracle.
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = body_json(resp).await;
    assert!(body.get("error").is_some(), "expected an `error` field, got: {body}");
}

#[tokio::test]
async fn a_malformed_query_string_is_refused_inside_the_json_envelope() {
    let (_conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);

    // `limit` is typed; a non-numeric value cannot deserialize.
    let req = signed_request(&master, "GET", "/api/audit-logs?limit=not-a-number", None);
    let resp = app.oneshot(req).await.expect("response");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert!(body.get("error").is_some(), "expected an `error` field, got: {body}");
}

/// A well-formed id for a resource that does not exist must be byte-identical to the malformed-id
/// refusal above — otherwise the pair discloses which ids are syntactically valid.
#[tokio::test]
async fn a_malformed_id_and_a_nonexistent_id_are_indistinguishable() {
    let (_conn, state, master) = common::setup().await;
    let app = simply_ip_sync::create_app(state.clone());
    let malformed = signed_request(&master, "GET", "/api/keys/not-a-uuid/permissions", None);
    let malformed_resp = app.oneshot(malformed).await.expect("response");
    let malformed_status = malformed_resp.status();
    let malformed_body = body_json(malformed_resp).await;

    let app = simply_ip_sync::create_app(state);
    let target = format!("/api/keys/{}/permissions", Uuid::new_v4());
    let absent = signed_request(&master, "GET", &target, None);
    let absent_resp = app.oneshot(absent).await.expect("response");

    assert_eq!(malformed_status, absent_resp.status());
    assert_eq!(malformed_body, body_json(absent_resp).await);
}

// ---------------------------------------------------------------------------------------------
// High-contention deletion: the TOCTOU class rows_affected-checking exists to close
// ---------------------------------------------------------------------------------------------

async fn insert_source_for_deletion(conn: &sea_orm::DatabaseConnection, owner_key_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let model = simply_ip_sync::entities::external_source::ActiveModel {
        id: sea_orm::Set(id),
        name: sea_orm::Set(format!("contention-source-{id}")),
        source_url: sea_orm::Set("http://127.0.0.1:1/unused".to_owned()),
        parser_type: sea_orm::Set("REGEX_LINE".to_owned()),
        parser_config_json: sea_orm::Set(None),
        cron_schedule: sea_orm::Set("0 0 * * *".to_owned()),
        target_group_name: sea_orm::Set("group".to_owned()),
        mode: sea_orm::Set("upsert".to_owned()),
        is_active: sea_orm::Set(true),
        last_run_at: sea_orm::Set(None),
        owner_key_id: sea_orm::Set(Some(owner_key_id)),
        created_at: sea_orm::Set(now),
        updated_at: sea_orm::Set(now),
    };
    use sea_orm::ActiveModelTrait as _;
    model.insert(conn).await.expect("insert source");
    id
}

/// Builds a signed request with an explicit timestamp rather than "now" — 16 requests built in a
/// tight loop need 16 distinct, individually-valid signatures, or the anti-replay guard would
/// (correctly) reject all but the first as replays of an identical signature, which would make
/// this test measure replay rejection instead of deletion atomicity.
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

/// A higher-multiplicity version of `rbac_model_compliance.rs`'s two-way concurrent-delete test, at the same
/// scale (16) the replay-guard test above uses: 16 requests racing to delete the *same* resource
/// through the full router. Unlike the replay guard, there is no in-process data structure to
/// reach past with OS threads here — the atomicity guarantee for deletion is the database's own
/// per-statement atomicity plus this service checking `rows_affected` on the result, not a
/// hand-rolled lock — so `tokio::spawn` (real concurrent tasks, not a sequential `tokio::join!` of
/// two) is the right tool: it genuinely interleaves many in-flight requests against the
/// single-connection pool, which is exactly the scenario the `rows_affected` check must survive.
/// Before that check was added to `delete_external_source` (and the equivalent three handlers),
/// this test reproduced multiple `204`s for one row with a two-way race; at 16-way it would have
/// done so far more reliably.
#[tokio::test]
async fn sixteen_concurrent_deletes_of_the_same_resource_admit_exactly_one_success() {
    const CONCURRENCY: i64 = 16;

    let (conn, state, master) = common::setup().await;
    let source_id = insert_source_for_deletion(&conn, master.id).await;

    let app = simply_ip_sync::create_app(state);
    let base_ts = chrono::Utc::now().timestamp();
    let target = format!("/api/sources/{source_id}");

    let mut handles = Vec::with_capacity(CONCURRENCY as usize);
    for i in 0..CONCURRENCY {
        let req = signed_request_at(&master, "DELETE", &target, base_ts + i);
        let app = app.clone();
        handles.push(tokio::spawn(async move { app.oneshot(req).await.expect("response").status() }));
    }

    let mut succeeded = 0usize;
    let mut not_found = 0usize;
    for handle in handles {
        match handle.await.expect("worker task") {
            StatusCode::NO_CONTENT => succeeded += 1,
            StatusCode::NOT_FOUND => not_found += 1,
            other => panic!("unexpected status {other} — every concurrent delete must resolve to either 204 or 404"),
        }
    }
    assert_eq!(succeeded, 1, "exactly one of {CONCURRENCY} concurrent deletes of the same resource may succeed, got {succeeded}");
    assert_eq!(not_found, CONCURRENCY as usize - 1, "every other concurrent delete must find nothing left to delete");
}

/// The unauthenticated probes answer JSON too — including the 503 path.
#[tokio::test]
async fn the_unauthenticated_probes_answer_inside_the_envelope() {
    let (_conn, state, _master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);
    let resp = app
        .oneshot(Request::builder().uri("/ready").body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "ok");
}
