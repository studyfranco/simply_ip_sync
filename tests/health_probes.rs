//! `/health`/`/healthz` and `/ready`/`/readyz`: liveness must never depend on the database,
//! readiness must depend on *both* the database and boot-time invariants (the Master identity
//! pin), and neither may leak internal state to the anonymous caller both endpoints are open to.
//!
//! Adapted from a pattern audited in `example/simply_hook_executor/tests/health_probes.rs`
//! (2026-08-17 cross-project test audit — see `AGENT_NOTES.MD`): a dedicated file proving these
//! probes' two failure-independence properties directly (sever the dependency, don't mock it), not
//! just their happy path.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

fn probe_request(target: &str) -> Request<Body> {
    let mut req = Request::builder().method("GET").uri(target).body(Body::empty()).expect("build");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 55555))));
    req
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
    serde_json::from_slice(&bytes).expect("valid json body")
}

/// The liveness body is a small, deliberately fixed contract (`status`, `service`) — asserting the
/// exact field count, not just that the two expected keys are present, means a field added later
/// (which might leak something) fails this test until someone consciously updates it, rather than
/// slipping through a test that only checks for the fields it already knows about.
#[tokio::test]
async fn liveness_body_has_exactly_two_fields() {
    let (_conn, state, _master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);
    let resp = app.oneshot(probe_request("/health")).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let obj = body.as_object().expect("object body");
    assert_eq!(obj.len(), 2, "liveness body grew a field — was that intentional, and could it leak internals? got: {body}");
    assert_eq!(obj.get("status"), Some(&serde_json::json!("ok")));
    assert_eq!(obj.get("service"), Some(&serde_json::json!("simply_ip_sync")));
}

/// Liveness must answer `200` even with a completely dead database connection — it exists
/// specifically so an orchestrator never restart-loops a process whose only problem is a
/// downstream dependency, and the only way to prove that independence is to sever the dependency
/// for real, not assume `health_check`'s lack of a `State<AppState>` parameter is enough.
#[tokio::test]
async fn liveness_stays_ok_even_when_the_database_is_closed() {
    let (_conn, state, _master) = common::setup().await;
    state.db.close_by_ref().await.ok();

    let app = simply_ip_sync::create_app(state);
    let resp = app.oneshot(probe_request("/health")).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK, "liveness must never depend on the database");
}

#[tokio::test]
async fn readiness_reports_ok_when_db_and_master_pin_are_both_ready() {
    let (_conn, state, _master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);
    let resp = app.oneshot(probe_request("/ready")).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["status"], serde_json::json!("ok"));
}

/// A closed connection pool must flip readiness to `503` — and the response body must not leak
/// *how* the database failed (driver name, pool internals, the underlying `DbErr` text), since
/// `/ready` is one of only two unauthenticated routes in the service.
#[tokio::test]
async fn readiness_reports_unavailable_and_leaks_nothing_when_the_db_pool_is_closed() {
    let (_conn, state, _master) = common::setup().await;
    state.db.close_by_ref().await.ok();

    let app = simply_ip_sync::create_app(state);
    let resp = app.oneshot(probe_request("/ready")).await.expect("response");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
    let raw = String::from_utf8_lossy(&bytes).to_lowercase();
    for leaky_token in ["sqlite", "sqlx", "pool", "closed", "dberr", "panic"] {
        assert!(!raw.contains(leaky_token), "readiness body leaked an internal token '{leaky_token}': {raw}");
    }
    let body: serde_json::Value = serde_json::from_str(&raw).expect("valid json body");
    assert_eq!(body["status"], serde_json::json!("not_ready"));
}

/// Startup-ordering invariant: a process that has a healthy database but hasn't finished pinning
/// its Master identity yet must still report un-ready. This guards against a future refactor that
/// reorders `bind()` ahead of `pin_at_boot()` — the kind of regression a steady-state-only test
/// suite can never catch, since by the time any other test runs, `common::setup()` has always
/// already pinned the master.
#[tokio::test]
async fn readiness_reports_unavailable_when_master_pin_not_yet_set() {
    let (_conn, mut state, _master) = common::setup().await;
    state.master_pin = std::sync::Arc::new(simply_ip_sync::master::MasterPin::new());

    let app = simply_ip_sync::create_app(state);
    let resp = app.oneshot(probe_request("/ready")).await.expect("response");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "an unpinned master must never report ready, even with a healthy database");
}

#[tokio::test]
async fn healthz_and_readyz_aliases_behave_identically_to_their_canonical_routes() {
    let (_conn, state, _master) = common::setup().await;
    let app = simply_ip_sync::create_app(state);
    let resp = app.clone().oneshot(probe_request("/healthz")).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app.oneshot(probe_request("/readyz")).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
}
