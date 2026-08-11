//! Unauthenticated liveness and readiness probes. The only endpoints in the service that answer
//! without a credential, so they are held to a stricter rule than the authenticated routes:
//! disclose nothing an anonymous caller could not already infer.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sea_orm::{ConnectionTrait, Statement};
use serde_json::json;

use crate::state::AppState;

/// `GET /health`, `/healthz`. Liveness only: does not touch the database, so a database outage
/// never turns into an orchestrator restart loop.
pub async fn health_check() -> impl IntoResponse {
    Json(json!({ "status": "ok", "service": "simply_ip_sync" }))
}

/// `GET /ready`, `/readyz`. Readiness: proves the database answers and the Master identity is
/// pinned. Returns `503` otherwise.
pub async fn readiness_check(State(state): State<AppState>) -> impl IntoResponse {
    let backend = state.db.get_database_backend();
    let db_ok = state
        .db
        .query_one_raw(Statement::from_string(backend, "SELECT 1".to_owned()))
        .await
        .is_ok();
    let master_ready = state.master_pin.get().is_some();

    if db_ok && master_ready {
        (StatusCode::OK, Json(json!({ "status": "ok", "service": "simply_ip_sync" })))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "not_ready", "service": "simply_ip_sync" })),
        )
    }
}
