//! Unauthenticated liveness and readiness probes. The only endpoints in the service that answer
//! without a credential, so they are held to a stricter rule than the authenticated routes:
//! disclose nothing an anonymous caller could not already infer.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sea_orm::{EntityTrait, PaginatorTrait};
use serde_json::json;

use crate::entities::prelude::ApiKey;
use crate::state::AppState;

/// `GET /health`, `/healthz`. Liveness only: does not touch the database, so a database outage
/// never turns into an orchestrator restart loop.
pub async fn health_check() -> impl IntoResponse {
    Json(json!({ "status": "ok", "service": "simply_ip_sync" }))
}

/// `GET /ready`, `/readyz`. Readiness: proves the database answers and the Master identity is
/// pinned. Returns `503` otherwise.
pub async fn readiness_check(State(state): State<AppState>) -> impl IntoResponse {
    // Deliberately a typed entity query rather than a raw `SELECT 1`: this is the one route
    // reachable without a credential, so it holds no raw-SQL surface at all, and the count also
    // proves the schema (not merely the socket) is live. The number is never disclosed.
    let db_ok = ApiKey::find().count(&state.db).await.is_ok();
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
