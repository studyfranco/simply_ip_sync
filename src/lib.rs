#![warn(missing_docs)]
//! `simply_ip_sync` — threat intelligence ingestion orchestrator and multi-site inter-vault
//! replication daemon.
//!
//! [`create_app`] assembles the full route table and middleware layering; [`setup_state`] builds
//! [`state::AppState`] from a database connection. Everything else is either a handler module
//! (`api/`), a background worker (`jobs/`, `scheduler`), or a security primitive
//! (`crypto`, `middleware`, `replay`, `master`).

pub mod api;
pub mod client;
pub mod config;
pub mod crypto;
pub mod db;
pub mod entities;
pub mod error;
pub mod extract;
pub mod jobs;
pub mod master;
pub mod middleware;
pub mod migration;
pub mod parsers;
pub mod replay;
pub mod retry;
pub mod scheduler;
pub mod state;

use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post};
use axum::Router;
use sea_orm::DatabaseConnection;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

use state::{AppState, StartupConfigError};

/// Maximum accepted request body size, in bytes. Single source of truth referenced by both the
/// router's `DefaultBodyLimit` and the inbound auth middleware's signed-body buffer cap, so the
/// two layers can never drift.
pub fn max_request_body_bytes() -> usize {
    config::max_body_bytes()
}

/// Builds [`state::AppState`] from a database connection, reading environment configuration and
/// starting the cron scheduler. Does not load scheduled jobs from the database yet — call
/// `state.scheduler.boot(&state)` once the caller is ready to start dispatching.
pub async fn setup_state(db: DatabaseConnection) -> Result<AppState, StartupConfigError> {
    AppState::new(db).await
}

/// Assembles the full route table: public probes outside authentication, every `/api/*` route
/// behind [`middleware::auth_middleware`], and a static-file fallback for the dashboard.
pub fn create_app(state: AppState) -> Router {
    let api_routes = Router::new()
        .route("/auth/me", get(api::get_me))
        .route("/keys", get(api::list_api_keys).post(api::create_api_key))
        .route(
            "/keys/{id}",
            get(api::get_api_key).patch(api::update_api_key).delete(api::delete_api_key),
        )
        .route("/keys/{id}/rotate", post(api::rotate_api_key))
        .route("/keys/{id}/rotate-secret", post(api::rotate_signing_secret))
        .route("/keys/{id}/permissions", get(api::list_key_permissions).put(api::grant_key_permission))
        .route("/keys/{id}/permissions/{permission_id}", delete(api::revoke_key_permission))
        .route("/vaults", get(api::list_vault_endpoints).post(api::create_vault_endpoint))
        .route(
            "/vaults/{id}",
            get(api::get_vault_endpoint).patch(api::update_vault_endpoint).delete(api::delete_vault_endpoint),
        )
        .route("/sources", get(api::list_external_sources).post(api::create_external_source))
        .route(
            "/sources/{id}",
            get(api::get_external_source).patch(api::update_external_source).delete(api::delete_external_source),
        )
        .route("/sources/{id}/trigger", post(api::trigger_external_source))
        .route("/sync-tasks", get(api::list_vault_sync_tasks).post(api::create_vault_sync_task))
        .route(
            "/sync-tasks/{id}",
            get(api::get_vault_sync_task).patch(api::update_vault_sync_task).delete(api::delete_vault_sync_task),
        )
        .route("/sync-tasks/{id}/trigger", post(api::trigger_vault_sync_task))
        .route("/sync-logs", get(api::list_sync_logs))
        .route("/audit-logs", get(api::list_audit_logs))
        .layer(axum::middleware::from_fn_with_state(state.clone(), middleware::auth_middleware));

    Router::new()
        .route("/health", get(api::health_check))
        .route("/healthz", get(api::health_check))
        .route("/ready", get(api::readiness_check))
        .route("/readyz", get(api::readiness_check))
        .nest("/api", api_routes)
        .fallback_service(ServeDir::new("static"))
        .layer(DefaultBodyLimit::max(max_request_body_bytes()))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
