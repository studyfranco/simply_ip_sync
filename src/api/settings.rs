//! System settings & introspection endpoint (`GET /api/settings`).
//! Master-only: reports effective runtime configuration and entity counts.

use axum::extract::State;
use axum::Json;
use axum::response::IntoResponse;
use sea_orm::{EntityTrait, PaginatorTrait};
use serde::Serialize;

use crate::entities::{api_key, audit_log, destination_group, sync_log, vault_endpoint, vault_sync_task};
use crate::error::AppError;
use crate::state::AppState;

/// Runtime system configuration and entity counts shown on the System Settings tab.
#[derive(Debug, Serialize)]
pub struct SettingsResponse {
    /// Peers whose forwarding headers are believed.
    pub trusted_proxies: Vec<String>,
    /// Whether secrets-at-rest encryption is active.
    pub encryption_enabled: bool,
    /// Maximum allowable decompressed stream bytes.
    pub max_decompressed_bytes: u64,
    /// Timeout for outbound HTTP requests to vaults, in seconds.
    pub outbound_http_timeout_secs: u64,
    /// Total configured destination groups.
    pub destination_group_count: u64,
    /// Total configured vault sync tasks.
    pub sync_task_count: u64,
    /// Total registered vault endpoints.
    pub vault_endpoint_count: u64,
    /// Total active API keys.
    pub api_key_count: u64,
    /// Total sync log records retained.
    pub sync_log_count: u64,
    /// Total audit log records retained.
    pub audit_log_count: u64,
}

/// Handles `GET /api/settings`. Master-only.
pub async fn get_settings(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    if !caller.is_master {
        return Err(AppError::Forbidden(
            "System settings are visible to the Master key only".to_owned(),
        ));
    }

    let destination_group_count = destination_group::Entity::find().count(&state.db).await?;
    let sync_task_count = vault_sync_task::Entity::find().count(&state.db).await?;
    let vault_endpoint_count = vault_endpoint::Entity::find().count(&state.db).await?;
    let api_key_count = api_key::Entity::find().count(&state.db).await?;
    let sync_log_count = sync_log::Entity::find().count(&state.db).await?;
    let audit_log_count = audit_log::Entity::find().count(&state.db).await?;

    Ok(Json(SettingsResponse {
        trusted_proxies: state.trusted_proxies.matchers().iter().map(ToString::to_string).collect(),
        encryption_enabled: state.cipher.is_encrypting(),
        max_decompressed_bytes: crate::config::max_decompressed_bytes(),
        outbound_http_timeout_secs: crate::config::outbound_http_timeout().as_secs(),
        destination_group_count,
        sync_task_count,
        vault_endpoint_count,
        api_key_count,
        sync_log_count,
        audit_log_count,
    }))
}
