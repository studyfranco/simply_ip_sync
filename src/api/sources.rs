//! `external_sources` CRUD and manual trigger.

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::support::{create_audit_log, find_permission, grant_full_permission, RESOURCE_EXTERNAL_SOURCE};
use super::{guard_can_sync, guard_resource_creation, guard_resource_lifecycle, guard_resource_manage};
use crate::entities::{api_key, external_source, external_source_vault_target};
use crate::error::AppError;
use crate::extract::StrictJson;
use crate::middleware::ClientIp;
use crate::state::AppState;

/// One target-vault mapping in a create/update payload.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TargetSpec {
    /// Target vault endpoint id.
    pub vault_endpoint_id: Uuid,
    /// Group name override for this target. `None` falls back to the source's own
    /// `target_group_name`.
    #[serde(default)]
    pub target_group_name: Option<String>,
}

/// An `external_sources` row plus its resolved targets, as returned by the API.
#[derive(Debug, Serialize)]
pub struct ExternalSourceResponse {
    /// Source id.
    pub id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// HTTP/HTTPS feed URL.
    pub source_url: String,
    /// Parser algorithm: `"REGEX_LINE"` or `"JSON_PATH"`.
    pub parser_type: String,
    /// Parser configuration JSON, if any.
    pub parser_config_json: Option<String>,
    /// Cron expression for periodic execution.
    pub cron_schedule: String,
    /// Default target group name.
    pub target_group_name: String,
    /// Ingestion mode: `"upsert"` or `"full_replace"`. See [`CreateExternalSourcePayload::mode`].
    pub mode: String,
    /// Whether automatic scheduling is enabled.
    pub is_active: bool,
    /// Timestamp of the last execution.
    pub last_run_at: Option<chrono::DateTime<Utc>>,
    /// Key holding lifecycle authority over this source.
    pub owner_key_id: Option<Uuid>,
    /// Configured target vaults.
    pub targets: Vec<TargetSpec>,
    /// Creation timestamp.
    pub created_at: chrono::DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: chrono::DateTime<Utc>,
}

async fn load_targets(db: &sea_orm::DatabaseConnection, source_id: Uuid) -> Result<Vec<TargetSpec>, AppError> {
    let rows = external_source_vault_target::Entity::find()
        .filter(external_source_vault_target::Column::ExternalSourceId.eq(source_id))
        .all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| TargetSpec {
            vault_endpoint_id: r.vault_endpoint_id,
            target_group_name: r.target_group_name,
        })
        .collect())
}

fn to_response(m: external_source::Model, targets: Vec<TargetSpec>) -> ExternalSourceResponse {
    ExternalSourceResponse {
        id: m.id,
        name: m.name,
        source_url: m.source_url,
        parser_type: m.parser_type,
        parser_config_json: m.parser_config_json,
        cron_schedule: m.cron_schedule,
        target_group_name: m.target_group_name,
        mode: m.mode,
        is_active: m.is_active,
        last_run_at: m.last_run_at,
        owner_key_id: m.owner_key_id,
        targets,
        created_at: m.created_at,
        updated_at: m.updated_at,
    }
}

/// Body of `POST /api/sources`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateExternalSourcePayload {
    /// Human-readable name. Must be unique.
    pub name: String,
    /// HTTP/HTTPS feed URL.
    pub source_url: String,
    /// Parser algorithm: `"REGEX_LINE"` or `"JSON_PATH"`.
    #[serde(default = "default_parser_type")]
    pub parser_type: String,
    /// Parser configuration JSON.
    #[serde(default)]
    pub parser_config_json: Option<String>,
    /// Cron expression for periodic execution.
    pub cron_schedule: String,
    /// Default target group name.
    pub target_group_name: String,
    /// Ingestion mode: `"upsert"` (default — never implicitly deletes) or `"full_replace"` (the
    /// first chunk of each run's push to a given target clears anything not in this run's fetched
    /// content; every subsequent chunk of the same run automatically downgrades to `upsert` — see
    /// `jobs::mode_for_chunk_index` — so a multi-chunk feed can never have a later chunk erase an
    /// earlier one's just-delivered records).
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Whether automatic scheduling is enabled. Defaults to `true`.
    #[serde(default = "default_true")]
    pub is_active: bool,
    /// Target vault endpoints to push parsed records to.
    #[serde(default)]
    pub targets: Vec<TargetSpec>,
}

fn default_parser_type() -> String {
    "REGEX_LINE".to_owned()
}

fn default_mode() -> String {
    "upsert".to_owned()
}

fn default_true() -> bool {
    true
}

/// Body of `PATCH /api/sources/{id}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateExternalSourcePayload {
    /// New name.
    #[serde(default)]
    pub name: Option<String>,
    /// New feed URL.
    #[serde(default)]
    pub source_url: Option<String>,
    /// New parser type.
    #[serde(default)]
    pub parser_type: Option<String>,
    /// New parser configuration JSON.
    #[serde(default)]
    pub parser_config_json: Option<String>,
    /// New cron expression.
    #[serde(default)]
    pub cron_schedule: Option<String>,
    /// New default target group name.
    #[serde(default)]
    pub target_group_name: Option<String>,
    /// New ingestion mode: `"upsert"` or `"full_replace"`.
    #[serde(default)]
    pub mode: Option<String>,
    /// New active flag.
    #[serde(default)]
    pub is_active: Option<bool>,
    /// Replaces the full set of target vaults, when present.
    #[serde(default)]
    pub targets: Option<Vec<TargetSpec>>,
}

async fn visible_to(state: &AppState, caller: &api_key::Model, source: &external_source::Model) -> Result<bool, AppError> {
    Ok(caller.is_master
        || source.owner_key_id == Some(caller.id)
        || find_permission(&state.db, caller.id, RESOURCE_EXTERNAL_SOURCE, source.id).await?.is_some())
}

/// `GET /api/sources`.
pub async fn list_external_sources(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    let all = external_source::Entity::find().all(&state.db).await?;
    let mut visible = Vec::new();
    for source in all {
        if visible_to(&state, &caller, &source).await? {
            let targets = load_targets(&state.db, source.id).await?;
            visible.push(to_response(source, targets));
        }
    }
    Ok(Json(visible))
}

/// `GET /api/sources/{id}`.
pub async fn get_external_source(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let source = external_source::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if !visible_to(&state, &caller, &source).await? {
        return Err(AppError::NotFound);
    }
    let targets = load_targets(&state.db, id).await?;
    Ok(Json(to_response(source, targets)))
}

/// `POST /api/sources`. Requires `can_manage_sources` or Master.
pub async fn create_external_source(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    StrictJson(payload): StrictJson<CreateExternalSourcePayload>,
) -> Result<impl IntoResponse, AppError> {
    guard_resource_creation(&caller, caller.can_manage_sources)?;
    if payload.parser_type != "REGEX_LINE" && payload.parser_type != "JSON_PATH" {
        return Err(AppError::InvalidInput("parser_type must be REGEX_LINE or JSON_PATH".to_owned()));
    }
    if crate::client::BatchMode::parse(&payload.mode).is_none() {
        return Err(AppError::InvalidInput("mode must be upsert or full_replace".to_owned()));
    }
    crate::scheduler::validate_cron_expression(&payload.cron_schedule)
        .map_err(|e| AppError::InvalidInput(format!("invalid cron_schedule: {e}")))?;

    let now = Utc::now();
    let id = Uuid::new_v4();
    let txn = state.db.begin().await?;

    let model = external_source::ActiveModel {
        id: Set(id),
        name: Set(payload.name.clone()),
        source_url: Set(payload.source_url),
        parser_type: Set(payload.parser_type),
        parser_config_json: Set(payload.parser_config_json),
        cron_schedule: Set(payload.cron_schedule),
        target_group_name: Set(payload.target_group_name),
        mode: Set(payload.mode),
        is_active: Set(payload.is_active),
        last_run_at: Set(None),
        owner_key_id: Set(Some(caller.id)),
        created_at: Set(now),
        updated_at: Set(now),
    };
    let inserted = external_source::Entity::insert(model).exec_with_returning(&txn).await.map_err(|e| {
        if matches!(e.sql_err(), Some(sea_orm::SqlErr::UniqueConstraintViolation(_))) {
            AppError::Conflict(format!("an external source named '{}' already exists", payload.name))
        } else {
            AppError::DbError(e)
        }
    })?;

    for target in &payload.targets {
        let row = external_source_vault_target::ActiveModel {
            external_source_id: Set(id),
            vault_endpoint_id: Set(target.vault_endpoint_id),
            target_group_name: Set(target.target_group_name.clone()),
        };
        external_source_vault_target::Entity::insert(row).exec(&txn).await?;
    }

    grant_full_permission(&txn, caller.id, RESOURCE_EXTERNAL_SOURCE, id).await?;
    create_audit_log(&txn, &caller, client_ip.0, "SOURCE_CREATE", Some(inserted.name.clone()), None).await?;
    txn.commit().await?;

    state.scheduler.upsert_source(&state, &inserted).await;

    Ok(Json(to_response(inserted, payload.targets)))
}

/// `PATCH /api/sources/{id}`. Requires RBAC R2.
pub async fn update_external_source(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    Path(id): Path<Uuid>,
    StrictJson(payload): StrictJson<UpdateExternalSourcePayload>,
) -> Result<impl IntoResponse, AppError> {
    let existing = external_source::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    let permission = find_permission(&state.db, caller.id, RESOURCE_EXTERNAL_SOURCE, id).await?;
    guard_resource_manage(&caller, permission.as_ref())?;

    if let Some(parser_type) = &payload.parser_type
        && parser_type != "REGEX_LINE"
        && parser_type != "JSON_PATH"
    {
        return Err(AppError::InvalidInput("parser_type must be REGEX_LINE or JSON_PATH".to_owned()));
    }
    if let Some(cron) = &payload.cron_schedule {
        crate::scheduler::validate_cron_expression(cron)
            .map_err(|e| AppError::InvalidInput(format!("invalid cron_schedule: {e}")))?;
    }
    if let Some(mode) = &payload.mode
        && crate::client::BatchMode::parse(mode).is_none()
    {
        return Err(AppError::InvalidInput("mode must be upsert or full_replace".to_owned()));
    }

    let txn = state.db.begin().await?;
    let mut active: external_source::ActiveModel = existing.into();
    if let Some(name) = payload.name {
        active.name = Set(name);
    }
    if let Some(source_url) = payload.source_url {
        active.source_url = Set(source_url);
    }
    if let Some(parser_type) = payload.parser_type {
        active.parser_type = Set(parser_type);
    }
    if let Some(config) = payload.parser_config_json {
        active.parser_config_json = Set(Some(config));
    }
    if let Some(cron) = payload.cron_schedule {
        active.cron_schedule = Set(cron);
    }
    if let Some(group) = payload.target_group_name {
        active.target_group_name = Set(group);
    }
    if let Some(mode) = payload.mode {
        active.mode = Set(mode);
    }
    if let Some(is_active) = payload.is_active {
        active.is_active = Set(is_active);
    }
    active.updated_at = Set(Utc::now());
    let updated = active.update(&txn).await?;

    if let Some(targets) = &payload.targets {
        external_source_vault_target::Entity::delete_many()
            .filter(external_source_vault_target::Column::ExternalSourceId.eq(id))
            .exec(&txn)
            .await?;
        for target in targets {
            let row = external_source_vault_target::ActiveModel {
                external_source_id: Set(id),
                vault_endpoint_id: Set(target.vault_endpoint_id),
                target_group_name: Set(target.target_group_name.clone()),
            };
            external_source_vault_target::Entity::insert(row).exec(&txn).await?;
        }
    }

    create_audit_log(&txn, &caller, client_ip.0, "SOURCE_UPDATE", Some(updated.name.clone()), None).await?;
    txn.commit().await?;

    state.scheduler.upsert_source(&state, &updated).await;

    let targets = load_targets(&state.db, id).await?;
    Ok(Json(to_response(updated, targets)))
}

/// `DELETE /api/sources/{id}`. Requires RBAC §3.
pub async fn delete_external_source(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let existing = external_source::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    guard_resource_lifecycle(&caller, existing.owner_key_id)?;

    let name = existing.name.clone();
    external_source::Entity::delete_by_id(id).exec(&state.db).await?;
    state.scheduler.remove_source(id).await;
    create_audit_log(&state.db, &caller, client_ip.0, "SOURCE_DELETE", Some(name), None).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// `POST /api/sources/{id}/trigger`. Requires `can_sync` on this source, or Master.
pub async fn trigger_external_source(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let existing = external_source::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    let permission = find_permission(&state.db, caller.id, RESOURCE_EXTERNAL_SOURCE, id).await?;
    guard_can_sync(&caller, permission.as_ref())?;

    // Refuses a second concurrent run of the same source rather than letting two overlapping
    // executions race — e.g. a manual trigger landing while a cron tick for the same source is
    // still fetching. The guard is released automatically when `_job_guard` drops at the end of
    // this function, on every exit path including the `?` below.
    let _job_guard = crate::jobs::try_start_job(&state.running_jobs, id)
        .ok_or_else(|| AppError::Conflict("a sync for this source is already in progress".to_owned()))?;

    create_audit_log(&state.db, &caller, client_ip.0, "SOURCE_TRIGGER", Some(existing.name.clone()), None).await?;
    let summary = crate::jobs::external_ingestion::run(&state, id).await?;
    Ok(Json(serde_json::json!({
        "status": summary.status,
        "items_processed": summary.items_processed,
        "chunks_sent": summary.chunks_sent,
        "duration_ms": summary.duration_ms,
        "error_message": summary.error_message,
    })))
}
