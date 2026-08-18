//! `vault_sync_tasks` CRUD and manual trigger.

use axum::extract::State;

use crate::extract::StrictPath;
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::sources::TargetSpec;
use super::support::{create_audit_log, find_permission, grant_full_permission, RESOURCE_SYNC_TASK};
use super::{guard_can_sync, guard_resource_creation, guard_resource_lifecycle, guard_resource_manage};
use crate::entities::{api_key, vault_sync_task, vault_sync_task_target};
use crate::error::AppError;
use crate::extract::StrictJson;
use crate::middleware::ClientIp;
use crate::state::AppState;

/// A `vault_sync_tasks` row plus its resolved targets, as returned by the API.
#[derive(Debug, Serialize)]
pub struct VaultSyncTaskResponse {
    /// Task id.
    pub id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// Source vault endpoint id.
    pub source_vault_id: Uuid,
    /// Group name queried on the source vault.
    pub source_group_name: String,
    /// Default target group name on receiving vaults.
    pub target_group_name: String,
    /// Cron expression for periodic delta polling.
    pub cron_schedule: String,
    /// High-water mark used for `since=` delta queries.
    pub last_sync_at: Option<chrono::DateTime<Utc>>,
    /// Sync mode. Always `"upsert"`.
    pub mode: String,
    /// Whether automatic scheduling is enabled.
    pub is_active: bool,
    /// Key holding lifecycle authority over this task.
    pub owner_key_id: Option<Uuid>,
    /// Configured target vaults.
    pub targets: Vec<TargetSpec>,
    /// Creation timestamp.
    pub created_at: chrono::DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: chrono::DateTime<Utc>,
}

async fn load_targets(db: &sea_orm::DatabaseConnection, task_id: Uuid) -> Result<Vec<TargetSpec>, AppError> {
    let rows = vault_sync_task_target::Entity::find()
        .filter(vault_sync_task_target::Column::VaultSyncTaskId.eq(task_id))
        .all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| TargetSpec {
            vault_endpoint_id: r.target_vault_id,
            target_group_name: r.target_group_name,
        })
        .collect())
}

fn to_response(m: vault_sync_task::Model, targets: Vec<TargetSpec>) -> VaultSyncTaskResponse {
    VaultSyncTaskResponse {
        id: m.id,
        name: m.name,
        source_vault_id: m.source_vault_id,
        source_group_name: m.source_group_name,
        target_group_name: m.target_group_name,
        cron_schedule: m.cron_schedule,
        last_sync_at: m.last_sync_at,
        mode: m.mode,
        is_active: m.is_active,
        owner_key_id: m.owner_key_id,
        targets,
        created_at: m.created_at,
        updated_at: m.updated_at,
    }
}

/// Body of `POST /api/sync-tasks`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateVaultSyncTaskPayload {
    /// Human-readable name. Must be unique.
    pub name: String,
    /// Source vault endpoint id.
    pub source_vault_id: Uuid,
    /// Group name to query on the source vault.
    pub source_group_name: String,
    /// Default target group name on receiving vaults.
    pub target_group_name: String,
    /// Cron expression for periodic delta polling.
    pub cron_schedule: String,
    /// Whether automatic scheduling is enabled. Defaults to `true`.
    #[serde(default = "default_true")]
    pub is_active: bool,
    /// Target vault endpoints to replicate delta records to.
    #[serde(default)]
    pub targets: Vec<TargetSpec>,
}

fn default_true() -> bool {
    true
}

/// Body of `PATCH /api/sync-tasks/{id}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateVaultSyncTaskPayload {
    /// New name.
    #[serde(default)]
    pub name: Option<String>,
    /// New source vault endpoint id.
    #[serde(default)]
    pub source_vault_id: Option<Uuid>,
    /// New source group name.
    #[serde(default)]
    pub source_group_name: Option<String>,
    /// New default target group name.
    #[serde(default)]
    pub target_group_name: Option<String>,
    /// New cron expression.
    #[serde(default)]
    pub cron_schedule: Option<String>,
    /// New active flag.
    #[serde(default)]
    pub is_active: Option<bool>,
    /// Replaces the full set of target vaults, when present.
    #[serde(default)]
    pub targets: Option<Vec<TargetSpec>>,
}

async fn visible_to(state: &AppState, caller: &api_key::Model, task: &vault_sync_task::Model) -> Result<bool, AppError> {
    Ok(caller.is_master
        || task.owner_key_id == Some(caller.id)
        || find_permission(&state.db, caller.id, RESOURCE_SYNC_TASK, task.id).await?.is_some())
}

/// `GET /api/sync-tasks`.
pub async fn list_vault_sync_tasks(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    let all = vault_sync_task::Entity::find().all(&state.db).await?;
    let mut visible = Vec::new();
    for task in all {
        if visible_to(&state, &caller, &task).await? {
            let targets = load_targets(&state.db, task.id).await?;
            visible.push(to_response(task, targets));
        }
    }
    Ok(Json(visible))
}

/// `GET /api/sync-tasks/{id}`.
pub async fn get_vault_sync_task(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let task = vault_sync_task::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if !visible_to(&state, &caller, &task).await? {
        return Err(AppError::NotFound);
    }
    let targets = load_targets(&state.db, id).await?;
    Ok(Json(to_response(task, targets)))
}

/// `POST /api/sync-tasks`. Requires `can_manage_vaults` or Master (an inter-vault sync task is a
/// vault-to-vault topology object).
pub async fn create_vault_sync_task(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    StrictJson(payload): StrictJson<CreateVaultSyncTaskPayload>,
) -> Result<impl IntoResponse, AppError> {
    guard_resource_creation(&caller, caller.can_manage_vaults)?;
    crate::scheduler::validate_cron_expression(&payload.cron_schedule)
        .map_err(|e| AppError::InvalidInput(format!("invalid cron_schedule: {e}")))?;

    let now = Utc::now();
    let id = Uuid::new_v4();
    let txn = state.db.begin().await?;

    let model = vault_sync_task::ActiveModel {
        id: Set(id),
        name: Set(payload.name.clone()),
        source_vault_id: Set(payload.source_vault_id),
        source_group_name: Set(payload.source_group_name),
        target_group_name: Set(payload.target_group_name),
        cron_schedule: Set(payload.cron_schedule),
        last_sync_at: Set(None),
        mode: Set("upsert".to_owned()),
        is_active: Set(payload.is_active),
        owner_key_id: Set(Some(caller.id)),
        created_at: Set(now),
        updated_at: Set(now),
    };
    let inserted = vault_sync_task::Entity::insert(model).exec_with_returning(&txn).await.map_err(|e| {
        if matches!(e.sql_err(), Some(sea_orm::SqlErr::UniqueConstraintViolation(_))) {
            AppError::Conflict(format!("a sync task named '{}' already exists", payload.name))
        } else {
            AppError::DbError(e)
        }
    })?;

    for target in &payload.targets {
        let row = vault_sync_task_target::ActiveModel {
            vault_sync_task_id: Set(id),
            target_vault_id: Set(target.vault_endpoint_id),
            target_group_name: Set(target.target_group_name.clone()),
        };
        vault_sync_task_target::Entity::insert(row).exec(&txn).await?;
    }

    grant_full_permission(&txn, caller.id, RESOURCE_SYNC_TASK, id).await?;
    create_audit_log(&txn, &caller, client_ip.0, "SYNC_TASK_CREATE", Some(inserted.name.clone()), None).await?;
    txn.commit().await?;

    state.scheduler.upsert_task(&state, &inserted).await;

    Ok(Json(to_response(inserted, payload.targets)))
}

/// `PATCH /api/sync-tasks/{id}`. Requires RBAC R2.
pub async fn update_vault_sync_task(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
    StrictJson(payload): StrictJson<UpdateVaultSyncTaskPayload>,
) -> Result<impl IntoResponse, AppError> {
    let existing = vault_sync_task::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    let permission = find_permission(&state.db, caller.id, RESOURCE_SYNC_TASK, id).await?;
    guard_resource_manage(&caller, permission.as_ref())?;

    if let Some(cron) = &payload.cron_schedule {
        crate::scheduler::validate_cron_expression(cron)
            .map_err(|e| AppError::InvalidInput(format!("invalid cron_schedule: {e}")))?;
    }

    let txn = state.db.begin().await?;
    let mut active: vault_sync_task::ActiveModel = existing.into();
    if let Some(name) = payload.name {
        active.name = Set(name);
    }
    if let Some(source_vault_id) = payload.source_vault_id {
        active.source_vault_id = Set(source_vault_id);
    }
    if let Some(group) = payload.source_group_name {
        active.source_group_name = Set(group);
    }
    if let Some(group) = payload.target_group_name {
        active.target_group_name = Set(group);
    }
    if let Some(cron) = payload.cron_schedule {
        active.cron_schedule = Set(cron);
    }
    if let Some(is_active) = payload.is_active {
        active.is_active = Set(is_active);
    }
    active.updated_at = Set(Utc::now());
    let updated = active.update(&txn).await?;

    if let Some(targets) = &payload.targets {
        vault_sync_task_target::Entity::delete_many()
            .filter(vault_sync_task_target::Column::VaultSyncTaskId.eq(id))
            .exec(&txn)
            .await?;
        for target in targets {
            let row = vault_sync_task_target::ActiveModel {
                vault_sync_task_id: Set(id),
                target_vault_id: Set(target.vault_endpoint_id),
                target_group_name: Set(target.target_group_name.clone()),
            };
            vault_sync_task_target::Entity::insert(row).exec(&txn).await?;
        }
    }

    create_audit_log(&txn, &caller, client_ip.0, "SYNC_TASK_UPDATE", Some(updated.name.clone()), None).await?;
    txn.commit().await?;

    state.scheduler.upsert_task(&state, &updated).await;

    let targets = load_targets(&state.db, id).await?;
    Ok(Json(to_response(updated, targets)))
}

/// `DELETE /api/sync-tasks/{id}`. Requires RBAC §3.
pub async fn delete_vault_sync_task(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let existing = vault_sync_task::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    guard_resource_lifecycle(&caller, existing.owner_key_id)?;

    let name = existing.name.clone();
    // See `sources.rs::delete_external_source`'s identical comment: two concurrent deletes of the
    // same id can both pass `find_by_id` before either `DELETE` runs.
    let result = vault_sync_task::Entity::delete_by_id(id).exec(&state.db).await?;
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }
    state.scheduler.remove_task(id).await;
    create_audit_log(&state.db, &caller, client_ip.0, "SYNC_TASK_DELETE", Some(name), None).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// `POST /api/sync-tasks/{id}/trigger`. Requires `can_sync` on this task, or Master.
pub async fn trigger_vault_sync_task(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let existing = vault_sync_task::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    let permission = find_permission(&state.db, caller.id, RESOURCE_SYNC_TASK, id).await?;
    guard_can_sync(&caller, permission.as_ref())?;

    // See api/sources.rs::trigger_external_source for why this guard exists: refuses a second
    // concurrent run of the same task rather than racing two overlapping executions.
    let _job_guard = crate::jobs::try_start_job(&state.running_jobs, id)
        .ok_or_else(|| AppError::Conflict("a sync for this task is already in progress".to_owned()))?;

    create_audit_log(&state.db, &caller, client_ip.0, "SYNC_TASK_TRIGGER", Some(existing.name.clone()), None).await?;
    let summary = crate::jobs::vault_sync::run(&state, id).await?;
    Ok(Json(serde_json::json!({
        "status": summary.status,
        "items_processed": summary.items_processed,
        "chunks_sent": summary.chunks_sent,
        "duration_ms": summary.duration_ms,
        "error_message": summary.error_message,
    })))
}
