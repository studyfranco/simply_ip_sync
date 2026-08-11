//! `GET /api/sync-logs` — execution history for external ingestion and inter-vault sync jobs.

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Json;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::Deserialize;
use uuid::Uuid;

use super::support::{find_permission, RESOURCE_EXTERNAL_SOURCE, RESOURCE_SYNC_TASK};
use super::guard_can_view_logs;
use crate::entities::{api_key, sync_log};
use crate::error::AppError;
use crate::state::AppState;

/// Query parameters for `GET /api/sync-logs`.
#[derive(Debug, Deserialize)]
pub struct SyncLogQuery {
    /// Filter by job type: `"EXTERNAL_FEED"` or `"VAULT_SYNC"`.
    pub job_type: Option<String>,
    /// Filter by the id of a specific external source or sync task.
    pub job_id: Option<Uuid>,
    /// Maximum rows to return. Defaults to 100.
    pub limit: Option<u64>,
    /// Row offset for pagination. Defaults to 0.
    pub offset: Option<u64>,
}

fn resource_type_for(job_type: &str) -> Option<&'static str> {
    match job_type {
        "EXTERNAL_FEED" => Some(RESOURCE_EXTERNAL_SOURCE),
        "VAULT_SYNC" => Some(RESOURCE_SYNC_TASK),
        _ => None,
    }
}

/// `GET /api/sync-logs`. Visible rows are scoped per-resource by `can_view_logs`; Master sees all.
pub async fn list_sync_logs(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    Query(query): Query<SyncLogQuery>,
) -> Result<impl IntoResponse, AppError> {
    let mut find = sync_log::Entity::find();
    if let Some(job_type) = &query.job_type {
        find = find.filter(sync_log::Column::JobType.eq(job_type.clone()));
    }
    if let Some(job_id) = query.job_id {
        find = find.filter(sync_log::Column::JobId.eq(job_id));
    }
    let rows = find
        .order_by_desc(sync_log::Column::Timestamp)
        .limit(query.limit.unwrap_or(100).min(1000))
        .offset(query.offset.unwrap_or(0))
        .all(&state.db)
        .await?;

    if caller.is_master {
        return Ok(Json(rows));
    }

    let mut visible = Vec::new();
    for row in rows {
        let Some(resource_type) = resource_type_for(&row.job_type) else {
            continue;
        };
        let permission = find_permission(&state.db, caller.id, resource_type, row.job_id).await?;
        if guard_can_view_logs(&caller, permission.as_ref()) {
            visible.push(row);
        }
    }
    Ok(Json(visible))
}
