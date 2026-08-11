//! `GET /api/audit-logs` — the security audit trail. Master-only: it is the one read surface
//! spanning every domain, so scoping it per-caller would be arbitrary.

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Json;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::Deserialize;

use crate::entities::{api_key, audit_log};
use crate::error::AppError;
use crate::state::AppState;

/// Query parameters for `GET /api/audit-logs`.
#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    /// Filter by action name (exact match).
    pub action: Option<String>,
    /// Maximum rows to return. Defaults to 100.
    pub limit: Option<u64>,
    /// Row offset for pagination. Defaults to 0.
    pub offset: Option<u64>,
}

/// `GET /api/audit-logs`. Master-only.
pub async fn list_audit_logs(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    Query(query): Query<AuditLogQuery>,
) -> Result<impl IntoResponse, AppError> {
    if !caller.is_master {
        return Err(AppError::Forbidden("audit logs are visible to the Master key only".to_owned()));
    }
    let mut find = audit_log::Entity::find();
    if let Some(action) = &query.action {
        find = find.filter(audit_log::Column::Action.eq(action.clone()));
    }
    let rows = find
        .order_by_desc(audit_log::Column::Timestamp)
        .limit(query.limit.unwrap_or(100).min(1000))
        .offset(query.offset.unwrap_or(0))
        .all(&state.db)
        .await?;
    Ok(Json(rows))
}
