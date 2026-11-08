//! `GET /api/audit-logs` — the security audit trail. Master-only: it is the one read surface
//! spanning every domain, so scoping it per-caller would be arbitrary.

use axum::extract::State;

use crate::extract::StrictQuery;
use axum::Json;
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::Deserialize;

use crate::entities::{api_key, audit_log};
use crate::error::AppError;
use crate::state::AppState;

/// Query parameters for `GET /api/audit-logs`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditLogQuery {
    /// Filter by action name (exact match).
    pub action: Option<String>,
    /// Filter by client IP substring.
    pub client_ip: Option<String>,
    /// Filter by acting key name, prefix, or UUID.
    pub api_key: Option<String>,
    /// Lower timestamp bound (RFC 3339).
    pub since: Option<String>,
    /// Upper timestamp bound (RFC 3339).
    pub until: Option<String>,
    /// Maximum rows to return. Defaults to 100.
    pub limit: Option<u64>,
    /// Row offset for pagination. Defaults to 0.
    pub offset: Option<u64>,
}

fn parse_rfc3339(field: &str, raw: &str) -> Result<DateTime<Utc>, AppError> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| {
            AppError::InvalidInput(format!("invalid {field} timestamp (expected RFC 3339)"))
        })
}

/// `GET /api/audit-logs`. Master-only.
pub async fn list_audit_logs(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    StrictQuery(query): StrictQuery<AuditLogQuery>,
) -> Result<impl IntoResponse, AppError> {
    if !caller.is_master {
        return Err(AppError::Forbidden(
            "audit logs are visible to the Master key only".to_owned(),
        ));
    }
    let mut find = audit_log::Entity::find();
    if let Some(action) = query
        .action
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        find = find.filter(audit_log::Column::Action.eq(action));
    }
    if let Some(client_ip) = query
        .client_ip
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        find = find.filter(audit_log::Column::ClientIp.contains(client_ip));
    }
    if let Some(key_filter) = query
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let mut cond = Condition::any()
            .add(audit_log::Column::ApiKeyName.contains(key_filter))
            .add(audit_log::Column::ApiKeyPrefix.contains(key_filter));
        if let Ok(uuid) = uuid::Uuid::parse_str(key_filter) {
            cond = cond.add(audit_log::Column::ApiKeyId.eq(uuid));
        }
        find = find.filter(cond);
    }
    if let Some(since) = query
        .since
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        find = find.filter(audit_log::Column::Timestamp.gte(parse_rfc3339("since", since)?));
    }
    if let Some(until) = query
        .until
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        find = find.filter(audit_log::Column::Timestamp.lt(parse_rfc3339("until", until)?));
    }
    let rows = find
        .order_by_desc(audit_log::Column::Timestamp)
        .limit(query.limit.unwrap_or(100).min(1000))
        .offset(query.offset.unwrap_or(0))
        .all(&state.db)
        .await?;
    Ok(Json(rows))
}
