//! `destination_groups` CRUD and manual trigger, plus child-feed (`external_sources`) management
//! nested under a group. Feeds carry no RBAC of their own — every guard here resolves to the
//! owning group's permission row (`RESOURCE_DESTINATION_GROUP`), since a group's 1-to-N feeds are
//! always scheduled, fetched, and pushed together as one execution.

use axum::extract::State;

use crate::extract::StrictPath;
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::support::{create_audit_log, find_permission, grant_full_permission, RESOURCE_DESTINATION_GROUP};
use super::{guard_can_sync, guard_resource_creation, guard_resource_lifecycle, guard_resource_manage};
use crate::entities::{api_key, destination_group, destination_group_vault_target, external_source};
use crate::error::AppError;
use crate::extract::StrictJson;
use crate::middleware::ClientIp;
use crate::state::AppState;

/// One target-vault mapping in a create/update payload.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TargetSpec {
    /// Target vault endpoint id.
    pub vault_endpoint_id: Uuid,
    /// Group name override for this target. `None` falls back to the owning group's own
    /// `target_group_name`.
    #[serde(default)]
    pub target_group_name: Option<String>,
}

/// One `external_sources` ("feed") row, as returned by the API.
#[derive(Debug, Serialize)]
pub struct FeedResponse {
    /// Feed id.
    pub id: Uuid,
    /// Owning destination group id.
    pub destination_group_id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// HTTP/HTTPS feed URL.
    pub source_url: String,
    /// Parser algorithm: `"REGEX_LINE"` or `"JSON_PATH"`.
    pub parser_type: String,
    /// Parser configuration JSON, if any.
    pub parser_config_json: Option<String>,
    /// Discards a record older than this many days (only meaningful together with a `JSON_PATH`
    /// `last_seen_at` selector — see `parsers::json_path`'s doc comment).
    pub max_age_days: Option<i32>,
    /// Per-feed override of the owning group's `skip_bogon_filtering`. `None` inherits the
    /// group's own setting.
    pub skip_bogon_filtering: Option<bool>,
    /// Creation timestamp.
    pub created_at: chrono::DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: chrono::DateTime<Utc>,
}

fn to_feed_response(m: external_source::Model) -> FeedResponse {
    FeedResponse {
        id: m.id,
        destination_group_id: m.destination_group_id,
        name: m.name,
        source_url: m.source_url,
        parser_type: m.parser_type,
        parser_config_json: m.parser_config_json,
        max_age_days: m.max_age_days,
        skip_bogon_filtering: m.skip_bogon_filtering,
        created_at: m.created_at,
        updated_at: m.updated_at,
    }
}

/// A `destination_groups` row plus its resolved target vaults and child feeds, as returned by the
/// API.
#[derive(Debug, Serialize)]
pub struct DestinationGroupResponse {
    /// Group id.
    pub id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// Default target group name in target vaults.
    pub target_group_name: String,
    /// Cron expression for periodic execution of every child feed, concurrently.
    pub cron_schedule: String,
    /// Ingestion mode: `"upsert"` or `"full_replace"`. See [`CreateDestinationGroupPayload::mode`].
    pub mode: String,
    /// Whether automatic scheduling is enabled.
    pub is_active: bool,
    /// When `false` (the default), the aggregated feed set is sanitized (bogon/private/link-local
    /// stripped) before push; a feed may override this individually.
    pub skip_bogon_filtering: bool,
    /// Timestamp of the last execution (across every child feed).
    pub last_run_at: Option<chrono::DateTime<Utc>>,
    /// Key holding lifecycle authority over this group (and, transitively, every child feed).
    pub owner_key_id: Option<Uuid>,
    /// Configured target vaults.
    pub targets: Vec<TargetSpec>,
    /// Child feeds belonging to this group.
    pub feeds: Vec<FeedResponse>,
    /// Creation timestamp.
    pub created_at: chrono::DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: chrono::DateTime<Utc>,
}

async fn load_targets(db: &sea_orm::DatabaseConnection, group_id: Uuid) -> Result<Vec<TargetSpec>, AppError> {
    let rows = destination_group_vault_target::Entity::find()
        .filter(destination_group_vault_target::Column::DestinationGroupId.eq(group_id))
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

async fn load_feeds(db: &sea_orm::DatabaseConnection, group_id: Uuid) -> Result<Vec<FeedResponse>, AppError> {
    let rows = external_source::Entity::find()
        .filter(external_source::Column::DestinationGroupId.eq(group_id))
        .all(db)
        .await?;
    Ok(rows.into_iter().map(to_feed_response).collect())
}

fn to_group_response(
    m: destination_group::Model,
    targets: Vec<TargetSpec>,
    feeds: Vec<FeedResponse>,
) -> DestinationGroupResponse {
    DestinationGroupResponse {
        id: m.id,
        name: m.name,
        target_group_name: m.target_group_name,
        cron_schedule: m.cron_schedule,
        mode: m.mode,
        is_active: m.is_active,
        skip_bogon_filtering: m.skip_bogon_filtering,
        last_run_at: m.last_run_at,
        owner_key_id: m.owner_key_id,
        targets,
        feeds,
        created_at: m.created_at,
        updated_at: m.updated_at,
    }
}

/// Body of `POST /api/destination-groups`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDestinationGroupPayload {
    /// Human-readable name. Must be unique.
    pub name: String,
    /// Default target group name.
    pub target_group_name: String,
    /// Cron expression for periodic execution.
    pub cron_schedule: String,
    /// Ingestion mode: `"upsert"` (default — never implicitly deletes) or `"full_replace"` (the
    /// first chunk of each run's push to a given target clears anything not in this run's
    /// aggregated content; every subsequent chunk of the same run automatically downgrades to
    /// `upsert` — see `jobs::mode_for_chunk_index`).
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Whether automatic scheduling is enabled. Defaults to `true`.
    #[serde(default = "default_true")]
    pub is_active: bool,
    /// When `false` (the default), the aggregated feed set is sanitized before push.
    #[serde(default)]
    pub skip_bogon_filtering: bool,
    /// Target vault endpoints to push the aggregated, deduplicated feed content to.
    #[serde(default)]
    pub targets: Vec<TargetSpec>,
}

fn default_mode() -> String {
    "upsert".to_owned()
}

fn default_true() -> bool {
    true
}

/// Body of `PATCH /api/destination-groups/{id}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateDestinationGroupPayload {
    /// New name.
    #[serde(default)]
    pub name: Option<String>,
    /// New default target group name.
    #[serde(default)]
    pub target_group_name: Option<String>,
    /// New cron expression.
    #[serde(default)]
    pub cron_schedule: Option<String>,
    /// New ingestion mode: `"upsert"` or `"full_replace"`.
    #[serde(default)]
    pub mode: Option<String>,
    /// New active flag.
    #[serde(default)]
    pub is_active: Option<bool>,
    /// New bogon-filtering-bypass flag.
    #[serde(default)]
    pub skip_bogon_filtering: Option<bool>,
    /// Replaces the full set of target vaults, when present.
    #[serde(default)]
    pub targets: Option<Vec<TargetSpec>>,
}

fn validate_mode(mode: &str) -> Result<(), AppError> {
    if crate::client::BatchMode::parse(mode).is_none() {
        return Err(AppError::InvalidInput("mode must be upsert or full_replace".to_owned()));
    }
    Ok(())
}

async fn group_visible_to(state: &AppState, caller: &api_key::Model, group: &destination_group::Model) -> Result<bool, AppError> {
    Ok(caller.is_master
        || group.owner_key_id == Some(caller.id)
        || find_permission(&state.db, caller.id, RESOURCE_DESTINATION_GROUP, group.id).await?.is_some())
}

/// `GET /api/destination-groups`.
pub async fn list_destination_groups(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    let all = destination_group::Entity::find().all(&state.db).await?;
    let mut visible = Vec::new();
    for group in all {
        if group_visible_to(&state, &caller, &group).await? {
            let targets = load_targets(&state.db, group.id).await?;
            let feeds = load_feeds(&state.db, group.id).await?;
            visible.push(to_group_response(group, targets, feeds));
        }
    }
    Ok(Json(visible))
}

/// `GET /api/destination-groups/{id}`.
pub async fn get_destination_group(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let group = destination_group::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if !group_visible_to(&state, &caller, &group).await? {
        return Err(AppError::NotFound);
    }
    let targets = load_targets(&state.db, id).await?;
    let feeds = load_feeds(&state.db, id).await?;
    Ok(Json(to_group_response(group, targets, feeds)))
}

/// `POST /api/destination-groups`. Requires `can_manage_sources` or Master.
pub async fn create_destination_group(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    StrictJson(payload): StrictJson<CreateDestinationGroupPayload>,
) -> Result<impl IntoResponse, AppError> {
    guard_resource_creation(&caller, caller.can_manage_sources)?;
    validate_mode(&payload.mode)?;
    crate::scheduler::validate_cron_expression(&payload.cron_schedule)
        .map_err(|e| AppError::InvalidInput(format!("invalid cron_schedule: {e}")))?;

    let now = Utc::now();
    let id = Uuid::new_v4();
    let txn = state.db.begin().await?;

    let model = destination_group::ActiveModel {
        id: Set(id),
        name: Set(payload.name.clone()),
        target_group_name: Set(payload.target_group_name),
        cron_schedule: Set(payload.cron_schedule),
        mode: Set(payload.mode),
        is_active: Set(payload.is_active),
        skip_bogon_filtering: Set(payload.skip_bogon_filtering),
        last_run_at: Set(None),
        owner_key_id: Set(Some(caller.id)),
        created_at: Set(now),
        updated_at: Set(now),
    };
    let inserted = destination_group::Entity::insert(model).exec_with_returning(&txn).await.map_err(|e| {
        if matches!(e.sql_err(), Some(sea_orm::SqlErr::UniqueConstraintViolation(_))) {
            AppError::Conflict(format!("a destination group named '{}' already exists", payload.name))
        } else {
            AppError::DbError(e)
        }
    })?;

    for target in &payload.targets {
        let row = destination_group_vault_target::ActiveModel {
            destination_group_id: Set(id),
            vault_endpoint_id: Set(target.vault_endpoint_id),
            target_group_name: Set(target.target_group_name.clone()),
        };
        destination_group_vault_target::Entity::insert(row).exec(&txn).await?;
    }

    grant_full_permission(&txn, caller.id, RESOURCE_DESTINATION_GROUP, id).await?;
    create_audit_log(&txn, &caller, client_ip.0, "GROUP_CREATE", Some(inserted.name.clone()), None).await?;
    txn.commit().await?;

    state.scheduler.upsert_source(&state, &inserted).await;

    Ok(Json(to_group_response(inserted, payload.targets, Vec::new())))
}

/// `PATCH /api/destination-groups/{id}`. Requires RBAC R2.
pub async fn update_destination_group(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
    StrictJson(payload): StrictJson<UpdateDestinationGroupPayload>,
) -> Result<impl IntoResponse, AppError> {
    let existing = destination_group::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    let permission = find_permission(&state.db, caller.id, RESOURCE_DESTINATION_GROUP, id).await?;
    guard_resource_manage(&caller, permission.as_ref())?;

    if let Some(cron) = &payload.cron_schedule {
        crate::scheduler::validate_cron_expression(cron)
            .map_err(|e| AppError::InvalidInput(format!("invalid cron_schedule: {e}")))?;
    }
    if let Some(mode) = &payload.mode {
        validate_mode(mode)?;
    }

    let txn = state.db.begin().await?;
    let mut active: destination_group::ActiveModel = existing.into();
    if let Some(name) = payload.name {
        active.name = Set(name);
    }
    if let Some(group_name) = payload.target_group_name {
        active.target_group_name = Set(group_name);
    }
    if let Some(cron) = payload.cron_schedule {
        active.cron_schedule = Set(cron);
    }
    if let Some(mode) = payload.mode {
        active.mode = Set(mode);
    }
    if let Some(is_active) = payload.is_active {
        active.is_active = Set(is_active);
    }
    if let Some(skip_bogon_filtering) = payload.skip_bogon_filtering {
        active.skip_bogon_filtering = Set(skip_bogon_filtering);
    }
    active.updated_at = Set(Utc::now());
    let updated = active.update(&txn).await?;

    if let Some(targets) = &payload.targets {
        destination_group_vault_target::Entity::delete_many()
            .filter(destination_group_vault_target::Column::DestinationGroupId.eq(id))
            .exec(&txn)
            .await?;
        for target in targets {
            let row = destination_group_vault_target::ActiveModel {
                destination_group_id: Set(id),
                vault_endpoint_id: Set(target.vault_endpoint_id),
                target_group_name: Set(target.target_group_name.clone()),
            };
            destination_group_vault_target::Entity::insert(row).exec(&txn).await?;
        }
    }

    create_audit_log(&txn, &caller, client_ip.0, "GROUP_UPDATE", Some(updated.name.clone()), None).await?;
    txn.commit().await?;

    state.scheduler.upsert_source(&state, &updated).await;

    let targets = load_targets(&state.db, id).await?;
    let feeds = load_feeds(&state.db, id).await?;
    Ok(Json(to_group_response(updated, targets, feeds)))
}

/// `DELETE /api/destination-groups/{id}`. Requires RBAC §3. Cascades to every child feed and
/// target-vault mapping.
pub async fn delete_destination_group(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let existing = destination_group::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    guard_resource_lifecycle(&caller, existing.owner_key_id)?;

    let name = existing.name.clone();
    // Two concurrent deletes of the same id can both pass the `find_by_id` check above before
    // either's `DELETE` runs; checking `rows_affected` is what keeps only the one that actually
    // removed a row from reporting success — the other must see 404, not a second, empty 204.
    let result = destination_group::Entity::delete_by_id(id).exec(&state.db).await?;
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }
    state.scheduler.remove_source(id).await;
    create_audit_log(&state.db, &caller, client_ip.0, "GROUP_DELETE", Some(name), None).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// `POST /api/destination-groups/{id}/trigger`. Requires `can_sync` on this group, or Master.
pub async fn trigger_destination_group(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let existing = destination_group::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    let permission = find_permission(&state.db, caller.id, RESOURCE_DESTINATION_GROUP, id).await?;
    guard_can_sync(&caller, permission.as_ref())?;

    // Refuses a second concurrent run of the same group rather than letting two overlapping
    // executions race — e.g. a manual trigger landing while a cron tick for the same group is
    // still fetching. The guard is released automatically when `_job_guard` drops at the end of
    // this function, on every exit path including the `?` below.
    let _job_guard = crate::jobs::try_start_job(&state.running_jobs, id)
        .ok_or_else(|| AppError::Conflict("a sync for this group is already in progress".to_owned()))?;

    create_audit_log(&state.db, &caller, client_ip.0, "GROUP_TRIGGER", Some(existing.name.clone()), None).await?;
    let summary = crate::jobs::external_ingestion::run(&state, id).await?;
    Ok(Json(serde_json::json!({
        "status": summary.status,
        "items_processed": summary.items_processed,
        "chunks_sent": summary.chunks_sent,
        "duration_ms": summary.duration_ms,
        "error_message": summary.error_message,
    })))
}

// ── Child feed management ───────────────────────────────────────────────────────────────────

/// Validates `parser_type`, and — for `JSON_PATH` — the `parser_config_json` shape itself
/// (`target_address` selector present and `$.`-prefixed), so a malformed feed configuration is
/// rejected with `400` at save time rather than discovered later as a `FAILED` sync log entry.
fn validate_feed_parser(parser_type: &str, parser_config_json: Option<&str>) -> Result<(), AppError> {
    if parser_type != "REGEX_LINE" && parser_type != "JSON_PATH" {
        return Err(AppError::InvalidInput("parser_type must be REGEX_LINE or JSON_PATH".to_owned()));
    }
    if parser_type == "JSON_PATH" {
        crate::parsers::json_path::validate_config(parser_config_json)
            .map_err(|e| AppError::InvalidInput(format!("invalid parser_config_json: {e}")))?;
    }
    Ok(())
}

fn validate_max_age_days(max_age_days: Option<i32>) -> Result<(), AppError> {
    if let Some(n) = max_age_days
        && n <= 0
    {
        return Err(AppError::InvalidInput("max_age_days must be a positive integer".to_owned()));
    }
    Ok(())
}

/// Body of `POST /api/destination-groups/{group_id}/feeds`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateFeedPayload {
    /// Human-readable name. Must be unique across all feeds, regardless of group.
    pub name: String,
    /// HTTP/HTTPS feed URL.
    pub source_url: String,
    /// Parser algorithm: `"REGEX_LINE"` or `"JSON_PATH"`.
    #[serde(default = "default_parser_type")]
    pub parser_type: String,
    /// Parser configuration JSON. Mandatory (and validated) for `JSON_PATH`.
    #[serde(default)]
    pub parser_config_json: Option<String>,
    /// Discards a record older than this many days. Only meaningful with a `JSON_PATH`
    /// `last_seen_at` selector.
    #[serde(default)]
    pub max_age_days: Option<i32>,
    /// Per-feed override of the owning group's `skip_bogon_filtering`.
    #[serde(default)]
    pub skip_bogon_filtering: Option<bool>,
}

fn default_parser_type() -> String {
    "REGEX_LINE".to_owned()
}

/// Body of `PATCH /api/destination-groups/{group_id}/feeds/{feed_id}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateFeedPayload {
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
    /// New max-age-in-days filter. `Some(None)` (an explicit JSON `null`) clears it; omitted
    /// leaves it unchanged. Modeled as a nested `Option` via `#[serde(default)]` on an
    /// `Option<Option<i32>>` would be more precise but adds real complexity for a rarely-cleared
    /// field — clearing it today means sending `0` or re-creating the feed; documented here so
    /// the limitation is explicit rather than silently surprising.
    #[serde(default)]
    pub max_age_days: Option<i32>,
    /// New per-feed bogon-filtering override.
    #[serde(default)]
    pub skip_bogon_filtering: Option<bool>,
}

/// Loads feed `feed_id`, confirms it belongs to `group_id` (so a client can't reach a different
/// group's feed through a mismatched path pair), and returns it — `404` on either a missing feed
/// or a feed/group mismatch, identical to a genuinely nonexistent id (RBAC_MODEL.md §4's oracle
/// discipline).
async fn load_feed_in_group(
    db: &sea_orm::DatabaseConnection,
    group_id: Uuid,
    feed_id: Uuid,
) -> Result<external_source::Model, AppError> {
    let feed = external_source::Entity::find_by_id(feed_id).one(db).await?.ok_or(AppError::NotFound)?;
    if feed.destination_group_id != group_id {
        return Err(AppError::NotFound);
    }
    Ok(feed)
}

/// `POST /api/destination-groups/{group_id}/feeds`. Requires RBAC R2 on the owning group — a feed
/// has no permission row of its own; adding one is "managing the group's configuration".
pub async fn create_feed(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    StrictPath(group_id): StrictPath<Uuid>,
    StrictJson(payload): StrictJson<CreateFeedPayload>,
) -> Result<impl IntoResponse, AppError> {
    destination_group::Entity::find_by_id(group_id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    let permission = find_permission(&state.db, caller.id, RESOURCE_DESTINATION_GROUP, group_id).await?;
    guard_resource_manage(&caller, permission.as_ref())?;

    validate_feed_parser(&payload.parser_type, payload.parser_config_json.as_deref())?;
    validate_max_age_days(payload.max_age_days)?;

    let now = Utc::now();
    let id = Uuid::new_v4();
    let model = external_source::ActiveModel {
        id: Set(id),
        destination_group_id: Set(group_id),
        name: Set(payload.name.clone()),
        source_url: Set(payload.source_url),
        parser_type: Set(payload.parser_type),
        parser_config_json: Set(payload.parser_config_json),
        max_age_days: Set(payload.max_age_days),
        skip_bogon_filtering: Set(payload.skip_bogon_filtering),
        created_at: Set(now),
        updated_at: Set(now),
    };
    let inserted = external_source::Entity::insert(model).exec_with_returning(&state.db).await.map_err(|e| {
        if matches!(e.sql_err(), Some(sea_orm::SqlErr::UniqueConstraintViolation(_))) {
            AppError::Conflict(format!("a feed named '{}' already exists", payload.name))
        } else {
            AppError::DbError(e)
        }
    })?;

    create_audit_log(&state.db, &caller, client_ip.0, "FEED_CREATE", Some(inserted.name.clone()), None).await?;

    Ok(Json(to_feed_response(inserted)))
}

/// `PATCH /api/destination-groups/{group_id}/feeds/{feed_id}`. Requires RBAC R2 on the owning
/// group.
pub async fn update_feed(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    StrictPath((group_id, feed_id)): StrictPath<(Uuid, Uuid)>,
    StrictJson(payload): StrictJson<UpdateFeedPayload>,
) -> Result<impl IntoResponse, AppError> {
    let existing = load_feed_in_group(&state.db, group_id, feed_id).await?;
    let permission = find_permission(&state.db, caller.id, RESOURCE_DESTINATION_GROUP, group_id).await?;
    guard_resource_manage(&caller, permission.as_ref())?;

    let effective_parser_type = payload.parser_type.as_deref().unwrap_or(&existing.parser_type);
    let effective_config = payload.parser_config_json.as_deref().or(existing.parser_config_json.as_deref());
    validate_feed_parser(effective_parser_type, effective_config)?;
    validate_max_age_days(payload.max_age_days)?;

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
    if let Some(max_age_days) = payload.max_age_days {
        active.max_age_days = Set(Some(max_age_days));
    }
    if let Some(skip_bogon_filtering) = payload.skip_bogon_filtering {
        active.skip_bogon_filtering = Set(Some(skip_bogon_filtering));
    }
    active.updated_at = Set(Utc::now());
    let updated = active.update(&state.db).await?;

    create_audit_log(&state.db, &caller, client_ip.0, "FEED_UPDATE", Some(updated.name.clone()), None).await?;

    Ok(Json(to_feed_response(updated)))
}

/// `DELETE /api/destination-groups/{group_id}/feeds/{feed_id}`. Requires RBAC R2 on the owning
/// group.
pub async fn delete_feed(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    StrictPath((group_id, feed_id)): StrictPath<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    let existing = load_feed_in_group(&state.db, group_id, feed_id).await?;
    let permission = find_permission(&state.db, caller.id, RESOURCE_DESTINATION_GROUP, group_id).await?;
    guard_resource_manage(&caller, permission.as_ref())?;

    let name = existing.name.clone();
    let result = external_source::Entity::delete_by_id(feed_id).exec(&state.db).await?;
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }
    create_audit_log(&state.db, &caller, client_ip.0, "FEED_DELETE", Some(name), None).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ── Test Fetch (unrelated to grouping — dry-runs an arbitrary URL/parser combination) ─────────

/// `POST /api/sources/test-fetch` request: the same fields a feed create/update payload would
/// carry for the fetch+parse pipeline, and nothing else — no `id`, no group, no target vaults.
/// This is deliberately usable against values that have never been saved (the WebUI's "Test
/// Fetch" button in the New/Edit Feed form calls it with whatever is currently typed, before
/// `Create` or `Save` is even clicked).
#[derive(Debug, Deserialize)]
pub struct TestFetchPayload {
    /// HTTP/HTTPS feed URL to fetch.
    pub source_url: String,
    /// Parser algorithm: `"REGEX_LINE"` or `"JSON_PATH"`.
    pub parser_type: String,
    /// Parser configuration JSON (parser-specific keys, plus the generic `headers`/`user_agent`
    /// `FetchOptions` reads — the same blob a real feed's `parser_config_json` would hold).
    #[serde(default)]
    pub parser_config_json: Option<String>,
}

/// Cap on how many extracted addresses the response actually carries. A feed can legitimately
/// contain hundreds of thousands of entries; the WebUI's whole purpose here is "does this
/// config work and does it look right", not a full preview of the result set, so returning
/// everything would make the request slow to transfer and the response unusable to actually read.
const TEST_FETCH_SAMPLE_LIMIT: usize = 50;

/// `POST /api/sources/test-fetch`. Requires `can_manage_sources`, or Master — the same right
/// needed to actually create a destination group (and, transitively, a feed within one), since
/// this exists to be tried before that point. Read-only: runs the exact fetch→decompress→parse
/// pipeline a real scheduled run would (`jobs::external_ingestion::fetch_and_parse`, so there is
/// exactly one implementation of that pipeline for this to accidentally test something different
/// from), but never pushes to any vault and never persists anything, so it writes no `sync_logs`
/// row and no `audit_logs` row — nothing mutated, nothing to audit.
///
/// Mirrors `trigger_destination_group`'s response shape (`200` with a `status`/`error_message`
/// pair) rather than mapping a feed/network failure to an HTTP error status: "the remote feed is
/// unreachable" or "the parser config doesn't match this body" is exactly the information this
/// endpoint exists to surface, not a malformed-request condition on the caller's part. A `400` is
/// reserved for `parser_type` (or, for `JSON_PATH`, `parser_config_json`'s own shape) itself being
/// invalid, since that is a caller mistake the fetch never gets a chance to attempt.
pub async fn test_fetch_external_source(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    StrictJson(payload): StrictJson<TestFetchPayload>,
) -> Result<impl IntoResponse, AppError> {
    guard_resource_creation(&caller, caller.can_manage_sources)?;
    validate_feed_parser(&payload.parser_type, payload.parser_config_json.as_deref())?;

    let start = std::time::Instant::now();
    let result = crate::jobs::external_ingestion::fetch_and_parse(
        &state.http,
        &payload.source_url,
        &payload.parser_type,
        payload.parser_config_json.as_deref(),
    )
    .await;
    let duration_ms = start.elapsed().as_millis() as i32;

    let (status, total_extracted, sample, error) = match result {
        Ok(records) => {
            let mut seen = std::collections::HashSet::new();
            let deduped: Vec<String> =
                records.into_iter().filter(|r| seen.insert(r.address.clone())).map(|r| r.address).collect();
            if deduped.is_empty() {
                // Same "zero is not trustworthy" reasoning as `execute`'s own status derivation: a
                // syntactically clean fetch+parse that found nothing is far more often a
                // misconfigured selector/regex or a captive-portal page than a feed that is
                // genuinely, momentarily empty.
                ("PARTIAL", 0, Vec::new(), None)
            } else {
                let total = deduped.len();
                let sample: Vec<String> = deduped.into_iter().take(TEST_FETCH_SAMPLE_LIMIT).collect();
                ("SUCCESS", total, sample, None)
            }
        }
        Err(e) => ("FAILED", 0, Vec::new(), Some(e)),
    };

    Ok(Json(serde_json::json!({
        "status": status,
        "total_extracted": total_extracted,
        "sample": sample,
        "truncated": total_extracted > TEST_FETCH_SAMPLE_LIMIT,
        "duration_ms": duration_ms,
        "error": error,
    })))
}
