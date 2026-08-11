//! API key endpoints: identity (`get_me`), CRUD, rotation, and per-resource permission grants.
//! Deliberately not split further — R1–R7 are about how keys delegate to other keys, so subtree
//! resolution, lifecycle, and permission grants are one subject.

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ExprTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use super::support::{create_audit_log, generate_random_key, hash_key, key_prefix};
use super::{guard_delegated_grant, guard_manage_keys, guard_master_immutable, guard_revocation, guard_rotation_allowed, guard_scope_elevation};
use crate::entities::{api_key, api_key_sync_permission, external_source, vault_endpoint, vault_sync_task};
use crate::error::AppError;
use crate::extract::StrictJson;
use crate::middleware::ClientIp;
use crate::state::AppState;

/// An `api_keys` row as returned by the API. Never includes `key_hash` or `signing_secret`.
#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    /// Key id.
    pub id: Uuid,
    /// Human-readable description.
    pub name: String,
    /// First 8 characters of the plaintext key.
    pub prefix: String,
    /// Whether this is the (unique) Master key.
    pub is_master: bool,
    /// Global privilege to manage other API keys.
    pub can_manage_keys: bool,
    /// Global privilege to create external sources.
    pub can_manage_sources: bool,
    /// Global privilege to register vault endpoints and inter-vault sync tasks.
    pub can_manage_vaults: bool,
    /// Parent key creator id. Lineage only.
    pub parent_key_id: Option<Uuid>,
    /// Comma-separated CIDR ranges permitted to use this key.
    pub bound_ips: Option<String>,
    /// Creation timestamp.
    pub created_at: chrono::DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: chrono::DateTime<Utc>,
}

impl From<api_key::Model> for ApiKeyResponse {
    fn from(m: api_key::Model) -> Self {
        Self {
            id: m.id,
            name: m.name,
            prefix: m.prefix,
            is_master: m.is_master,
            can_manage_keys: m.can_manage_keys,
            can_manage_sources: m.can_manage_sources,
            can_manage_vaults: m.can_manage_vaults,
            parent_key_id: m.parent_key_id,
            bound_ips: m.bound_ips,
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

fn can_administer(caller: &api_key::Model, target: &api_key::Model) -> bool {
    caller.is_master || (caller.can_manage_keys && target.parent_key_id == Some(caller.id))
}

/// `GET /api/auth/me`. Every authenticated key can read its own identity.
pub async fn get_me(axum::Extension(caller): axum::Extension<api_key::Model>) -> impl IntoResponse {
    Json(ApiKeyResponse::from(caller))
}

/// `GET /api/keys`. Master sees every key; a Parent sees itself and its direct daughters; a
/// Daughter sees only itself.
pub async fn list_api_keys(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    let keys = if caller.is_master {
        api_key::Entity::find().all(&state.db).await?
    } else {
        api_key::Entity::find()
            .filter(api_key::Column::Id.eq(caller.id).or(api_key::Column::ParentKeyId.eq(caller.id)))
            .all(&state.db)
            .await?
    };
    Ok(Json(keys.into_iter().map(ApiKeyResponse::from).collect::<Vec<_>>()))
}

/// `GET /api/keys/{id}`.
pub async fn get_api_key(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let target = api_key::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if !(caller.is_master || target.id == caller.id || target.parent_key_id == Some(caller.id)) {
        return Err(AppError::NotFound);
    }
    Ok(Json(ApiKeyResponse::from(target)))
}

/// Body of `POST /api/keys`. `is_master` is deliberately absent from this type (RBAC §5): it must
/// never be settable through any API payload, not merely rejected in a handler.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateApiKeyPayload {
    /// Human-readable description.
    pub name: String,
    /// Grants `can_manage_keys`. Requires the caller to be Master (RBAC R4).
    #[serde(default)]
    pub can_manage_keys: bool,
    /// Grants `can_manage_sources`. Requires the caller to be Master (RBAC R4).
    #[serde(default)]
    pub can_manage_sources: bool,
    /// Grants `can_manage_vaults`. Requires the caller to be Master (RBAC R4).
    #[serde(default)]
    pub can_manage_vaults: bool,
    /// Comma-separated CIDR ranges permitted to use this key.
    #[serde(default)]
    pub bound_ips: Option<String>,
}

/// `POST /api/keys`. Requires `can_manage_keys` or Master. Returns the plaintext key and signing
/// secret exactly once — they are never recoverable again except by rotation.
pub async fn create_api_key(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    StrictJson(payload): StrictJson<CreateApiKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    guard_manage_keys(&caller)?;
    guard_scope_elevation(&caller, payload.can_manage_keys, payload.can_manage_sources, payload.can_manage_vaults)?;

    let plaintext_key = generate_random_key();
    let plaintext_secret = crate::crypto::generate_signing_secret();
    let now = Utc::now();
    let id = Uuid::new_v4();

    let model = api_key::ActiveModel {
        id: Set(id),
        name: Set(payload.name),
        key_hash: Set(hash_key(&plaintext_key)),
        signing_secret: Set(Some(state.cipher.seal(&plaintext_secret)?)),
        prefix: Set(key_prefix(&plaintext_key)),
        is_master: Set(false),
        can_manage_keys: Set(payload.can_manage_keys),
        can_manage_sources: Set(payload.can_manage_sources),
        can_manage_vaults: Set(payload.can_manage_vaults),
        parent_key_id: Set(Some(caller.id)),
        bound_ips: Set(payload.bound_ips),
        created_at: Set(now),
        updated_at: Set(now),
    };
    let inserted = api_key::Entity::insert(model).exec_with_returning(&state.db).await?;

    create_audit_log(&state.db, &caller, client_ip.0, "KEY_CREATE", Some(inserted.name.clone()), None).await?;

    Ok(Json(json!({
        "key": ApiKeyResponse::from(inserted),
        "plaintext_key": plaintext_key,
        "plaintext_signing_secret": plaintext_secret,
    })))
}

/// Body of `PATCH /api/keys/{id}`. `is_master` is deliberately absent (RBAC §5).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateApiKeyPayload {
    /// New description.
    #[serde(default)]
    pub name: Option<String>,
    /// New `can_manage_keys` value. Setting to `true` requires the caller to be Master (RBAC R4).
    #[serde(default)]
    pub can_manage_keys: Option<bool>,
    /// New `can_manage_sources` value. Setting to `true` requires the caller to be Master.
    #[serde(default)]
    pub can_manage_sources: Option<bool>,
    /// New `can_manage_vaults` value. Setting to `true` requires the caller to be Master.
    #[serde(default)]
    pub can_manage_vaults: Option<bool>,
    /// New comma-separated CIDR ranges. The Master key may only ever change this field (RBAC §5).
    #[serde(default)]
    pub bound_ips: Option<String>,
}

/// `PATCH /api/keys/{id}`. Requires `can_manage_keys` and administrative authority over `id`
/// (Master, or its direct parent).
pub async fn update_api_key(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    Path(id): Path<Uuid>,
    StrictJson(payload): StrictJson<UpdateApiKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    guard_manage_keys(&caller)?;
    let target = api_key::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if !can_administer(&caller, &target) {
        return Err(AppError::Forbidden("no administrative authority over this key".to_owned()));
    }
    let touches_non_bound_ips =
        payload.name.is_some() || payload.can_manage_keys.is_some() || payload.can_manage_sources.is_some() || payload.can_manage_vaults.is_some();
    guard_master_immutable(target.is_master, touches_non_bound_ips)?;
    guard_scope_elevation(
        &caller,
        payload.can_manage_keys.unwrap_or(false),
        payload.can_manage_sources.unwrap_or(false),
        payload.can_manage_vaults.unwrap_or(false),
    )?;

    let mut active: api_key::ActiveModel = target.into();
    if let Some(name) = payload.name {
        active.name = Set(name);
    }
    if let Some(v) = payload.can_manage_keys {
        active.can_manage_keys = Set(v);
    }
    if let Some(v) = payload.can_manage_sources {
        active.can_manage_sources = Set(v);
    }
    if let Some(v) = payload.can_manage_vaults {
        active.can_manage_vaults = Set(v);
    }
    if let Some(bound_ips) = payload.bound_ips {
        active.bound_ips = Set(Some(bound_ips));
    }
    active.updated_at = Set(Utc::now());
    let updated = active.update(&state.db).await?;

    create_audit_log(&state.db, &caller, client_ip.0, "KEY_UPDATE", Some(updated.name.clone()), None).await?;
    Ok(Json(ApiKeyResponse::from(updated)))
}

async fn collect_subtree(db: &sea_orm::DatabaseConnection, root: api_key::Model) -> Result<Vec<api_key::Model>, AppError> {
    let mut result = vec![root.clone()];
    let mut frontier = vec![root.id];
    while !frontier.is_empty() {
        let children = api_key::Entity::find()
            .filter(api_key::Column::ParentKeyId.is_in(frontier.clone()))
            .all(db)
            .await?;
        frontier = children.iter().map(|c| c.id).collect();
        result.extend(children);
    }
    Ok(result)
}

async fn owned_resource_inventory(
    db: &sea_orm::DatabaseConnection,
    key_ids: &[Uuid],
) -> Result<Vec<serde_json::Value>, AppError> {
    let mut inventory = Vec::new();
    let vaults = vault_endpoint::Entity::find()
        .filter(vault_endpoint::Column::OwnerKeyId.is_in(key_ids.to_vec()))
        .all(db)
        .await?;
    inventory.extend(vaults.into_iter().map(|v| json!({"type": "vault_endpoint", "id": v.id, "name": v.name, "owner_key_id": v.owner_key_id})));
    let sources = external_source::Entity::find()
        .filter(external_source::Column::OwnerKeyId.is_in(key_ids.to_vec()))
        .all(db)
        .await?;
    inventory.extend(sources.into_iter().map(|s| json!({"type": "external_source", "id": s.id, "name": s.name, "owner_key_id": s.owner_key_id})));
    let tasks = vault_sync_task::Entity::find()
        .filter(vault_sync_task::Column::OwnerKeyId.is_in(key_ids.to_vec()))
        .all(db)
        .await?;
    inventory.extend(tasks.into_iter().map(|t| json!({"type": "sync_task", "id": t.id, "name": t.name, "owner_key_id": t.owner_key_id})));
    Ok(inventory)
}

/// `DELETE /api/keys/{id}`. Requires `can_manage_keys` and administrative authority. Cascades
/// recursively through the key's daughter subtree. Data is never destroyed implicitly (RBAC §6):
/// if any key in the subtree still owns a vault endpoint, external source, or sync task, deletion
/// is refused with a structured inventory — reassign or delete those resources first.
pub async fn delete_api_key(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    guard_manage_keys(&caller)?;
    let target = api_key::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if target.is_master {
        return Err(AppError::Forbidden("the Master key cannot be deleted through the API (RBAC §5)".to_owned()));
    }
    if !can_administer(&caller, &target) {
        return Err(AppError::Forbidden("no administrative authority over this key".to_owned()));
    }

    let name = target.name.clone();
    let subtree = collect_subtree(&state.db, target).await?;
    let subtree_ids: Vec<Uuid> = subtree.iter().map(|k| k.id).collect();

    let inventory = owned_resource_inventory(&state.db, &subtree_ids).await?;
    if !inventory.is_empty() {
        return Err(AppError::ConflictWithDetails {
            message: "this key (or a daughter in its subtree) still owns resources; reassign or delete them first"
                .to_owned(),
            details: json!({ "owned_resources": inventory }),
        });
    }

    api_key::Entity::delete_many().filter(api_key::Column::Id.is_in(subtree_ids)).exec(&state.db).await?;
    create_audit_log(&state.db, &caller, client_ip.0, "KEY_DELETE", Some(name), None).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// `POST /api/keys/{id}/rotate`. Requires `can_manage_keys` and administrative authority. Refused
/// for the Master key (RBAC §5). Returns the new plaintext key exactly once.
pub async fn rotate_api_key(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    guard_manage_keys(&caller)?;
    let target = api_key::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    guard_rotation_allowed(target.is_master)?;
    if !can_administer(&caller, &target) {
        return Err(AppError::Forbidden("no administrative authority over this key".to_owned()));
    }

    let plaintext_key = generate_random_key();
    let mut active: api_key::ActiveModel = target.into();
    active.key_hash = Set(hash_key(&plaintext_key));
    active.prefix = Set(key_prefix(&plaintext_key));
    active.updated_at = Set(Utc::now());
    let updated = active.update(&state.db).await?;

    create_audit_log(&state.db, &caller, client_ip.0, "KEY_ROTATE", Some(updated.name.clone()), None).await?;
    Ok(Json(json!({ "plaintext_key": plaintext_key })))
}

/// `POST /api/keys/{id}/rotate-secret`. Requires `can_manage_keys` and administrative authority.
/// Refused for the Master key (RBAC §5). Returns the new plaintext signing secret exactly once.
pub async fn rotate_signing_secret(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    guard_manage_keys(&caller)?;
    let target = api_key::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    guard_rotation_allowed(target.is_master)?;
    if !can_administer(&caller, &target) {
        return Err(AppError::Forbidden("no administrative authority over this key".to_owned()));
    }

    let plaintext_secret = crate::crypto::generate_signing_secret();
    let mut active: api_key::ActiveModel = target.into();
    active.signing_secret = Set(Some(state.cipher.seal(&plaintext_secret)?));
    active.updated_at = Set(Utc::now());
    let updated = active.update(&state.db).await?;

    create_audit_log(&state.db, &caller, client_ip.0, "KEY_ROTATE_SECRET", Some(updated.name.clone()), None).await?;
    Ok(Json(json!({ "plaintext_signing_secret": plaintext_secret })))
}

/// Body of `PUT /api/keys/{id}/permissions`: grants or updates a permission row for `id` on a
/// specific resource.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantPermissionPayload {
    /// Resource category: `"external_source"`, `"sync_task"`, or `"vault_endpoint"`.
    pub resource_type: String,
    /// Id of the specific resource.
    pub resource_id: Uuid,
    /// Grants permission to manually trigger the resource.
    #[serde(default)]
    pub can_sync: bool,
    /// Grants permission to manage (edit config of, or delegate rights on) the resource.
    #[serde(default)]
    pub can_manage: bool,
    /// Grants permission to view the resource's execution logs.
    #[serde(default)]
    pub can_view_logs: bool,
}

/// `GET /api/keys/{id}/permissions`.
pub async fn list_key_permissions(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let target = api_key::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if !(caller.is_master || target.id == caller.id || target.parent_key_id == Some(caller.id)) {
        return Err(AppError::NotFound);
    }
    let rows = api_key_sync_permission::Entity::find()
        .filter(api_key_sync_permission::Column::ApiKeyId.eq(id))
        .all(&state.db)
        .await?;
    Ok(Json(rows))
}

/// `PUT /api/keys/{id}/permissions`. Requires `can_manage_keys`, RBAC R2 (manage rights on the
/// target resource), and R1/R7 (the caller may only grant verbs it holds itself).
pub async fn grant_key_permission(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    Path(id): Path<Uuid>,
    StrictJson(payload): StrictJson<GrantPermissionPayload>,
) -> Result<impl IntoResponse, AppError> {
    guard_manage_keys(&caller)?;
    let target = api_key::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if payload.resource_type != "external_source" && payload.resource_type != "sync_task" && payload.resource_type != "vault_endpoint" {
        return Err(AppError::InvalidInput("resource_type must be external_source, sync_task, or vault_endpoint".to_owned()));
    }

    let caller_permission =
        super::support::find_permission(&state.db, caller.id, &payload.resource_type, payload.resource_id).await?;
    guard_delegated_grant(&caller, caller_permission.as_ref(), payload.can_sync, payload.can_manage, payload.can_view_logs)?;

    let existing =
        super::support::find_permission(&state.db, target.id, &payload.resource_type, payload.resource_id).await?;
    let row = match existing {
        Some(existing) => {
            let mut active: api_key_sync_permission::ActiveModel = existing.into();
            active.can_sync = Set(payload.can_sync);
            active.can_manage = Set(payload.can_manage);
            active.can_view_logs = Set(payload.can_view_logs);
            active.update(&state.db).await?
        }
        None => {
            let active = api_key_sync_permission::ActiveModel {
                id: Set(Uuid::new_v4()),
                api_key_id: Set(target.id),
                resource_type: Set(payload.resource_type.clone()),
                resource_id: Set(payload.resource_id),
                can_sync: Set(payload.can_sync),
                can_manage: Set(payload.can_manage),
                can_view_logs: Set(payload.can_view_logs),
                created_at: Set(Utc::now()),
            };
            active.insert(&state.db).await?
        }
    };

    create_audit_log(
        &state.db,
        &caller,
        client_ip.0,
        "PERMISSION_GRANT",
        Some(format!("{} on {}:{}", target.name, payload.resource_type, payload.resource_id)),
        None,
    )
    .await?;
    Ok(Json(row))
}

/// `DELETE /api/keys/{id}/permissions/{permission_id}`. Requires `can_manage_keys` and RBAC R2/R6
/// (manage rights on the resource; the revoker need not hold the verb being removed).
pub async fn revoke_key_permission(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    Path((id, permission_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    guard_manage_keys(&caller)?;
    let permission = api_key_sync_permission::Entity::find_by_id(permission_id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;
    if permission.api_key_id != id {
        return Err(AppError::NotFound);
    }
    let caller_permission =
        super::support::find_permission(&state.db, caller.id, &permission.resource_type, permission.resource_id).await?;
    guard_revocation(&caller, caller_permission.as_ref())?;

    api_key_sync_permission::Entity::delete_by_id(permission_id).exec(&state.db).await?;
    create_audit_log(&state.db, &caller, client_ip.0, "PERMISSION_REVOKE", Some(format!("permission {permission_id}")), None)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
