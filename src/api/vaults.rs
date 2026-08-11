//! `vault_endpoints` CRUD — configuration and credentials for remote `simply_ip_vault` instances.

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::support::{create_audit_log, find_permission, grant_full_permission, RESOURCE_VAULT_ENDPOINT};
use super::{guard_resource_creation, guard_resource_lifecycle, guard_resource_manage};
use crate::entities::{api_key, vault_endpoint};
use crate::error::AppError;
use crate::extract::StrictJson;
use crate::middleware::ClientIp;
use crate::state::AppState;

/// A `vault_endpoints` row as returned by the API. Credentials (`api_key`, `signing_secret`) are
/// never included — only whether they are set.
#[derive(Debug, Serialize)]
pub struct VaultEndpointResponse {
    /// Endpoint id.
    pub id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// Base URL of the remote vault.
    pub target_url: String,
    /// Optional description.
    pub description: Option<String>,
    /// Key holding lifecycle authority over this endpoint.
    pub owner_key_id: Option<Uuid>,
    /// Creation timestamp.
    pub created_at: chrono::DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: chrono::DateTime<Utc>,
}

impl From<vault_endpoint::Model> for VaultEndpointResponse {
    fn from(m: vault_endpoint::Model) -> Self {
        Self {
            id: m.id,
            name: m.name,
            target_url: m.target_url,
            description: m.description,
            owner_key_id: m.owner_key_id,
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

/// Body of `POST /api/vaults`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateVaultEndpointPayload {
    /// Human-readable name. Must be unique.
    pub name: String,
    /// Base HTTP/HTTPS URL of the remote vault.
    pub target_url: String,
    /// Plaintext `X-API-Key` this service will send to the remote vault.
    pub api_key: String,
    /// HMAC signing secret used to sign requests to the remote vault. Sealed at rest.
    pub signing_secret: String,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
}

/// Body of `PATCH /api/vaults/{id}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateVaultEndpointPayload {
    /// New name, if renaming.
    #[serde(default)]
    pub name: Option<String>,
    /// New target URL.
    #[serde(default)]
    pub target_url: Option<String>,
    /// New plaintext remote API key.
    #[serde(default)]
    pub api_key: Option<String>,
    /// New signing secret (will be sealed at rest).
    #[serde(default)]
    pub signing_secret: Option<String>,
    /// New description.
    #[serde(default)]
    pub description: Option<String>,
}

/// `GET /api/vaults`. Visible to Master, the owner, or any key holding a permission row on the
/// endpoint.
pub async fn list_vault_endpoints(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    let all = vault_endpoint::Entity::find().all(&state.db).await?;
    let mut visible = Vec::new();
    for endpoint in all {
        if caller.is_master
            || endpoint.owner_key_id == Some(caller.id)
            || find_permission(&state.db, caller.id, RESOURCE_VAULT_ENDPOINT, endpoint.id).await?.is_some()
        {
            visible.push(VaultEndpointResponse::from(endpoint));
        }
    }
    Ok(Json(visible))
}

/// `GET /api/vaults/{id}`.
pub async fn get_vault_endpoint(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let endpoint = vault_endpoint::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    let visible = caller.is_master
        || endpoint.owner_key_id == Some(caller.id)
        || find_permission(&state.db, caller.id, RESOURCE_VAULT_ENDPOINT, id).await?.is_some();
    if !visible {
        return Err(AppError::NotFound);
    }
    Ok(Json(VaultEndpointResponse::from(endpoint)))
}

/// `POST /api/vaults`. Requires `can_manage_vaults` or Master.
pub async fn create_vault_endpoint(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    StrictJson(payload): StrictJson<CreateVaultEndpointPayload>,
) -> Result<impl IntoResponse, AppError> {
    guard_resource_creation(&caller, caller.can_manage_vaults)?;

    let sealed_secret = state.cipher.seal(&payload.signing_secret)?;
    let now = Utc::now();
    let id = Uuid::new_v4();
    let model = vault_endpoint::ActiveModel {
        id: Set(id),
        name: Set(payload.name.clone()),
        target_url: Set(payload.target_url),
        api_key: Set(payload.api_key),
        signing_secret: Set(sealed_secret),
        description: Set(payload.description),
        owner_key_id: Set(Some(caller.id)),
        created_at: Set(now),
        updated_at: Set(now),
    };
    let inserted = vault_endpoint::Entity::insert(model).exec_with_returning(&state.db).await.map_err(|e| {
        if matches!(e.sql_err(), Some(sea_orm::SqlErr::UniqueConstraintViolation(_))) {
            AppError::Conflict(format!("a vault endpoint named '{}' already exists", payload.name))
        } else {
            AppError::DbError(e)
        }
    })?;

    grant_full_permission(&state.db, caller.id, RESOURCE_VAULT_ENDPOINT, id).await?;
    create_audit_log(&state.db, &caller, client_ip.0, "VAULT_CREATE", Some(inserted.name.clone()), None).await?;

    Ok(Json(VaultEndpointResponse::from(inserted)))
}

/// `PATCH /api/vaults/{id}`. Requires RBAC R2 (`can_manage_keys` + a `can_manage` row on this
/// endpoint), or Master.
pub async fn update_vault_endpoint(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    Path(id): Path<Uuid>,
    StrictJson(payload): StrictJson<UpdateVaultEndpointPayload>,
) -> Result<impl IntoResponse, AppError> {
    let existing = vault_endpoint::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    let permission = find_permission(&state.db, caller.id, RESOURCE_VAULT_ENDPOINT, id).await?;
    guard_resource_manage(&caller, permission.as_ref())?;

    let mut active: vault_endpoint::ActiveModel = existing.into();
    if let Some(name) = payload.name {
        active.name = Set(name);
    }
    if let Some(target_url) = payload.target_url {
        active.target_url = Set(target_url);
    }
    if let Some(api_key_val) = payload.api_key {
        active.api_key = Set(api_key_val);
    }
    if let Some(secret) = payload.signing_secret {
        active.signing_secret = Set(state.cipher.seal(&secret)?);
    }
    if let Some(description) = payload.description {
        active.description = Set(Some(description));
    }
    active.updated_at = Set(Utc::now());

    let updated = active.update(&state.db).await?;
    create_audit_log(&state.db, &caller, client_ip.0, "VAULT_UPDATE", Some(updated.name.clone()), None).await?;
    Ok(Json(VaultEndpointResponse::from(updated)))
}

/// `DELETE /api/vaults/{id}`. Requires RBAC §3 (Master or the endpoint's owner).
pub async fn delete_vault_endpoint(
    State(state): State<AppState>,
    axum::Extension(caller): axum::Extension<api_key::Model>,
    axum::Extension(client_ip): axum::Extension<ClientIp>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let existing = vault_endpoint::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    guard_resource_lifecycle(&caller, existing.owner_key_id)?;

    let name = existing.name.clone();
    vault_endpoint::Entity::delete_by_id(id).exec(&state.db).await?;
    create_audit_log(&state.db, &caller, client_ip.0, "VAULT_DELETE", Some(name), None).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
