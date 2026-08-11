//! Shared plumbing used by three or more handler domains. Decides nothing: nothing here inspects
//! *who* is calling or returns a refusal that depends on the caller — that boundary belongs to
//! `guards.rs`.

use std::net::IpAddr;

use chrono::Utc;
use rand::RngExt;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::entities::{api_key, api_key_sync_permission, audit_log};
use crate::error::AppError;

/// `api_key_sync_permissions.resource_type` value for external feed sources.
pub const RESOURCE_EXTERNAL_SOURCE: &str = "external_source";
/// `api_key_sync_permissions.resource_type` value for inter-vault sync tasks.
pub const RESOURCE_SYNC_TASK: &str = "sync_task";
/// `api_key_sync_permissions.resource_type` value for vault endpoints.
pub const RESOURCE_VAULT_ENDPOINT: &str = "vault_endpoint";

/// Generates a fresh, high-entropy plaintext API key (64 hex characters).
pub fn generate_random_key() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Hashes a plaintext API key for storage/lookup (`api_keys.key_hash`). Matches the hashing
/// `middleware.rs` performs on every inbound `X-API-Key` header.
pub fn hash_key(plaintext: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    hex::encode(hasher.finalize())
}

/// The first 8 characters of a plaintext key, used for display and fast prefix lookups.
pub fn key_prefix(plaintext: &str) -> String {
    plaintext.chars().take(8).collect()
}

/// Looks up the permission row (if any) that `api_key_id` holds on a specific resource.
pub async fn find_permission<C: ConnectionTrait>(
    db: &C,
    api_key_id: Uuid,
    resource_type: &str,
    resource_id: Uuid,
) -> Result<Option<api_key_sync_permission::Model>, AppError> {
    Ok(api_key_sync_permission::Entity::find()
        .filter(api_key_sync_permission::Column::ApiKeyId.eq(api_key_id))
        .filter(api_key_sync_permission::Column::ResourceType.eq(resource_type))
        .filter(api_key_sync_permission::Column::ResourceId.eq(resource_id))
        .one(db)
        .await?)
}

/// Auto-grants the creator of a new resource full rights (`can_sync`, `can_manage`,
/// `can_view_logs`) on it. Called once, immediately after a resource is created.
pub async fn grant_full_permission<C: ConnectionTrait>(
    db: &C,
    api_key_id: Uuid,
    resource_type: &str,
    resource_id: Uuid,
) -> Result<(), AppError> {
    let row = api_key_sync_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(api_key_id),
        resource_type: Set(resource_type.to_owned()),
        resource_id: Set(resource_id),
        can_sync: Set(true),
        can_manage: Set(true),
        can_view_logs: Set(true),
        created_at: Set(Utc::now()),
    };
    api_key_sync_permission::Entity::insert(row).exec(db).await?;
    Ok(())
}

/// Writes one `audit_logs` row. `key` and `client_ip` are taken by value (not `Option`) because
/// every mutating handler runs behind `auth_middleware`, which guarantees both are already
/// resolved — an unattributed audit write is thereby unrepresentable, not just discouraged.
pub async fn create_audit_log<C: ConnectionTrait>(
    db: &C,
    key: &api_key::Model,
    client_ip: IpAddr,
    action: &str,
    target_resource: Option<String>,
    details: Option<String>,
) -> Result<(), AppError> {
    let log = audit_log::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(Some(key.id)),
        api_key_name: Set(Some(key.name.clone())),
        api_key_prefix: Set(Some(key.prefix.clone())),
        client_ip: Set(Some(client_ip.to_string())),
        action: Set(action.to_owned()),
        target_resource: Set(target_resource),
        details: Set(details),
        timestamp: Set(Utc::now()),
    };
    audit_log::Entity::insert(log).exec(db).await?;
    Ok(())
}
