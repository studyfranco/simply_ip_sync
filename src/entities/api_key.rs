//! `api_keys` — authentication tokens, global access rights, and CIDR network binding.
//!
//! `master_marker` is deliberately **not** a field on this `Model`. The column exists in the
//! database as `GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)` under a unique
//! index (see `migration::m20260101_000002_derive_master_marker`); SeaORM builds explicit column
//! lists from the entity, so omitting the field is what guarantees no query ever names it, and
//! every supported engine rejects a write to a generated column. Do not add it back.

use sea_orm::entity::prelude::*;

/// The `api_keys` row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "api_keys")]
pub struct Model {
    /// Primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Human-readable key description.
    pub name: String,
    /// Argon2/SHA-256 hash of the secret API key.
    #[sea_orm(unique)]
    pub key_hash: String,
    /// Per-key HMAC-SHA256 secret, sealed via `SecretCipher` at rest.
    pub signing_secret: Option<String>,
    /// First 8 characters of the key, for display and fast lookup.
    pub prefix: String,
    /// Bypasses all permission checks. Bootstrap-only; never settable through the API.
    pub is_master: bool,
    /// Global privilege to manage API keys. Master-only grant.
    pub can_manage_keys: bool,
    /// Global privilege to create external sources. Master-only grant.
    pub can_manage_sources: bool,
    /// Global privilege to register vault endpoints and inter-vault sync tasks. Master-only grant.
    pub can_manage_vaults: bool,
    /// Parent key creator id. Lineage only; confers no authority (RBAC R3).
    pub parent_key_id: Option<Uuid>,
    /// Comma-separated CIDR ranges permitted to use this key. Empty/`None` means unrestricted.
    pub bound_ips: Option<String>,
    /// Creation timestamp.
    pub created_at: DateTimeUtc,
    /// Last update timestamp.
    pub updated_at: DateTimeUtc,
}

/// Relations from `api_keys`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
