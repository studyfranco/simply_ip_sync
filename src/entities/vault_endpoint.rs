//! `vault_endpoints` — configuration and credentials for target/source `simply_ip_vault`
//! instances.

use sea_orm::entity::prelude::*;

/// The `vault_endpoints` row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "vault_endpoints")]
pub struct Model {
    /// Primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Human-readable endpoint name (e.g. `Vault-Paris-DMZ`).
    #[sea_orm(unique)]
    pub name: String,
    /// Base HTTP/HTTPS URL of the distant vault.
    pub target_url: String,
    /// Plaintext `X-API-Key` sent to the remote vault.
    pub api_key: String,
    /// HMAC signing secret used to compute `X-Signature-256` for remote calls. Sealed at rest.
    pub signing_secret: String,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Key holding lifecycle authority over this endpoint (RBAC §3).
    pub owner_key_id: Option<Uuid>,
    /// Creation timestamp.
    pub created_at: DateTimeUtc,
    /// Last update timestamp.
    pub updated_at: DateTimeUtc,
}

/// Relations from `vault_endpoints`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
