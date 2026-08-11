//! `external_sources` — external threat intelligence HTTP feeds (Spamhaus, FireHOL, AbuseIPDB…).

use sea_orm::entity::prelude::*;

/// The `external_sources` row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "external_sources")]
pub struct Model {
    /// Primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Human-readable name (e.g. `Spamhaus_DROP`).
    #[sea_orm(unique)]
    pub name: String,
    /// HTTP/HTTPS URL of the raw feed.
    pub source_url: String,
    /// Parser algorithm: `"REGEX_LINE"` or `"JSON_PATH"`.
    pub parser_type: String,
    /// JSON configuration for the parser (JSONPath pointer, custom headers, user agent).
    pub parser_config_json: Option<String>,
    /// Cron expression for periodic execution.
    pub cron_schedule: String,
    /// Default group name in target vaults where parsed IPs land.
    pub target_group_name: String,
    /// Ingestion mode. Strictly `"upsert"`.
    pub mode: String,
    /// Enable/disable automatic scheduling.
    pub is_active: bool,
    /// Timestamp of the last execution.
    pub last_run_at: Option<DateTimeUtc>,
    /// Key holding lifecycle authority over this source (RBAC §3).
    pub owner_key_id: Option<Uuid>,
    /// Creation timestamp.
    pub created_at: DateTimeUtc,
    /// Last update timestamp.
    pub updated_at: DateTimeUtc,
}

/// Relations from `external_sources`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// One source maps to many vault targets.
    #[sea_orm(has_many = "super::external_source_vault_target::Entity")]
    ExternalSourceVaultTarget,
}

impl Related<super::external_source_vault_target::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ExternalSourceVaultTarget.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
