//! `destination_groups` — the scheduled, RBAC-managed parent resource for external-feed ingestion.
//! Owns the cron schedule, default target group name, ingestion mode, target vaults, and the
//! group-wide `skip_bogon_filtering` policy; 1-to-N child feeds (`external_sources`) supply the
//! actual URLs/parsers and are fetched concurrently, aggregated, and pushed as one deduplicated
//! batch per group execution (`jobs::external_ingestion`).

use sea_orm::entity::prelude::*;

/// The `destination_groups` row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "destination_groups")]
pub struct Model {
    /// Primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Human-readable name (e.g. `Public_Blocklists`).
    #[sea_orm(unique)]
    pub name: String,
    /// Default target group name in target vaults where the aggregated, deduplicated feed content
    /// lands.
    pub target_group_name: String,
    /// Cron expression for periodic execution of every child feed, concurrently, as one run.
    pub cron_schedule: String,
    /// Ingestion mode. Strictly `"upsert"` or `"full_replace"`; see `AGENT.MD` §3.A for the
    /// per-chunk `full_replace`-only-on-chunk-0 rule this still applies to, now over the
    /// aggregated multi-feed set rather than one feed's own content.
    pub mode: String,
    /// Enable/disable automatic scheduling.
    pub is_active: bool,
    /// When `false` (the default), the aggregated set is sanitized with `bogon::sanitize`
    /// (loopback/private/link-local/other reserved ranges stripped) before push. `true` bypasses
    /// that stripping for a group deliberately ingesting internal/lab address space. A child feed
    /// may override this per-feed (`external_sources.skip_bogon_filtering`, `None` = inherit this).
    pub skip_bogon_filtering: bool,
    /// Timestamp of the last execution (across every child feed).
    pub last_run_at: Option<DateTimeUtc>,
    /// Key holding lifecycle authority over this group (RBAC §3). Also governs every child feed —
    /// feeds carry no independent RBAC of their own.
    pub owner_key_id: Option<Uuid>,
    /// Creation timestamp.
    pub created_at: DateTimeUtc,
    /// Last update timestamp.
    pub updated_at: DateTimeUtc,
}

/// Relations from `destination_groups`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// One group maps to many target vaults.
    #[sea_orm(has_many = "super::destination_group_vault_target::Entity")]
    DestinationGroupVaultTarget,
    /// One group owns many child feeds.
    #[sea_orm(has_many = "super::external_source::Entity")]
    ExternalSource,
}

impl Related<super::destination_group_vault_target::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::DestinationGroupVaultTarget.def()
    }
}

impl Related<super::external_source::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ExternalSource.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
