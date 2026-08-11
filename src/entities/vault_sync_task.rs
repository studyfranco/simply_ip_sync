//! `vault_sync_tasks` — inter-vault delta replication tasks from a source vault group to target
//! vaults.

use sea_orm::entity::prelude::*;

/// The `vault_sync_tasks` row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "vault_sync_tasks")]
pub struct Model {
    /// Primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Human-readable task name (e.g. `Sync_Paris_To_Lyon`).
    #[sea_orm(unique)]
    pub name: String,
    /// Source vault endpoint id.
    pub source_vault_id: Uuid,
    /// Group name to query on the source vault.
    pub source_group_name: String,
    /// Default target group name on receiving vaults.
    pub target_group_name: String,
    /// Cron expression for periodic delta polling.
    pub cron_schedule: String,
    /// High-water mark timestamp used for `since=` delta queries.
    pub last_sync_at: Option<DateTimeUtc>,
    /// Sync mode. Strictly `"upsert"`.
    pub mode: String,
    /// Enable/disable task execution.
    pub is_active: bool,
    /// Key holding lifecycle authority over this task (RBAC §3).
    pub owner_key_id: Option<Uuid>,
    /// Creation timestamp.
    pub created_at: DateTimeUtc,
    /// Last update timestamp.
    pub updated_at: DateTimeUtc,
}

/// Relations from `vault_sync_tasks`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Belongs to its source vault endpoint.
    #[sea_orm(
        belongs_to = "super::vault_endpoint::Entity",
        from = "Column::SourceVaultId",
        to = "super::vault_endpoint::Column::Id",
        on_delete = "Cascade"
    )]
    SourceVault,
    /// One task maps to many target vaults.
    #[sea_orm(has_many = "super::vault_sync_task_target::Entity")]
    VaultSyncTaskTarget,
}

impl Related<super::vault_endpoint::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SourceVault.def()
    }
}

impl Related<super::vault_sync_task_target::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VaultSyncTaskTarget.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
