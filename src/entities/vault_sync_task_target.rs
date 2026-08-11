//! `vault_sync_task_targets` — M:N junction mapping an inter-vault sync task to one or more target
//! vault endpoints, with an optional per-target group name override.

use sea_orm::entity::prelude::*;

/// The `vault_sync_task_targets` row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "vault_sync_task_targets")]
pub struct Model {
    /// Inter-vault sync task id. Part of the composite primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub vault_sync_task_id: Uuid,
    /// Target receiving vault endpoint id. Part of the composite primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub target_vault_id: Uuid,
    /// Group name override for this specific receiving vault. `None` falls back to
    /// `vault_sync_tasks.target_group_name`.
    pub target_group_name: Option<String>,
}

/// Relations from `vault_sync_task_targets`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Belongs to its sync task.
    #[sea_orm(
        belongs_to = "super::vault_sync_task::Entity",
        from = "Column::VaultSyncTaskId",
        to = "super::vault_sync_task::Column::Id",
        on_delete = "Cascade"
    )]
    VaultSyncTask,
    /// Belongs to its target vault endpoint.
    #[sea_orm(
        belongs_to = "super::vault_endpoint::Entity",
        from = "Column::TargetVaultId",
        to = "super::vault_endpoint::Column::Id",
        on_delete = "Cascade"
    )]
    TargetVault,
}

impl Related<super::vault_sync_task::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VaultSyncTask.def()
    }
}

impl Related<super::vault_endpoint::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::TargetVault.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
