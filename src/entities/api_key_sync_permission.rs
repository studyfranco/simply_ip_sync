//! `api_key_sync_permissions` — granular per-resource permissions for an API key.

use sea_orm::entity::prelude::*;
use serde::Serialize;

/// The `api_key_sync_permissions` row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "api_key_sync_permissions")]
pub struct Model {
    /// Primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Target API key.
    pub api_key_id: Uuid,
    /// Resource category: `"external_source"`, `"sync_task"`, or `"vault_endpoint"`.
    pub resource_type: String,
    /// Id of the specific resource.
    pub resource_id: Uuid,
    /// Permission to manually trigger the resource's `/trigger` endpoint.
    pub can_sync: bool,
    /// Resource management half of the RBAC R2 conjunction (requires `can_manage_keys` too).
    pub can_manage: bool,
    /// Permission to view this resource's execution logs.
    pub can_view_logs: bool,
    /// Assignment timestamp.
    pub created_at: DateTimeUtc,
}

/// Relations from `api_key_sync_permissions`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Belongs to its API key.
    #[sea_orm(
        belongs_to = "super::api_key::Entity",
        from = "Column::ApiKeyId",
        to = "super::api_key::Column::Id",
        on_delete = "Cascade"
    )]
    ApiKey,
}

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKey.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
