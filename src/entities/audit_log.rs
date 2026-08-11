//! `audit_logs` — security audit trail tracking mutating operations.

use sea_orm::entity::prelude::*;
use serde::Serialize;

/// The `audit_logs` row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "audit_logs")]
pub struct Model {
    /// Primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Performing API key id. `NULL` once the key is deleted (`ON DELETE SET NULL`).
    pub api_key_id: Option<Uuid>,
    /// Denormalized actor name, so the trail survives key deletion.
    pub api_key_name: Option<String>,
    /// Denormalized actor key prefix.
    pub api_key_prefix: Option<String>,
    /// Resolved client IP.
    pub client_ip: Option<String>,
    /// Action name (e.g. `SOURCE_CREATE`, `SOURCE_TRIGGER`, `TASK_UPDATE`, `KEY_ROTATE`).
    pub action: String,
    /// Human-readable target name.
    pub target_resource: Option<String>,
    /// Additional payload context.
    pub details: Option<String>,
    /// Event timestamp.
    pub timestamp: DateTimeUtc,
}

/// Relations from `audit_logs`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Belongs to the performing API key, if it still exists.
    #[sea_orm(
        belongs_to = "super::api_key::Entity",
        from = "Column::ApiKeyId",
        to = "super::api_key::Column::Id",
        on_delete = "SetNull"
    )]
    ApiKey,
}

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKey.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
