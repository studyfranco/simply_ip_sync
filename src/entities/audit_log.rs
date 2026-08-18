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
    /// Denormalized actor name, so the trail survives key deletion. `NOT NULL`: every audited
    /// route runs behind `auth_middleware`, so `create_audit_log` always has a real key to
    /// denormalize from — see `m20260818_000003_audit_attribution_not_null` for why this is
    /// enforced at the schema layer rather than left as an application convention.
    pub api_key_name: String,
    /// Denormalized actor key prefix. `NOT NULL`, same rationale as `api_key_name`.
    pub api_key_prefix: String,
    /// Resolved client IP. `NOT NULL`, same rationale as `api_key_name`.
    pub client_ip: String,
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
