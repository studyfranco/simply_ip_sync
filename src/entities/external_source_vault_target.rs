//! `external_source_vault_targets` — M:N junction mapping an external source to one or more
//! target vault endpoints, with an optional per-target group name override.

use sea_orm::entity::prelude::*;

/// The `external_source_vault_targets` row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "external_source_vault_targets")]
pub struct Model {
    /// Source feed id. Part of the composite primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub external_source_id: Uuid,
    /// Target vault endpoint id. Part of the composite primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub vault_endpoint_id: Uuid,
    /// Group name override for this specific vault endpoint. `None` falls back to
    /// `external_sources.target_group_name`.
    pub target_group_name: Option<String>,
}

/// Relations from `external_source_vault_targets`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Belongs to an external source.
    #[sea_orm(
        belongs_to = "super::external_source::Entity",
        from = "Column::ExternalSourceId",
        to = "super::external_source::Column::Id",
        on_delete = "Cascade"
    )]
    ExternalSource,
    /// Belongs to a vault endpoint.
    #[sea_orm(
        belongs_to = "super::vault_endpoint::Entity",
        from = "Column::VaultEndpointId",
        to = "super::vault_endpoint::Column::Id",
        on_delete = "Cascade"
    )]
    VaultEndpoint,
}

impl Related<super::external_source::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ExternalSource.def()
    }
}

impl Related<super::vault_endpoint::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VaultEndpoint.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
