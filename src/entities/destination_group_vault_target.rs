//! `destination_group_vault_targets` — M:N junction mapping a destination group to one or more
//! target vault endpoints, with an optional per-target group name override. Replaces
//! `external_source_vault_targets` (dropped in the same migration that introduced this table) now
//! that target vaults are configured once per group rather than once per individual feed.

use sea_orm::entity::prelude::*;

/// The `destination_group_vault_targets` row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "destination_group_vault_targets")]
pub struct Model {
    /// Destination group id. Part of the composite primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub destination_group_id: Uuid,
    /// Target vault endpoint id. Part of the composite primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub vault_endpoint_id: Uuid,
    /// Group name override for this specific vault endpoint. `None` falls back to
    /// `destination_groups.target_group_name`.
    pub target_group_name: Option<String>,
}

/// Relations from `destination_group_vault_targets`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Belongs to a destination group.
    #[sea_orm(
        belongs_to = "super::destination_group::Entity",
        from = "Column::DestinationGroupId",
        to = "super::destination_group::Column::Id",
        on_delete = "Cascade"
    )]
    DestinationGroup,
    /// Belongs to a vault endpoint.
    #[sea_orm(
        belongs_to = "super::vault_endpoint::Entity",
        from = "Column::VaultEndpointId",
        to = "super::vault_endpoint::Column::Id",
        on_delete = "Cascade"
    )]
    VaultEndpoint,
}

impl Related<super::destination_group::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::DestinationGroup.def()
    }
}

impl Related<super::vault_endpoint::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VaultEndpoint.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
