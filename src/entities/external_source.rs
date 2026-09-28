//! `external_sources` — one feed ("child") belonging to a `destination_groups` ("parent") row.
//! Carries only what's specific to fetching and parsing *this* feed (URL, parser, its config); the
//! schedule, target vaults, ingestion mode, and default group-wide bogon-filtering policy all live
//! on the owning `destination_groups` row, since 1-to-N feeds in the same group are fetched
//! concurrently and pushed as one aggregated batch, not independently.

use sea_orm::entity::prelude::*;

/// The `external_sources` row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "external_sources")]
pub struct Model {
    /// Primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Owning destination group.
    pub destination_group_id: Uuid,
    /// Human-readable name (e.g. `Spamhaus_DROP`), unique across all feeds regardless of group.
    #[sea_orm(unique)]
    pub name: String,
    /// HTTP/HTTPS URL of the raw feed.
    pub source_url: String,
    /// Parser algorithm: `"REGEX_LINE"` or `"JSON_PATH"`.
    pub parser_type: String,
    /// JSON configuration for the parser (field mapping, custom headers, user agent — see
    /// `parsers::json_path` for the `JSON_PATH` `$.`-prefixed selector format).
    pub parser_config_json: Option<String>,
    /// Discards a record whose `last_seen_at` (per the `JSON_PATH` config's optional
    /// `last_seen_at` selector) is older than this many days. Ignored when no `last_seen_at`
    /// selector is configured — there is no timestamp to filter on. `None` disables the filter
    /// even when a selector is present (keep everything, however old).
    pub max_age_days: Option<i32>,
    /// Per-feed override of the owning group's `skip_bogon_filtering`. `None` inherits the
    /// group's own setting; `Some(_)` takes precedence for this feed's own contribution to the
    /// group's aggregated set.
    pub skip_bogon_filtering: Option<bool>,
    /// Creation timestamp.
    pub created_at: DateTimeUtc,
    /// Last update timestamp.
    pub updated_at: DateTimeUtc,
}

/// Relations from `external_sources`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Belongs to its destination group.
    #[sea_orm(
        belongs_to = "super::destination_group::Entity",
        from = "Column::DestinationGroupId",
        to = "super::destination_group::Column::Id",
        on_delete = "Cascade"
    )]
    DestinationGroup,
}

impl Related<super::destination_group::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::DestinationGroup.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
