//! Refactors `external_sources` from a flat, independently-scheduled feed into a child "feed" of
//! a new parent resource, `destination_groups`: the cron schedule, target group name, target
//! vaults, ingestion mode, and (new) `skip_bogon_filtering` policy move up to the group, which can
//! now own 1-to-N feeds that are fetched concurrently and pushed as one aggregated, deduplicated
//! batch (`jobs::external_ingestion`). See `AGENT_NOTES.MD`'s corresponding session entry for the
//! full rationale.
//!
//! # Data migration, not just a structural rename
//!
//! There is no production deployment of this service yet (confirmed in an earlier session — see
//! `AGENT.MD` §7's migration-naming note, which relied on the same fact), so a destructive
//! rebuild would be defensible on its own. It still carries every existing row across rather than
//! dropping them, because the mapping is trivial and free: each pre-existing `external_sources`
//! row becomes its own 1:1 `destination_groups` row, reusing the **same UUID** for both — a
//! feed's own id doubles as its new parent group's id. That trick is what makes backfilling the
//! new `external_sources.destination_group_id` foreign key a plain `id` self-reference instead of
//! a name-matching join that could collide or miss.
//!
//! # Why SQLite needs a full rebuild here but `vault_sync_tasks` (a sibling migration, same
//! session) only needs a plain `ADD COLUMN`
//!
//! Adding one nullable-then-backfilled-then-constrained column (`vault_sync_tasks.skip_bogon_filtering`)
//! is exactly SQLite's supported `ALTER TABLE ADD COLUMN` case. This migration instead adds *and*
//! drops several columns and adds a new foreign key on `external_sources` — SQLite has no `DROP
//! COLUMN` prior to a rebuild-free path being safe to rely on across all three backends, and no
//! `ALTER TABLE ... ADD CONSTRAINT` for a self-referential-looking new FK either, so the same
//! create-copy-drop-rename rebuild `m20260818_010217_audit_attribution_not_null` established is
//! reused here, via `SchemaManager::get_database_backend() == DatabaseBackend::Sqlite` branching.

use sea_orm::{ConnectionTrait, DatabaseBackend};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum DestinationGroups {
    Table,
    Id,
    Name,
    TargetGroupName,
    CronSchedule,
    Mode,
    IsActive,
    SkipBogonFiltering,
    LastRunAt,
    OwnerKeyId,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum DestinationGroupVaultTargets {
    Table,
    DestinationGroupId,
    VaultEndpointId,
    TargetGroupName,
}

#[derive(DeriveIden)]
enum VaultEndpoints {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum ExternalSources {
    Table,
    Id,
    DestinationGroupId,
    Name,
    SourceUrl,
    ParserType,
    ParserConfigJson,
    MaxAgeDays,
    SkipBogonFiltering,
    CreatedAt,
    UpdatedAt,
    // Pre-refactor columns, dropped by this migration (still read during the data migration and
    // the SQLite rebuild's `down` path).
    CronSchedule,
    TargetGroupName,
    Mode,
    IsActive,
    LastRunAt,
    OwnerKeyId,
}

#[derive(DeriveIden)]
enum ExternalSourceVaultTargets {
    Table,
    ExternalSourceId,
    VaultEndpointId,
    TargetGroupName,
}

#[derive(DeriveIden)]
enum ExternalSourcesRebuild {
    #[sea_orm(iden = "external_sources_rebuild")]
    Table,
}

/// The post-refactor `external_sources` ("feed") shape, and — when `post_refactor` is `false` —
/// the exact pre-refactor shape it replaces. One function for both directions for the same reason
/// `audit_attribution_not_null` gives: a hand-maintained pair drifts, and `down` silently
/// resurrecting the wrong shape is the failure mode that matters least visibly.
pub(super) fn external_sources_definition(
    table: TableRef,
    post_refactor: bool,
) -> TableCreateStatement {
    let mut stmt = Table::create();
    stmt.table(table)
        .col(
            ColumnDef::new(ExternalSources::Id)
                .uuid()
                .not_null()
                .primary_key(),
        )
        .col(
            ColumnDef::new(ExternalSources::Name)
                .string()
                .not_null()
                .unique_key(),
        )
        .col(
            ColumnDef::new(ExternalSources::SourceUrl)
                .string()
                .not_null(),
        )
        .col(
            ColumnDef::new(ExternalSources::ParserType)
                .string()
                .not_null()
                .default("REGEX_LINE"),
        )
        .col(ColumnDef::new(ExternalSources::ParserConfigJson).text());

    if post_refactor {
        stmt.col(
            ColumnDef::new(ExternalSources::DestinationGroupId)
                .uuid()
                .not_null(),
        )
        .col(ColumnDef::new(ExternalSources::MaxAgeDays).integer())
        .col(ColumnDef::new(ExternalSources::SkipBogonFiltering).boolean());
    } else {
        stmt.col(
            ColumnDef::new(ExternalSources::CronSchedule)
                .string()
                .not_null(),
        )
        .col(
            ColumnDef::new(ExternalSources::TargetGroupName)
                .string()
                .not_null(),
        )
        .col(
            ColumnDef::new(ExternalSources::Mode)
                .string()
                .not_null()
                .default("upsert"),
        )
        .col(
            ColumnDef::new(ExternalSources::IsActive)
                .boolean()
                .not_null()
                .default(true),
        )
        .col(ColumnDef::new(ExternalSources::LastRunAt).timestamp_with_time_zone())
        .col(ColumnDef::new(ExternalSources::OwnerKeyId).uuid());
    }

    stmt.col(
        ColumnDef::new(ExternalSources::CreatedAt)
            .timestamp_with_time_zone()
            .not_null(),
    )
    .col(
        ColumnDef::new(ExternalSources::UpdatedAt)
            .timestamp_with_time_zone()
            .not_null(),
    );

    if post_refactor {
        stmt.foreign_key(
            ForeignKey::create()
                .name("fk-external_sources-destination_group")
                .from(ExternalSources::Table, ExternalSources::DestinationGroupId)
                .to(DestinationGroups::Table, DestinationGroups::Id)
                .on_delete(ForeignKeyAction::Cascade),
        );
    }

    stmt.take()
}

pub(super) fn destination_groups_definition() -> TableCreateStatement {
    Table::create()
        .table(DestinationGroups::Table)
        .if_not_exists()
        .col(
            ColumnDef::new(DestinationGroups::Id)
                .uuid()
                .not_null()
                .primary_key(),
        )
        .col(
            ColumnDef::new(DestinationGroups::Name)
                .string()
                .not_null()
                .unique_key(),
        )
        .col(
            ColumnDef::new(DestinationGroups::TargetGroupName)
                .string()
                .not_null(),
        )
        .col(
            ColumnDef::new(DestinationGroups::CronSchedule)
                .string()
                .not_null(),
        )
        .col(
            ColumnDef::new(DestinationGroups::Mode)
                .string()
                .not_null()
                .default("upsert"),
        )
        .col(
            ColumnDef::new(DestinationGroups::IsActive)
                .boolean()
                .not_null()
                .default(true),
        )
        .col(
            ColumnDef::new(DestinationGroups::SkipBogonFiltering)
                .boolean()
                .not_null()
                .default(false),
        )
        .col(ColumnDef::new(DestinationGroups::LastRunAt).timestamp_with_time_zone())
        .col(ColumnDef::new(DestinationGroups::OwnerKeyId).uuid())
        .col(
            ColumnDef::new(DestinationGroups::CreatedAt)
                .timestamp_with_time_zone()
                .not_null(),
        )
        .col(
            ColumnDef::new(DestinationGroups::UpdatedAt)
                .timestamp_with_time_zone()
                .not_null(),
        )
        .take()
}

async fn create_destination_groups(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(destination_groups_definition())
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx-destination_groups-owner_key_id")
                .table(DestinationGroups::Table)
                .col(DestinationGroups::OwnerKeyId)
                .to_owned(),
        )
        .await
}

pub(super) fn destination_group_vault_targets_definition() -> TableCreateStatement {
    Table::create()
        .table(DestinationGroupVaultTargets::Table)
        .if_not_exists()
        .col(
            ColumnDef::new(DestinationGroupVaultTargets::DestinationGroupId)
                .uuid()
                .not_null(),
        )
        .col(
            ColumnDef::new(DestinationGroupVaultTargets::VaultEndpointId)
                .uuid()
                .not_null(),
        )
        .col(ColumnDef::new(DestinationGroupVaultTargets::TargetGroupName).text())
        .primary_key(
            Index::create()
                .col(DestinationGroupVaultTargets::DestinationGroupId)
                .col(DestinationGroupVaultTargets::VaultEndpointId),
        )
        .foreign_key(
            ForeignKey::create()
                .name("fk-dgvt-destination_group")
                .from(
                    DestinationGroupVaultTargets::Table,
                    DestinationGroupVaultTargets::DestinationGroupId,
                )
                .to(DestinationGroups::Table, DestinationGroups::Id)
                .on_delete(ForeignKeyAction::Cascade),
        )
        .foreign_key(
            ForeignKey::create()
                .name("fk-dgvt-vault_endpoint")
                .from(
                    DestinationGroupVaultTargets::Table,
                    DestinationGroupVaultTargets::VaultEndpointId,
                )
                .to(VaultEndpoints::Table, VaultEndpoints::Id)
                .on_delete(ForeignKeyAction::Cascade),
        )
        .take()
}

async fn create_destination_group_vault_targets(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(destination_group_vault_targets_definition())
        .await
}

/// Copies every pre-existing `external_sources` row into its own new, 1:1 `destination_groups`
/// row (same id), and every `external_source_vault_targets` row into the equivalent
/// `destination_group_vault_targets` row. Column lists are written out explicitly, not
/// `SELECT *` — see `audit_attribution_not_null`'s own rationale for why a positional copy is
/// exactly the kind of bug that stays invisible until a later column reorder.
async fn migrate_existing_rows_into_groups(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .exec_stmt(
            Query::insert()
                .into_table(DestinationGroups::Table)
                .columns([
                    "id",
                    "name",
                    "target_group_name",
                    "cron_schedule",
                    "mode",
                    "is_active",
                    "skip_bogon_filtering",
                    "last_run_at",
                    "owner_key_id",
                    "created_at",
                    "updated_at",
                ])
                .select_from(
                    Query::select()
                        .columns([
                            "id",
                            "name",
                            "target_group_name",
                            "cron_schedule",
                            "mode",
                            "is_active",
                        ])
                        .expr(Expr::val(false))
                        .columns(["last_run_at", "owner_key_id", "created_at", "updated_at"])
                        .from(ExternalSources::Table)
                        .take(),
                )
                .map_err(|error| DbErr::Custom(error.to_string()))?
                .take(),
        )
        .await?;
    manager
        .exec_stmt(
            Query::insert()
                .into_table(DestinationGroupVaultTargets::Table)
                .columns([
                    "destination_group_id",
                    "vault_endpoint_id",
                    "target_group_name",
                ])
                .select_from(
                    Query::select()
                        .columns([
                            "external_source_id",
                            "vault_endpoint_id",
                            "target_group_name",
                        ])
                        .from(ExternalSourceVaultTargets::Table)
                        .take(),
                )
                .map_err(|error| DbErr::Custom(error.to_string()))?
                .take(),
        )
        .await?;
    Ok(())
}

/// SQLite rebuild: creates the table under `post_refactor`'s shape, copies rows across (backfilling
/// `destination_group_id = id`, the self-mapping the data migration above set up), drops the
/// original, renames the replacement into place.
async fn rebuild_external_sources_sqlite(
    manager: &SchemaManager<'_>,
    post_refactor: bool,
) -> Result<(), DbErr> {
    manager
        .create_table(external_sources_definition(
            ExternalSourcesRebuild::Table.into_table_ref(),
            post_refactor,
        ))
        .await?;

    let mut select = Query::select();
    select.from(ExternalSources::Table);
    let mut columns = vec![
        "id",
        "name",
        "source_url",
        "parser_type",
        "parser_config_json",
    ];
    select.columns(
        columns
            .iter()
            .map(|&column| (ExternalSources::Table, column)),
    );
    if post_refactor {
        columns.extend([
            "destination_group_id",
            "max_age_days",
            "skip_bogon_filtering",
        ]);
        select
            .column(ExternalSources::Id)
            .expr(Expr::val(Option::<i32>::None))
            .expr(Expr::val(Option::<bool>::None));
    } else {
        let group_columns = [
            "cron_schedule",
            "target_group_name",
            "mode",
            "is_active",
            "last_run_at",
            "owner_key_id",
        ];
        columns.extend(group_columns);
        select
            .inner_join(
                DestinationGroups::Table,
                Expr::col((DestinationGroups::Table, DestinationGroups::Id))
                    .equals((ExternalSources::Table, ExternalSources::DestinationGroupId)),
            )
            .columns(group_columns.map(|column| (DestinationGroups::Table, column)));
    }
    let timestamps = ["created_at", "updated_at"];
    columns.extend(timestamps);
    select.columns(timestamps.map(|column| (ExternalSources::Table, column)));
    manager
        .exec_stmt(
            Query::insert()
                .into_table(ExternalSourcesRebuild::Table)
                .columns(columns)
                .select_from(select.take())
                .map_err(|error| DbErr::Custom(error.to_string()))?
                .take(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(ExternalSources::Table).to_owned())
        .await?;
    manager
        .rename_table(
            Table::rename()
                .table(ExternalSourcesRebuild::Table, ExternalSources::Table)
                .to_owned(),
        )
        .await
}

/// Postgres/MySQL path: these backends support `ADD COLUMN`/`DROP COLUMN`/`ALTER COLUMN` directly,
/// so no rebuild is needed — add the new columns nullable, backfill, tighten `destination_group_id`
/// to `NOT NULL` and attach its foreign key, then drop the columns that moved up to the group.
async fn alter_external_sources_directly(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(ExternalSources::Table)
                .add_column(ColumnDef::new(ExternalSources::DestinationGroupId).uuid())
                .add_column(ColumnDef::new(ExternalSources::MaxAgeDays).integer())
                .add_column(ColumnDef::new(ExternalSources::SkipBogonFiltering).boolean())
                .to_owned(),
        )
        .await?;

    manager
        .exec_stmt(
            Query::update()
                .table(ExternalSources::Table)
                .value(
                    ExternalSources::DestinationGroupId,
                    Expr::col(ExternalSources::Id),
                )
                .take(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(ExternalSources::Table)
                .modify_column(
                    ColumnDef::new(ExternalSources::DestinationGroupId)
                        .uuid()
                        .not_null(),
                )
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(ExternalSources::Table)
                .add_foreign_key(
                    TableForeignKey::new()
                        .name("fk-external_sources-destination_group")
                        .from_tbl(ExternalSources::Table)
                        .from_col(ExternalSources::DestinationGroupId)
                        .to_tbl(DestinationGroups::Table)
                        .to_col(DestinationGroups::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(ExternalSources::Table)
                .drop_column(ExternalSources::CronSchedule)
                .drop_column(ExternalSources::TargetGroupName)
                .drop_column(ExternalSources::Mode)
                .drop_column(ExternalSources::IsActive)
                .drop_column(ExternalSources::LastRunAt)
                .drop_column(ExternalSources::OwnerKeyId)
                .to_owned(),
        )
        .await
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        create_destination_groups(manager).await?;
        create_destination_group_vault_targets(manager).await?;
        migrate_existing_rows_into_groups(manager).await?;

        manager
            .drop_table(
                Table::drop()
                    .table(ExternalSourceVaultTargets::Table)
                    .take(),
            )
            .await?;
        if manager.get_database_backend() == DatabaseBackend::Sqlite {
            rebuild_external_sources_sqlite(manager, true).await
        } else {
            alter_external_sources_directly(manager).await
        }
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        restore_external_source_vault_targets(manager).await?;
        if manager.get_database_backend() == DatabaseBackend::Sqlite {
            rebuild_external_sources_sqlite(manager, false).await?;
        } else {
            restore_external_sources_columns_directly(manager).await?;
        }

        manager
            .drop_table(
                Table::drop()
                    .table(DestinationGroupVaultTargets::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(DestinationGroups::Table).to_owned())
            .await
    }
}

async fn restore_external_source_vault_targets(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(ExternalSourceVaultTargets::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(ExternalSourceVaultTargets::ExternalSourceId)
                        .uuid()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ExternalSourceVaultTargets::VaultEndpointId)
                        .uuid()
                        .not_null(),
                )
                .col(ColumnDef::new(ExternalSourceVaultTargets::TargetGroupName).text())
                .primary_key(
                    Index::create()
                        .col(ExternalSourceVaultTargets::ExternalSourceId)
                        .col(ExternalSourceVaultTargets::VaultEndpointId),
                )
                .to_owned(),
        )
        .await?;
    manager
        .exec_stmt(
            Query::insert()
                .into_table(ExternalSourceVaultTargets::Table)
                .columns([
                    "external_source_id",
                    "vault_endpoint_id",
                    "target_group_name",
                ])
                .select_from(
                    Query::select()
                        .columns([
                            "destination_group_id",
                            "vault_endpoint_id",
                            "target_group_name",
                        ])
                        .from(DestinationGroupVaultTargets::Table)
                        .take(),
                )
                .map_err(|error| DbErr::Custom(error.to_string()))?
                .take(),
        )
        .await?;
    Ok(())
}

async fn restore_external_sources_columns_directly(
    manager: &SchemaManager<'_>,
) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(ExternalSources::Table)
                .add_column(ColumnDef::new(ExternalSources::CronSchedule).string())
                .add_column(ColumnDef::new(ExternalSources::TargetGroupName).string())
                .add_column(
                    ColumnDef::new(ExternalSources::Mode)
                        .string()
                        .default("upsert"),
                )
                .add_column(
                    ColumnDef::new(ExternalSources::IsActive)
                        .boolean()
                        .default(true),
                )
                .add_column(ColumnDef::new(ExternalSources::LastRunAt).timestamp_with_time_zone())
                .add_column(ColumnDef::new(ExternalSources::OwnerKeyId).uuid())
                .to_owned(),
        )
        .await?;
    backfill_external_sources_from_groups(manager).await?;
    manager
        .alter_table(
            Table::alter()
                .table(ExternalSources::Table)
                .modify_column(
                    ColumnDef::new(ExternalSources::CronSchedule)
                        .string()
                        .not_null(),
                )
                .modify_column(
                    ColumnDef::new(ExternalSources::TargetGroupName)
                        .string()
                        .not_null(),
                )
                .to_owned(),
        )
        .await?;
    manager
        .drop_foreign_key(
            ForeignKey::drop()
                .table(ExternalSources::Table)
                .name("fk-external_sources-destination_group")
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(ExternalSources::Table)
                .drop_column(ExternalSources::DestinationGroupId)
                .drop_column(ExternalSources::MaxAgeDays)
                .drop_column(ExternalSources::SkipBogonFiltering)
                .to_owned(),
        )
        .await
}

async fn backfill_external_sources_from_groups(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let select = Query::select()
        .columns([
            "id",
            "cron_schedule",
            "target_group_name",
            "mode",
            "is_active",
            "last_run_at",
            "owner_key_id",
        ])
        .from(DestinationGroups::Table)
        .take();
    for group in manager.get_connection().query_all(&select).await? {
        let id: uuid::Uuid = group.try_get("", "id")?;
        manager
            .exec_stmt(
                Query::update()
                    .table(ExternalSources::Table)
                    .value(
                        ExternalSources::CronSchedule,
                        group.try_get::<String>("", "cron_schedule")?,
                    )
                    .value(
                        ExternalSources::TargetGroupName,
                        group.try_get::<String>("", "target_group_name")?,
                    )
                    .value(ExternalSources::Mode, group.try_get::<String>("", "mode")?)
                    .value(
                        ExternalSources::IsActive,
                        group.try_get::<bool>("", "is_active")?,
                    )
                    .value(
                        ExternalSources::LastRunAt,
                        group
                            .try_get::<Option<chrono::DateTime<chrono::Utc>>>("", "last_run_at")?,
                    )
                    .value(
                        ExternalSources::OwnerKeyId,
                        group.try_get::<Option<uuid::Uuid>>("", "owner_key_id")?,
                    )
                    .and_where(Expr::col(ExternalSources::DestinationGroupId).eq(id))
                    .take(),
            )
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both directions of the rebuild must agree on the primary key, the parser columns, and the
    /// timestamps — only the group-membership vs. flat-scheduling columns may differ. Same
    /// "hand-maintained pair drifts" guard `audit_attribution_not_null` uses for its own two-shape
    /// function.
    #[test]
    fn the_two_external_sources_shapes_share_every_column_except_the_ones_that_moved() {
        let post = external_sources_definition(ExternalSources::Table.into_table_ref(), true)
            .to_string(sea_orm::sea_query::SqliteQueryBuilder);
        let pre = external_sources_definition(ExternalSources::Table.into_table_ref(), false)
            .to_string(sea_orm::sea_query::SqliteQueryBuilder);

        assert_ne!(post, pre, "the flag must actually change the DDL");
        for shared in [
            "source_url",
            "parser_type",
            "parser_config_json",
            "created_at",
            "updated_at",
        ] {
            assert!(
                post.contains(shared),
                "{shared} missing from post-refactor shape"
            );
            assert!(
                pre.contains(shared),
                "{shared} missing from pre-refactor shape"
            );
        }
        for moved_up in [
            "cron_schedule",
            "target_group_name",
            "\"mode\"",
            "is_active",
            "last_run_at",
            "owner_key_id",
        ] {
            assert!(
                pre.contains(moved_up),
                "{moved_up} missing from the pre-refactor shape"
            );
            assert!(
                !post.contains(moved_up),
                "{moved_up} must not remain on the post-refactor (feed) shape"
            );
        }
        for new_on_feed in [
            "destination_group_id",
            "max_age_days",
            "skip_bogon_filtering",
        ] {
            assert!(
                post.contains(new_on_feed),
                "{new_on_feed} missing from the post-refactor shape"
            );
            assert!(
                !pre.contains(new_on_feed),
                "{new_on_feed} must not exist before the refactor"
            );
        }
    }
}
