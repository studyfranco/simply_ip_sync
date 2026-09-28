//! Adds `vault_sync_tasks.skip_bogon_filtering` — the same pre-push sanitization toggle
//! `destination_groups` got in the previous migration (`m20260928_033617_destination_groups`),
//! applied independently here since inter-vault replication is an unrelated pipeline (vault-to-vault
//! delta sync, not external-feed ingestion) that can carry the exact same garbage (a source vault's
//! own group occasionally accumulates a loopback/private entry from a bad manual ban) and needs the
//! identical policy knob, not a dependency on the destination-group concept.
//!
//! A single `ADD COLUMN` suffices here — unlike the `external_sources` refactor in the previous
//! migration, this adds one new, nullable-by-shape-but-constrained-by-default column with no
//! column removals and no new foreign key, which is squarely within what SQLite's `ALTER TABLE`
//! supports directly. No rebuild needed.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum VaultSyncTasks {
    Table,
    SkipBogonFiltering,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(VaultSyncTasks::Table)
                    .add_column(
                        ColumnDef::new(VaultSyncTasks::SkipBogonFiltering)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter().table(VaultSyncTasks::Table).drop_column(VaultSyncTasks::SkipBogonFiltering).to_owned(),
            )
            .await
    }
}
