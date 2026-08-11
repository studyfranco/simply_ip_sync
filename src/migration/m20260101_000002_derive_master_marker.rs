//! Adds `api_keys.master_marker`, a database-engine-derived column enforcing single-master
//! uniqueness: `GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)` under a plain
//! unique index. An application-maintained marker does not satisfy this rule — any writer could
//! set `is_master = true` and leave a hand-maintained marker `NULL`, and `NULL` values never
//! collide in a unique index, so a second Master would be silently accepted. The generated-column
//! storage mode differs per engine: Postgres accepts `STORED`, SQLite requires `VIRTUAL`, MySQL
//! accepts either — pinned here since the wrong pairing only fails against a live server no local
//! suite starts.
//!
//! `master_marker` must never appear on the `api_key` entity `Model` (see `entities/api_key.rs`):
//! SeaORM builds explicit column lists from the entity, so a declared field would enter every
//! `INSERT`, and every engine rejects a write to a generated column.

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = manager.get_database_backend();

        // Pre-flight: abort before any DDL if the database already holds two or more masters
        // (never triggers on a fresh install, but keeps the migration correct if ever replayed
        // against a database seeded by something other than this service's own bootstrap path).
        let existing_masters = db
            .query_all_raw(Statement::from_string(
                backend,
                "SELECT id FROM api_keys WHERE is_master = true".to_owned(),
            ))
            .await?;
        if existing_masters.len() > 1 {
            return Err(DbErr::Custom(format!(
                "refusing to add master_marker: {} rows already have is_master=true, expected at most 1",
                existing_masters.len()
            )));
        }

        let storage = match backend {
            DatabaseBackend::Postgres => "STORED",
            _ => "VIRTUAL",
        };
        let expression = "CASE WHEN is_master THEN 1 ELSE NULL END";
        db.execute_unprepared(&format!(
            "ALTER TABLE api_keys ADD COLUMN master_marker INTEGER GENERATED ALWAYS AS ({expression}) {storage}"
        ))
        .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-api_keys-master_marker")
                    .table(ApiKeys::Table)
                    .col(MasterMarker::MasterMarker)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(Index::drop().name("idx-api_keys-master_marker").to_owned())
            .await?;
        let db = manager.get_connection();
        db.execute_unprepared("ALTER TABLE api_keys DROP COLUMN master_marker")
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum ApiKeys {
    Table,
}

#[derive(DeriveIden)]
enum MasterMarker {
    MasterMarker,
}
