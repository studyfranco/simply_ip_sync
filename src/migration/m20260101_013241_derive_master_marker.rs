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
//! `SeaORM` builds explicit column lists from the entity, so a declared field would enter every
//! `INSERT`, and every engine rejects a write to a generated column.

use super::runner::{MigrationTrait, SchemaManager};
use sea_orm::sea_query::{ColumnDef, Expr, ExprTrait, Index, Query, Table};
use sea_orm::{ConnectionTrait, DatabaseBackend};
use sea_orm::{DbErr, DeriveIden};

pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    fn name(&self) -> &'static str {
        stringify!(m20260101_013241_derive_master_marker)
    }

    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = manager.get_database_backend();

        // Pre-flight: abort before any DDL if the database already holds two or more masters
        // (never triggers on a fresh install, but keeps the migration correct if ever replayed
        // against a database seeded by something other than this service's own bootstrap path).
        let select = Query::select()
            .column(ApiKeys::Id)
            .from(ApiKeys::Table)
            .and_where(Expr::col(ApiKeys::IsMaster).eq(true))
            .take();
        let existing_masters = db.query_all(&select).await?;
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
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .add_column(
                        ColumnDef::new(MasterMarker::MasterMarker)
                            .integer()
                            .extra(format!("GENERATED ALWAYS AS ({expression}) {storage}")),
                    )
                    .take(),
            )
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

    async fn down(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .table(ApiKeys::Table)
                    .name("idx-api_keys-master_marker")
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .drop_column(MasterMarker::MasterMarker)
                    .take(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum ApiKeys {
    Table,
    Id,
    IsMaster,
}

#[derive(DeriveIden)]
enum MasterMarker {
    MasterMarker,
}
