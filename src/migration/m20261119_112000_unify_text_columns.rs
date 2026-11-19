//! Widens URLs, group names, and audit targets to text.
//!
//! SQLite rebuilds the affected foreign-key graph in one transaction. Staging tables hold the
//! rows while originals are dropped in child-first order, so foreign-key enforcement stays on.

use IndexOrder::{Asc, Desc};
use sea_orm::{DatabaseBackend, TransactionTrait};
use sea_orm_migration::prelude::*;

use super::m20260101_013240_initial_schema::{
    vault_endpoints_definition, vault_sync_task_targets_definition, vault_sync_tasks_definition,
};
use super::m20260818_010217_audit_attribution_not_null as audit;
use super::m20260928_033617_destination_groups::{
    destination_group_vault_targets_definition, destination_groups_definition,
    external_sources_definition,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

const TEXT_COLUMNS: [(&str, &str, bool); 6] = [
    ("vault_endpoints", "target_url", true),
    ("external_sources", "source_url", true),
    ("destination_groups", "target_group_name", true),
    ("vault_sync_tasks", "source_group_name", true),
    ("vault_sync_tasks", "target_group_name", true),
    ("audit_logs", "target_resource", false),
];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        change_types(manager, true).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        change_types(manager, false).await
    }
}

fn set_type(column: &mut ColumnDef, text: bool) {
    if text {
        column.text();
    } else {
        column.string();
    }
}

async fn change_types(manager: &SchemaManager<'_>, text: bool) -> Result<(), DbErr> {
    if manager.get_database_backend() == DatabaseBackend::Sqlite {
        let txn = manager.get_connection().begin().await?;
        if let Err(error) = rebuild_sqlite(&SchemaManager::new(&txn), text).await {
            txn.rollback().await?;
            return Err(error);
        }
        return txn.commit().await;
    }

    for (table, column, not_null) in TEXT_COLUMNS {
        let mut definition = ColumnDef::new(column);
        set_type(&mut definition, text);
        if not_null {
            definition.not_null();
        } else {
            definition.null();
        }
        manager
            .alter_table(Table::alter().table(table).modify_column(definition).take())
            .await?;
    }
    Ok(())
}

async fn rebuild_sqlite(manager: &SchemaManager<'_>, text: bool) -> Result<(), DbErr> {
    let mut tasks = vault_sync_tasks_definition();
    tasks.col(
        ColumnDef::new("skip_bogon_filtering")
            .boolean()
            .not_null()
            .default(false),
    );

    // Parent-first so that the data can be restored with all foreign keys enforced.
    let tables = [
        ("vault_endpoints", vault_endpoints_definition()),
        ("destination_groups", destination_groups_definition()),
        ("vault_sync_tasks", tasks),
        (
            "external_sources",
            external_sources_definition("external_sources".into_table_ref(), true),
        ),
        (
            "audit_logs",
            audit::table_definition("audit_logs".into_table_ref(), true),
        ),
        (
            "destination_group_vault_targets",
            destination_group_vault_targets_definition(),
        ),
        (
            "vault_sync_task_targets",
            vault_sync_task_targets_definition(),
        ),
    ];

    for (table, definition) in &tables {
        let staging = format!("_unify_text_{table}");
        let mut backup = Table::create();
        backup.table(staging.clone()).temporary();
        for column in definition.get_columns() {
            backup.col(column.clone());
        }
        manager.create_table(backup).await?;
        copy_rows(manager, table, &staging, definition).await?;
    }

    for (table, _) in tables.iter().rev() {
        manager
            .drop_table(Table::drop().table(*table).take())
            .await?;
    }

    for (table, definition) in &tables {
        let mut replacement = Table::create();
        replacement.table(*table);
        for column in definition.get_columns() {
            let mut column = column.clone();
            let name = column.get_column_name();
            if TEXT_COLUMNS
                .iter()
                .any(|(t, c, _)| t == table && *c == name)
            {
                set_type(&mut column, text);
            }
            replacement.col(column);
        }
        for index in definition.get_indexes() {
            replacement.index(&mut index.clone());
        }
        for foreign_key in definition.get_foreign_key_create_stmts() {
            replacement.foreign_key(&mut foreign_key.clone());
        }

        manager.create_table(replacement).await?;
        let staging = format!("_unify_text_{table}");
        copy_rows(manager, &staging, table, definition).await?;
        manager
            .drop_table(Table::drop().table(staging).take())
            .await?;
    }

    recreate_indexes(manager).await
}

async fn copy_rows(
    manager: &SchemaManager<'_>,
    source: &str,
    target: &str,
    definition: &TableCreateStatement,
) -> Result<(), DbErr> {
    let columns: Vec<_> = definition
        .get_columns()
        .iter()
        .map(ColumnDef::get_column_name)
        .collect();
    manager
        .exec_stmt(
            Query::insert()
                .into_table(target.to_owned())
                .columns(columns.iter().cloned())
                .select_from(
                    Query::select()
                        .columns(columns.iter().cloned())
                        .from(source.to_owned())
                        .take(),
                )
                .map_err(|error| DbErr::Custom(error.to_string()))?
                .take(),
        )
        .await
}

type IndexDefinition = (
    &'static str,
    &'static str,
    &'static [(&'static str, IndexOrder)],
);

const INDEXES: &[IndexDefinition] = &[
    (
        "vault_endpoints",
        "idx-vault_endpoints-owner_key_id",
        &[("owner_key_id", Asc)],
    ),
    (
        "vault_endpoints",
        "idx_vault_endpoints_created_at",
        &[("created_at", Desc)],
    ),
    (
        "destination_groups",
        "idx-destination_groups-owner_key_id",
        &[("owner_key_id", Asc)],
    ),
    (
        "destination_groups",
        "idx_destination_groups_is_active",
        &[("is_active", Asc)],
    ),
    (
        "destination_groups",
        "idx_destination_groups_last_run_at",
        &[("last_run_at", Desc)],
    ),
    (
        "destination_groups",
        "idx_destination_groups_created_at",
        &[("created_at", Desc)],
    ),
    (
        "vault_sync_tasks",
        "idx-vault_sync_tasks-owner_key_id",
        &[("owner_key_id", Asc)],
    ),
    (
        "vault_sync_tasks",
        "idx_vault_sync_tasks_source_vault_id",
        &[("source_vault_id", Asc)],
    ),
    (
        "vault_sync_tasks",
        "idx_vault_sync_tasks_is_active",
        &[("is_active", Asc)],
    ),
    (
        "vault_sync_tasks",
        "idx_vault_sync_tasks_last_sync_at",
        &[("last_sync_at", Desc)],
    ),
    (
        "vault_sync_tasks",
        "idx_vault_sync_tasks_created_at",
        &[("created_at", Desc)],
    ),
    (
        "external_sources",
        "idx_external_sources_destination_group_id",
        &[("destination_group_id", Asc)],
    ),
    (
        "external_sources",
        "idx_external_sources_created_at",
        &[("created_at", Desc)],
    ),
    (
        "audit_logs",
        "idx_audit_logs_timestamp_desc",
        &[("timestamp", Desc)],
    ),
    (
        "audit_logs",
        "idx_audit_logs_action_timestamp_desc",
        &[("action", Asc), ("timestamp", Desc)],
    ),
    (
        "audit_logs",
        "idx_audit_logs_api_key_id_timestamp",
        &[("api_key_id", Asc), ("timestamp", Desc)],
    ),
    (
        "destination_group_vault_targets",
        "idx_dgvt_vault_endpoint_id",
        &[("vault_endpoint_id", Asc)],
    ),
    (
        "vault_sync_task_targets",
        "idx_vault_sync_task_targets_target_vault_id",
        &[("target_vault_id", Asc)],
    ),
];
async fn recreate_indexes(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    audit::recreate_index(manager).await?;
    for (table, name, columns) in INDEXES {
        let mut index = Index::create();
        index.table(*table).name(*name);
        for (column, order) in *columns {
            index.col((*column, order.clone()));
        }
        manager.create_index(index.take()).await?;
    }
    Ok(())
}
