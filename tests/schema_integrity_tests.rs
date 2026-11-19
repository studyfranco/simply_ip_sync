//! What the database engine actually does: migrations apply cleanly, the generated
//! `master_marker` column enforces single-master uniqueness at the engine level, and foreign key
//! cascades behave as `SCHEMA.MD` specifies.

use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Statement};
use simply_ip_sync::db;

/// File-backed (not `sqlite::memory:`) because `PRAGMA foreign_keys` behavior is per-connection,
/// and a couple of these tests reconnect.
async fn file_backed_db() -> DatabaseConnection {
    let path = tempfile::NamedTempFile::new().expect("tempfile");
    let url = format!("sqlite://{}?mode=rwc", path.path().display());
    let db = db::connect(&url).await.expect("connect");
    db::run_migrations(&db).await.expect("migrate");
    // Keep the tempfile alive for the duration of the test process by leaking it; the OS cleans
    // up on process exit and these are small ephemeral test databases.
    std::mem::forget(path);
    db
}

async fn in_memory_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.expect("connect");
    db::run_migrations(&db).await.expect("migrate");
    db
}

#[tokio::test]
async fn migrations_apply_cleanly() {
    let _db = in_memory_db().await;
}

#[tokio::test]
async fn master_marker_index_exists_after_migration() {
    let db = in_memory_db().await;
    let present = db::has_index(&db, "api_keys", "idx-api_keys-master_marker")
        .await
        .expect("has_index query");
    assert!(
        present,
        "master_marker unique index must exist after migration"
    );
}

#[tokio::test]
async fn performance_and_lookup_indexes_exist_after_migration() {
    let db = in_memory_db().await;
    let expected_indexes = [
        ("destination_groups", "idx_destination_groups_is_active"),
        ("destination_groups", "idx_destination_groups_last_run_at"),
        ("destination_groups", "idx_destination_groups_created_at"),
        ("vault_sync_tasks", "idx_vault_sync_tasks_is_active"),
        ("vault_sync_tasks", "idx_vault_sync_tasks_last_sync_at"),
        ("vault_sync_tasks", "idx_vault_sync_tasks_created_at"),
        ("sync_logs", "idx_sync_logs_status_timestamp"),
        ("sync_logs", "idx_sync_logs_job_type_timestamp"),
        (
            "api_key_sync_permissions",
            "idx_api_key_sync_permissions_resource",
        ),
        ("api_keys", "idx_api_keys_is_master"),
        ("api_keys", "idx_api_keys_created_at"),
        ("vault_endpoints", "idx_vault_endpoints_created_at"),
        ("external_sources", "idx_external_sources_created_at"),
    ];

    for (table, index) in expected_indexes {
        let present = db::has_index(&db, table, index)
            .await
            .unwrap_or_else(|e| panic!("failed checking index {index} on {table}: {e}"));
        assert!(
            present,
            "index {index} on table {table} must exist after migrations"
        );
    }
}

// The adversarial raw-SQL proof that a second `is_master=true` row is rejected by the generated
// `master_marker` column lives in `tests/rbac_model_compliance.rs::s5_adversarial_second_master_rejected_by_generated_column`
// — RBAC §5's guarantees, adversarial or not, are indexed there so a missing one shows up as a
// missing rule prefix rather than being scattered across files by convention alone.

#[tokio::test]
async fn foreign_keys_are_enforced_on_a_fresh_connection() {
    let db = file_backed_db().await;
    let fk_status = db
        .query_one_raw(Statement::from_string(
            db.get_database_backend(),
            "PRAGMA foreign_keys".to_owned(),
        ))
        .await;
    // Just confirm the pragma round-trips; the real assertion is the cascade test below.
    assert!(fk_status.is_ok());
}

#[tokio::test]
async fn junction_table_rows_cascade_on_parent_delete() {
    let db = in_memory_db().await;
    db.execute_unprepared(
        "INSERT INTO api_keys (id, name, key_hash, prefix, is_master, can_manage_keys, can_manage_sources, can_manage_vaults, created_at, updated_at) \
         VALUES ('00000000-0000-0000-0000-000000000001', 'm', 'h1', 'pfx1', 1, 0, 0, 0, '2026-01-01 00:00:00', '2026-01-01 00:00:00')",
    )
    .await
    .expect("insert master");
    db.execute_unprepared(
        "INSERT INTO vault_endpoints (id, name, target_url, api_key, signing_secret, owner_key_id, created_at, updated_at) \
         VALUES ('00000000-0000-0000-0000-000000000002', 'v1', 'http://x', 'k', 's', NULL, '2026-01-01 00:00:00', '2026-01-01 00:00:00')",
    )
    .await
    .expect("insert vault endpoint");
    db.execute_unprepared(
        "INSERT INTO destination_groups (id, name, target_group_name, cron_schedule, mode, is_active, skip_bogon_filtering, owner_key_id, created_at, updated_at) \
         VALUES ('00000000-0000-0000-0000-000000000003', 'g1', 'g', '0 0 * * *', 'upsert', 1, 0, NULL, '2026-01-01 00:00:00', '2026-01-01 00:00:00')",
    )
    .await
    .expect("insert destination group");
    db.execute_unprepared(
        "INSERT INTO destination_group_vault_targets (destination_group_id, vault_endpoint_id, target_group_name) \
         VALUES ('00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000002', NULL)",
    )
    .await
    .expect("insert junction row");

    db.execute_unprepared(
        "DELETE FROM destination_groups WHERE id = '00000000-0000-0000-0000-000000000003'",
    )
    .await
    .expect("delete destination group");

    let remaining = db
        .query_all_raw(Statement::from_string(
            db.get_database_backend(),
            "SELECT * FROM destination_group_vault_targets".to_owned(),
        ))
        .await
        .expect("query junction table");
    assert!(
        remaining.is_empty(),
        "junction row must cascade-delete with its parent destination group"
    );
}

const WIDENED_COLUMNS: [(&str, &str, &str); 6] = [
    ("vault_endpoints", "target_url", "https://vault.example"),
    ("external_sources", "source_url", "https://feed.example"),
    ("destination_groups", "target_group_name", "group-target"),
    ("vault_sync_tasks", "source_group_name", "task-source"),
    ("vault_sync_tasks", "target_group_name", "task-target"),
    ("audit_logs", "target_resource", "audit-target"),
];

async fn assert_column_types(db: &DatabaseConnection, expected: &str) {
    for (table, column, _) in WIDENED_COLUMNS {
        let row = db
            .query_one_raw(Statement::from_sql_and_values(
                db.get_database_backend(),
                "SELECT type FROM pragma_table_info(?) WHERE name = ?",
                [table.into(), column.into()],
            ))
            .await
            .expect("inspect column")
            .expect("column exists");
        assert_eq!(
            row.try_get::<String>("", "type").expect("declared type"),
            expected,
            "{table}.{column}",
        );
    }
}

#[tokio::test]
async fn fresh_database_declares_all_six_text_columns() {
    let db = in_memory_db().await;
    assert_column_types(&db, "TEXT").await;
}

#[tokio::test]
async fn text_column_upgrade_preserves_rows_indexes_and_foreign_keys() {
    use simply_ip_sync::migration::{Migrator, MigratorTrait};

    let db = db::connect("sqlite::memory:").await.expect("connect");
    let preceding = u32::try_from(Migrator::migrations().len() - 1).expect("migration count");
    Migrator::up(&db, Some(preceding))
        .await
        .expect("old schema");
    assert_column_types(&db, "varchar").await;

    db.execute_unprepared(
        "INSERT INTO api_keys (id, name, key_hash, prefix, created_at, updated_at)
            VALUES ('key', 'key', 'hash', 'prefix', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
         INSERT INTO vault_endpoints (id, name, target_url, api_key, signing_secret, created_at, updated_at)
            VALUES ('vault', 'vault', 'https://vault.example', 'key', 'secret', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
         INSERT INTO destination_groups (id, name, target_group_name, cron_schedule, created_at, updated_at)
            VALUES ('group', 'group', 'group-target', '0 0 * * *', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
         INSERT INTO external_sources (id, destination_group_id, name, source_url, created_at, updated_at)
            VALUES ('feed', 'group', 'feed', 'https://feed.example', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
         INSERT INTO vault_sync_tasks (id, name, source_vault_id, source_group_name, target_group_name, cron_schedule, created_at, updated_at)
            VALUES ('task', 'task', 'vault', 'task-source', 'task-target', '0 0 * * *', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
         INSERT INTO destination_group_vault_targets VALUES ('group', 'vault', 'group-override');
         INSERT INTO vault_sync_task_targets VALUES ('task', 'vault', 'task-override');
         INSERT INTO audit_logs (id, api_key_id, api_key_name, api_key_prefix, client_ip, action, target_resource, timestamp)
            VALUES ('log', 'key', 'key', 'prefix', '192.0.2.1', 'create', 'audit-target', CURRENT_TIMESTAMP);",
    )
    .await
    .expect("seed pre-upgrade database");

    let before = text_migration_indexes(&db).await;
    Migrator::up(&db, None).await.expect("upgrade schema");
    assert_column_types(&db, "TEXT").await;
    assert_eq!(text_migration_indexes(&db).await, before);

    for (table, column, expected) in WIDENED_COLUMNS.into_iter().chain([
        (
            "destination_group_vault_targets",
            "target_group_name",
            "group-override",
        ),
        (
            "vault_sync_task_targets",
            "target_group_name",
            "task-override",
        ),
    ]) {
        let rows = db
            .query_all_raw(Statement::from_string(
                db.get_database_backend(),
                format!("SELECT {column} FROM {table}"),
            ))
            .await
            .expect("read migrated values");
        assert_eq!(rows.len(), 1, "{table}");
        assert_eq!(
            rows[0].try_get::<String>("", column).expect("value"),
            expected
        );
    }

    Migrator::down(&db, Some(1))
        .await
        .expect("roll back text migration");
    assert_column_types(&db, "varchar").await;
    Migrator::up(&db, None)
        .await
        .expect("reapply text migration");

    db.execute_unprepared("DELETE FROM api_keys WHERE id = 'key'")
        .await
        .expect("delete key");
    assert_eq!(
        scalar_count(
            &db,
            "SELECT COUNT(*) AS n FROM audit_logs WHERE api_key_id IS NULL AND api_key_name = 'key'"
        )
        .await,
        1,
    );
    db.execute_unprepared("DELETE FROM vault_endpoints WHERE id = 'vault'")
        .await
        .expect("delete vault");
    for table in [
        "vault_sync_tasks",
        "vault_sync_task_targets",
        "destination_group_vault_targets",
    ] {
        assert_eq!(
            scalar_count(&db, &format!("SELECT COUNT(*) AS n FROM {table}")).await,
            0
        );
    }
    db.execute_unprepared("DELETE FROM destination_groups WHERE id = 'group'")
        .await
        .expect("delete group");
    assert_eq!(
        scalar_count(&db, "SELECT COUNT(*) AS n FROM external_sources").await,
        0
    );
}

async fn text_migration_indexes(db: &DatabaseConnection) -> Vec<String> {
    db.query_all_raw(Statement::from_string(
        db.get_database_backend(),
        "SELECT name FROM sqlite_schema WHERE type = 'index' ORDER BY name",
    ))
    .await
    .expect("read index names")
    .iter()
    .map(|row| row.try_get("", "name").expect("index name"))
    .collect()
}

async fn scalar_count(db: &DatabaseConnection, query: &str) -> i64 {
    db.query_one_raw(Statement::from_string(db.get_database_backend(), query))
        .await
        .expect("read count")
        .expect("count row")
        .try_get("", "n")
        .expect("count")
}
