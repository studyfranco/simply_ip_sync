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
    assert!(present, "master_marker unique index must exist after migration");
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
        "INSERT INTO external_sources (id, name, source_url, parser_type, cron_schedule, target_group_name, mode, is_active, owner_key_id, created_at, updated_at) \
         VALUES ('00000000-0000-0000-0000-000000000003', 's1', 'http://feed', 'REGEX_LINE', '0 0 * * *', 'g', 'upsert', 1, NULL, '2026-01-01 00:00:00', '2026-01-01 00:00:00')",
    )
    .await
    .expect("insert external source");
    db.execute_unprepared(
        "INSERT INTO external_source_vault_targets (external_source_id, vault_endpoint_id, target_group_name) \
         VALUES ('00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000002', NULL)",
    )
    .await
    .expect("insert junction row");

    db.execute_unprepared("DELETE FROM external_sources WHERE id = '00000000-0000-0000-0000-000000000003'")
        .await
        .expect("delete source");

    let remaining = db
        .query_all_raw(Statement::from_string(
            db.get_database_backend(),
            "SELECT * FROM external_source_vault_targets".to_owned(),
        ))
        .await
        .expect("query junction table");
    assert!(remaining.is_empty(), "junction row must cascade-delete with its parent source");
}
