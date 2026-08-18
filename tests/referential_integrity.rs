//! Foreign-key enforcement and ownership semantics, at the database layer and at the app layer
//! that deliberately substitutes for it where a hard FK would be actively wrong.
//!
//! Adapted from a pattern audited in `example/simply_hook_executor/tests/referential_integrity.rs`
//! (2026-08-17 cross-project test audit — see `AGENT_NOTES.MD`): prove cascades bidirectionally
//! (a survivor row from an unrelated parent must *not* be swept up by a sibling's cascade), prove
//! FK enforcement at write time as well as delete time, and document a deliberately unconstrained
//! column with a test rather than a comment alone.
//!
//! Uses `db::connect` (not `Database::connect("sqlite::memory:")`, which `tests/common/mod.rs`
//! uses for every other integration test) because only `db::connect` sets `PRAGMA foreign_keys =
//! ON` — see `schema_integrity_tests.rs`'s identical `file_backed_db` helper. Every FK-dependent
//! assertion here would pass vacuously (nothing to enforce) on a connection that skipped it.

use sea_orm::{ConnectionTrait, DatabaseConnection, Statement};
use simply_ip_sync::db;

async fn file_backed_db() -> DatabaseConnection {
    let path = tempfile::NamedTempFile::new().expect("tempfile");
    let url = format!("sqlite://{}?mode=rwc", path.path().display());
    let conn = db::connect(&url).await.expect("connect");
    db::run_migrations(&conn).await.expect("migrate");
    std::mem::forget(path);
    conn
}

fn insert_source_sql(id: &str, owner_key_id: Option<&str>) -> String {
    let owner = owner_key_id.map(|o| format!("'{o}'")).unwrap_or_else(|| "NULL".to_owned());
    format!(
        "INSERT INTO external_sources (id, name, source_url, parser_type, cron_schedule, target_group_name, mode, is_active, owner_key_id, created_at, updated_at) \
         VALUES ('{id}', 's-{id}', 'http://feed/{id}', 'REGEX_LINE', '0 0 * * *', 'g', 'upsert', 1, {owner}, '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
    )
}

fn insert_vault_sql(id: &str) -> String {
    format!(
        "INSERT INTO vault_endpoints (id, name, target_url, api_key, signing_secret, owner_key_id, created_at, updated_at) \
         VALUES ('{id}', 'v-{id}', 'http://x/{id}', 'k', 's', NULL, '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
    )
}

async fn row_count(db: &DatabaseConnection, table: &str) -> i64 {
    let row = db
        .query_one_raw(Statement::from_string(db.get_database_backend(), format!("SELECT COUNT(*) AS c FROM {table}")))
        .await
        .expect("count query")
        .expect("count row");
    row.try_get_by_index::<i64>(0).expect("count column")
}

/// Two sources, each fanning out to the same target vault (so the junction table has two rows
/// sharing a `vault_endpoint_id` but different `external_source_id`s). Deleting only the *doomed*
/// source must cascade-delete only its own junction row — the *survivor* source's junction row
/// (same target vault, different parent) must remain untouched. A single-row cascade test (as
/// `schema_integrity_tests.rs::junction_table_rows_cascade_on_parent_delete` already has) cannot
/// distinguish "cascaded correctly" from "cascaded too broadly" — this one can.
#[tokio::test]
async fn cascade_delete_does_not_reach_into_an_unrelated_parents_row() {
    let db = file_backed_db().await;
    db.execute_unprepared(&insert_source_sql("d0000000-0000-0000-0000-000000000001", None)).await.expect("doomed source");
    db.execute_unprepared(&insert_source_sql("50000000-0000-0000-0000-000000000002", None)).await.expect("survivor source");
    db.execute_unprepared(&insert_vault_sql("70000000-0000-0000-0000-000000000003")).await.expect("shared target vault");
    db.execute_unprepared(
        "INSERT INTO external_source_vault_targets (external_source_id, vault_endpoint_id, target_group_name) \
         VALUES ('d0000000-0000-0000-0000-000000000001', '70000000-0000-0000-0000-000000000003', NULL)",
    )
    .await
    .expect("doomed junction row");
    db.execute_unprepared(
        "INSERT INTO external_source_vault_targets (external_source_id, vault_endpoint_id, target_group_name) \
         VALUES ('50000000-0000-0000-0000-000000000002', '70000000-0000-0000-0000-000000000003', NULL)",
    )
    .await
    .expect("survivor junction row");

    db.execute_unprepared("DELETE FROM external_sources WHERE id = 'd0000000-0000-0000-0000-000000000001'")
        .await
        .expect("delete doomed source");

    let remaining = row_count(&db, "external_source_vault_targets").await;
    assert_eq!(remaining, 1, "exactly the survivor's junction row must remain — the cascade must not have swept up an unrelated parent's row");
    let survivor_still_present = db
        .query_all_raw(Statement::from_string(
            db.get_database_backend(),
            "SELECT * FROM external_source_vault_targets WHERE external_source_id = '50000000-0000-0000-0000-000000000002'".to_owned(),
        ))
        .await
        .expect("query");
    assert_eq!(survivor_still_present.len(), 1, "the survivor's own row must be exactly the one that remains");
}

/// Write-time enforcement, not just delete-time: a junction row naming an `external_source_id`
/// that does not exist must be refused by the database itself, not merely tolerated until a
/// cascade happens to clean it up later.
#[tokio::test]
async fn junction_row_with_a_dangling_foreign_key_is_rejected_at_insert_time() {
    let db = file_backed_db().await;
    db.execute_unprepared(&insert_vault_sql("70000000-0000-0000-0000-000000000004")).await.expect("target vault");

    let result = db
        .execute_unprepared(
            "INSERT INTO external_source_vault_targets (external_source_id, vault_endpoint_id, target_group_name) \
             VALUES ('ffffffff-ffff-ffff-ffff-ffffffffffff', '70000000-0000-0000-0000-000000000004', NULL)",
        )
        .await;
    assert!(result.is_err(), "a junction row naming a non-existent external_source_id must be refused at write time, not silently accepted");
}

/// `owner_key_id` on `external_sources`/`vault_endpoints`/`vault_sync_tasks` carries no FK
/// constraint at all (confirmed against `src/migration/m20260101_000001_initial_schema.rs`: no
/// `ForeignKey::create()` targets this column, unlike every other cross-table reference in the
/// schema) — deliberately, not by oversight. `keys.rs::delete_api_key` enforces ownership
/// transfer/cleanup at the *application* layer instead (see
/// `tests/rbac_model_compliance.rs::s6_deleting_a_key_that_still_owns_resources_is_blocked_with_inventory`),
/// because a DB-level `CASCADE` here would silently delete every resource a Parent key ever
/// created the moment that key is deleted, and a DB-level `RESTRICT`/`SET NULL` would either block
/// key deletion outright or erase ownership with no record of what happened — neither gives an
/// operator the "reassign or delete them first" chance `delete_api_key`'s `409 ConflictWithDetails`
/// does. This test proves the absence the same way a presence would be proven: by trying the thing
/// the missing constraint would otherwise forbid.
#[tokio::test]
async fn owner_key_id_is_deliberately_unconstrained_by_design() {
    let db = file_backed_db().await;
    // No api_keys row with this id exists anywhere — if owner_key_id carried a real FK, this
    // insert would be rejected exactly like the dangling-external_source_id case above.
    let result = db.execute_unprepared(&insert_source_sql(
        "90000000-0000-0000-0000-000000000005",
        Some("ffffffff-ffff-ffff-ffff-ffffffffffff"),
    ))
    .await;
    assert!(result.is_ok(), "owner_key_id must not be FK-constrained — the application layer, not the database, governs ownership cleanup");
}
