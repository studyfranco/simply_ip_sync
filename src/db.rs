//! Connection setup, session pragmas, and migrations.
//!
//! The only place in `src/` outside `migration/` permitted to issue raw SQL, and then only
//! `PRAGMA`/catalog-inspection statements — never DML.

use std::str::FromStr;
use std::time::Duration;

use sea_orm::sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, DbErr, Statement};

/// SQLite permits exactly one writer. A pool size of 2+ does not survive a DDL sequence spread
/// across connections — a migration that adds a generated column on one connection while another
/// connection's cached schema still holds the old shape fails deterministically. This is not a
/// tuning knob.
pub const SQLITE_MAX_CONNECTIONS: u32 = 1;

/// Busy-wait timeout before SQLite gives up waiting for a lock to clear.
pub const SQLITE_BUSY_TIMEOUT_MS: u64 = 5_000;

/// Connects to `database_url`. For SQLite URLs, pins the pool to one connection and applies the
/// four mandatory session pragmas on `SqliteConnectOptions` (so they survive SQLx reconnects,
/// rather than being issued once as raw statements and forgotten). Other backends fall through to
/// a plain `Database::connect`.
pub async fn connect(database_url: &str) -> Result<DatabaseConnection, DbErr> {
    if let Some(sqlite_url) = database_url.strip_prefix("sqlite://") {
        let connect_options = SqliteConnectOptions::from_str(&format!("sqlite://{sqlite_url}"))
            .map_err(|e| DbErr::Custom(format!("invalid DATABASE_URL: {e}")))?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS));
        let pool = SqlitePoolOptions::new()
            .max_connections(SQLITE_MAX_CONNECTIONS)
            .connect_with(connect_options)
            .await
            .map_err(|e| DbErr::Custom(format!("failed to connect to SQLite: {e}")))?;
        return Ok(sea_orm::SqlxSqliteConnector::from_sqlx_sqlite_pool(pool));
    }
    sea_orm::Database::connect(database_url).await
}

/// Secondary, never-fatal confirmation pass: reads `PRAGMA journal_mode` back and re-issues the
/// other three pragmas per-connection. In-memory databases silently cannot use WAL, which is
/// tolerated, not an error.
pub async fn apply_sqlite_pragmas(db: &DatabaseConnection) {
    if db.get_database_backend() != DatabaseBackend::Sqlite {
        return;
    }
    let statements = [
        "PRAGMA foreign_keys = ON",
        "PRAGMA synchronous = NORMAL",
        &format!("PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}"),
    ];
    for stmt in statements {
        if let Err(e) = db
            .execute_raw(Statement::from_string(DatabaseBackend::Sqlite, stmt.to_owned()))
            .await
        {
            tracing::warn!("failed to (re)apply session pragma '{stmt}': {e}");
        }
    }
    match db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA journal_mode".to_owned(),
        ))
        .await
    {
        Ok(Some(row)) => {
            if let Ok(mode) = row.try_get::<String>("", "journal_mode") {
                tracing::debug!("SQLite journal_mode is '{mode}'");
            }
        }
        Ok(None) => {}
        Err(e) => tracing::warn!("failed to read back journal_mode: {e}"),
    }
}

/// Runs all pending migrations.
pub async fn run_migrations(db: &DatabaseConnection) -> Result<(), DbErr> {
    use sea_orm_migration::MigratorTrait;
    crate::migration::Migrator::up(db, None).await
}

/// Checks whether `index_name` exists on `table_name`, using each backend's own catalog rather
/// than `SchemaManager::has_index` — that helper's arm for a backend is compiled out unless the
/// corresponding `sqlx-*` feature is enabled on `sea-orm-migration`, and this crate does not
/// enable every backend there, so the generic helper would answer "unsupported" against a
/// database whose index is genuinely present.
pub async fn has_index(db: &DatabaseConnection, table_name: &str, index_name: &str) -> Result<bool, DbErr> {
    let backend = db.get_database_backend();
    let stmt = match backend {
        DatabaseBackend::Sqlite => Statement::from_sql_and_values(
            backend,
            "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ? AND tbl_name = ?",
            [index_name.into(), table_name.into()],
        ),
        DatabaseBackend::Postgres => Statement::from_sql_and_values(
            backend,
            "SELECT 1 FROM pg_indexes WHERE indexname = $1 AND tablename = $2",
            [index_name.into(), table_name.into()],
        ),
        DatabaseBackend::MySql => Statement::from_sql_and_values(
            backend,
            "SELECT 1 FROM information_schema.statistics WHERE index_name = ? AND table_name = ?",
            [index_name.into(), table_name.into()],
        ),
        other => {
            return Err(DbErr::Custom(format!("has_index: unsupported database backend {other:?}")));
        }
    };
    Ok(db.query_one_raw(stmt).await?.is_some())
}
