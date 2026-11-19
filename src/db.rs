//! Database connections, SQLite session settings, and schema migration helpers.

use std::str::FromStr;
use std::time::Duration;

use sea_orm::sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
};
use sea_orm::{DatabaseConnection, DbErr};

/// SQLite permits exactly one writer. A pool size of 2+ does not survive a DDL sequence spread
/// across connections — a migration that adds a generated column on one connection while another
/// connection's cached schema still holds the old shape fails deterministically. This is not a
/// tuning knob.
pub const SQLITE_MAX_CONNECTIONS: u32 = 1;

/// Busy-wait timeout before SQLite gives up waiting for a lock to clear.
pub const SQLITE_BUSY_TIMEOUT_MS: u64 = 5_000;

/// Connects to `database_url`. For SQLite URLs, pins the pool to one connection and applies the
/// session settings on `SqliteConnectOptions` for every connection. Other backends use
/// a plain `Database::connect`.
///
/// # Errors
///
/// Returns `DbErr` if the URL cannot be parsed or the connection pool fails to connect.
pub async fn connect(database_url: &str) -> Result<DatabaseConnection, DbErr> {
    if database_url.starts_with("sqlite:") {
        let connect_options = SqliteConnectOptions::from_str(database_url)
            .map_err(|e| DbErr::Custom(format!("invalid DATABASE_URL: {e}")))?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))
            .pragma("temp_store", "MEMORY")
            .pragma("mmap_size", "268435456")
            .pragma("cache_size", "-64000")
            .pragma("analysis_limit", "1000");
        let pool = SqlitePoolOptions::new()
            .max_connections(SQLITE_MAX_CONNECTIONS)
            .connect_with(connect_options)
            .await
            .map_err(|e| DbErr::Custom(format!("failed to connect to SQLite: {e}")))?;
        return Ok(sea_orm::SqlxSqliteConnector::from_sqlx_sqlite_pool(pool));
    }
    sea_orm::Database::connect(database_url).await
}

/// Runs all pending migrations.
///
/// # Errors
///
/// Returns `DbErr` if any migration fails to apply.
pub async fn run_migrations(db: &DatabaseConnection) -> Result<(), DbErr> {
    use sea_orm_migration::MigratorTrait;
    crate::migration::Migrator::up(db, None).await
}

/// Checks whether `index_name` exists on `table_name`.
///
/// # Errors
///
/// Returns `DbErr` if the database backend is unsupported or schema inspection fails.
pub async fn has_index(
    db: &DatabaseConnection,
    table_name: &str,
    index_name: &str,
) -> Result<bool, DbErr> {
    sea_orm_migration::SchemaManager::new(db)
        .has_index(table_name, index_name)
        .await
}
