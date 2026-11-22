//! Database connections, SQLite session settings, and schema migration helpers.

use std::str::FromStr;
use std::time::Duration;

use sea_orm::sea_query::{Expr, Func, IntoColumnRef};
use sea_orm::sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
};
use sea_orm::{DatabaseBackend, DatabaseConnection, DbErr};

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
    use crate::migration::MigratorTrait;
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
    crate::migration::SchemaManager::new(db)
        .has_index(table_name, index_name)
        .await
}

// SQLite compares its timestamp text lexically. Normalize the old UTC offset spelling and the
// new Z spelling to a fixed-width UTC key, retaining all nine fractional digits.
pub(crate) fn timestamp_order(db: &DatabaseConnection, column: impl IntoColumnRef) -> Expr {
    let column = Expr::col(column);
    if db.get_database_backend() != DatabaseBackend::Sqlite {
        return column;
    }

    let replace = |source: Expr, old, new| {
        Expr::from(Func::cust("replace").args([source, Expr::val(old), Expr::val(new)]))
    };
    let substring = |source: Expr, start, length| {
        Expr::from(Func::cust("substr").args([source, Expr::val(start), Expr::val(length)]))
    };
    let concatenate = |left: Expr, right: Expr| {
        Expr::from(Func::cust("printf").args([Expr::val("%s%s"), left, right]))
    };

    let seconds = replace(substring(column.clone(), 1, 19), " ", "T");
    let fraction = replace(substring(column, 20, 16), "+00:00", "");
    let fraction = replace(replace(fraction, "Z", ""), ".", "");
    let fraction = substring(concatenate(fraction, Expr::val("000000000")), 1, 9);
    concatenate(seconds, fraction)
}

pub(crate) fn timestamp_bound(db: &DatabaseConnection, timestamp: time::OffsetDateTime) -> Expr {
    if db.get_database_backend() != DatabaseBackend::Sqlite {
        return Expr::val(timestamp);
    }
    let (year, month, day) = timestamp.to_calendar_date();
    let (hour, minute, second, nanos) = timestamp.to_hms_nano();
    let month = u8::from(month);
    Expr::val(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{nanos:09}"
    ))
}
