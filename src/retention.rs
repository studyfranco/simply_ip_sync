//! Background retention worker: purges historic `sync_logs` and `audit_logs` rows once they age
//! out.
//!
//! # Why this project purges logs rather than soft-deleted resources
//!
//! `simply_ip_vault`'s equivalent module purges soft-deleted `ip_records` — that project keeps a
//! reversible `is_deleted`/`deleted_at` pair on its managed resource so a mistaken delete is
//! recoverable, and retention is what bounds how long the trash is kept. `simply_ip_sync`'s
//! `RBAC_MODEL.md` §6 takes a different approach to the same problem: deletion of a resource
//! (`external_sources`, `vault_endpoints`, `vault_sync_tasks`) is a hard delete, but is *refused
//! outright* — with a structured pre-flight inventory — while anything still depends on it, so the
//! safety net is "you cannot delete this by accident" rather than "you can undo it after". There is
//! no soft-deleted resource row anywhere in this schema (`grep -rn is_deleted src/entities/`
//! returns nothing) for a retention worker to purge.
//!
//! What *does* grow without bound here is history: `sync_logs` (one row per scheduled or
//! manually-triggered job execution) and `audit_logs` (one row per mutating API call). Both are
//! append-only, both are useful for a while, and neither should be kept forever on principle alone
//! — an unbounded table is a data-retention liability whether or not anything in it is sensitive.
//! This module purges both, on independent configurable windows, because they serve different
//! purposes and a deployment reasonably wants different horizons for them: `sync_logs` is
//! operational noise an operator mostly cares about for the last few weeks, while `audit_logs` is
//! the security trail RBAC_MODEL.md's cascade-deletion and privilege-change guarantees rely on
//! being reviewable after the fact, and typically needs a much longer horizon (or none at all).
//!
//! `0` disables purging for that table entirely, for an operator who would rather keep everything
//! and manage it themselves — matching every other "safe default, explicit opt-out" env var in this
//! codebase (`config.rs`'s `max_body_bytes`, `max_decompressed_bytes`, etc.).

use std::time::Duration;

use chrono::Utc;
use sea_orm::{ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter};

use crate::entities::{audit_log, sync_log};

/// Default days a `sync_logs` row is kept before the purge removes it. 92 days ≈ one quarter.
pub const DEFAULT_SYNC_LOG_RETENTION_DAYS: i64 = 92;

/// Default days an `audit_logs` row is kept before the purge removes it. A year, reflecting that
/// this table is the security/compliance trail rather than operational noise — the same reasoning
/// `RBAC_MODEL.md` §6 gives for never destroying resource data implicitly applies, in degree, to
/// not discarding the record of who changed what sooner than an operator would expect.
pub const DEFAULT_AUDIT_LOG_RETENTION_DAYS: i64 = 365;

/// Overrides [`DEFAULT_SYNC_LOG_RETENTION_DAYS`]. `0` disables `sync_logs` purging.
pub const SYNC_LOG_RETENTION_DAYS_ENV: &str = "SYNC_LOG_RETENTION_DAYS";

/// Overrides [`DEFAULT_AUDIT_LOG_RETENTION_DAYS`]. `0` disables `audit_logs` purging.
pub const AUDIT_LOG_RETENTION_DAYS_ENV: &str = "AUDIT_LOG_RETENTION_DAYS";

/// Overrides the interval between sweeps, in seconds. Defaults to hourly.
pub const RETENTION_SWEEP_ENV: &str = "LOG_RETENTION_SWEEP_SECONDS";

/// Default seconds between sweeps.
const DEFAULT_SWEEP_SECONDS: u64 = 3600;

/// Reads a `*_DAYS` retention env var, falling back to `default_days` on absence or a malformed
/// value.
///
/// A malformed value warns and falls back rather than aborting startup, matching how the rest of
/// the codebase treats bad overrides — and the fallback is the *safe* direction: keeping data
/// longer than intended is recoverable, deleting it early is not.
fn retention_days_from_env(env_var: &str, default_days: i64) -> i64 {
    match std::env::var(env_var) {
        Ok(raw) => match raw.trim().parse::<i64>() {
            Ok(days) if days >= 0 => days,
            _ => {
                tracing::warn!("Invalid {env_var} value {raw:?} — falling back to {default_days} days.");
                default_days
            }
        },
        Err(_) => default_days,
    }
}

/// Reads the configured sweep interval, clamped to at least one second.
fn sweep_seconds_from_env() -> u64 {
    match std::env::var(RETENTION_SWEEP_ENV) {
        Ok(raw) => raw.trim().parse::<u64>().unwrap_or(DEFAULT_SWEEP_SECONDS).max(1),
        Err(_) => DEFAULT_SWEEP_SECONDS,
    }
}

/// Permanently deletes `sync_logs` rows older than `retention_days`. Returns the number of rows
/// removed. A non-positive `retention_days` disables purging and is a no-op.
pub async fn purge_expired_sync_logs(db: &DatabaseConnection, retention_days: i64) -> Result<u64, DbErr> {
    if retention_days <= 0 {
        return Ok(0);
    }
    let threshold = (Utc::now() - chrono::Duration::days(retention_days)).naive_utc();
    let result = sync_log::Entity::delete_many().filter(sync_log::Column::Timestamp.lt(threshold)).exec(db).await?;
    Ok(result.rows_affected)
}

/// Permanently deletes `audit_logs` rows older than `retention_days`. Returns the number of rows
/// removed. A non-positive `retention_days` disables purging and is a no-op.
pub async fn purge_expired_audit_logs(db: &DatabaseConnection, retention_days: i64) -> Result<u64, DbErr> {
    if retention_days <= 0 {
        return Ok(0);
    }
    let threshold = (Utc::now() - chrono::Duration::days(retention_days)).naive_utc();
    let result = audit_log::Entity::delete_many().filter(audit_log::Column::Timestamp.lt(threshold)).exec(db).await?;
    Ok(result.rows_affected)
}

/// Runs the retention sweep on a fixed interval for the lifetime of the process.
///
/// Detached via `tokio::spawn` from `main.rs` rather than threaded through graceful shutdown: a
/// sweep is a bounded, idempotent `DELETE ... WHERE timestamp < threshold`, safe to let a sweep in
/// flight finish (or safe to simply not run again) when the process exits, unlike the HTTP server's
/// in-flight requests, which is the one thing this codebase's graceful shutdown actually needs to
/// drain. The first tick fires immediately, so a process restarted more often than the sweep
/// interval still clears its backlog rather than never running.
pub async fn run_retention_worker(db: DatabaseConnection) {
    let sync_log_days = retention_days_from_env(SYNC_LOG_RETENTION_DAYS_ENV, DEFAULT_SYNC_LOG_RETENTION_DAYS);
    let audit_log_days = retention_days_from_env(AUDIT_LOG_RETENTION_DAYS_ENV, DEFAULT_AUDIT_LOG_RETENTION_DAYS);

    if sync_log_days <= 0 && audit_log_days <= 0 {
        tracing::info!(
            "Log retention purge is fully disabled ({SYNC_LOG_RETENTION_DAYS_ENV}=0, \
             {AUDIT_LOG_RETENTION_DAYS_ENV}=0): sync_logs and audit_logs are kept indefinitely."
        );
        return;
    }

    let sweep_seconds = sweep_seconds_from_env();
    tracing::info!(
        sync_log_days,
        audit_log_days,
        sweep_seconds,
        "Log retention worker started."
    );

    let mut ticker = tokio::time::interval(Duration::from_secs(sweep_seconds));
    // If a sweep runs long (a large backlog on slow storage), skip the ticks it missed rather than
    // firing them back to back the moment it finishes.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;
        match purge_expired_sync_logs(&db, sync_log_days).await {
            Ok(0) => tracing::debug!("Retention sweep: no sync_logs rows to purge."),
            Ok(n) => tracing::info!("Retention sweep: purged {n} sync_logs row(s)."),
            Err(e) => tracing::error!("sync_logs retention sweep failed: {e}"),
        }
        match purge_expired_audit_logs(&db, audit_log_days).await {
            Ok(0) => tracing::debug!("Retention sweep: no audit_logs rows to purge."),
            Ok(n) => tracing::info!("Retention sweep: purged {n} audit_logs row(s)."),
            Err(e) => tracing::error!("audit_logs retention sweep failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{ActiveModelTrait, Set};
    use uuid::Uuid;

    use super::*;

    async fn memory_db() -> DatabaseConnection {
        let db = sea_orm::Database::connect("sqlite::memory:").await.expect("connect");
        crate::db::run_migrations(&db).await.expect("migrate");
        db
    }

    async fn insert_sync_log(db: &DatabaseConnection, timestamp: chrono::DateTime<Utc>) {
        sync_log::ActiveModel {
            id: Set(Uuid::new_v4()),
            job_type: Set("EXTERNAL_FEED".to_owned()),
            job_id: Set(Uuid::new_v4()),
            job_name: Set("test-source".to_owned()),
            status: Set("SUCCESS".to_owned()),
            items_processed: Set(0),
            chunks_sent: Set(0),
            duration_ms: Set(0),
            error_message: Set(None),
            timestamp: Set(timestamp),
        }
        .insert(db)
        .await
        .expect("insert sync_log");
    }

    async fn insert_audit_log(db: &DatabaseConnection, timestamp: chrono::DateTime<Utc>) {
        audit_log::ActiveModel {
            id: Set(Uuid::new_v4()),
            api_key_id: Set(None),
            api_key_name: Set("test-key".to_owned()),
            api_key_prefix: Set("abcd1234".to_owned()),
            client_ip: Set("127.0.0.1".to_owned()),
            action: Set("KEY_CREATE".to_owned()),
            target_resource: Set(None),
            details: Set(None),
            timestamp: Set(timestamp),
        }
        .insert(db)
        .await
        .expect("insert audit_log");
    }

    #[tokio::test]
    async fn purge_removes_only_sync_logs_older_than_the_window() {
        let db = memory_db().await;
        let now = Utc::now();
        insert_sync_log(&db, now - chrono::Duration::days(100)).await;
        insert_sync_log(&db, now - chrono::Duration::days(10)).await;

        let purged = purge_expired_sync_logs(&db, 92).await.expect("purge");
        assert_eq!(purged, 1, "only the 100-day-old row is past a 92-day window");

        let remaining = sync_log::Entity::find().all(&db).await.expect("list");
        assert_eq!(remaining.len(), 1, "the 10-day-old row must survive");
    }

    #[tokio::test]
    async fn purge_removes_only_audit_logs_older_than_the_window() {
        let db = memory_db().await;
        let now = Utc::now();
        insert_audit_log(&db, now - chrono::Duration::days(400)).await;
        insert_audit_log(&db, now - chrono::Duration::days(30)).await;

        let purged = purge_expired_audit_logs(&db, 365).await.expect("purge");
        assert_eq!(purged, 1, "only the 400-day-old row is past a 365-day window");

        let remaining = audit_log::Entity::find().all(&db).await.expect("list");
        assert_eq!(remaining.len(), 1, "the 30-day-old row must survive");
    }

    #[tokio::test]
    async fn a_non_positive_retention_window_disables_purging() {
        let db = memory_db().await;
        let now = Utc::now();
        insert_sync_log(&db, now - chrono::Duration::days(9999)).await;
        insert_audit_log(&db, now - chrono::Duration::days(9999)).await;

        assert_eq!(purge_expired_sync_logs(&db, 0).await.expect("purge"), 0);
        assert_eq!(purge_expired_audit_logs(&db, 0).await.expect("purge"), 0);

        assert_eq!(sync_log::Entity::find().all(&db).await.expect("list").len(), 1);
        assert_eq!(audit_log::Entity::find().all(&db).await.expect("list").len(), 1);
    }

    #[test]
    fn a_malformed_env_override_falls_back_to_the_default_rather_than_aborting() {
        // SAFETY: test-only env mutation, single-threaded within this test's scope by convention
        // used elsewhere in this codebase's env-parsing tests.
        unsafe {
            std::env::set_var(SYNC_LOG_RETENTION_DAYS_ENV, "not-a-number");
        }
        let days = retention_days_from_env(SYNC_LOG_RETENTION_DAYS_ENV, DEFAULT_SYNC_LOG_RETENTION_DAYS);
        unsafe {
            std::env::remove_var(SYNC_LOG_RETENTION_DAYS_ENV);
        }
        assert_eq!(days, DEFAULT_SYNC_LOG_RETENTION_DAYS);
    }
}
