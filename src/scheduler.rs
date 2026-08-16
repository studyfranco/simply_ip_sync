//! In-process cron scheduler, wrapping `tokio-cron-scheduler`. Loads active `external_sources`
//! and `vault_sync_tasks` at boot and keeps the live job set in sync with CRUD mutations, so a
//! change to `cron_schedule` or `is_active` never requires a restart to take effect.

use std::collections::HashMap;
use std::sync::Mutex;

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use tokio_cron_scheduler::{Job, JobScheduler, JobSchedulerError};
use uuid::Uuid;

use crate::entities::{external_source, vault_sync_task};
use crate::state::AppState;

/// Converts a conventional 5-field cron expression (`min hour dom month dow`, as documented in
/// `SCHEMA.MD`'s examples) into the 6-field `sec min hour dom month dow` form
/// `tokio-cron-scheduler` requires. A 6-field (or otherwise non-5-field) expression passes through
/// unchanged.
fn normalize_cron(expr: &str) -> String {
    if expr.split_whitespace().count() == 5 {
        format!("0 {expr}")
    } else {
        expr.to_owned()
    }
}

/// Validates a `cron_schedule` string the same way `normalize_cron` plus the scheduler's own
/// parser will interpret it, so anything this function accepts is guaranteed schedulable and
/// anything it rejects genuinely could never run. Called from the `POST`/`PATCH` handlers in
/// `api/sources.rs` and `api/sync_tasks.rs` *before* any database write, so a malformed
/// expression never reaches persistence — a source or task that can never be scheduled is not a
/// source or task, it is silent data corruption waiting to be noticed at the next cron tick that
/// never comes.
pub fn validate_cron_expression(expr: &str) -> Result<(), String> {
    if expr.trim().is_empty() {
        return Err("cron_schedule must not be empty".to_owned());
    }
    let normalized = normalize_cron(expr);
    croner::Cron::new(&normalized)
        .with_seconds_required()
        .with_dom_and_dow()
        .parse()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Wraps a running `JobScheduler` plus the mapping from this service's own resource ids to the
/// scheduler's internal job ids, so a resource can be rescheduled or removed by its own id.
pub struct SchedulerHandle {
    scheduler: JobScheduler,
    source_jobs: Mutex<HashMap<Uuid, Uuid>>,
    task_jobs: Mutex<HashMap<Uuid, Uuid>>,
}

impl SchedulerHandle {
    /// Builds and starts a new scheduler with no jobs registered yet.
    pub async fn new() -> Result<Self, JobSchedulerError> {
        let scheduler = JobScheduler::new().await?;
        scheduler.start().await?;
        Ok(Self {
            scheduler,
            source_jobs: Mutex::new(HashMap::new()),
            task_jobs: Mutex::new(HashMap::new()),
        })
    }

    /// Loads every `is_active = true` external source and sync task from the database and
    /// registers a cron job for each. Called once at startup, after `AppState` is fully built.
    pub async fn boot(&self, state: &AppState) -> Result<(), sea_orm::DbErr> {
        let sources = external_source::Entity::find()
            .filter(external_source::Column::IsActive.eq(true))
            .all(&state.db)
            .await?;
        for source in &sources {
            self.upsert_source(state, source).await;
        }

        let tasks = vault_sync_task::Entity::find()
            .filter(vault_sync_task::Column::IsActive.eq(true))
            .all(&state.db)
            .await?;
        for task in &tasks {
            self.upsert_task(state, task).await;
        }
        Ok(())
    }

    /// (Re)registers the cron job for `source`. Removes any existing job for the same id first,
    /// so this is safe to call on every create/update.
    pub async fn upsert_source(&self, state: &AppState, source: &external_source::Model) {
        self.remove_source(source.id).await;
        if !source.is_active {
            return;
        }
        let cron = normalize_cron(&source.cron_schedule);
        let state = state.clone();
        let source_id = source.id;
        let job = match Job::new_async(cron.as_str(), move |_uuid, _lock| {
            let state = state.clone();
            Box::pin(async move {
                if let Err(e) = crate::jobs::external_ingestion::run(&state, source_id).await {
                    tracing::error!("scheduled external ingestion job {source_id} failed: {e}");
                }
            })
        }) {
            Ok(job) => job,
            Err(e) => {
                tracing::error!("invalid cron_schedule for external source {source_id}: {e}");
                return;
            }
        };
        match self.scheduler.add(job).await {
            Ok(job_id) => {
                if let Ok(mut map) = self.source_jobs.lock() {
                    map.insert(source_id, job_id);
                }
            }
            Err(e) => tracing::error!("failed to schedule external source {source_id}: {e}"),
        }
    }

    /// Removes the scheduled job for external source `id`, if one is registered.
    pub async fn remove_source(&self, id: Uuid) {
        let existing = self.source_jobs.lock().ok().and_then(|mut map| map.remove(&id));
        if let Some(job_id) = existing
            && let Err(e) = self.scheduler.remove(&job_id).await
        {
            tracing::warn!("failed to remove scheduled job for external source {id}: {e}");
        }
    }

    /// (Re)registers the cron job for `task`. Removes any existing job for the same id first, so
    /// this is safe to call on every create/update.
    pub async fn upsert_task(&self, state: &AppState, task: &vault_sync_task::Model) {
        self.remove_task(task.id).await;
        if !task.is_active {
            return;
        }
        let cron = normalize_cron(&task.cron_schedule);
        let state = state.clone();
        let task_id = task.id;
        let job = match Job::new_async(cron.as_str(), move |_uuid, _lock| {
            let state = state.clone();
            Box::pin(async move {
                if let Err(e) = crate::jobs::vault_sync::run(&state, task_id).await {
                    tracing::error!("scheduled vault sync job {task_id} failed: {e}");
                }
            })
        }) {
            Ok(job) => job,
            Err(e) => {
                tracing::error!("invalid cron_schedule for sync task {task_id}: {e}");
                return;
            }
        };
        match self.scheduler.add(job).await {
            Ok(job_id) => {
                if let Ok(mut map) = self.task_jobs.lock() {
                    map.insert(task_id, job_id);
                }
            }
            Err(e) => tracing::error!("failed to schedule sync task {task_id}: {e}"),
        }
    }

    /// Removes the scheduled job for sync task `id`, if one is registered.
    pub async fn remove_task(&self, id: Uuid) {
        let existing = self.task_jobs.lock().ok().and_then(|mut map| map.remove(&id));
        if let Some(job_id) = existing
            && let Err(e) = self.scheduler.remove(&job_id).await
        {
            tracing::warn!("failed to remove scheduled job for sync task {id}: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_cron_prepends_seconds_to_5_field_expression() {
        assert_eq!(normalize_cron("0 0 * * *"), "0 0 0 * * *");
    }

    #[test]
    fn normalize_cron_leaves_6_field_expression_unchanged() {
        assert_eq!(normalize_cron("*/30 * * * * *"), "*/30 * * * * *");
    }

    #[test]
    fn validate_cron_expression_accepts_conventional_5_field_forms() {
        assert!(validate_cron_expression("0 0 * * *").is_ok());
        assert!(validate_cron_expression("*/15 * * * *").is_ok());
        assert!(validate_cron_expression("0 3 * * 1").is_ok());
    }

    #[test]
    fn validate_cron_expression_accepts_6_field_forms() {
        assert!(validate_cron_expression("0 */5 * * * *").is_ok());
    }

    #[test]
    fn validate_cron_expression_rejects_garbage() {
        assert!(validate_cron_expression("invalid_cron").is_err());
        assert!(validate_cron_expression("* * *").is_err());
        assert!(validate_cron_expression("").is_err());
        assert!(validate_cron_expression("   ").is_err());
        assert!(validate_cron_expression("99 99 99 * *").is_err());
    }
}
