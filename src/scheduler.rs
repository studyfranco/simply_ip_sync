//! UTC cron dispatch for destination groups and vault sync tasks.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;

use croner::Cron;
use croner::errors::CronError;
use croner::time::{CivilDate, CivilDateTime, CivilTime, CronDateTime, Resolution, Weekday};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use time::{Date, Duration, Month, OffsetDateTime, PrimitiveDateTime, Time};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::entities::{destination_group, vault_sync_task};
use crate::state::AppState;

fn normalize_cron(expr: &str) -> String {
    if expr.split_whitespace().count() == 5 {
        format!("0 {expr}")
    } else {
        expr.to_owned()
    }
}

fn parse_cron(expr: &str) -> Result<Cron, CronError> {
    croner::parser::CronParser::builder()
        .seconds(croner::parser::Seconds::Required)
        .dom_and_dow(true)
        .build()
        .parse(&normalize_cron(expr))
}

/// Validates the same cron syntax used by scheduled jobs.
///
/// # Errors
/// Returns a description of the parse error for an invalid expression.
pub fn validate_cron_expression(expr: &str) -> Result<(), String> {
    if expr.trim().is_empty() {
        return Err("cron_schedule must not be empty".to_owned());
    }
    parse_cron(expr)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[derive(Clone, Copy)]
struct UtcTick(OffsetDateTime);

impl CronDateTime for UtcTick {
    fn to_civil(&self) -> CivilDateTime {
        CivilDateTime::new(
            CivilDate::from_parts_unchecked(
                self.0.year(),
                u32::from(u8::from(self.0.month())),
                u32::from(self.0.day()),
            ),
            CivilTime::from_parts_unchecked(
                u32::from(self.0.hour()),
                u32::from(self.0.minute()),
                u32::from(self.0.second()),
            ),
        )
    }

    fn civil_weekday(&self) -> Weekday {
        Weekday::from_days_from_sunday(u32::from(self.0.weekday().number_days_from_sunday()))
    }

    fn resolve_civil(&self, civil: CivilDateTime) -> Result<Resolution<Self>, CronError> {
        let month =
            Month::try_from(u8::try_from(civil.month()).map_err(|_| CronError::InvalidDate)?)
                .map_err(|_| CronError::InvalidDate)?;
        let day = u8::try_from(civil.day()).map_err(|_| CronError::InvalidDate)?;
        let date = Date::from_calendar_date(civil.year(), month, day)
            .map_err(|_| CronError::InvalidDate)?;
        let hour = u8::try_from(civil.hour()).map_err(|_| CronError::InvalidTime)?;
        let minute = u8::try_from(civil.minute()).map_err(|_| CronError::InvalidTime)?;
        let second = u8::try_from(civil.second()).map_err(|_| CronError::InvalidTime)?;
        let time = Time::from_hms(hour, minute, second).map_err(|_| CronError::InvalidTime)?;
        Ok(Resolution::Single(Self(
            PrimitiveDateTime::new(date, time).assume_utc(),
        )))
    }

    fn checked_add_seconds(&self, seconds: i64) -> Option<Self> {
        self.0.checked_add(Duration::seconds(seconds)).map(Self)
    }

    fn cmp_instant(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

// Dropping or replacing a registration stops future ticks. An admitted run can finish.
struct ScheduledJob(JoinHandle<()>);

impl Drop for ScheduledJob {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Owns one cancellable Tokio task per registered group or sync task.
#[derive(Default)]
pub struct SchedulerHandle {
    source_jobs: Mutex<HashMap<Uuid, ScheduledJob>>,
    task_jobs: Mutex<HashMap<Uuid, ScheduledJob>>,
}

impl SchedulerHandle {
    /// Creates an empty scheduler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads every `is_active = true` destination group and sync task from the database and
    /// registers a cron job for each. Called once at startup, after `AppState` is fully built.
    ///
    /// # Errors
    ///
    /// Returns `DbErr` if loading active groups or sync tasks fails.
    pub async fn boot(&self, state: &AppState) -> Result<(), sea_orm::DbErr> {
        let groups = destination_group::Entity::find()
            .filter(destination_group::Column::IsActive.eq(true))
            .all(&state.db)
            .await?;
        for group in &groups {
            self.upsert_source(state, group);
        }

        let tasks = vault_sync_task::Entity::find()
            .filter(vault_sync_task::Column::IsActive.eq(true))
            .all(&state.db)
            .await?;
        for task in &tasks {
            self.upsert_task(state, task);
        }
        Ok(())
    }

    /// Registers or replaces the timer for an active destination group.
    pub fn upsert_source(&self, state: &AppState, group: &destination_group::Model) {
        let context = state.jobs.clone();
        let running = state.running_jobs.clone();
        let id = group.id;
        register(
            &self.source_jobs,
            id,
            group.is_active,
            &group.cron_schedule,
            move || {
                let context = context.clone();
                let running = running.clone();
                async move {
                    let Some(_guard) = crate::jobs::try_start_job(&running, id) else {
                        tracing::warn!(%id, "scheduled external ingestion skipped because a run is active");
                        return;
                    };
                    if let Err(error) = crate::jobs::external_ingestion::run(&context, id).await {
                        tracing::error!(%id, %error, "scheduled external ingestion failed");
                    }
                }
            },
        );
    }

    /// Cancels the timer for a destination group.
    pub fn remove_source(&self, id: Uuid) {
        if let Ok(mut jobs) = self.source_jobs.lock() {
            jobs.remove(&id);
        }
    }

    /// Registers or replaces the timer for an active vault sync task.
    pub fn upsert_task(&self, state: &AppState, task: &vault_sync_task::Model) {
        let context = state.jobs.clone();
        let running = state.running_jobs.clone();
        let id = task.id;
        register(
            &self.task_jobs,
            id,
            task.is_active,
            &task.cron_schedule,
            move || {
                let context = context.clone();
                let running = running.clone();
                async move {
                    let Some(_guard) = crate::jobs::try_start_job(&running, id) else {
                        tracing::warn!(%id, "scheduled vault sync skipped because a run is active");
                        return;
                    };
                    if let Err(error) = crate::jobs::vault_sync::run(&context, id).await {
                        tracing::error!(%id, %error, "scheduled vault sync failed");
                    }
                }
            },
        );
    }

    /// Cancels the timer for a vault sync task.
    pub fn remove_task(&self, id: Uuid) {
        if let Ok(mut jobs) = self.task_jobs.lock() {
            jobs.remove(&id);
        }
    }
}

fn register<F>(
    jobs: &Mutex<HashMap<Uuid, ScheduledJob>>,
    id: Uuid,
    active: bool,
    expression: &str,
    dispatch: impl Fn() -> F + Send + 'static,
) where
    F: Future<Output = ()> + Send + 'static,
{
    let Ok(mut jobs) = jobs.lock() else { return };
    jobs.remove(&id);
    if !active {
        return;
    }
    let cron = match parse_cron(expression) {
        Ok(cron) => cron,
        Err(error) => {
            tracing::error!(%id, %error, "invalid cron schedule");
            return;
        }
    };

    jobs.insert(
        id,
        ScheduledJob(tokio::spawn(async move {
            loop {
                let now = OffsetDateTime::now_utc();
                let next = match cron.find_next_occurrence(&UtcTick(now), false) {
                    Ok(tick) => tick.0,
                    Err(error) => {
                        tracing::error!(%id, %error, "could not compute next cron tick");
                        return;
                    }
                };
                if let Ok(delay) = std::time::Duration::try_from(next - now) {
                    tokio::time::sleep(delay).await;
                }
                if let Err(error) = tokio::spawn(dispatch()).await {
                    tracing::error!(%id, %error, "scheduled job terminated unexpectedly");
                }
            }
        })),
    );
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

    #[test]
    fn next_tick_handles_subseconds_and_calendar_rollover() {
        let cron = parse_cron("0 0 * * *").unwrap();
        let now = UtcTick(time::macros::datetime!(2026-11-30 23:59:59.500 UTC));
        let next = cron.find_next_occurrence(&now, false).unwrap();
        assert_eq!(next.0, time::macros::datetime!(2026-12-01 00:00 UTC));
        let second = parse_cron("*/15 * * * * *").unwrap();
        assert_eq!(
            second.find_next_occurrence(&next, false).unwrap().0,
            time::macros::datetime!(2026-12-01 00:00:15 UTC)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn scheduler_dispatches_and_aborts_replaced_and_dropped_jobs() {
        let scheduler = SchedulerHandle::new();
        let id = Uuid::new_v4();
        let (sender, mut ticks) = tokio::sync::mpsc::unbounded_channel();
        register(&scheduler.source_jobs, id, true, "* * * * * *", move || {
            let sender = sender.clone();
            async move { sender.send(()).unwrap() }
        });
        let original = scheduler.source_jobs.lock().unwrap()[&id].0.abort_handle();
        tokio::time::timeout(std::time::Duration::from_secs(2), ticks.recv())
            .await
            .unwrap()
            .unwrap();

        register(&scheduler.source_jobs, id, true, "0 0 * * *", || async {});
        tokio::task::yield_now().await;
        assert!(original.is_finished());

        let replacement = scheduler.source_jobs.lock().unwrap()[&id].0.abort_handle();
        scheduler.remove_source(id);
        tokio::task::yield_now().await;
        assert!(replacement.is_finished());

        register(&scheduler.task_jobs, id, true, "0 0 * * *", || async {});
        let task = scheduler.task_jobs.lock().unwrap()[&id].0.abort_handle();
        drop(scheduler);
        tokio::task::yield_now().await;
        assert!(task.is_finished());
    }
}
