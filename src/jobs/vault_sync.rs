//! Inter-vault delta replication pipeline: fetch a source vault's delta (including tombstones)
//! since the task's high-water mark, chunk, and push to every configured target vault, in
//! `upsert` mode.

use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

use super::{chunk_records, JobSummary, MAX_BATCH_SIZE};
use crate::client::{self, BatchMode, BatchRecordInput};
use crate::entities::{vault_endpoint, vault_sync_task, vault_sync_task_target};
use crate::error::AppError;
use crate::state::AppState;

/// Runs one execution of inter-vault sync task `task_id`: fetches the source vault's delta since
/// `last_sync_at` (including soft-deleted tombstones), chunks it, and pushes to every configured
/// target vault. `last_sync_at` only advances when **every** target succeeds — a partial delivery
/// must not skip the undelivered records on the next run.
pub async fn run(state: &AppState, task_id: Uuid) -> Result<JobSummary, AppError> {
    let started_at = Utc::now();

    let task = vault_sync_task::Entity::find_by_id(task_id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    let source_vault = vault_endpoint::Entity::find_by_id(task.source_vault_id).one(&state.db).await?;

    let targets = vault_sync_task_target::Entity::find()
        .filter(vault_sync_task_target::Column::VaultSyncTaskId.eq(task_id))
        .find_also_related(vault_endpoint::Entity)
        .all(&state.db)
        .await?;

    let (summary, all_targets_succeeded) = execute(state, &task, source_vault.as_ref(), &targets).await;

    super::write_sync_log(&state.db, "VAULT_SYNC", task_id, &task.name, &summary, started_at).await?;

    if all_targets_succeeded {
        let mut active: vault_sync_task::ActiveModel = task.into();
        active.last_sync_at = Set(Some(started_at));
        active.update(&state.db).await?;
    }

    Ok(summary)
}

async fn execute(
    state: &AppState,
    task: &vault_sync_task::Model,
    source_vault: Option<&vault_endpoint::Model>,
    targets: &[(vault_sync_task_target::Model, Option<vault_endpoint::Model>)],
) -> (JobSummary, bool) {
    let start = std::time::Instant::now();

    let Some(source_vault) = source_vault else {
        return (
            JobSummary {
                status: "FAILED",
                items_processed: 0,
                chunks_sent: 0,
                duration_ms: start.elapsed().as_millis() as i32,
                error_message: Some("source vault endpoint no longer exists".to_owned()),
            },
            false,
        );
    };

    let delta = match client::get_ips_delta(
        &state.http,
        &state.cipher,
        source_vault,
        &task.source_group_name,
        task.last_sync_at,
        true,
    )
    .await
    {
        Ok(records) => records,
        Err(e) => {
            return (
                JobSummary {
                    status: "FAILED",
                    items_processed: 0,
                    chunks_sent: 0,
                    duration_ms: start.elapsed().as_millis() as i32,
                    error_message: Some(format!("delta fetch from '{}' failed: {e}", source_vault.name)),
                },
                false,
            );
        }
    };

    let items_processed = delta.len();
    let mapped: Vec<BatchRecordInput> = delta
        .into_iter()
        .map(|record| BatchRecordInput {
            target_address: record.target_address,
            cause: record.cause,
            is_deleted: Some(record.is_deleted),
            created_at: record.created_at,
            updated_at: record.updated_at,
            last_seen_at: record.last_seen_at,
            deleted_at: record.deleted_at,
        })
        .collect();

    let chunks = chunk_records(mapped, MAX_BATCH_SIZE);
    let mut chunks_sent = 0i32;
    let mut errors: Vec<String> = Vec::new();
    let mut any_success = targets.is_empty();
    let mut all_succeeded = true;

    for (target, vault) in targets {
        let Some(vault) = vault else {
            errors.push(format!("target vault {} no longer exists", target.target_vault_id));
            all_succeeded = false;
            continue;
        };
        let group_name = target
            .target_group_name
            .clone()
            .unwrap_or_else(|| task.target_group_name.clone());

        let mut target_ok = true;
        for chunk in &chunks {
            match client::post_batch(&state.http, &state.cipher, vault, &group_name, chunk, BatchMode::Upsert).await
            {
                Ok(_) => chunks_sent += 1,
                Err(e) => {
                    target_ok = false;
                    errors.push(format!("vault '{}': {e}", vault.name));
                    break;
                }
            }
        }
        if target_ok {
            any_success = true;
        } else {
            all_succeeded = false;
        }
    }

    let status = if errors.is_empty() {
        "SUCCESS"
    } else if any_success {
        "PARTIAL"
    } else {
        "FAILED"
    };

    (
        JobSummary {
            status,
            items_processed: items_processed as i32,
            chunks_sent,
            duration_ms: start.elapsed().as_millis() as i32,
            error_message: if errors.is_empty() { None } else { Some(errors.join("; ")) },
        },
        all_succeeded,
    )
}
