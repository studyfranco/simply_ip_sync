//! Background execution pipelines: external feed ingestion and inter-vault delta replication.
//! Both are plain async functions taking `(&AppState, Uuid)`, callable identically from the cron
//! scheduler and from the manual-trigger HTTP handlers.

pub mod external_ingestion;
pub mod vault_sync;

use chrono::Utc;
use sea_orm::{EntityTrait, Set};
use uuid::Uuid;

use crate::entities::sync_log;

/// Maximum number of records sent in a single `POST /api/records/batch` chunk. Below
/// `simply_ip_vault`'s own `MAX_BATCH_RECORDS = 10_000` ceiling, so a full-size chunk is never
/// rejected server-side.
pub const MAX_BATCH_SIZE: usize = 5_000;

/// Splits `items` into chunks of at most `max` elements. An empty input yields no chunks (not one
/// empty chunk).
pub fn chunk_records<T>(items: Vec<T>, max: usize) -> Vec<Vec<T>> {
    let mut iter = items.into_iter();
    let mut chunks = Vec::new();
    loop {
        let chunk: Vec<T> = iter.by_ref().take(max).collect();
        if chunk.is_empty() {
            break;
        }
        chunks.push(chunk);
    }
    chunks
}

/// The outcome of one job execution, written to `sync_logs` and returned to a manual-trigger
/// caller. `status` is `"SUCCESS"`, `"PARTIAL"`, or `"FAILED"`.
pub struct JobSummary {
    /// Outcome status.
    pub status: &'static str,
    /// Total IP/CIDR records parsed and sent.
    pub items_processed: i32,
    /// Number of batch HTTP calls made.
    pub chunks_sent: i32,
    /// Total processing time in milliseconds.
    pub duration_ms: i32,
    /// Error details, if any target failed or the fetch/parse step failed.
    pub error_message: Option<String>,
}

/// Writes one `sync_logs` row for a completed job execution.
pub async fn write_sync_log<C: sea_orm::ConnectionTrait>(
    db: &C,
    job_type: &str,
    job_id: Uuid,
    job_name: &str,
    summary: &JobSummary,
    started_at: chrono::DateTime<Utc>,
) -> Result<(), sea_orm::DbErr> {
    let log = sync_log::ActiveModel {
        id: Set(Uuid::new_v4()),
        job_type: Set(job_type.to_owned()),
        job_id: Set(job_id),
        job_name: Set(job_name.to_owned()),
        status: Set(summary.status.to_owned()),
        items_processed: Set(summary.items_processed),
        chunks_sent: Set(summary.chunks_sent),
        duration_ms: Set(summary.duration_ms),
        error_message: Set(summary.error_message.clone()),
        timestamp: Set(started_at),
    };
    sync_log::Entity::insert(log).exec(db).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_boundary_exactly_max() {
        let items: Vec<u32> = (0..5000).collect();
        let chunks = chunk_records(items, 5000);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 5000);
    }

    #[test]
    fn chunk_boundary_one_over_max() {
        let items: Vec<u32> = (0..5001).collect();
        let chunks = chunk_records(items, 5000);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 5000);
        assert_eq!(chunks[1].len(), 1);
    }

    #[test]
    fn chunk_boundary_one_under_max() {
        let items: Vec<u32> = (0..9999).collect();
        let chunks = chunk_records(items, 5000);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 5000);
        assert_eq!(chunks[1].len(), 4999);
    }

    #[test]
    fn empty_input_yields_no_chunks() {
        let items: Vec<u32> = Vec::new();
        let chunks = chunk_records(items, 5000);
        assert!(chunks.is_empty());
    }
}
