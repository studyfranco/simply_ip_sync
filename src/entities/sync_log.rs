//! `sync_logs` — execution history for external ingestion and inter-vault sync tasks.

use sea_orm::entity::prelude::*;
use serde::Serialize;

/// The `sync_logs` row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "sync_logs")]
pub struct Model {
    /// Primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Task type: `"EXTERNAL_FEED"` or `"VAULT_SYNC"`.
    pub job_type: String,
    /// Id of the `external_sources` or `vault_sync_tasks` row this execution belongs to.
    pub job_id: Uuid,
    /// Denormalized task name at execution time.
    pub job_name: String,
    /// Outcome: `"SUCCESS"`, `"FAILED"`, or `"PARTIAL"`.
    pub status: String,
    /// Total IP/CIDR records parsed and sent.
    pub items_processed: i32,
    /// Number of 5,000-record batch HTTP calls made.
    pub chunks_sent: i32,
    /// Total processing time in milliseconds.
    pub duration_ms: i32,
    /// Error details on failure.
    pub error_message: Option<String>,
    /// Start timestamp of execution.
    pub timestamp: DateTimeUtc,
}

/// Relations from `sync_logs`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
