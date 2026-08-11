//! The Master identity pin.
//!
//! This file answers exactly one question — "is this key the Master this process pinned?" — and
//! nothing else. `migration::m20260101_000002_derive_master_marker`'s unique index guarantees *at
//! most one* Master row exists (it defends cardinality); this module defends *identity*: an
//! attacker with database write access does not need two Masters, only to demote the real one and
//! promote itself, which keeps the count at exactly one and satisfies the index. Neither control
//! substitutes for the other.

use std::sync::OnceLock;

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect};
use uuid::Uuid;

use crate::entities::api_key;
use crate::entities::prelude::ApiKey;

/// Table name used by [`MasterPin::pin_at_boot`]'s uniqueness-index existence check.
pub const API_KEYS_TABLE: &str = "api_keys";
/// Name of the unique index over the generated `master_marker` column.
pub const MASTER_MARKER_INDEX: &str = "idx-api_keys-master_marker";

/// Failure modes for pinning or resolving the Master identity.
#[derive(Debug, thiserror::Error)]
pub enum MasterPinError {
    /// No row has `is_master = true`.
    #[error("no Master key exists")]
    NoMaster,
    /// More than one row has `is_master = true` — the uniqueness index has been bypassed or is
    /// missing.
    #[error("multiple Master keys exist: {0:?}")]
    MultipleMasters(Vec<Uuid>),
    /// The `master_marker` unique index is missing from the database.
    #[error("master_marker uniqueness index is missing")]
    MissingUniquenessIndex,
    /// The lookup query itself failed.
    #[error(transparent)]
    Db(#[from] sea_orm::DbErr),
}

/// A write-once pin to the id of the single Master API key. Backed by a [`OnceLock`] so its value
/// cannot drift once set under a running process.
pub struct MasterPin {
    cell: OnceLock<Uuid>,
}

impl MasterPin {
    /// An unpinned handle.
    pub fn new() -> Self {
        Self { cell: OnceLock::new() }
    }

    /// Test-only: builds a handle already pinned to `id`, without a database query.
    pub fn pinned_to(id: Uuid) -> Self {
        let cell = OnceLock::new();
        let _ = cell.set(id);
        Self { cell }
    }

    /// The pinned Master id, if this handle has been pinned yet.
    pub fn get(&self) -> Option<Uuid> {
        self.cell.get().copied()
    }

    /// Pins the Master identity from the database. Must be called by `main.rs` after migrations
    /// and Master bootstrap, and before the listener binds — moving it later reopens the
    /// tampering window this module exists to close. Idempotent: a second call is a cheap
    /// `OnceLock` read.
    pub async fn pin_at_boot(&self, db: &DatabaseConnection) -> Result<Uuid, MasterPinError> {
        if let Some(pinned) = self.cell.get() {
            return Ok(*pinned);
        }
        let pinned = Self::sole_master(db).await?;
        if !crate::db::has_index(db, API_KEYS_TABLE, MASTER_MARKER_INDEX).await? {
            return Err(MasterPinError::MissingUniquenessIndex);
        }
        // Race-safe: if another task set it first, both resolvers agree on the same row, since
        // sole_master() can only ever return the one row that really is the Master.
        let _ = self.cell.set(pinned);
        Ok(pinned)
    }

    /// Re-resolves the current sole Master from the database. Fails closed: any error, or zero /
    /// multiple masters, yields `None` rather than propagating detail to a caller.
    pub async fn resolve(&self, db: &DatabaseConnection) -> Option<Uuid> {
        Self::sole_master(db).await.ok()
    }

    /// The single choke point every authenticated request passes through. If `key.is_master` is
    /// set but does not match the pinned identity, `key` is demoted in place (never rejected with
    /// a 401 — that demotion decision must not become an authentication oracle for a caller who
    /// merely forged the flag).
    pub async fn authenticate(&self, db: &DatabaseConnection, key: &mut api_key::Model) {
        if !key.is_master {
            return;
        }
        match self.resolve(db).await {
            Some(pinned) if pinned == key.id => {}
            _ => {
                tracing::error!(
                    key_id = %key.id,
                    "TAMPER: key claims is_master=true but does not match the pinned Master identity; demoting for this request"
                );
                key.is_master = false;
            }
        }
    }

    async fn sole_master(db: &DatabaseConnection) -> Result<Uuid, MasterPinError> {
        let masters: Vec<Uuid> = ApiKey::find()
            .select_only()
            .column(api_key::Column::Id)
            .filter(api_key::Column::IsMaster.eq(true))
            .into_tuple()
            .all(db)
            .await?;
        match masters.as_slice() {
            [only] => Ok(*only),
            [] => Err(MasterPinError::NoMaster),
            many => Err(MasterPinError::MultipleMasters(many.to_vec())),
        }
    }
}

impl Default for MasterPin {
    fn default() -> Self {
        Self::new()
    }
}
