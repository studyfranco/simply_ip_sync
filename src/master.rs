//! The Master identity pin.
//!
//! This file answers exactly one question — "is this key the Master this process pinned?" — and
//! nothing else. `migration::m20260101_013241_derive_master_marker`'s unique index guarantees *at
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
    #[must_use]
    pub fn new() -> Self {
        Self {
            cell: OnceLock::new(),
        }
    }

    /// Test-only: builds a handle already pinned to `id`, without a database query.
    #[must_use]
    pub fn pinned_to(id: Uuid) -> Self {
        let cell = OnceLock::new();
        let _ = cell.set(id);
        Self { cell }
    }

    /// The pinned Master id, if this handle has been pinned yet.
    #[must_use]
    pub fn get(&self) -> Option<Uuid> {
        self.cell.get().copied()
    }

    /// Pins the Master identity from the database. Must be called by `main.rs` after migrations
    /// and Master bootstrap, and before the listener binds — moving it later reopens the
    /// tampering window this module exists to close. Idempotent: a second call is a cheap
    /// `OnceLock` read.
    ///
    /// # Errors
    ///
    /// Returns [`MasterPinError`] if no Master key, multiple Master keys, a missing uniqueness
    /// index, or a database error is encountered.
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

    /// Returns the pinned Master id, resolving it from the database once if neither
    /// [`Self::pin_at_boot`] nor [`Self::pinned_to`] has populated the cell yet.
    ///
    /// Once set, `self.cell` is authoritative for the lifetime of the process — subsequent runtime
    /// `is_master` edits in the database cannot move the pin. Fails closed: any error, or zero /
    /// multiple masters before pinning, yields `None` rather than propagating detail to a caller.
    pub async fn resolve(&self, db: &DatabaseConnection) -> Option<Uuid> {
        if let Some(pinned) = self.cell.get().copied() {
            return Some(pinned);
        }
        match self.pin_at_boot(db).await {
            Ok(id) => Some(id),
            Err(e) => {
                tracing::error!(
                    "Master identity is unresolvable, so no caller will be treated as Master: {e}"
                );
                None
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ActiveValue::Set, Database};
    use sea_orm_migration::MigratorTrait;

    #[tokio::test]
    async fn resolve_ignores_runtime_is_master_promotion() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        crate::migration::Migrator::up(&db, None).await.unwrap();

        let original_id = Uuid::new_v4();
        let promoted_id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let original = api_key::ActiveModel {
            id: Set(original_id),
            name: Set("Master".to_owned()),
            key_hash: Set("h1".to_owned()),
            signing_secret: Set(Some("v1.plain.736563726574".to_owned())),
            prefix: Set("11111111".to_owned()),
            is_master: Set(true),
            can_manage_keys: Set(true),
            can_manage_sources: Set(true),
            can_manage_vaults: Set(true),
            parent_key_id: Set(None),
            bound_ips: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        };
        let other = api_key::ActiveModel {
            id: Set(promoted_id),
            name: Set("Attacker".to_owned()),
            key_hash: Set("h2".to_owned()),
            signing_secret: Set(Some("v1.plain.736563726574".to_owned())),
            prefix: Set("22222222".to_owned()),
            is_master: Set(false),
            can_manage_keys: Set(false),
            can_manage_sources: Set(false),
            can_manage_vaults: Set(false),
            parent_key_id: Set(Some(original_id)),
            bound_ips: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        };
        ApiKey::insert(original).exec(&db).await.unwrap();
        ApiKey::insert(other).exec(&db).await.unwrap();

        let pin = MasterPin::new();
        assert_eq!(pin.pin_at_boot(&db).await.unwrap(), original_id);

        // Simulate runtime tampering in DB: demote the original master and promote the attacker.
        ApiKey::update_many()
            .col_expr(
                api_key::Column::IsMaster,
                sea_orm::sea_query::Expr::value(false),
            )
            .filter(api_key::Column::Id.eq(original_id))
            .exec(&db)
            .await
            .unwrap();
        ApiKey::update_many()
            .col_expr(
                api_key::Column::IsMaster,
                sea_orm::sea_query::Expr::value(true),
            )
            .filter(api_key::Column::Id.eq(promoted_id))
            .exec(&db)
            .await
            .unwrap();

        assert_eq!(pin.resolve(&db).await, Some(original_id));

        let mut forged = ApiKey::find_by_id(promoted_id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert!(forged.is_master);
        pin.authenticate(&db, &mut forged).await;
        assert!(!forged.is_master, "runtime-promoted key must be demoted");
    }
}
