//! Schema migrations. Ordered below; each file is one applied migration and is immutable history
//! — only documentation may be corrected in place. This is the one directory (besides `db.rs`'s
//! `PRAGMA` setup) where raw SQL is permitted, because DDL for generated columns and per-engine
//! storage classes cannot be expressed portably through SeaQuery.

pub use sea_orm_migration::prelude::*;

mod m20260101_013240_initial_schema;
mod m20260101_013241_derive_master_marker;
mod m20260818_010217_audit_attribution_not_null;

/// The ordered set of migrations applied at startup.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260101_013240_initial_schema::Migration),
            Box::new(m20260101_013241_derive_master_marker::Migration),
            Box::new(m20260818_010217_audit_attribution_not_null::Migration),
        ]
    }
}
