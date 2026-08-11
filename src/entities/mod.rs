//! SeaORM entity models. One file per table, plus [`prelude`] for the flat `Entity` re-export
//! set. Every file is generated-shaped (`Model`, `ActiveModel`, `Column`, `Relation`,
//! `ActiveModelBehavior`) and must not hold business logic, defaults that encode policy, or
//! authorization helpers.

pub mod api_key;
pub mod api_key_sync_permission;
pub mod audit_log;
pub mod external_source;
pub mod external_source_vault_target;
pub mod prelude;
pub mod sync_log;
pub mod vault_endpoint;
pub mod vault_sync_task;
pub mod vault_sync_task_target;
