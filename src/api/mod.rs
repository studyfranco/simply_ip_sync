//! HTTP handlers, split by domain. Re-exported flat: `api::create_api_key` resolves the same
//! regardless of which file it lives in — the paths are the API, the files are an implementation
//! detail.

mod audit;
mod guards;
mod health;
mod keys;
mod settings;
mod sources;
mod support;
mod sync_logs;
mod sync_tasks;
mod vaults;

pub(crate) use guards::*;

/// Credential primitives genuinely needed outside `api/`: `main.rs`'s Master bootstrap and the
/// integration test suites, which mint keys directly against the database rather than through the
/// HTTP API.
pub use support::{generate_random_key, hash_key, key_prefix};

pub(crate) use audit::*;
pub(crate) use health::*;
pub(crate) use keys::*;
pub(crate) use settings::*;
pub(crate) use sources::*;
pub(crate) use sync_logs::*;
pub(crate) use sync_tasks::*;
pub(crate) use vaults::*;
