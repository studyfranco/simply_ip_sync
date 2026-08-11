//! HTTP handlers, split by domain. Re-exported flat: `api::create_api_key` resolves the same
//! regardless of which file it lives in — the paths are the API, the files are an implementation
//! detail.

mod audit;
mod guards;
mod health;
mod keys;
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

pub use audit::*;
pub use health::*;
pub use keys::*;
pub use sources::*;
pub use sync_logs::*;
pub use sync_tasks::*;
pub use vaults::*;
