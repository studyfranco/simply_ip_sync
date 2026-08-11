//! Shared application state.
//!
//! Everything here is built once at startup and carried, never re-derived per request — each
//! field is an input to a security decision, and a value that can change under a running process
//! cannot be reasoned about. Every field is behind an `Arc` (directly or via its own internal
//! `Arc`/`OnceLock`) so a `#[derive(Clone)]` can never silently hand a request its own private
//! copy of a security primitive.

use std::sync::Arc;

use ipnetwork::IpNetwork;
use reqwest::Client;
use sea_orm::DatabaseConnection;

use crate::crypto::SecretCipher;
use crate::master::MasterPin;
use crate::replay::ReplayGuard;
use crate::scheduler::SchedulerHandle;

/// Failure modes that prevent the service from starting at all.
#[derive(Debug, thiserror::Error)]
pub enum StartupConfigError {
    /// `SYNC_ENCRYPTION_KEY` was set but malformed.
    #[error("invalid SYNC_ENCRYPTION_KEY: {0}")]
    EncryptionKey(#[from] crate::crypto::CryptoError),
    /// `TRUSTED_PROXIES` was set but malformed.
    #[error("invalid TRUSTED_PROXIES: {0}")]
    TrustedProxies(#[from] crate::config::InvalidTrustedProxies),
    /// The outbound HTTP client could not be built.
    #[error("failed to build outbound HTTP client: {0}")]
    HttpClient(#[from] reqwest::Error),
    /// The cron scheduler could not be started.
    #[error("failed to start scheduler: {0}")]
    Scheduler(String),
}

/// Shared, cloneable application state passed to every handler and background job.
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool.
    pub db: DatabaseConnection,
    /// Secrets-at-rest cipher.
    pub cipher: Arc<SecretCipher>,
    /// Inbound anti-replay guard.
    pub replay: Arc<ReplayGuard>,
    /// Master identity pin.
    pub master_pin: Arc<MasterPin>,
    /// Parsed `TRUSTED_PROXIES` CIDR list.
    pub trusted_proxies: Arc<Vec<IpNetwork>>,
    /// Outbound HTTP client used to call remote vault endpoints.
    pub http: Client,
    /// The cron scheduler handle.
    pub scheduler: Arc<SchedulerHandle>,
}

impl AppState {
    /// Builds application state from a database connection, reading `SYNC_ENCRYPTION_KEY` and
    /// `TRUSTED_PROXIES` from the environment and starting the cron scheduler. Both env vars are
    /// security boundaries and fail hard on a malformed value.
    pub async fn new(db: DatabaseConnection) -> Result<Self, StartupConfigError> {
        let cipher = SecretCipher::from_env()?;
        let trusted_proxies = crate::config::trusted_proxies_from_env()?;
        let http = crate::client::build_http_client()?;
        let scheduler = SchedulerHandle::new()
            .await
            .map_err(|e| StartupConfigError::Scheduler(e.to_string()))?;

        Ok(Self {
            db,
            cipher: Arc::new(cipher),
            replay: Arc::new(ReplayGuard::default()),
            master_pin: Arc::new(MasterPin::new()),
            trusted_proxies: Arc::new(trusted_proxies),
            http,
            scheduler: Arc::new(scheduler),
        })
    }

    /// Test-only constructor: builds state with a pre-pinned Master identity and a plaintext
    /// cipher, skipping environment reads entirely. Public (rather than `cfg(test)`-gated) so
    /// integration tests under `tests/`, which link against this crate as an ordinary dependency,
    /// can use it too.
    pub async fn for_tests(db: DatabaseConnection, master_id: uuid::Uuid) -> Self {
        let scheduler = SchedulerHandle::new().await.expect("scheduler starts in tests");
        Self {
            db,
            cipher: Arc::new(SecretCipher::Plaintext),
            replay: Arc::new(ReplayGuard::default()),
            master_pin: Arc::new(MasterPin::pinned_to(master_id)),
            trusted_proxies: Arc::new(Vec::new()),
            http: crate::client::build_http_client().expect("http client builds"),
            scheduler: Arc::new(scheduler),
        }
    }
}
