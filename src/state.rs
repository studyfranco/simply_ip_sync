//! Shared application state.
//!
//! Everything here is built once at startup and carried, never re-derived per request — each
//! field is an input to a security decision, and a value that can change under a running process
//! cannot be reasoned about. Every field is behind an `Arc` (directly or via its own internal
//! `Arc`/`OnceLock`) so a `#[derive(Clone)]` can never silently hand a request its own private
//! copy of a security primitive.

use std::sync::Arc;

use reqwest::Client;
use sea_orm::DatabaseConnection;

use crate::config::TrustedProxies;
use crate::crypto::SecretCipher;
use crate::jobs::RunningJobs;
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
    /// Parsed `TRUSTED_PROXIES` list — CIDRs/IPs plus any hostnames, resolved (and cached) at
    /// request time via `TrustedProxies::resolved`. Already `Arc`-backed internally, so this field
    /// carries no extra `Arc` wrapper of its own.
    pub trusted_proxies: TrustedProxies,
    /// Outbound HTTP client used to call remote vault endpoints.
    pub http: Client,
    /// The cron scheduler handle.
    pub scheduler: Arc<SchedulerHandle>,
    /// Resource ids with a sync job currently executing (`jobs::try_start_job`/`JobGuard`) — guards
    /// against two overlapping executions of the same external source or sync task.
    pub running_jobs: RunningJobs,
    /// Whether external feed ingestion and `/api/sources/test-fetch` permit private/loopback IPs.
    /// Always `false` in production unless `ALLOW_PRIVATE_INGEST_URLS_FOR_TEST=true` is set.
    pub allow_private_ingest_urls: bool,
}

impl AppState {
    /// Builds application state from a database connection, reading `SYNC_ENCRYPTION_KEY` and
    /// `TRUSTED_PROXIES` from the environment and starting the cron scheduler. Both env vars are
    /// security boundaries and fail hard on a malformed value.
    ///
    /// # Errors
    ///
    /// Returns [`StartupConfigError`] if environment configuration, HTTP client creation, or
    /// scheduler startup fails.
    pub async fn new(db: DatabaseConnection) -> Result<Self, StartupConfigError> {
        let cipher = SecretCipher::from_env()?;
        let trusted_proxies = TrustedProxies::from_env()?;
        let http = crate::client::build_http_client()?;
        let scheduler = SchedulerHandle::new()
            .await
            .map_err(|e| StartupConfigError::Scheduler(e.to_string()))?;

        Ok(Self {
            db,
            cipher: Arc::new(cipher),
            replay: Arc::new(ReplayGuard::default()),
            master_pin: Arc::new(MasterPin::new()),
            trusted_proxies,
            http,
            scheduler: Arc::new(scheduler),
            running_jobs: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            allow_private_ingest_urls: crate::config::allow_private_ingest_urls(),
        })
    }

    /// Test-only constructor: builds state with a pre-pinned Master identity and a plaintext
    /// cipher, skipping environment reads entirely. Public (rather than `cfg(test)`-gated) so
    /// integration tests under `tests/`, which link against this crate as an ordinary dependency,
    /// can use it too.
    ///
    /// # Errors
    ///
    /// Returns [`StartupConfigError`] if the HTTP client or scheduler fails to initialize.
    pub async fn for_tests(
        db: DatabaseConnection,
        master_id: uuid::Uuid,
    ) -> Result<Self, StartupConfigError> {
        let scheduler = SchedulerHandle::new()
            .await
            .map_err(|e| StartupConfigError::Scheduler(e.to_string()))?;
        let http = crate::client::build_http_client()?;
        Ok(Self {
            db,
            cipher: Arc::new(SecretCipher::Plaintext),
            replay: Arc::new(ReplayGuard::default()),
            master_pin: Arc::new(MasterPin::pinned_to(master_id)),
            trusted_proxies: TrustedProxies::default(),
            http,
            scheduler: Arc::new(scheduler),
            running_jobs: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            allow_private_ingest_urls: true,
        })
    }

    /// Overrides the private-URL ingestion escape hatch (primarily for SSRF integration tests).
    #[must_use]
    pub fn with_allow_private_ingest_urls(mut self, allow: bool) -> Self {
        self.allow_private_ingest_urls = allow;
        self
    }
}
