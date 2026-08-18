//! Process entry point. The startup sequence, in order, and nothing else: connect → pragmas →
//! migrate → bootstrap Master → pin Master → build state → boot scheduler → bind → serve →
//! graceful shutdown. `bootstrap_master_key` is the only writer of `is_master = true` in the
//! entire service.

use chrono::Utc;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter, Set};
use simply_ip_sync::entities::api_key;
use simply_ip_sync::entities::prelude::ApiKey;
use uuid::Uuid;

/// Default `bound_ips` for the bootstrap Master key: unrestricted, covering both address
/// families so a native-IPv6 caller (e.g. `::1`) is never locked out.
const BOOTSTRAP_SUBNET: &str = "0.0.0.0/0,::/0";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    dotenvy::dotenv().ok();

    if let Err(e) = run().await {
        tracing::error!("fatal startup error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://simply_ip_sync.db?mode=rwc".to_owned());

    let db = simply_ip_sync::db::connect(&database_url).await?;
    simply_ip_sync::db::apply_sqlite_pragmas(&db).await;
    simply_ip_sync::db::run_migrations(&db).await?;

    bootstrap_master_key(&db).await?;
    verify_encryption_key(&db).await?;

    let state = simply_ip_sync::setup_state(db).await?;
    let pinned = state.master_pin.pin_at_boot(&state.db).await?;
    tracing::info!("Master key identity pinned: {pinned}");

    state.scheduler.boot(&state).await?;

    // Detached, not drained on shutdown: a retention sweep is a bounded, idempotent DELETE, unlike
    // the in-flight HTTP requests graceful shutdown below actually needs to wait for. See
    // `retention::run_retention_worker`'s doc comment.
    tokio::spawn(simply_ip_sync::retention::run_retention_worker(state.db.clone()));

    let app = simply_ip_sync::create_app(state);
    let addr = simply_ip_sync::config::resolve_bind_addr();
    tracing::info!("simply_ip_sync listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Boot canary for `SYNC_ENCRYPTION_KEY`: opens one stored signing secret to prove the configured
/// key is the one the data at rest was sealed under, and refuses to start if it is not.
///
/// Runs after `bootstrap_master_key` so a fresh database has a secret to check against; on a
/// genuinely empty database there is nothing sealed and the check passes vacuously. Without this,
/// a wrong-but-well-formed key starts cleanly, reports ready, and fails only inside outbound
/// syncs, where the error surfaces as an authentication failure against the *vault* rather than a
/// local misconfiguration.
async fn verify_encryption_key(db: &DatabaseConnection) -> Result<(), Box<dyn std::error::Error>> {
    let cipher = simply_ip_sync::crypto::SecretCipher::from_env()?;
    let sample = ApiKey::find()
        .filter(api_key::Column::SigningSecret.is_not_null())
        .one(db)
        .await?
        .and_then(|key| key.signing_secret);

    match simply_ip_sync::crypto::check_key_canary(&cipher, sample.as_deref()) {
        Ok(simply_ip_sync::crypto::KeyCanary::Verified) => {
            tracing::info!("Encryption key canary passed: secrets at rest open with the configured key.");
            Ok(())
        }
        Ok(simply_ip_sync::crypto::KeyCanary::NoSealedSecrets) => {
            tracing::info!("Encryption key canary skipped: no sealed secrets stored yet.");
            Ok(())
        }
        Err(e) => {
            // Logged before returning: `main` renders this error with `Debug`, which would drop
            // the operator-facing guidance below.
            tracing::error!(
                "Encryption key canary FAILED ({e}): the stored secrets cannot be opened with the \
                 current {} . Refusing to start rather than running with a key that does not match \
                 the data at rest. Restore the previous key, or re-provision the secrets under the \
                 new one.",
                simply_ip_sync::crypto::ENCRYPTION_KEY_ENV
            );
            Err(Box::new(e))
        }
    }
}

/// Bootstraps the sole Master key on first boot. A no-op if a Master already exists. The only
/// place in the service that ever writes `is_master = true`.
async fn bootstrap_master_key(db: &DatabaseConnection) -> Result<(), Box<dyn std::error::Error>> {
    let existing = ApiKey::find().filter(api_key::Column::IsMaster.eq(true)).count(db).await?;
    if existing > 0 {
        return Ok(());
    }

    let plaintext_key = match std::env::var(simply_ip_sync::config::INITIAL_MASTER_KEY_ENV) {
        Ok(raw) => {
            simply_ip_sync::config::validate_initial_master_key(&raw)?;
            raw
        }
        Err(_) => {
            let generated = simply_ip_sync::api::generate_random_key();
            tracing::warn!(
                "No {} set; generated a one-time Master key. This will not be shown again: {generated}",
                simply_ip_sync::config::INITIAL_MASTER_KEY_ENV
            );
            generated
        }
    };

    let cipher = simply_ip_sync::crypto::SecretCipher::from_env()?;
    let signing_secret = match std::env::var(simply_ip_sync::config::INITIAL_MASTER_SIGNING_SECRET_ENV) {
        Ok(raw) => {
            simply_ip_sync::config::validate_initial_master_signing_secret(&raw)?;
            raw
        }
        Err(_) => {
            let generated = simply_ip_sync::crypto::generate_signing_secret();
            // Rotation is refused for the Master key through the API (RBAC §5: rotation always
            // returns a fresh credential, and the Master's is never reachable that way). This log
            // line is therefore the only time a *generated* secret is ever knowable — it must be
            // surfaced unconditionally in this branch. (When the operator supplied one via
            // INITIAL_MASTER_SIGNING_SECRET instead, they already have it and logging it back
            // would just be needless secret exposure in the log stream.)
            tracing::warn!(
                "No {} set; generated a one-time Master signing secret. This will not be shown again: {generated}",
                simply_ip_sync::config::INITIAL_MASTER_SIGNING_SECRET_ENV
            );
            generated
        }
    };
    let now = Utc::now();

    let model = api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set("Master".to_owned()),
        key_hash: Set(simply_ip_sync::api::hash_key(&plaintext_key)),
        signing_secret: Set(Some(cipher.seal(&signing_secret)?)),
        prefix: Set(simply_ip_sync::api::key_prefix(&plaintext_key)),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_sources: Set(true),
        can_manage_vaults: Set(true),
        parent_key_id: Set(None),
        bound_ips: Set(Some(BOOTSTRAP_SUBNET.to_owned())),
        created_at: Set(now),
        updated_at: Set(now),
    };
    ApiKey::insert(model).exec(db).await?;
    tracing::info!("Bootstrapped the Master API key.");
    Ok(())
}

async fn shutdown_signal() {
    // A signal handler that fails to install must not panic the shutdown future: that would abort
    // the process mid-request instead of draining it, turning a degraded-but-serving container
    // into a crash loop. Each arm degrades to `pending` so the *other* signal still works, and the
    // server keeps serving if neither can be installed.
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {}
            Err(e) => {
                tracing::error!("failed to install Ctrl+C handler: {e}; ignoring SIGINT");
                std::future::pending::<()>().await
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::error!("failed to install SIGTERM handler: {e}; ignoring SIGTERM");
                std::future::pending::<()>().await
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
