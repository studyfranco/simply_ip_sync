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

    let state = simply_ip_sync::setup_state(db).await?;
    let pinned = state.master_pin.pin_at_boot(&state.db).await?;
    tracing::info!("Master key identity pinned: {pinned}");

    state.scheduler.boot(&state).await?;

    let app = simply_ip_sync::create_app(state);
    let addr = simply_ip_sync::config::resolve_bind_addr();
    tracing::info!("simply_ip_sync listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
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
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
