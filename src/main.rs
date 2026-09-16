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

    // Logged from `state.trusted_proxies` (not a second, separately-constructed
    // `TrustedProxies::from_env()` local) deliberately: a second instance would carry its own
    // resolution cache, so priming it here would warm a cache nothing ever reads from — the very
    // request path uses `state`'s own copy. Same reasoning as every other security-relevant field
    // on `AppState`: one instance, shared, not one built per call site that happens to need it.
    if state.trusted_proxies.is_empty() {
        tracing::warn!(
            "{} is not set: X-Forwarded-For and X-Real-IP are IGNORED and every key is matched \
             against its raw TCP peer address. This is correct for a directly-exposed deployment; \
             behind a reverse proxy you must set it, or CIDR-bound keys will be rejected.",
            simply_ip_sync::config::TRUSTED_PROXIES_ENV
        );
    } else {
        tracing::info!(
            "{} is set: forwarding headers are honoured from {} matcher(s): {:?}",
            simply_ip_sync::config::TRUSTED_PROXIES_ENV,
            state.trusted_proxies.matchers().len(),
            state.trusted_proxies.matchers()
        );
    }
    // Resolves every configured hostname once, now, so a typo is reported at boot rather than
    // discovered as an unexplained 403 later. Detached and non-blocking: an unresolvable entry is
    // retried after a grace period and left untrusted meanwhile, never a reason to refuse to start.
    state.trusted_proxies.prime_with_grace();

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
///
/// Random generation is the **normal** path and is not warned about — an operator running the
/// service exactly as documented sees no noise about it. `INITIAL_MASTER_KEY`/
/// `INITIAL_MASTER_SIGNING_SECRET` exist purely for deterministic test/CI bootstrap (a harness
/// that needs to know the credential up front rather than scraping it back out of a log), and it
/// is *that* — the unusual path — that gets a warning, matching `simply_ip_vault`'s convention:
/// setting either in a real deployment is the thing worth a human noticing, not their absence.
async fn bootstrap_master_key(db: &DatabaseConnection) -> Result<(), Box<dyn std::error::Error>> {
    let existing = ApiKey::find().filter(api_key::Column::IsMaster.eq(true)).count(db).await?;
    if existing > 0 {
        return Ok(());
    }

    let plaintext_key = match std::env::var(simply_ip_sync::config::INITIAL_MASTER_KEY_ENV) {
        Ok(raw) if !raw.is_empty() => {
            simply_ip_sync::config::validate_initial_master_key(&raw).map_err(|e| {
                tracing::error!("Refusing to start: {e}");
                e
            })?;
            tracing::warn!(
                "{} is set: using the provided value as the Master key instead of generating a \
                 random one. This is intended for deterministic test/CI bootstrap only — do not \
                 set this in a real deployment.",
                simply_ip_sync::config::INITIAL_MASTER_KEY_ENV
            );
            raw
        }
        _ => simply_ip_sync::api::generate_random_key(),
    };

    let cipher = simply_ip_sync::crypto::SecretCipher::from_env()?;
    let signing_secret = match std::env::var(simply_ip_sync::config::INITIAL_MASTER_SIGNING_SECRET_ENV) {
        Ok(raw) if !raw.is_empty() => {
            simply_ip_sync::config::validate_initial_master_signing_secret(&raw).map_err(|e| {
                tracing::error!("Refusing to start: {e}");
                e
            })?;
            tracing::warn!(
                "{} is set: using the provided value as the Master key's HMAC signing secret \
                 instead of generating a random one. Intended for deterministic test/CI bootstrap \
                 only — do not set this in a real deployment.",
                simply_ip_sync::config::INITIAL_MASTER_SIGNING_SECRET_ENV
            );
            raw
        }
        _ => simply_ip_sync::crypto::generate_signing_secret(),
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

    // Shown unconditionally — regardless of whether the values above were generated or
    // operator-supplied — because this is the one and only moment either is knowable: rotation is
    // refused for the Master key through the API (RBAC §5), so there is no way to recover them
    // later. The box is drawn against an explicit inner width rather than hardcoded runs of `═`,
    // so the borders stay aligned around a 64-hex-character credential.
    const W: usize = 82;
    let border = "═".repeat(W);
    let body: String = [
        format!("X-API-Key      : {plaintext_key}"),
        format!("Signing secret : {signing_secret}"),
        format!("Bound IPs      : {BOOTSTRAP_SUBNET}"),
        String::new(),
        "Both values are needed to sign requests (X-Timestamp + X-Signature-256).".to_owned(),
        "They will NOT be shown again — store them securely!".to_owned(),
    ]
    .iter()
    .map(|row| format!("║ {row:<W$} ║\n"))
    .collect();

    tracing::info!(
        "\n╔{border}╗\n║ {:<W$} ║\n╠{border}╣\n{body}╚{border}╝",
        "BOOTSTRAP: Master API Key Generated"
    );

    // tracing's fmt subscriber buffers writes; flushing makes the banner's appearance in a
    // redirected/tailed log deterministic rather than a short race against the next log line.
    use std::io::Write;
    std::io::stdout().flush().ok();
    std::io::stderr().flush().ok();

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
