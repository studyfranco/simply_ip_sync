//! Inbound request authentication.
//!
//! [`auth_middleware`] answers "who is calling, and may they call at all" — never "may they touch
//! *this* resource" (that is `api/guards.rs`). Ordering here is a security control: signature
//! verification runs before the `bound_ips` check, so a 401/403 pair can never be used as an
//! oracle for whether a key exists; and Master demotion happens at the single point a key model
//! enters the request extensions, since ~dozens of downstream reads of `key.is_master` would
//! otherwise each need their own check.

use axum::body::Body;
use axum::extract::{ConnectInfo, OriginalUri, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use chrono::Utc;
use ipnetwork::IpNetwork;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};

use crate::crypto::{self, MAX_TIMESTAMP_SKEW_SECS};
use crate::entities::api_key;
use crate::entities::prelude::ApiKey;
use crate::error::AppError;
use crate::state::AppState;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

/// The resolved client IP address, inserted into request extensions by [`auth_middleware`].
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub IpAddr);

fn signed_target(parts: &axum::http::request::Parts) -> String {
    // Middleware sits inside `.nest("/api", …)`, which rewrites `req.uri()` to be nest-relative;
    // `OriginalUri` carries the full, unrewritten path and query string that the client actually
    // signed.
    let uri = parts
        .extensions
        .get::<OriginalUri>()
        .map(|original| &original.0)
        .unwrap_or(&parts.uri);
    uri.path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| uri.path().to_owned())
}

fn validate_timestamp(headers: &axum::http::HeaderMap) -> Result<String, AppError> {
    let raw = headers
        .get("X-Timestamp")
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .ok_or_else(|| AppError::Unauthorized("Missing X-Timestamp header".to_owned()))?;
    let supplied: i64 = raw
        .parse()
        .map_err(|_| AppError::Unauthorized("Malformed X-Timestamp header".to_owned()))?;
    let skew = (Utc::now().timestamp() - supplied).abs();
    if skew > MAX_TIMESTAMP_SKEW_SECS {
        return Err(AppError::Unauthorized(format!(
            "Request timestamp outside the permitted {MAX_TIMESTAMP_SKEW_SECS}s window"
        )));
    }
    Ok(raw.to_owned())
}

/// Authenticates every inbound `/api/*` request: HMAC-SHA256 signature verification over
/// `CANONICAL_V1`, anti-replay, and `bound_ips` CIDR enforcement. On success, inserts the
/// authenticated [`api_key::Model`] and [`ClientIp`] into the request's extensions for handlers
/// and `api/guards.rs` to read.
pub async fn auth_middleware(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let client_ip = crate::config::resolve_client_ip(addr.ip(), &headers, &state.trusted_proxies);

    // Timestamp validation first: cheap, no DB round-trip, and rejects a stale/malformed request
    // before spending a lookup on it.
    let timestamp = validate_timestamp(&headers)?;

    let provided_key = headers
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing X-API-Key header".to_owned()))?;
    let provided_signature = headers
        .get("X-Signature-256")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| AppError::Unauthorized("Missing X-Signature-256 header".to_owned()))?;
    if !provided_signature.trim().starts_with(crypto::SIGNATURE_PREFIX) {
        return Err(AppError::Unauthorized(
            "X-Signature-256 must be formatted as sha256=<hex>".to_owned(),
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(provided_key.as_bytes());
    let key_hash = hex::encode(hasher.finalize());

    let key_record = ApiKey::find()
        .filter(api_key::Column::KeyHash.eq(key_hash))
        .one(&state.db)
        .await
        .map_err(AppError::DbError)?
        .ok_or_else(|| AppError::Unauthorized("Invalid API Key".to_owned()))?;

    let signing_secret = key_record
        .signing_secret
        .as_deref()
        .ok_or_else(|| AppError::Unauthorized("This API key has no signing secret; rotate it to obtain one".to_owned()))
        .and_then(|stored| state.cipher.open(stored).map_err(AppError::from))?;

    let method = req.method().as_str().to_owned();
    let (parts, body) = req.into_parts();
    let target = signed_target(&parts);
    let body_bytes = axum::body::to_bytes(body, crate::config::max_body_bytes())
        .await
        .map_err(|_| AppError::InvalidInput("Request body unreadable or too large to sign".to_owned()))?;

    let Some(digest) = crypto::verify_signature(
        &signing_secret,
        &method,
        &target,
        &timestamp,
        &body_bytes,
        &provided_signature,
    ) else {
        return Err(AppError::Unauthorized("Invalid request signature".to_owned()));
    };

    // Replay check only after the signature has actually been proven valid — recording an
    // unverified digest would let an attacker pre-insert a signature the legitimate client hasn't
    // sent yet, denying them service.
    if !state.replay.check_and_record(key_record.id, &digest) {
        return Err(AppError::Unauthorized(
            "This request signature has already been used; sign a fresh request".to_owned(),
        ));
    }

    // bound_ips checked last, only once the signature is proven: an attacker who merely guessed a
    // valid-looking key must not be able to distinguish "wrong key" from "right key, wrong IP" by
    // status code alone.
    let bound_ips_raw = key_record.bound_ips.as_deref().unwrap_or("");
    let networks: Vec<IpNetwork> = bound_ips_raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AppError::Internal)?;
    if !networks.is_empty() && !networks.iter().any(|net| net.contains(client_ip)) {
        return Err(AppError::Forbidden("Client IP not allowed".to_owned()));
    }

    let mut key_record = key_record;
    state.master_pin.authenticate(&state.db, &mut key_record).await;

    let mut req = Request::from_parts(parts, Body::from(body_bytes));
    req.extensions_mut().insert(ClientIp(client_ip));
    req.extensions_mut().insert(key_record);
    Ok(next.run(req).await)
}
