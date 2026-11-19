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
use ipnet::IpNet;
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
        .map_or(&parts.uri, |original| &original.0);
    uri.path_and_query()
        .map_or_else(|| uri.path().to_owned(), |pq| pq.as_str().to_owned())
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
async fn authenticate_key_and_secret(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<(api_key::Model, String, String), AppError> {
    let provided_key = headers
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing X-API-Key header".to_owned()))?;
    let provided_signature = headers
        .get("X-Signature-256")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| AppError::Unauthorized("Missing X-Signature-256 header".to_owned()))?;
    if !provided_signature
        .trim()
        .starts_with(crypto::SIGNATURE_PREFIX)
    {
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
        .ok_or_else(|| {
            AppError::Unauthorized(
                "This API key has no signing secret; rotate it to obtain one".to_owned(),
            )
        })
        .and_then(|stored| state.cipher.open(stored).map_err(AppError::from))?;

    Ok((key_record, signing_secret, provided_signature))
}

async fn read_bounded_body(
    req: Request<Body>,
) -> Result<(axum::http::request::Parts, axum::body::Bytes), AppError> {
    let (parts, body) = req.into_parts();
    let max_bytes = crate::config::max_body_bytes();
    let declared_len = parts
        .headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());
    if declared_len.is_some_and(|declared| declared > max_bytes) {
        return Err(AppError::BodyRejected(
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "Request body exceeds the maximum allowed size".to_owned(),
        ));
    }

    let body_bytes = axum::body::to_bytes(body, max_bytes).await.map_err(|_| {
        AppError::BodyRejected(
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "Request body exceeds the maximum allowed size".to_owned(),
        )
    })?;
    Ok((parts, body_bytes))
}

fn check_bound_ips(key_record: &api_key::Model, client_ip: IpAddr) -> Result<(), AppError> {
    let bound_ips_raw = key_record.bound_ips.as_deref().unwrap_or("");
    let networks: Vec<IpNet> = bound_ips_raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<IpNet>().or_else(|_| {
                s.parse::<IpAddr>()
                    .map(|ip| IpNet::from(crate::config::normalize_ip(ip)))
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AppError::Internal)?;
    if !networks.is_empty() && !networks.iter().any(|net| net.contains(&client_ip)) {
        return Err(AppError::Forbidden("Client IP not allowed".to_owned()));
    }
    Ok(())
}

///
/// # Errors
///
/// Returns [`AppError`] on missing/invalid auth headers, replayed signatures, disallowed client
/// IP, oversized payload, or database errors.
pub async fn auth_middleware(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let trusted_proxies = state.trusted_proxies.resolved().await;
    let client_ip = crate::config::resolve_client_ip(addr.ip(), &headers, &trusted_proxies);
    let timestamp = validate_timestamp(&headers)?;

    let (mut key_record, signing_secret, provided_signature) =
        authenticate_key_and_secret(&state, &headers).await?;

    let method = req.method().as_str().to_owned();
    let (parts, body_bytes) = read_bounded_body(req).await?;
    let target = signed_target(&parts);

    let Some(digest) = crypto::verify_signature(
        &signing_secret,
        &method,
        &target,
        &timestamp,
        &body_bytes,
        &provided_signature,
    ) else {
        return Err(AppError::Unauthorized(
            "Invalid request signature".to_owned(),
        ));
    };

    if !state.replay.check_and_record(key_record.id, &digest) {
        return Err(AppError::Unauthorized(
            "This request signature has already been used; sign a fresh request".to_owned(),
        ));
    }

    check_bound_ips(&key_record, client_ip)?;
    state
        .master_pin
        .authenticate(&state.db, &mut key_record)
        .await;

    let key_id = key_record.id;
    let mut req = Request::from_parts(parts, Body::from(body_bytes));
    req.extensions_mut().insert(ClientIp(client_ip));
    req.extensions_mut().insert(key_record);

    let res = next.run(req).await;
    if res.status().is_server_error() {
        state.replay.unrecord(key_id, &digest);
    }
    Ok(res)
}
