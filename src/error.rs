//! The single error type returned by every fallible operation reachable from an HTTP handler.
//!
//! A variant here is a status code plus a message shape, never domain logic. Handlers convert
//! into this type via `?` (through `#[from]` impls) or by constructing a variant directly.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Every failure a handler, job, or background worker in this crate can return.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// A database operation failed. Detail is logged server-side only; the response is generic.
    #[error("database error")]
    DbError(#[from] sea_orm::DbErr),
    /// The caller supplied a malformed or invalid payload.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// The caller did not authenticate successfully.
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    /// The caller authenticated but may not perform the requested action.
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// The requested resource does not exist, or is not visible to the caller.
    #[error("not found")]
    NotFound,
    /// The request conflicts with existing state (e.g. a duplicate unique field).
    #[error("conflict: {0}")]
    Conflict(String),
    /// A conflict carrying structured detail (e.g. a pre-flight cascade inventory).
    #[error("conflict: {message}")]
    ConflictWithDetails {
        /// Human-readable summary.
        message: String,
        /// Structured detail merged into the top level of the response body.
        details: serde_json::Value,
    },
    /// A request extractor rejected the body with its own status code (e.g. `413`).
    #[error("body rejected: {1}")]
    BodyRejected(StatusCode, String),
    /// An internal failure with no detail safe to disclose to the caller.
    #[error("internal error")]
    Internal,
}

/// Whether a [`sea_orm::DbErr`] is a transient lock/contention failure (`SQLITE_BUSY`,
/// `SQLITE_LOCKED`, pool timeout, or PostgreSQL lock/serialization conflict).
fn is_transient_lock_error(err: &sea_orm::DbErr) -> bool {
    if matches!(err, sea_orm::DbErr::ConnectionAcquire(_)) {
        return true;
    }
    let (sea_orm::DbErr::Conn(runtime_err)
    | sea_orm::DbErr::Exec(runtime_err)
    | sea_orm::DbErr::Query(runtime_err)) = err
    else {
        return false;
    };
    let sea_orm::RuntimeErr::SqlxError(sqlx_err) = runtime_err else {
        return false;
    };
    match sqlx_err.as_ref() {
        sea_orm::SqlxError::PoolTimedOut => true,
        sea_orm::SqlxError::Database(db_err) => match db_err.code().as_deref() {
            Some("55P03" | "40001" | "40P01") => true,
            Some(code) => code.parse::<u32>().is_ok_and(|n| matches!(n & 0xFF, 5 | 6)),
            None => false,
        },
        _ => false,
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            AppError::DbError(err) => {
                tracing::error!("database error: {err}");
                if is_transient_lock_error(&err) {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        json!({ "error": "Database busy or query timeout, please retry" }),
                    )
                } else {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({ "error": "Internal server error" }),
                    )
                }
            }
            AppError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, json!({ "error": msg })),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, json!({ "error": msg })),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, json!({ "error": msg })),
            AppError::NotFound => (
                StatusCode::NOT_FOUND,
                json!({ "error": "Resource not found" }),
            ),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, json!({ "error": msg })),
            AppError::ConflictWithDetails { message, details } => {
                let mut body = json!({ "error": message });
                if let (Some(body_map), Some(details_map)) =
                    (body.as_object_mut(), details.as_object())
                {
                    for (key, value) in details_map {
                        body_map.insert(key.clone(), value.clone());
                    }
                }
                (StatusCode::CONFLICT, body)
            }
            AppError::BodyRejected(status, msg) => (status, json!({ "error": msg })),
            AppError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "error": "Internal server error" }),
            ),
        };
        (status, Json(body)).into_response()
    }
}

impl From<crate::crypto::CryptoError> for AppError {
    fn from(err: crate::crypto::CryptoError) -> Self {
        tracing::error!("crypto error: {err}");
        AppError::Internal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_lock_and_pool_errors_map_to_503() {
        let pool_timeout = AppError::DbError(sea_orm::DbErr::Query(
            sea_orm::RuntimeErr::SqlxError(std::sync::Arc::new(sea_orm::SqlxError::PoolTimedOut)),
        ));
        assert_eq!(
            pool_timeout.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        let conn_acquire = AppError::DbError(sea_orm::DbErr::ConnectionAcquire(
            sea_orm::ConnAcquireErr::Timeout,
        ));
        assert_eq!(
            conn_acquire.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        let generic = AppError::DbError(sea_orm::DbErr::Custom("boom".to_owned()));
        assert_eq!(
            generic.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
