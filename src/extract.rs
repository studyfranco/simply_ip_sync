//! Strict request extractors.
//!
//! [`StrictJson`] is `Json` whose deserialization failures become [`AppError`] with the correct
//! status. This is an RBAC §5 control, not ergonomics: removing a field like `is_master` from a
//! payload type alone makes serde silently *ignore* it if present, which is worse than accepting
//! or rejecting; combined with `#[serde(deny_unknown_fields)]` on the payload type, an unexpected
//! field becomes a `400` refusal instead of a silent drop.

use axum::extract::{FromRequest, Json, Request};
use axum::http::StatusCode;
use serde::de::DeserializeOwned;

use crate::error::AppError;

/// `Json<T>` whose rejection is rendered as `AppError::InvalidInput` (or `AppError::BodyRejected`
/// for an oversized body), rather than axum's default rejection body shape.
pub struct StrictJson<T>(pub T);

impl<S, T> FromRequest<S> for StrictJson<T>
where
    Json<T>: FromRequest<S, Rejection = axum::extract::rejection::JsonRejection>,
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(StrictJson(value)),
            Err(rejection) => match rejection {
                axum::extract::rejection::JsonRejection::JsonDataError(e) => {
                    Err(AppError::InvalidInput(e.to_string()))
                }
                axum::extract::rejection::JsonRejection::JsonSyntaxError(e) => {
                    Err(AppError::InvalidInput(e.to_string()))
                }
                axum::extract::rejection::JsonRejection::MissingJsonContentType(e) => {
                    Err(AppError::InvalidInput(e.to_string()))
                }
                axum::extract::rejection::JsonRejection::BytesRejection(e) => {
                    Err(AppError::BodyRejected(StatusCode::PAYLOAD_TOO_LARGE, e.to_string()))
                }
                other => Err(AppError::InvalidInput(other.to_string())),
            },
        }
    }
}

/// `Path<T>` whose rejection is rendered as [`AppError`] rather than axum's default.
///
/// Axum's built-in `Path` and `Query` rejections serialize as **plain text**, not JSON. Every
/// other refusal in this service answers `{"error": "..."}`, so a malformed path segment (a
/// non-UUID id) or an unparseable query string was the one way to get a response whose shape a
/// client's error handling would not recognise. That is a contract hole, not a cosmetic one: a
/// caller that parses the envelope to decide whether to retry sees a parse failure instead of a
/// `400`. These wrappers close it so the envelope is total across every status the service emits.
pub struct StrictPath<T>(pub T);

impl<S, T> axum::extract::FromRequestParts<S> for StrictPath<T>
where
    axum::extract::Path<T>: axum::extract::FromRequestParts<S, Rejection = axum::extract::rejection::PathRejection>,
    T: Send,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match axum::extract::Path::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Path(value)) => Ok(StrictPath(value)),
            // A path segment that does not parse identifies no resource. `NotFound` (not
            // `InvalidInput`) is deliberate: it keeps a malformed id indistinguishable from a
            // well-formed id for a resource that does not exist, so the error shape cannot be used
            // to probe which ids are syntactically real (RBAC §4 oracle discipline).
            Err(_) => Err(AppError::NotFound),
        }
    }
}

/// `Query<T>` whose rejection is rendered as [`AppError::InvalidInput`]. See [`StrictPath`] for
/// why the default plain-text rejection is a problem.
pub struct StrictQuery<T>(pub T);

impl<S, T> axum::extract::FromRequestParts<S> for StrictQuery<T>
where
    axum::extract::Query<T>:
        axum::extract::FromRequestParts<S, Rejection = axum::extract::rejection::QueryRejection>,
    T: Send,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match axum::extract::Query::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Query(value)) => Ok(StrictQuery(value)),
            Err(rejection) => Err(AppError::InvalidInput(rejection.body_text())),
        }
    }
}
