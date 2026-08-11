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
