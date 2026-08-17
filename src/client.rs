//! Outbound signed HTTP client for calling remote `simply_ip_vault` instances.
//!
//! Generates valid `CANONICAL_V1` HMAC requests (`X-API-Key`, `X-Timestamp`, `X-Signature-256`)
//! using the decrypted credentials of a target `vault_endpoints` row. `vault_endpoints` are
//! admin-configured internal services gated by `can_manage_vaults`, not arbitrary user-supplied
//! URLs, so this client does not carry the private-IP SSRF blocklist a webhook-dispatch client
//! aimed at lower-trust targets would need — creating a vault endpoint is already a Master-granted
//! right. Redirects are refused outright (`redirect::Policy::none()`) since a target silently
//! redirecting elsewhere isn't a case that should be followed transparently.

use chrono::{DateTime, Utc};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};

use crate::crypto::{self, SecretCipher};
use crate::entities::vault_endpoint;

/// Failure modes for an outbound call to a vault endpoint.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The endpoint's `target_url` could not be parsed.
    #[error("invalid target_url: {0}")]
    InvalidUrl(String),
    /// The endpoint's `signing_secret` could not be decrypted.
    #[error("failed to decrypt vault endpoint signing secret")]
    Decrypt(#[from] crate::crypto::CryptoError),
    /// Signature computation failed.
    #[error("failed to compute request signature")]
    Signing,
    /// The underlying HTTP request failed (network error, timeout, TLS, etc).
    #[error("request to vault endpoint failed: {0}")]
    Request(#[from] reqwest::Error),
    /// The remote vault responded with a non-2xx status.
    #[error("vault endpoint returned {status}: {body}")]
    RemoteError {
        /// HTTP status code returned.
        status: u16,
        /// Response body, truncated.
        body: String,
    },
}

/// How a batch reconciles against what is already in the target group. Mirrors
/// `simply_ip_vault`'s `POST /api/records/batch` contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchMode {
    /// Insert new records, update existing ones. Never implicitly deletes.
    Upsert,
    /// Insert/update the records in this batch, and soft-delete anything in the target group this
    /// batch does not mention. **Only ever safe as the first batch a target group receives in a
    /// given execution run** — every later chunk of the same run must downgrade to [`Self::Upsert`]
    /// (see `jobs::mode_for_chunk_index`), or chunk 2 would read as "everything not in chunk 2"
    /// and erase chunk 1's just-delivered records on the receiving vault.
    FullReplace,
}

impl BatchMode {
    /// Parses a `SCHEMA.MD` `mode` column value (`"upsert"` or `"full_replace"`). Returns `None`
    /// for anything else — callers should treat that as a validation failure, not silently fall
    /// back to a default; a typo'd mode must be caught at the API boundary
    /// (`api/sources.rs`/`api/sync_tasks.rs`), not reinterpreted here.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "upsert" => Some(Self::Upsert),
            "full_replace" => Some(Self::FullReplace),
            _ => None,
        }
    }
}

/// One record in a `POST /api/records/batch` request, matching `simply_ip_vault`'s
/// `BatchRecordInput`.
#[derive(Debug, Clone, Serialize)]
pub struct BatchRecordInput {
    /// A bare IP address or CIDR subnet.
    pub target_address: String,
    /// Optional free-text cause/reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    /// Marks the record as a tombstone (soft-deleted) when `Some(true)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_deleted: Option<bool>,
    /// Only honoured for genuinely new rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<chrono::NaiveDateTime>,
    /// Update timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<chrono::NaiveDateTime>,
    /// Last-seen timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<chrono::NaiveDateTime>,
    /// Deletion timestamp, when `is_deleted` is `Some(true)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<chrono::NaiveDateTime>,
}

/// Response body of `POST /api/records/batch`.
#[derive(Debug, Default, Deserialize)]
pub struct BatchRecordsResponse {
    /// Number of newly created records.
    #[serde(default)]
    pub created: u64,
    /// Number of updated records.
    #[serde(default)]
    pub updated: u64,
    /// Number of records restored from a soft-deleted state.
    #[serde(default)]
    pub restored: u64,
    /// Number of records skipped because they were locked.
    #[serde(default)]
    pub locked_skipped: u64,
    /// Number of records soft-deleted by this batch.
    #[serde(default)]
    pub soft_deleted: u64,
    /// Number of group memberships linked.
    #[serde(default)]
    pub linked: u64,
}

impl BatchRecordsResponse {
    /// Accumulates `other` into `self`, field-wise. Used when a single caller-provided chunk gets
    /// adaptively split (on `413`) into multiple sub-requests — the caller sees one combined
    /// summary, exactly as if the whole chunk had been accepted in one request.
    fn merge(&mut self, other: Self) {
        self.created += other.created;
        self.updated += other.updated;
        self.restored += other.restored;
        self.locked_skipped += other.locked_skipped;
        self.soft_deleted += other.soft_deleted;
        self.linked += other.linked;
    }
}

/// One record as returned by `GET /api/ips`, matching `simply_ip_vault`'s `IpRecordResponse`.
#[derive(Debug, Clone, Deserialize)]
pub struct IpRecordResponse {
    /// Record id on the source vault.
    pub id: uuid::Uuid,
    /// The IP address or CIDR subnet.
    pub target_address: String,
    /// Group name this record belongs to.
    pub group_name: String,
    /// Free-text cause/reason.
    #[serde(default)]
    pub cause: Option<String>,
    /// Whether this record is currently soft-deleted (a tombstone).
    #[serde(default)]
    pub is_deleted: bool,
    /// Deletion timestamp, if soft-deleted.
    #[serde(default)]
    pub deleted_at: Option<chrono::NaiveDateTime>,
    /// Creation timestamp on the source vault.
    #[serde(default)]
    pub created_at: Option<chrono::NaiveDateTime>,
    /// Last update timestamp.
    #[serde(default)]
    pub updated_at: Option<chrono::NaiveDateTime>,
    /// Last-seen timestamp.
    #[serde(default)]
    pub last_seen_at: Option<chrono::NaiveDateTime>,
}

/// Builds a `reqwest::Client` suitable for outbound calls to vault endpoints: redirects refused, a
/// bounded timeout (`config::outbound_http_timeout`, default 60s) so a hung remote cannot stall a
/// scheduled job indefinitely, and transparent response decompression (gzip/deflate/brotli/zstd)
/// — many HTTP feed hosts and CDNs compress responses by default, and without this a compressed
/// body would be handed to a `FeedParser` as opaque bytes: `REGEX_LINE` would silently extract
/// zero addresses (compressed bytes essentially never contain an IP-shaped ASCII substring) and
/// `JSON_PATH` would fail to parse, both indistinguishable from the feed genuinely being empty or
/// broken. Tests that need to control the timeout precisely (e.g. against a deliberately slow
/// mock) should build their own `Client` and override `AppState.http` directly rather than going
/// through the process-wide `OUTBOUND_HTTP_TIMEOUT_SECS` cache this function reads.
pub fn build_http_client() -> Result<Client, reqwest::Error> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(crate::config::outbound_http_timeout())
        .build()
}

fn signed_headers(
    cipher: &SecretCipher,
    endpoint: &vault_endpoint::Model,
    method: &str,
    target: &str,
    body: &[u8],
) -> Result<(String, String, String), ClientError> {
    let secret = cipher.open(&endpoint.signing_secret)?;
    let timestamp = Utc::now().timestamp().to_string();
    let signature = crypto::compute_signature(&secret, method, target, &timestamp, body)
        .map_err(|_| ClientError::Signing)?;
    Ok((endpoint.api_key.clone(), timestamp, signature))
}

/// Sends one HTTP `POST {target_url}/api/records/batch` attempt, no retry and no splitting. The
/// building block both [`post_batch`] and its retry loop are made of.
async fn post_batch_once(
    http: &Client,
    cipher: &SecretCipher,
    endpoint: &vault_endpoint::Model,
    group_name: &str,
    records: &[BatchRecordInput],
    mode: BatchMode,
) -> Result<BatchRecordsResponse, ClientError> {
    let base = Url::parse(&endpoint.target_url).map_err(|e| ClientError::InvalidUrl(e.to_string()))?;
    let url = base
        .join("/api/records/batch")
        .map_err(|e| ClientError::InvalidUrl(e.to_string()))?;
    let target = url.path().to_owned();

    #[derive(Serialize)]
    struct Payload<'a> {
        group_name: &'a str,
        mode: BatchMode,
        records: &'a [BatchRecordInput],
    }
    let payload = Payload { group_name, mode, records };
    let body = serde_json::to_vec(&payload).map_err(|_| ClientError::Signing)?;

    // Signed fresh on every attempt — not just because CANONICAL_V1 covers the body (unchanged
    // between attempts of the same sub-chunk) but because it covers the timestamp too, and a
    // retry after a multi-second backoff sleep must never reuse a timestamp that might now be
    // outside the receiving side's own freshness window.
    let (api_key, timestamp, signature) = signed_headers(cipher, endpoint, "POST", &target, &body)?;

    let response = http
        .post(url)
        .header("X-API-Key", api_key)
        .header("X-Timestamp", timestamp)
        .header("X-Signature-256", signature)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        let truncated: String = body.chars().take(500).collect();
        return Err(ClientError::RemoteError { status: status.as_u16(), body: truncated });
    }
    Ok(response.json::<BatchRecordsResponse>().await?)
}

/// [`post_batch_once`] wrapped in a transient-failure retry loop: on `429`/`502`/`503`/`504`,
/// waits (`retry::backoff_with_jitter`) and retries with a freshly signed request, up to
/// `config::outbound_max_retries()` times. `413` is deliberately **not** retried here — an
/// oversized payload will still be oversized on attempt 2, and [`post_batch`]'s caller is
/// responsible for splitting it instead.
async fn post_batch_with_retry(
    http: &Client,
    cipher: &SecretCipher,
    endpoint: &vault_endpoint::Model,
    group_name: &str,
    records: &[BatchRecordInput],
    mode: BatchMode,
) -> Result<BatchRecordsResponse, ClientError> {
    let max_retries = crate::config::outbound_max_retries();
    let mut attempt: u32 = 0;
    loop {
        match post_batch_once(http, cipher, endpoint, group_name, records, mode).await {
            Ok(resp) => return Ok(resp),
            Err(ClientError::RemoteError { status, body }) if crate::retry::is_transient_status(status) && attempt < max_retries => {
                attempt += 1;
                let delay = crate::retry::backoff_with_jitter(attempt);
                tracing::warn!(
                    "vault '{}' returned {status} for a batch of {} record(s); retrying in {delay:?} (attempt {attempt}/{max_retries}): {body}",
                    endpoint.name,
                    records.len()
                );
                tokio::time::sleep(delay).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Sends `records` to `POST {target_url}/api/records/batch` on `endpoint`, signed with
/// `CANONICAL_V1`, transparently handling two failure modes a caller should never need to think
/// about: transient upstream errors (retried with exponential backoff — see
/// [`post_batch_with_retry`]) and an oversized payload (`413 Payload Too Large` — the batch is
/// split in half and each half sent as its own request, recursively, until every sub-chunk fits).
///
/// `mode` applies to `records` as a whole; if a `413` forces a split, only the *first* resulting
/// sub-chunk keeps `mode` — every subsequent piece is forced to [`BatchMode::Upsert`], for the
/// same reason [`crate::jobs::mode_for_chunk_index`] downgrades every chunk after the first at
/// the job layer: a second `full_replace` write against a target that already received the first
/// half would erase it.
pub async fn post_batch(
    http: &Client,
    cipher: &SecretCipher,
    endpoint: &vault_endpoint::Model,
    group_name: &str,
    records: &[BatchRecordInput],
    mode: BatchMode,
) -> Result<BatchRecordsResponse, ClientError> {
    // A FIFO work queue rather than true recursion: async fns can't recurse without boxing the
    // future, and a queue makes the "only the very first piece keeps `mode`" rule easy to state
    // correctly (push the tail piece back deliberately downgraded, regardless of how many times a
    // given chunk has already been re-split).
    let mut queue: std::collections::VecDeque<(Vec<BatchRecordInput>, BatchMode)> = std::collections::VecDeque::new();
    queue.push_back((records.to_vec(), mode));

    let mut aggregate = BatchRecordsResponse::default();

    while let Some((chunk, chunk_mode)) = queue.pop_front() {
        match post_batch_with_retry(http, cipher, endpoint, group_name, &chunk, chunk_mode).await {
            Ok(resp) => aggregate.merge(resp),
            Err(ClientError::RemoteError { status: 413, body }) if chunk.len() > 1 => {
                let mid = chunk.len() / 2;
                let mut first_half = chunk;
                let second_half = first_half.split_off(mid);
                tracing::warn!(
                    "vault '{}' returned 413 for a batch of {} record(s); splitting into {} + {} and retrying: {body}",
                    endpoint.name,
                    first_half.len() + second_half.len(),
                    first_half.len(),
                    second_half.len()
                );
                let second_mode = match chunk_mode {
                    BatchMode::FullReplace => BatchMode::Upsert,
                    BatchMode::Upsert => BatchMode::Upsert,
                };
                // Front-pushed in reverse delivery order so the queue processes `first_half`
                // (which may still legitimately carry `full_replace`) strictly before
                // `second_half` (already downgraded) on the next loop iteration.
                queue.push_front((second_half, second_mode));
                queue.push_front((first_half, chunk_mode));
            }
            Err(e) => return Err(e),
        }
    }

    Ok(aggregate)
}

/// Page size used to paginate `GET /api/ips`. Matches the outbound batch chunk size, so the
/// fetch and push sides of the pipeline move records in like-sized groups.
const DELTA_PAGE_SIZE: u64 = 5_000;

/// Fetches one page of `GET {target_url}/api/ips`, no retry. Building block for
/// [`get_ips_delta`]'s retry loop and pagination loop.
#[allow(clippy::too_many_arguments)]
async fn get_ips_page(
    http: &Client,
    cipher: &SecretCipher,
    endpoint: &vault_endpoint::Model,
    base: &Url,
    group_name: &str,
    since: Option<DateTime<Utc>>,
    include_deleted: bool,
    offset: u64,
) -> Result<Vec<IpRecordResponse>, ClientError> {
    let mut url = base.join("/api/ips").map_err(|e| ClientError::InvalidUrl(e.to_string()))?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("group_name", group_name);
        pairs.append_pair("include_deleted", if include_deleted { "true" } else { "false" });
        pairs.append_pair("limit", &DELTA_PAGE_SIZE.to_string());
        pairs.append_pair("offset", &offset.to_string());
        if let Some(since) = since {
            pairs.append_pair("since", &since.timestamp().to_string());
        }
    }
    let target = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_owned(),
    };

    // Signed fresh on every call — see post_batch_once's doc comment for why a retried request
    // must never reuse a timestamp from before its backoff sleep.
    let (api_key, timestamp, signature) = signed_headers(cipher, endpoint, "GET", &target, b"")?;

    let response = http
        .get(url)
        .header("X-API-Key", api_key)
        .header("X-Timestamp", timestamp)
        .header("X-Signature-256", signature)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        let truncated: String = body.chars().take(500).collect();
        return Err(ClientError::RemoteError { status: status.as_u16(), body: truncated });
    }
    Ok(response.json::<Vec<IpRecordResponse>>().await?)
}

/// [`get_ips_page`] wrapped in the same transient-failure retry loop as
/// [`post_batch_with_retry`]: `429`/`502`/`503`/`504` are retried with backoff, up to
/// `config::outbound_max_retries()` times.
#[allow(clippy::too_many_arguments)]
async fn get_ips_page_with_retry(
    http: &Client,
    cipher: &SecretCipher,
    endpoint: &vault_endpoint::Model,
    base: &Url,
    group_name: &str,
    since: Option<DateTime<Utc>>,
    include_deleted: bool,
    offset: u64,
) -> Result<Vec<IpRecordResponse>, ClientError> {
    let max_retries = crate::config::outbound_max_retries();
    let mut attempt: u32 = 0;
    loop {
        match get_ips_page(http, cipher, endpoint, base, group_name, since, include_deleted, offset).await {
            Ok(page) => return Ok(page),
            Err(ClientError::RemoteError { status, body }) if crate::retry::is_transient_status(status) && attempt < max_retries => {
                attempt += 1;
                let delay = crate::retry::backoff_with_jitter(attempt);
                tracing::warn!(
                    "vault '{}' returned {status} fetching delta page at offset {offset}; retrying in {delay:?} (attempt {attempt}/{max_retries}): {body}",
                    endpoint.name
                );
                tokio::time::sleep(delay).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Queries `GET {target_url}/api/ips?group_name=...&since=...&include_deleted=...` on `endpoint`,
/// signed with `CANONICAL_V1`, and pages through the full delta result set (the source vault
/// paginates with `limit`/`offset`; a single request only returns one page). The signed target
/// includes the query string on every page request, matching `simply_ip_vault`'s own rule that
/// the signed target is path plus query. Each page is retried independently on a transient
/// upstream failure — a 503 on page 3 of 4 does not require re-fetching pages 1 and 2.
pub async fn get_ips_delta(
    http: &Client,
    cipher: &SecretCipher,
    endpoint: &vault_endpoint::Model,
    group_name: &str,
    since: Option<DateTime<Utc>>,
    include_deleted: bool,
) -> Result<Vec<IpRecordResponse>, ClientError> {
    let base = Url::parse(&endpoint.target_url).map_err(|e| ClientError::InvalidUrl(e.to_string()))?;
    let mut all_records = Vec::new();
    let mut offset: u64 = 0;

    loop {
        let page =
            get_ips_page_with_retry(http, cipher, endpoint, &base, group_name, since, include_deleted, offset)
                .await?;
        let page_len = page.len() as u64;
        all_records.extend(page);
        if page_len < DELTA_PAGE_SIZE {
            break;
        }
        offset += DELTA_PAGE_SIZE;
    }

    Ok(all_records)
}
