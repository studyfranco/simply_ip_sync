//! External threat feed ingestion pipeline: fetch → parse → chunk → push to every configured
//! target vault, in `upsert` mode.

use std::collections::HashSet;

use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde_json::Value;
use uuid::Uuid;

use super::{chunk_records, JobSummary, MAX_BATCH_SIZE};
use crate::client::{self, BatchMode, BatchRecordInput};
use crate::entities::{external_source, external_source_vault_target, vault_endpoint};
use crate::error::AppError;
use crate::parsers;
use crate::state::AppState;

/// Runs one execution of external source `source_id`: fetches its feed, parses it, chunks the
/// result, and pushes each chunk to every configured target vault. Always writes one `sync_logs`
/// row and updates `external_sources.last_run_at`, regardless of outcome — "last execution" means
/// the job ran, not that it ran successfully.
pub async fn run(state: &AppState, source_id: Uuid) -> Result<JobSummary, AppError> {
    let started_at = Utc::now();
    let start_instant = std::time::Instant::now();

    let source = external_source::Entity::find_by_id(source_id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    let targets = external_source_vault_target::Entity::find()
        .filter(external_source_vault_target::Column::ExternalSourceId.eq(source_id))
        .find_also_related(vault_endpoint::Entity)
        .all(&state.db)
        .await?;

    let summary = execute(state, &source, &targets).await;

    super::write_sync_log(
        &state.db,
        "EXTERNAL_FEED",
        source_id,
        &source.name,
        &summary,
        started_at,
    )
    .await?;

    let mut active: external_source::ActiveModel = source.into();
    active.last_run_at = Set(Some(started_at));
    active.update(&state.db).await?;

    let _ = start_instant; // duration is captured inside `execute`
    Ok(summary)
}

async fn execute(
    state: &AppState,
    source: &external_source::Model,
    targets: &[(external_source_vault_target::Model, Option<vault_endpoint::Model>)],
) -> JobSummary {
    let start = std::time::Instant::now();

    let fetch_options = FetchOptions::from_config(source.parser_config_json.as_deref());
    let build_request = |http: &reqwest::Client| {
        let mut request = http.get(&source.source_url);
        if let Some(user_agent) = &fetch_options.user_agent {
            request = request.header(reqwest::header::USER_AGENT, user_agent);
        }
        for (name, value) in &fetch_options.headers {
            request = request.header(name, value);
        }
        request
    };

    // Transient upstream errors (429/502/503/504) are retried with backoff — the same policy
    // `client.rs` applies to vault calls, extended here since an external feed host is just as
    // likely to be rate-limiting or briefly overloaded. A non-transient error status fails the job
    // immediately, same as before.
    let max_retries = crate::config::outbound_max_retries();
    let mut attempt: u32 = 0;
    let response = loop {
        match build_request(&state.http).send().await {
            Ok(r) if r.status().is_success() => break r,
            Ok(r) if crate::retry::is_transient_status(r.status().as_u16()) && attempt < max_retries => {
                attempt += 1;
                let delay = crate::retry::backoff_with_jitter(attempt);
                tracing::warn!(
                    "fetching '{}' returned {}; retrying in {delay:?} (attempt {attempt}/{max_retries})",
                    source.source_url,
                    r.status()
                );
                tokio::time::sleep(delay).await;
            }
            Ok(r) => {
                return JobSummary {
                    status: "FAILED",
                    items_processed: 0,
                    chunks_sent: 0,
                    duration_ms: start.elapsed().as_millis() as i32,
                    error_message: Some(format!("fetch returned status {}", r.status())),
                };
            }
            Err(e) => {
                return JobSummary {
                    status: "FAILED",
                    items_processed: 0,
                    chunks_sent: 0,
                    duration_ms: start.elapsed().as_millis() as i32,
                    error_message: Some(format!("fetch failed: {e}")),
                };
            }
        }
    };
    let body = match response.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return JobSummary {
                status: "FAILED",
                items_processed: 0,
                chunks_sent: 0,
                duration_ms: start.elapsed().as_millis() as i32,
                error_message: Some(format!("failed to read response body: {e}")),
            };
        }
    };

    // Transparent to every parser type: a feed distributed as a `.zip` (e.g. StopForumSpam's
    // downloads) is decompressed here, before any parser ever sees it.
    let body = match super::decompress::decompress_if_zip(&body) {
        Ok(b) => b,
        Err(e) => {
            return JobSummary {
                status: "FAILED",
                items_processed: 0,
                chunks_sent: 0,
                duration_ms: start.elapsed().as_millis() as i32,
                error_message: Some(e.to_string()),
            };
        }
    };

    let effective_config = source.parser_config_json.clone();

    let parser = match parsers::for_type(&source.parser_type) {
        Ok(p) => p,
        Err(e) => {
            return JobSummary {
                status: "FAILED",
                items_processed: 0,
                chunks_sent: 0,
                duration_ms: start.elapsed().as_millis() as i32,
                error_message: Some(e.to_string()),
            };
        }
    };
    let raw_records = match parser.parse(&body, effective_config.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            return JobSummary {
                status: "FAILED",
                items_processed: 0,
                chunks_sent: 0,
                duration_ms: start.elapsed().as_millis() as i32,
                error_message: Some(e.to_string()),
            };
        }
    };

    let mut seen = HashSet::new();
    let deduped: Vec<String> = raw_records.into_iter().filter(|r| seen.insert(r.clone())).collect();
    let items_processed = deduped.len();

    let chunks = chunk_records(deduped, MAX_BATCH_SIZE);
    let mut chunks_sent = 0i32;
    let mut errors: Vec<String> = Vec::new();
    let mut any_success = targets.is_empty();

    // `source.mode` is validated to be "upsert"/"full_replace" at the API boundary
    // (api/sources.rs), so a value that fails to parse here can only mean the row predates that
    // validation or was edited directly in the database — fail closed to the non-destructive
    // choice rather than silently defaulting to full_replace's delete-anything-unmentioned
    // behavior on a misread.
    let base_mode = BatchMode::parse(&source.mode).unwrap_or_else(|| {
        tracing::warn!("external_sources.mode '{}' is not a recognised value; treating as upsert", source.mode);
        BatchMode::Upsert
    });

    for (target, vault) in targets {
        let Some(vault) = vault else {
            errors.push(format!("target vault {} no longer exists", target.vault_endpoint_id));
            continue;
        };
        let group_name = target
            .target_group_name
            .clone()
            .unwrap_or_else(|| source.target_group_name.clone());

        let mut target_ok = true;
        for (chunk_index, chunk) in chunks.iter().enumerate() {
            let batch: Vec<BatchRecordInput> = chunk
                .iter()
                .map(|addr| BatchRecordInput {
                    target_address: addr.clone(),
                    cause: None,
                    is_deleted: None,
                    created_at: None,
                    updated_at: None,
                    last_seen_at: None,
                    deleted_at: None,
                })
                .collect();
            // Only chunk 0 of *this target's* sequence may carry `full_replace` — see
            // `jobs::mode_for_chunk_index`'s doc comment for why every later chunk must downgrade
            // to `upsert` regardless of the source's configured mode.
            let chunk_mode = super::mode_for_chunk_index(base_mode, chunk_index);
            match client::post_batch(&state.http, &state.cipher, vault, &group_name, &batch, chunk_mode).await {
                Ok(_) => chunks_sent += 1,
                Err(e) => {
                    target_ok = false;
                    errors.push(format!("vault '{}': {e}", vault.name));
                    break;
                }
            }
        }
        if target_ok {
            any_success = true;
        }
    }

    let status = if errors.is_empty() {
        if items_processed == 0 {
            // A syntactically successful fetch and parse that yields *zero* records is not
            // trustworthy the way "zero new records" is for a delta sync (jobs::vault_sync) — this
            // pipeline fetches the feed's full current content on every run, not an incremental
            // diff, so a real threat-intelligence list going from N entries to genuinely 0 between
            // runs is itself an anomaly. It is also exactly what a captive portal, an
            // authentication redirect a client silently follows, or a CDN/WAF error page served
            // with `200 OK` and an HTML body looks like to `REGEX_LINE`: no parse *error* (HTML is
            // valid UTF-8 text), just no IP-shaped tokens on any line. Flagging this as PARTIAL
            // rather than SUCCESS keeps it visible in `sync_logs` for an operator to notice,
            // without treating a fetch/parse that technically completed as a hard FAILED.
            "PARTIAL"
        } else {
            "SUCCESS"
        }
    } else if any_success {
        "PARTIAL"
    } else {
        "FAILED"
    };
    let error_message = if items_processed == 0 && errors.is_empty() {
        Some(
            "feed returned zero parseable entries; the source may be misconfigured, rate-limited, \
             or returning an error/captive-portal page instead of its real content"
                .to_owned(),
        )
    } else if errors.is_empty() {
        None
    } else {
        Some(errors.join("; "))
    };

    JobSummary {
        status,
        items_processed: items_processed as i32,
        chunks_sent,
        duration_ms: start.elapsed().as_millis() as i32,
        error_message,
    }
}

/// Two well-known generic keys read directly off `parser_config_json` by the ingestion job
/// itself (`user_agent`, `headers`), independent of whatever parser-specific keys the chosen
/// parser expects — parser implementations extract only their own named fields, so the same JSON
/// blob can carry both without conflict.
#[derive(Default)]
struct FetchOptions {
    user_agent: Option<String>,
    headers: Vec<(String, String)>,
}

impl FetchOptions {
    fn from_config(config: Option<&str>) -> Self {
        let Some(config) = config else {
            return Self::default();
        };
        let Ok(Value::Object(map)) = serde_json::from_str::<Value>(config) else {
            return Self::default();
        };
        let user_agent = map.get("user_agent").and_then(Value::as_str).map(str::to_owned);
        let headers = map
            .get("headers")
            .and_then(Value::as_object)
            .map(|h| {
                h.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        Self { user_agent, headers }
    }
}
