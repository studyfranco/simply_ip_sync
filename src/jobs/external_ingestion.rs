//! External threat feed ingestion pipeline: a `destination_groups` row owns 1-to-N child feeds
//! (`external_sources`), fetched **concurrently**, aggregated into one deduplicated set, sanitized
//! (bogon filter, temporal filter), chunked, and pushed to every configured target vault as a
//! single batch sequence.

use std::collections::HashSet;

use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde_json::Value;
use uuid::Uuid;

use super::{chunk_records, JobSummary, MAX_BATCH_SIZE};
use crate::client::{self, BatchMode, BatchRecordInput};
use crate::entities::{destination_group, destination_group_vault_target, external_source, vault_endpoint};
use crate::error::AppError;
use crate::parsers::{self, ParsedRecord};
use crate::state::AppState;

/// Runs one execution of destination group `group_id`: fetches every child feed concurrently,
/// aggregates the results into one deduplicated set, sanitizes and pushes it to every configured
/// target vault. Always writes one `sync_logs` row and updates `destination_groups.last_run_at`,
/// regardless of outcome — "last execution" means the group ran, not that it ran successfully.
pub async fn run(state: &AppState, group_id: Uuid) -> Result<JobSummary, AppError> {
    let started_at = Utc::now();

    let group = destination_group::Entity::find_by_id(group_id).one(&state.db).await?.ok_or(AppError::NotFound)?;

    let feeds = external_source::Entity::find()
        .filter(external_source::Column::DestinationGroupId.eq(group_id))
        .all(&state.db)
        .await?;

    let targets = destination_group_vault_target::Entity::find()
        .filter(destination_group_vault_target::Column::DestinationGroupId.eq(group_id))
        .find_also_related(vault_endpoint::Entity)
        .all(&state.db)
        .await?;

    let summary = execute(state, &group, &feeds, &targets).await;

    super::write_sync_log(&state.db, "EXTERNAL_FEED", group_id, &group.name, &summary, started_at).await?;

    let mut active: destination_group::ActiveModel = group.into();
    active.last_run_at = Set(Some(started_at));
    active.update(&state.db).await?;

    Ok(summary)
}

/// Fetches `source_url` (with `parser_config_json`'s `headers`/`user_agent`, if any, applied —
/// see [`FetchOptions`]) and runs it through the `parser_type` parser, returning the raw
/// (non-deduplicated) extracted records. This is the entire "does this feed actually work"
/// question — fetch, decompress, parse — with no push to any vault, which is exactly the subset
/// [`execute`] (per child feed) and the WebUI's "Test Fetch" preview
/// (`api::test_fetch_external_source`) both need; factored out once so there is exactly one
/// implementation of the fetch/decompress/parse pipeline, not two that could quietly drift apart.
///
/// Errors are returned as a formatted `String` rather than a typed error, matching how every
/// caller already needs to render them.
pub(crate) async fn fetch_and_parse(
    http: &reqwest::Client,
    source_url: &str,
    parser_type: &str,
    parser_config_json: Option<&str>,
) -> Result<Vec<ParsedRecord>, String> {
    let fetch_options = FetchOptions::from_config(parser_config_json);
    let build_request = |http: &reqwest::Client| {
        let mut request = http.get(source_url);
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
    // likely to be rate-limiting or briefly overloaded. A non-transient error status fails
    // immediately, same as before.
    let max_retries = crate::config::outbound_max_retries();
    let mut attempt: u32 = 0;
    let response = loop {
        match build_request(http).send().await {
            Ok(r) if r.status().is_success() => break r,
            Ok(r) if crate::retry::is_transient_status(r.status().as_u16()) && attempt < max_retries => {
                attempt += 1;
                let delay = crate::retry::backoff_with_jitter(attempt);
                tracing::warn!(
                    "fetching '{source_url}' returned {}; retrying in {delay:?} (attempt {attempt}/{max_retries})",
                    r.status()
                );
                tokio::time::sleep(delay).await;
            }
            Ok(r) => return Err(format!("fetch returned status {}", r.status())),
            Err(e) => return Err(format!("fetch failed: {e}")),
        }
    };
    // Streamed with a running byte-count cap, not `response.bytes()` — see
    // `decompress::read_capped_body`'s doc comment for why a single-shot read would already have
    // fully decompressed (and buffered) an arbitrarily large `Content-Encoding` payload by the
    // time anything got a chance to check its length.
    let max_decompressed_bytes = crate::config::max_decompressed_bytes();
    let body = super::decompress::read_capped_body(response, max_decompressed_bytes)
        .await
        .map_err(|e| format!("failed to read response body: {e}"))?;

    // Transparent to every parser type: a feed distributed as a `.zip` (e.g. StopForumSpam's
    // downloads) is decompressed here, before any parser ever sees it. Same byte ceiling applied
    // again — independently — since a ZIP archive's internal members can expand far beyond the
    // (already-capped) compressed archive bytes that got us here.
    let body =
        super::decompress::decompress_if_zip(&body, max_decompressed_bytes).map_err(|e| e.to_string())?;

    let parser = parsers::for_type(parser_type).map_err(|e| e.to_string())?;
    parser.parse(&body, parser_config_json).map_err(|e| e.to_string())
}

/// The outcome of fetching+parsing one child feed, kept per-feed until the aggregation step below
/// so a single bad feed's error can be reported without discarding every other feed's results.
struct FeedResult {
    feed_name: String,
    records: Result<Vec<ParsedRecord>, String>,
}

/// Fetches every feed in `feeds` concurrently (`tokio::spawn` + `futures::future::join_all`, not
/// sequentially) — the whole point of grouping several feeds under one destination group is that
/// their fetch latency overlaps instead of stacking, and one feed's slow host doesn't gate every
/// other feed's already-available response.
async fn fetch_all_feeds_concurrently(state: &AppState, feeds: &[external_source::Model]) -> Vec<FeedResult> {
    let handles: Vec<_> = feeds
        .iter()
        .map(|feed| {
            let http = state.http.clone();
            let feed_name = feed.name.clone();
            let source_url = feed.source_url.clone();
            let parser_type = feed.parser_type.clone();
            let parser_config_json = feed.parser_config_json.clone();
            tokio::spawn(async move {
                let records = fetch_and_parse(&http, &source_url, &parser_type, parser_config_json.as_deref()).await;
                FeedResult { feed_name, records }
            })
        })
        .collect();

    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        match handle.await {
            Ok(result) => results.push(result),
            // A `JoinError` here means the spawned task itself panicked, not that the fetch
            // failed cleanly — surfaced as a feed-level error like any other, rather than
            // panicking the whole group's execution over one feed's internal panic.
            Err(join_err) => results.push(FeedResult {
                feed_name: "(unknown feed)".to_owned(),
                records: Err(format!("feed fetch task panicked: {join_err}")),
            }),
        }
    }
    results
}

/// Applies one feed's own `max_age_days` (if set) against its own records' `last_seen_at` (if the
/// parser configuration supplied one) — a record with no `last_seen_at` at all is always kept
/// (nothing to judge staleness by), and a record whose `last_seen_at` predates
/// `now - max_age_days` is dropped.
fn apply_temporal_filter(records: Vec<ParsedRecord>, max_age_days: Option<i32>) -> Vec<ParsedRecord> {
    let Some(max_age_days) = max_age_days else {
        return records;
    };
    let cutoff = Utc::now() - chrono::Duration::days(i64::from(max_age_days));
    records
        .into_iter()
        .filter(|r| r.last_seen_at.is_none_or(|last_seen| last_seen >= cutoff))
        .collect()
}

async fn execute(
    state: &AppState,
    group: &destination_group::Model,
    feeds: &[external_source::Model],
    targets: &[(destination_group_vault_target::Model, Option<vault_endpoint::Model>)],
) -> JobSummary {
    let start = std::time::Instant::now();

    let feed_results = fetch_all_feeds_concurrently(state, feeds).await;

    // Per feed, in order: apply that feed's own temporal filter (`max_age_days`), then that feed's
    // own *effective* bogon policy (its own `skip_bogon_filtering` override if set, else the
    // group's) — both **before** merging into the shared aggregated pool. Doing this per-feed
    // rather than once on the merged set is what lets a feed explicitly marked
    // "clean/private-capable" keep its private addresses even when a sibling feed in the same
    // group is bogon-filtered, and vice versa; by the time records are merged, "which feed did
    // this come from" would otherwise be lost. Exact deduplication only (a `HashSet<String>` on
    // the normalized address) — never supernetting/aggregating adjacent CIDRs into a larger block.
    let mut seen = HashSet::new();
    let mut aggregated: Vec<String> = Vec::new();
    let mut feed_errors: Vec<String> = Vec::new();
    let mut bogons_removed = 0usize;
    for FeedResult { feed_name, records } in feed_results {
        match records {
            Ok(records) => {
                let feed = feeds.iter().find(|f| f.name == feed_name);
                let max_age_days = feed.and_then(|f| f.max_age_days);
                let skip_bogon_filtering = feed.and_then(|f| f.skip_bogon_filtering).unwrap_or(group.skip_bogon_filtering);

                let temporally_filtered = apply_temporal_filter(records, max_age_days);
                let addresses: Vec<String> = temporally_filtered.into_iter().map(|r| r.address).collect();
                let sanitized = if skip_bogon_filtering {
                    addresses
                } else {
                    let (kept, removed) = crate::bogon::sanitize(addresses);
                    bogons_removed += removed;
                    kept
                };

                for address in sanitized {
                    if seen.insert(address.clone()) {
                        aggregated.push(address);
                    }
                }
            }
            Err(e) => feed_errors.push(format!("feed '{feed_name}': {e}")),
        }
    }

    let feed_error_count = feed_errors.len();
    let items_processed = aggregated.len();
    let chunks = chunk_records(aggregated, MAX_BATCH_SIZE);
    let mut chunks_sent = 0i32;
    let mut errors: Vec<String> = feed_errors;
    let mut any_success = targets.is_empty();

    // `group.mode` is validated to be "upsert"/"full_replace" at the API boundary
    // (api/sources.rs), so a value that fails to parse here can only mean the row predates that
    // validation or was edited directly in the database — fail closed to the non-destructive
    // choice rather than silently defaulting to full_replace's delete-anything-unmentioned
    // behavior on a misread.
    let base_mode = BatchMode::parse(&group.mode).unwrap_or_else(|| {
        tracing::warn!("destination_groups.mode '{}' is not a recognised value; treating as upsert", group.mode);
        BatchMode::Upsert
    });

    for (target, vault) in targets {
        let Some(vault) = vault else {
            errors.push(format!("target vault {} no longer exists", target.vault_endpoint_id));
            continue;
        };
        let group_name = target.target_group_name.clone().unwrap_or_else(|| group.target_group_name.clone());

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
            // to `upsert` regardless of the group's configured mode.
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

    // Every configured feed failing to even fetch/parse is a hard failure regardless of how many
    // targets are configured — `any_success` below defaults to `true` when there are zero targets
    // (nothing to fail *at push time*), which must not be read as "the group's run succeeded" when
    // nothing was actually fetched at all. A single-feed group whose one feed hits a decompression
    // bomb or a parse error is exactly this case, and must report FAILED, not PARTIAL.
    let all_feeds_failed = !feeds.is_empty() && feed_error_count == feeds.len();

    let status = if all_feeds_failed {
        "FAILED"
    } else if errors.is_empty() {
        if items_processed == 0 {
            // A syntactically successful fetch and parse that yields *zero* records is not
            // trustworthy the way "zero new records" is for a delta sync (jobs::vault_sync) — this
            // pipeline fetches every feed's full current content on every run, not an incremental
            // diff, so a real threat-intelligence set going from N entries to genuinely 0 between
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
    let mut error_parts = Vec::new();
    if bogons_removed > 0 {
        error_parts.push(format!("{bogons_removed} bogon/private/reserved address(es) sanitized before push"));
    }
    if items_processed == 0 && errors.is_empty() {
        error_parts.push(
            "every feed in this group returned zero parseable entries; the feed(s) may be misconfigured, \
             rate-limited, or returning an error/captive-portal page instead of real content"
                .to_owned(),
        );
    }
    error_parts.extend(errors);
    let error_message = if error_parts.is_empty() { None } else { Some(error_parts.join("; ")) };

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
