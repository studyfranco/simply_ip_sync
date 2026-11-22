//! External threat feed ingestion pipeline: a `destination_groups` row owns 1-to-N child feeds
//! (`external_sources`), fetched **concurrently**, aggregated into one deduplicated set, sanitized
//! (bogon filter, temporal filter), chunked, and pushed to every configured target vault as a
//! single batch sequence.

use std::collections::HashSet;
use std::net::IpAddr;

use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde_json::Value;
use uuid::Uuid;

use super::JobContext;
use super::{JobSummary, MAX_BATCH_SIZE, chunk_records};
use crate::client::{self, BatchMode, BatchRecordInput};
use crate::entities::{
    destination_group, destination_group_vault_target, external_source, vault_endpoint,
};
use crate::error::AppError;
use crate::parsers::{self, ParsedRecord};

/// Runs one execution of destination group `group_id`: fetches every child feed concurrently,
/// aggregates the results into one deduplicated set, sanitizes and pushes it to every configured
/// target vault. Always writes one `sync_logs` row and updates `destination_groups.last_run_at`,
/// regardless of outcome — "last execution" means the group ran, not that it ran successfully.
///
/// # Errors
///
/// Returns [`AppError::NotFound`] if the group no longer exists or [`AppError::DbError`] on
/// database failures.
pub async fn run(state: &JobContext, group_id: Uuid) -> Result<JobSummary, AppError> {
    let started_at = time::OffsetDateTime::now_utc();

    let group = destination_group::Entity::find_by_id(group_id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

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

    super::write_sync_log(
        &state.db,
        "EXTERNAL_FEED",
        group_id,
        &group.name,
        &summary,
        started_at,
    )
    .await?;

    let mut active: destination_group::ActiveModel = group.into();
    active.last_run_at = Set(Some(started_at));
    active.update(&state.db).await?;

    Ok(summary)
}

pub(crate) fn is_ssrf_blocked_ip(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
                || v4.octets()[0] == 0
                || v4.octets()[..3] == [192, 0, 0]
                || (v4.octets()[0] == 198 && (v4.octets()[1] & 0xfe) == 18)
                || v4.octets()[0] >= 240
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (segs[0] & 0xfe00) == 0xfc00
                || (segs[0] & 0xffc0) == 0xfe80
                || (segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0)
                || (segs[0] == 0x2001 && segs[1] == 0x0db8)
                || (segs[0] == 0x0064
                    && segs[1] == 0xff9b
                    && segs[2] == 0
                    && segs[3] == 0
                    && segs[4] == 0
                    && segs[5] == 0)
        }
    }
}

pub(crate) async fn validate_feed_url(url_str: &str, allow_private: bool) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url_str).map_err(|e| format!("invalid source URL: {e}"))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err("blocked source URL: only http and https schemes are permitted".to_owned());
    }
    let Some(raw_host) = parsed.host_str() else {
        return Err("blocked source URL: missing host".to_owned());
    };
    let host = raw_host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err("blocked source URL: empty host".to_owned());
    }
    if allow_private {
        return Ok(());
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_ssrf_blocked_ip(ip) {
            return Err(format!(
                "blocked source URL: target IP '{ip}' is in a restricted/private range"
            ));
        }
        return Ok(());
    }

    let port = parsed.port_or_known_default().unwrap_or(80);
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("blocked source URL: DNS lookup failed for '{host}': {e}"))?
        .map(|sock| sock.ip())
        .collect();
    if addrs.is_empty() {
        return Err(format!(
            "blocked source URL: '{host}' resolved to no addresses"
        ));
    }
    if let Some(blocked) = addrs.into_iter().find(|ip| is_ssrf_blocked_ip(*ip)) {
        return Err(format!(
            "blocked source URL: '{host}' resolved to restricted/private address '{blocked}'"
        ));
    }
    Ok(())
}

/// Fetches `source_url` (with `parser_config_json`'s `headers`/`user_agent`, if any, applied —
/// see [`FetchOptions`]) and runs it through the `parser_type` parser, returning the raw
/// (non-deduplicated) extracted records. This is the entire "does this feed actually work"
/// question — fetch, decompress, parse — with no push to any vault, which is exactly the subset
/// [`execute`] (per child feed) and the `WebUI`'s "Test Fetch" preview
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
    allow_private_urls: bool,
) -> Result<Vec<ParsedRecord>, String> {
    let source_url = source_url.trim();
    validate_feed_url(source_url, allow_private_urls).await?;
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
            Ok(r)
                if crate::retry::is_transient_status(r.status().as_u16())
                    && attempt < max_retries =>
            {
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
    let body = super::decompress::decompress_if_zip(&body, max_decompressed_bytes)
        .map_err(|e| e.to_string())?;

    let parser = parsers::for_type(parser_type).map_err(|e| e.to_string())?;
    parser
        .parse(&body, parser_config_json)
        .map_err(|e| e.to_string())
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
async fn fetch_all_feeds_concurrently(
    state: &JobContext,
    feeds: &[external_source::Model],
) -> Vec<FeedResult> {
    let allow_private_urls = state.allow_private_ingest_urls;
    let handles: Vec<_> = feeds
        .iter()
        .map(|feed| {
            let http = state.http.clone();
            let feed_name = feed.name.clone();
            let source_url = feed.source_url.clone();
            let parser_type = feed.parser_type.clone();
            let parser_config_json = feed.parser_config_json.clone();
            tokio::spawn(async move {
                let records = fetch_and_parse(
                    &http,
                    &source_url,
                    &parser_type,
                    parser_config_json.as_deref(),
                    allow_private_urls,
                )
                .await;
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
fn apply_temporal_filter(
    records: Vec<ParsedRecord>,
    max_age_days: Option<i32>,
) -> Vec<ParsedRecord> {
    let Some(max_age_days) = max_age_days else {
        return records;
    };
    let cutoff = time::OffsetDateTime::now_utc() - time::Duration::days(i64::from(max_age_days));
    records
        .into_iter()
        .filter(|r| r.last_seen_at.is_none_or(|last_seen| last_seen >= cutoff))
        .collect()
}

struct AggregatedFeeds {
    addresses: Vec<String>,
    feed_errors: Vec<String>,
    bogons_removed: usize,
}

fn aggregate_feed_results(
    feed_results: Vec<FeedResult>,
    feeds: &[external_source::Model],
    default_skip_bogon: bool,
) -> AggregatedFeeds {
    let mut seen = HashSet::new();
    let mut addresses: Vec<String> = Vec::new();
    let mut feed_errors: Vec<String> = Vec::new();
    let mut bogons_removed = 0usize;

    for FeedResult { feed_name, records } in feed_results {
        match records {
            Ok(records) => {
                let feed = feeds.iter().find(|f| f.name == feed_name);
                let max_age_days = feed.and_then(|f| f.max_age_days);
                let skip_bogon_filtering = feed
                    .and_then(|f| f.skip_bogon_filtering)
                    .unwrap_or(default_skip_bogon);

                let temporally_filtered = apply_temporal_filter(records, max_age_days);
                let raw_addresses: Vec<String> =
                    temporally_filtered.into_iter().map(|r| r.address).collect();
                let sanitized = if skip_bogon_filtering {
                    raw_addresses
                } else {
                    let (kept, removed) = crate::bogon::sanitize(raw_addresses);
                    bogons_removed += removed;
                    kept
                };

                for address in sanitized {
                    if seen.insert(address.clone()) {
                        addresses.push(address);
                    }
                }
            }
            Err(e) => feed_errors.push(format!("feed '{feed_name}': {e}")),
        }
    }

    AggregatedFeeds {
        addresses,
        feed_errors,
        bogons_removed,
    }
}

async fn push_aggregated_chunks(
    state: &JobContext,
    group: &destination_group::Model,
    targets: &[(
        destination_group_vault_target::Model,
        Option<vault_endpoint::Model>,
    )],
    chunks: &[Vec<String>],
    base_mode: BatchMode,
) -> (i32, Vec<String>, bool) {
    let mut chunks_sent = 0i32;
    let mut errors = Vec::new();
    let mut any_success = targets.is_empty();

    for (target, vault) in targets {
        let Some(vault) = vault else {
            errors.push(format!(
                "target vault {} no longer exists",
                target.vault_endpoint_id
            ));
            continue;
        };
        let group_name = target
            .target_group_name
            .clone()
            .unwrap_or_else(|| group.target_group_name.clone());

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
            let chunk_mode = super::mode_for_chunk_index(base_mode, chunk_index);
            match client::post_batch(
                &state.http,
                &state.cipher,
                vault,
                &group_name,
                &batch,
                chunk_mode,
            )
            .await
            {
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

    (chunks_sent, errors, any_success)
}

async fn execute(
    state: &JobContext,
    group: &destination_group::Model,
    feeds: &[external_source::Model],
    targets: &[(
        destination_group_vault_target::Model,
        Option<vault_endpoint::Model>,
    )],
) -> JobSummary {
    let start = std::time::Instant::now();
    let feed_results = fetch_all_feeds_concurrently(state, feeds).await;
    let aggregated = aggregate_feed_results(feed_results, feeds, group.skip_bogon_filtering);

    let feed_error_count = aggregated.feed_errors.len();
    let items_processed = aggregated.addresses.len();
    let chunks = chunk_records(aggregated.addresses, MAX_BATCH_SIZE);
    let base_mode = BatchMode::parse(&group.mode).unwrap_or_else(|| {
        tracing::warn!(
            "destination_groups.mode '{}' is not a recognised value; treating as upsert",
            group.mode
        );
        BatchMode::Upsert
    });

    let (chunks_sent, push_errors, any_success) =
        push_aggregated_chunks(state, group, targets, &chunks, base_mode).await;
    let mut errors = aggregated.feed_errors;
    errors.extend(push_errors);

    let all_feeds_failed = !feeds.is_empty() && feed_error_count == feeds.len();
    let status = if all_feeds_failed {
        "FAILED"
    } else if errors.is_empty() {
        if items_processed == 0 {
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
    if aggregated.bogons_removed > 0 {
        error_parts.push(format!(
            "{} bogon/private/reserved address(es) sanitized before push",
            aggregated.bogons_removed
        ));
    }
    if items_processed == 0 && errors.is_empty() {
        error_parts.push(
            "every feed in this group returned zero parseable entries; the feed(s) may be misconfigured, \
             rate-limited, or returning an error/captive-portal page instead of real content"
                .to_owned(),
        );
    }
    error_parts.extend(errors);

    JobSummary {
        status,
        items_processed: i32::try_from(items_processed).unwrap_or(i32::MAX),
        chunks_sent,
        duration_ms: i32::try_from(start.elapsed().as_millis()).unwrap_or(i32::MAX),
        error_message: if error_parts.is_empty() {
            None
        } else {
            Some(error_parts.join("; "))
        },
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
        let user_agent = map
            .get("user_agent")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let headers = map
            .get("headers")
            .and_then(Value::as_object)
            .map(|h| {
                h.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            user_agent,
            headers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn validate_feed_url_blocks_private_loopback_cgnat_and_non_http() {
        for blocked in [
            "http://127.0.0.1/feed.txt",
            "http://10.0.0.5/feed.txt",
            "http://172.16.0.1/feed.txt",
            "http://192.168.1.1/feed.txt",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.64.0.1/feed.txt",
            "http://[::1]/feed.txt",
            "http://[fc00::1]/feed.txt",
            "http://[fe80::1]/feed.txt",
            "http://[::ffff:127.0.0.1]/feed.txt",
            "file:///etc/passwd",
        ] {
            assert!(
                validate_feed_url(blocked, false).await.is_err(),
                "{blocked} must be blocked by SSRF guard"
            );
        }
        assert!(
            validate_feed_url("https://1.1.1.1/feed.txt", false)
                .await
                .is_ok()
        );
        assert!(
            validate_feed_url("http://127.0.0.1/feed.txt", true)
                .await
                .is_ok()
        );
        assert!(validate_feed_url("file:///etc/passwd", true).await.is_err());
    }
}
