//! `JSON_PATH` parser: structured JSON feeds (AbuseIPDB API responses, SANS ISC's
//! `?json`-suffixed threat lists, pfSense exports, Spamhaus DROP lists).
//!
//! Configured via `parser_config_json`:
//! ```json
//! {"array_path": "data", "target_address": "$.ipAddress", "last_seen_at": "$.lastReportedAt"}
//! ```
//! `array_path` is the existing dotted-string path to the array of items (e.g. `"data.items"`,
//! omitted for a bare top-level array or when `jsonl` is set) — unchanged from before. The two
//! per-item field selectors are new: `target_address` (alias `ip`) is **mandatory** and must
//! start with `$.` followed by one or more dot-separated field names walked against each array
//! element (`$.ipAddress` → `item.ipAddress`; `$.meta.ip` → `item.meta.ip`); `last_seen_at` (alias
//! `timestamp`) is optional, in the same `$.`-prefixed shape, and — together with a feed's own
//! `max_age_days` column — lets `jobs::external_ingestion` discard stale entries before
//! aggregating a destination group's feeds. A value under `last_seen_at`'s selector is parsed as
//! RFC 3339 first, falling back to a bare `YYYY-MM-DD` date (SANS ISC's `erratasec` threat list
//! reports `lastseen` this way); anything else parses to `None` for that record (kept, just
//! without an age to filter on) rather than failing the whole feed.
//!
//! # Why `$.`, and how it relates to (and differs from) `simply_ip_vault`'s own `$name` convention
//!
//! Audited before choosing this: `simply_ip_vault`'s webhook dispatch has its own `$name`
//! substitution language (`$target_address`, `$cause`, `$group_name`, `$action`/`$event`,
//! `$group_id`, `$timestamp` — bare names, no dot, no braces, no escape mechanism), but it is an
//! **output**-side template substitution over a fixed, known set of event fields — there is
//! nothing there to borrow for **input**-side field *selection* into an arbitrary third-party
//! JSON document's own, unknown shape, which is what this parser configuration actually needs to
//! express. The `$.` prefix used here is instead the ordinary JSONPath "root object" convention
//! (a `$` anchors the document root, `.field` walks into it) — a different, unrelated `$` idiom
//! chosen because it recognizably marks "this is a field-selector expression", not because it was
//! copied from the peer.
//!
//! Set `"jsonl": true` for newline-delimited JSON feeds (one JSON object per line, no enclosing
//! array) — this is Spamhaus DROP's actual wire format (`drop_v6.json` is **not** a JSON array; it
//! is one object per line, plus a trailing `{"type":"metadata", ...}` footer line with no
//! `target_address` match, which is silently skipped the same way any other item missing the
//! selected field is).
//!
//! Non-`jsonl` bodies are handed to `serde_json::from_slice` directly, which already validates
//! UTF-8 as an ordinary part of JSON syntax and returns a clean `Err` (never a panic) on invalid
//! bytes — no separate lossy-decoding step is needed there. `jsonl` mode decodes each line with
//! [`String::from_utf8_lossy`] instead (see `parse_jsonl`), since a single non-UTF-8 *line* among
//! otherwise well-formed ones should only fail that line, the same way any other malformed line
//! already does — not the whole feed.

use chrono::{DateTime, NaiveDate, Utc};
use serde_json::Value;

use super::{normalize_ip_or_cidr, FeedParser, ParseError, ParsedRecord};

/// A `$.`-prefixed field selector, already split into its dot-separated segments (`$.meta.ip` →
/// `["meta", "ip"]`).
type Selector = Vec<String>;

fn parse_selector(raw: &str) -> Result<Selector, String> {
    let rest = raw
        .strip_prefix("$.")
        .ok_or_else(|| format!("selector '{raw}' must start with '$.' (e.g. \"$.ipAddress\")"))?;
    if rest.is_empty() {
        return Err(format!("selector '{raw}' must name at least one field after '$.'"));
    }
    Ok(rest.split('.').map(str::to_owned).collect())
}

fn walk_selector<'a>(item: &'a Value, selector: &[String]) -> Option<&'a Value> {
    let mut current = item;
    for segment in selector {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Parses a value string as `last_seen_at`: RFC 3339 first, then a bare `YYYY-MM-DD` date at
/// midnight UTC (SANS ISC's `erratasec` list's own shape). Returns `None` for anything else,
/// rather than an error — a record with an unparseable or absent timestamp is still kept, simply
/// without an age `jobs::external_ingestion` can filter on.
fn parse_last_seen_at(raw: &str) -> Option<DateTime<Utc>> {
    if let Ok(parsed) = DateTime::parse_from_rfc3339(raw) {
        return Some(parsed.with_timezone(&Utc));
    }
    NaiveDate::parse_from_str(raw, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| dt.and_utc())
}

struct JsonPathConfig {
    array_path: Option<String>,
    target_address: Selector,
    last_seen_at: Option<Selector>,
    jsonl: bool,
}

impl JsonPathConfig {
    fn parse(config_str: &str) -> Result<Self, String> {
        let value: Value =
            serde_json::from_str(config_str).map_err(|e| format!("invalid parser_config_json: {e}"))?;
        let obj = value.as_object().ok_or_else(|| "parser_config_json must be a JSON object".to_owned())?;

        let array_path = obj.get("array_path").and_then(Value::as_str).map(str::to_owned);
        let jsonl = obj.get("jsonl").and_then(Value::as_bool).unwrap_or(false);

        let target_address_raw = obj
            .get("target_address")
            .and_then(Value::as_str)
            .or_else(|| obj.get("ip").and_then(Value::as_str))
            .ok_or_else(|| {
                "parser_config_json must set \"target_address\" (or its alias \"ip\") to a '$.'-prefixed \
                 field selector, e.g. \"$.ipAddress\""
                    .to_owned()
            })?;
        let target_address = parse_selector(target_address_raw)?;

        let last_seen_at = obj
            .get("last_seen_at")
            .and_then(Value::as_str)
            .or_else(|| obj.get("timestamp").and_then(Value::as_str))
            .map(parse_selector)
            .transpose()?;

        Ok(Self { array_path, target_address, last_seen_at, jsonl })
    }
}

/// Validates `config` (an `external_sources.parser_config_json` value) as a `JSON_PATH`
/// configuration, without needing a fetched feed body — called from the API boundary
/// (`api/sources.rs`'s feed create/update handlers) so a missing/malformed `target_address`
/// selector is rejected with `400` at save time, not discovered later as a `FAILED` sync log
/// entry. The parser itself re-validates at parse time regardless (defense in depth, the same
/// two-layer pattern `scheduler::validate_cron_expression` already uses for `cron_schedule`).
pub fn validate_config(config: Option<&str>) -> Result<(), String> {
    let config_str =
        config.ok_or_else(|| "JSON_PATH requires parser_config_json with a target_address selector".to_owned())?;
    JsonPathConfig::parse(config_str).map(|_| ())
}

/// Parses a JSON feed body, either by walking a dotted path to an array and pulling the configured
/// selectors per element, or — in `jsonl` mode — by parsing each non-empty line as its own JSON
/// object.
pub struct JsonPathParser;

impl FeedParser for JsonPathParser {
    fn parse(&self, raw: &[u8], config: Option<&str>) -> Result<Vec<ParsedRecord>, ParseError> {
        let config_str = config.ok_or_else(|| {
            ParseError::InvalidConfig("JSON_PATH requires parser_config_json with a target_address selector".to_owned())
        })?;
        let config = JsonPathConfig::parse(config_str).map_err(ParseError::InvalidConfig)?;

        if config.jsonl {
            return parse_jsonl(raw, &config);
        }

        let root: Value = serde_json::from_slice(raw).map_err(|e| ParseError::MalformedBody(e.to_string()))?;

        let array = match &config.array_path {
            Some(path) => walk_dotted_path(&root, path)
                .ok_or_else(|| ParseError::InvalidConfig(format!("array_path '{path}' not found in feed body")))?,
            None => &root,
        };
        let items = array
            .as_array()
            .ok_or_else(|| ParseError::InvalidConfig("array_path did not resolve to a JSON array".to_owned()))?;

        Ok(extract_records(items.iter(), &config))
    }
}

/// Parses newline-delimited JSON: one object per non-empty line. A line that fails to parse as
/// JSON, or parses but lacks the `target_address` selector's field, is skipped rather than
/// aborting the whole feed — this is what lets Spamhaus DROP's trailing
/// `{"type":"metadata", ...}` footer line pass through harmlessly instead of failing the entire
/// ingestion. Decoded with [`String::from_utf8_lossy`] for the same reason `regex_line.rs` is: a
/// single non-UTF-8 line (see this module's doc comment) becomes `U+FFFD` replacement characters,
/// which then simply fails that one line's JSON parse (or its selector lookup) and gets skipped
/// exactly like any other malformed line already is — never a hard failure for the whole body
/// over one bad line.
fn parse_jsonl(raw: &[u8], config: &JsonPathConfig) -> Result<Vec<ParsedRecord>, ParseError> {
    let text = String::from_utf8_lossy(raw);
    let values = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok());
    Ok(extract_records(values, config))
}

fn extract_records<'a, I, T>(items: I, config: &JsonPathConfig) -> Vec<ParsedRecord>
where
    I: Iterator<Item = T>,
    T: std::borrow::Borrow<Value> + 'a,
{
    let mut results = Vec::new();
    for item in items {
        let item = item.borrow();
        let Some(candidate) = walk_selector(item, &config.target_address).and_then(Value::as_str) else {
            continue;
        };
        let Some(address) = normalize_ip_or_cidr(candidate) else {
            continue;
        };
        let last_seen_at = config
            .last_seen_at
            .as_ref()
            .and_then(|selector| walk_selector(item, selector))
            .and_then(Value::as_str)
            .and_then(parse_last_seen_at);
        results.push(ParsedRecord { address, last_seen_at });
    }
    results
}

fn walk_dotted_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = root;
    for segment in path.split('.').filter(|s| !s.is_empty()) {
        current = current.get(segment)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs(parser: &JsonPathParser, body: &[u8], config: &str) -> Vec<String> {
        parser.parse(body, Some(config)).expect("parse").into_iter().map(|r| r.address).collect()
    }

    #[test]
    fn parses_nested_array_path() {
        let parser = JsonPathParser;
        let body = br#"{"data":{"items":[{"ipAddress":"1.2.3.4"},{"ipAddress":"5.6.7.8"}]}}"#;
        let config = r#"{"array_path":"data.items","target_address":"$.ipAddress"}"#;
        assert_eq!(addrs(&parser, body, config), vec!["1.2.3.4".to_owned(), "5.6.7.8".to_owned()]);
    }

    #[test]
    fn parses_bare_top_level_array() {
        let parser = JsonPathParser;
        let body = br#"[{"ip":"9.9.9.9"}]"#;
        let config = r#"{"target_address":"$.ip"}"#;
        assert_eq!(addrs(&parser, body, config), vec!["9.9.9.9".to_owned()]);
    }

    #[test]
    fn the_ip_alias_for_target_address_is_accepted() {
        let parser = JsonPathParser;
        let body = br#"[{"addr":"9.9.9.9"}]"#;
        let config = r#"{"ip":"$.addr"}"#;
        assert_eq!(addrs(&parser, body, config), vec!["9.9.9.9".to_owned()]);
    }

    #[test]
    fn skips_items_missing_the_target_address_field() {
        let parser = JsonPathParser;
        let body = br#"[{"other":"x"},{"ip":"1.1.1.1"}]"#;
        let config = r#"{"target_address":"$.ip"}"#;
        assert_eq!(addrs(&parser, body, config), vec!["1.1.1.1".to_owned()]);
    }

    #[test]
    fn errors_without_config() {
        let parser = JsonPathParser;
        assert!(parser.parse(b"[]", None).is_err());
    }

    #[test]
    fn errors_when_array_path_missing() {
        let parser = JsonPathParser;
        let body = br#"{"other":true}"#;
        let config = r#"{"array_path":"data.items","target_address":"$.ip"}"#;
        assert!(parser.parse(body, Some(config)).is_err());
    }

    #[test]
    fn errors_on_malformed_json_body() {
        let parser = JsonPathParser;
        let config = r#"{"target_address":"$.ip"}"#;
        assert!(parser.parse(b"not json", Some(config)).is_err());
    }

    #[test]
    fn errors_when_target_address_is_missing_entirely() {
        let parser = JsonPathParser;
        let config = r#"{"array_path":"data"}"#;
        let err = parser.parse(br#"{"data":[]}"#, Some(config)).expect_err("must reject");
        assert!(matches!(err, ParseError::InvalidConfig(_)));
    }

    #[test]
    fn errors_when_target_address_lacks_the_dollar_dot_prefix() {
        let parser = JsonPathParser;
        let config = r#"{"target_address":"ipAddress"}"#;
        let err = parser.parse(br#"[{"ipAddress":"1.2.3.4"}]"#, Some(config)).expect_err("must reject");
        assert!(matches!(err, ParseError::InvalidConfig(_)));
    }

    #[test]
    fn validate_config_accepts_a_well_formed_configuration() {
        assert!(validate_config(Some(r#"{"array_path":"data","target_address":"$.ipAddress"}"#)).is_ok());
    }

    #[test]
    fn validate_config_rejects_a_missing_target_address() {
        assert!(validate_config(Some(r#"{"array_path":"data"}"#)).is_err());
    }

    #[test]
    fn validate_config_rejects_no_config_at_all() {
        assert!(validate_config(None).is_err());
    }

    /// Task 4: an optional `last_seen_at` selector, RFC 3339-shaped — the real AbuseIPDB
    /// `lastReportedAt` format.
    #[test]
    fn last_seen_at_selector_parses_rfc3339_timestamps() {
        let parser = JsonPathParser;
        let body = br#"[{"ipAddress":"1.2.3.4","lastReportedAt":"2026-09-26T15:17:01+00:00"}]"#;
        let config = r#"{"target_address":"$.ipAddress","last_seen_at":"$.lastReportedAt"}"#;
        let out = parser.parse(body, Some(config)).expect("parse");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].last_seen_at, Some("2026-09-26T15:17:01+00:00".parse().unwrap()));
    }

    /// Task 5: the real SANS ISC `erratasec` threat list's own `lastseen` shape is a bare
    /// `YYYY-MM-DD` date, not RFC 3339 — verified against a live fetch during development
    /// (`https://isc.sans.edu/api/threatlist/erratasec?json`).
    #[test]
    fn last_seen_at_selector_also_parses_a_bare_date_the_sans_isc_erratasec_list_uses() {
        let parser = JsonPathParser;
        let body = br#"[{"ipv4":"209.126.230.71","lastseen":"2026-09-28"}]"#;
        let config = r#"{"target_address":"$.ipv4","timestamp":"$.lastseen"}"#;
        let out = parser.parse(body, Some(config)).expect("parse");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].last_seen_at, Some("2026-09-28T00:00:00Z".parse().unwrap()));
    }

    #[test]
    fn an_unparseable_last_seen_at_value_is_none_not_a_failure() {
        let parser = JsonPathParser;
        let body = br#"[{"ip":"1.2.3.4","seen":"not-a-date"}]"#;
        let config = r#"{"target_address":"$.ip","last_seen_at":"$.seen"}"#;
        let out = parser.parse(body, Some(config)).expect("parse");
        assert_eq!(out.len(), 1, "the record itself is kept even though its timestamp didn't parse");
        assert_eq!(out[0].last_seen_at, None);
    }

    /// A nested selector (`$.meta.ip`) walks more than one segment, matching `array_path`'s own
    /// existing dotted-path convention.
    #[test]
    fn a_nested_selector_walks_multiple_segments() {
        let parser = JsonPathParser;
        let body = br#"[{"meta":{"ip":"1.2.3.4"}}]"#;
        let config = r#"{"target_address":"$.meta.ip"}"#;
        assert_eq!(addrs(&parser, body, config), vec!["1.2.3.4".to_owned()]);
    }

    #[test]
    fn jsonl_mode_parses_spamhaus_drop_v6_shape() {
        let parser = JsonPathParser;
        let body = concat!(
            "{\"cidr\":\"2001:678:254::/48\",\"sblid\":\"SBL697648\",\"rir\":\"ripencc\"}\n",
            "{\"cidr\":\"2001:678:6c0::/48\",\"sblid\":\"SBL624855\",\"rir\":\"ripencc\"}\n",
            "{\"type\":\"metadata\",\"timestamp\":1786614242,\"records\":2}\n",
        );
        let config = r#"{"jsonl":true,"target_address":"$.cidr"}"#;
        assert_eq!(
            addrs(&parser, body.as_bytes(), config),
            vec!["2001:678:254::/48".to_owned(), "2001:678:6c0::/48".to_owned()]
        );
    }

    #[test]
    fn jsonl_mode_skips_unparseable_lines_without_failing() {
        let parser = JsonPathParser;
        let body = "{\"cidr\":\"2001:db8::/32\"}\nnot json at all\n{\"cidr\":\"2001:db9::/32\"}\n";
        let config = r#"{"jsonl":true,"target_address":"$.cidr"}"#;
        assert_eq!(
            addrs(&parser, body.as_bytes(), config),
            vec!["2001:db8::/32".to_owned(), "2001:db9::/32".to_owned()]
        );
    }

    /// Task 3 (historical): a raw binary/non-UTF-8 body is not valid JSON either way, so
    /// `JSON_PATH`'s non-`jsonl` path (`serde_json::from_slice`, which validates UTF-8 as part of
    /// JSON syntax) must still surface this as a clean `Err`, never a panic.
    #[test]
    fn raw_binary_body_is_a_clean_parse_error_not_a_panic() {
        let parser = JsonPathParser;
        let config = r#"{"target_address":"$.ip"}"#;
        let body: &[u8] = &[0x00, 0xff, 0xfe, 0x80, 0x81, 0x00, 0x00, 0xc0, 0xc1];
        assert!(parser.parse(body, Some(config)).is_err(), "raw binary is not valid JSON and must be rejected cleanly, not panic");
    }

    /// Task 3 (historical), `jsonl` mode specifically: a non-UTF-8 line among otherwise
    /// well-formed JSONL lines must not fail the whole body.
    #[test]
    fn jsonl_mode_skips_a_non_utf8_line_without_failing_the_whole_body() {
        let parser = JsonPathParser;
        let mut body = b"{\"cidr\":\"2001:db8::/32\"}\n".to_vec();
        body.extend_from_slice(&[0xff, 0xfe, 0x00]); // invalid UTF-8, not valid JSON either way
        body.extend_from_slice(b"\n{\"cidr\":\"2001:db9::/32\"}\n");
        let config = r#"{"jsonl":true,"target_address":"$.cidr"}"#;
        assert_eq!(
            addrs(&parser, &body, config),
            vec!["2001:db8::/32".to_owned(), "2001:db9::/32".to_owned()]
        );
    }
}
