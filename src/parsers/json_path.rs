//! `JSON_PATH` parser: structured JSON feeds (AbuseIPDB API responses, pfSense exports, Spamhaus
//! DROP lists). Configured via `parser_config_json`:
//! `{"array_path": "data.items", "ip_field": "ipAddress"}`. `array_path` may be omitted when the
//! feed body is itself a bare top-level array.
//!
//! Set `"jsonl": true` for newline-delimited JSON feeds (one JSON object per line, no enclosing
//! array) — this is Spamhaus DROP's actual wire format (`drop_v6.json` is **not** a JSON array;
//! it is one object per line, plus a trailing `{"type":"metadata", ...}` footer line with no
//! `ip_field`, which is silently skipped the same way any other item missing `ip_field` is).
//!
//! Non-`jsonl` bodies are handed to `serde_json::from_slice` directly, which already validates
//! UTF-8 as an ordinary part of JSON syntax and returns a clean `Err` (never a panic) on invalid
//! bytes — no separate lossy-decoding step is needed there. `jsonl` mode decodes each line with
//! [`String::from_utf8_lossy`] instead (see `parse_jsonl`), since a single non-UTF-8 *line* among
//! otherwise well-formed ones should only fail that line, the same way any other malformed line
//! already does — not the whole feed.

use serde::Deserialize;
use serde_json::Value;

use super::{normalize_ip_or_cidr, FeedParser, ParseError};

#[derive(Deserialize)]
struct JsonPathConfig {
    /// Dotted path to the array of items, e.g. `"data.items"`. Omitted for a bare top-level array
    /// or when `jsonl` is set.
    #[serde(default)]
    array_path: Option<String>,
    /// Key holding the IP/CIDR string on each array element (e.g. `"ipAddress"`, or `"cidr"` for
    /// Spamhaus DROP).
    ip_field: String,
    /// When `true`, the body is newline-delimited JSON (one object per line) rather than a single
    /// JSON document containing an array.
    #[serde(default)]
    jsonl: bool,
}

/// Parses a JSON feed body, either by walking a dotted path to an array and pulling one field per
/// element, or — in `jsonl` mode — by parsing each non-empty line as its own JSON object.
pub struct JsonPathParser;

impl FeedParser for JsonPathParser {
    fn parse(&self, raw: &[u8], config: Option<&str>) -> Result<Vec<String>, ParseError> {
        let config_str = config.ok_or_else(|| {
            ParseError::InvalidConfig("JSON_PATH requires parser_config_json with an ip_field".to_owned())
        })?;
        let config: JsonPathConfig = serde_json::from_str(config_str)
            .map_err(|e| ParseError::InvalidConfig(format!("invalid parser_config_json: {e}")))?;

        if config.jsonl {
            return parse_jsonl(raw, &config.ip_field);
        }

        let root: Value =
            serde_json::from_slice(raw).map_err(|e| ParseError::MalformedBody(e.to_string()))?;

        let array = match &config.array_path {
            Some(path) => walk_path(&root, path)
                .ok_or_else(|| ParseError::InvalidConfig(format!("array_path '{path}' not found in feed body")))?,
            None => &root,
        };
        let items = array
            .as_array()
            .ok_or_else(|| ParseError::InvalidConfig("array_path did not resolve to a JSON array".to_owned()))?;

        Ok(extract_field(items.iter(), &config.ip_field))
    }
}

/// Parses newline-delimited JSON: one object per non-empty line. A line that fails to parse as
/// JSON, or parses but lacks `ip_field`, is skipped rather than aborting the whole feed — this is
/// what lets Spamhaus DROP's trailing `{"type":"metadata", ...}` footer line pass through
/// harmlessly instead of failing the entire ingestion. Decoded with [`String::from_utf8_lossy`]
/// for the same reason `regex_line.rs` is: a single non-UTF-8 line (see this module's doc comment)
/// becomes `U+FFFD` replacement characters, which then simply fails that one line's JSON parse (or
/// its `ip_field` lookup) and gets skipped exactly like any other malformed line already is —
/// never a hard failure for the whole body over one bad line.
fn parse_jsonl(raw: &[u8], ip_field: &str) -> Result<Vec<String>, ParseError> {
    let text = String::from_utf8_lossy(raw);
    let values = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok());
    Ok(extract_field(values, ip_field))
}

fn extract_field<'a, I, T>(items: I, ip_field: &str) -> Vec<String>
where
    I: Iterator<Item = T>,
    T: std::borrow::Borrow<Value> + 'a,
{
    let mut results = Vec::new();
    for item in items {
        let Some(candidate) = item.borrow().get(ip_field).and_then(Value::as_str) else {
            continue;
        };
        if let Some(normalized) = normalize_ip_or_cidr(candidate) {
            results.push(normalized);
        }
    }
    results
}

fn walk_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = root;
    for segment in path.split('.').filter(|s| !s.is_empty()) {
        current = current.get(segment)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_array_path() {
        let parser = JsonPathParser;
        let body = br#"{"data":{"items":[{"ipAddress":"1.2.3.4"},{"ipAddress":"5.6.7.8"}]}}"#;
        let config = r#"{"array_path":"data.items","ip_field":"ipAddress"}"#;
        let out = parser.parse(body, Some(config)).expect("parse");
        assert_eq!(out, vec!["1.2.3.4".to_owned(), "5.6.7.8".to_owned()]);
    }

    #[test]
    fn parses_bare_top_level_array() {
        let parser = JsonPathParser;
        let body = br#"[{"ip":"9.9.9.9"}]"#;
        let config = r#"{"ip_field":"ip"}"#;
        let out = parser.parse(body, Some(config)).expect("parse");
        assert_eq!(out, vec!["9.9.9.9".to_owned()]);
    }

    #[test]
    fn skips_items_missing_the_ip_field() {
        let parser = JsonPathParser;
        let body = br#"[{"other":"x"},{"ip":"1.1.1.1"}]"#;
        let config = r#"{"ip_field":"ip"}"#;
        let out = parser.parse(body, Some(config)).expect("parse");
        assert_eq!(out, vec!["1.1.1.1".to_owned()]);
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
        let config = r#"{"array_path":"data.items","ip_field":"ip"}"#;
        assert!(parser.parse(body, Some(config)).is_err());
    }

    #[test]
    fn errors_on_malformed_json_body() {
        let parser = JsonPathParser;
        let config = r#"{"ip_field":"ip"}"#;
        assert!(parser.parse(b"not json", Some(config)).is_err());
    }

    #[test]
    fn jsonl_mode_parses_spamhaus_drop_v6_shape() {
        let parser = JsonPathParser;
        let body = concat!(
            "{\"cidr\":\"2001:678:254::/48\",\"sblid\":\"SBL697648\",\"rir\":\"ripencc\"}\n",
            "{\"cidr\":\"2001:678:6c0::/48\",\"sblid\":\"SBL624855\",\"rir\":\"ripencc\"}\n",
            "{\"type\":\"metadata\",\"timestamp\":1786614242,\"records\":2}\n",
        );
        let config = r#"{"jsonl":true,"ip_field":"cidr"}"#;
        let out = parser.parse(body.as_bytes(), Some(config)).expect("parse");
        assert_eq!(out, vec!["2001:678:254::/48".to_owned(), "2001:678:6c0::/48".to_owned()]);
    }

    #[test]
    fn jsonl_mode_skips_unparseable_lines_without_failing() {
        let parser = JsonPathParser;
        let body = "{\"cidr\":\"2001:db8::/32\"}\nnot json at all\n{\"cidr\":\"2001:db9::/32\"}\n";
        let config = r#"{"jsonl":true,"ip_field":"cidr"}"#;
        let out = parser.parse(body.as_bytes(), Some(config)).expect("parse");
        assert_eq!(out, vec!["2001:db8::/32".to_owned(), "2001:db9::/32".to_owned()]);
    }

    /// Task 3: a raw binary/non-UTF-8 body is not valid JSON either way, so `JSON_PATH`'s
    /// non-`jsonl` path (`serde_json::from_slice`, which validates UTF-8 as part of JSON syntax)
    /// must still surface this as a clean `Err`, never a panic.
    #[test]
    fn raw_binary_body_is_a_clean_parse_error_not_a_panic() {
        let parser = JsonPathParser;
        let config = r#"{"ip_field":"ip"}"#;
        let body: &[u8] = &[0x00, 0xff, 0xfe, 0x80, 0x81, 0x00, 0x00, 0xc0, 0xc1];
        let result = parser.parse(body, Some(config));
        assert!(result.is_err(), "raw binary is not valid JSON and must be rejected cleanly, not panic");
    }

    /// Task 3, `jsonl` mode specifically: a non-UTF-8 line among otherwise well-formed JSONL lines
    /// must not fail the whole body — lossy decoding turns the bad line into replacement
    /// characters, which then simply fails *that* line's JSON parse and gets skipped, exactly like
    /// `jsonl_mode_skips_unparseable_lines_without_failing`'s plain-garbage line does.
    #[test]
    fn jsonl_mode_skips_a_non_utf8_line_without_failing_the_whole_body() {
        let parser = JsonPathParser;
        let mut body = b"{\"cidr\":\"2001:db8::/32\"}\n".to_vec();
        body.extend_from_slice(&[0xff, 0xfe, 0x00]); // invalid UTF-8, not valid JSON either way
        body.extend_from_slice(b"\n{\"cidr\":\"2001:db9::/32\"}\n");
        let config = r#"{"jsonl":true,"ip_field":"cidr"}"#;
        let out = parser.parse(&body, Some(config)).expect("must not error on an invalid UTF-8 line");
        assert_eq!(out, vec!["2001:db8::/32".to_owned(), "2001:db9::/32".to_owned()]);
    }
}
