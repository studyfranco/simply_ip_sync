//! `JSON_PATH` parser: structured JSON feeds (AbuseIPDB API responses, pfSense exports).
//! Configured via `parser_config_json`: `{"array_path": "data.items", "ip_field": "ipAddress"}`.
//! `array_path` may be omitted when the feed body is itself a bare top-level array.

use serde::Deserialize;
use serde_json::Value;

use super::{normalize_ip_or_cidr, FeedParser, ParseError};

#[derive(Deserialize)]
struct JsonPathConfig {
    /// Dotted path to the array of items, e.g. `"data.items"`. Omitted for a bare top-level array.
    #[serde(default)]
    array_path: Option<String>,
    /// Key holding the IP/CIDR string on each array element.
    ip_field: String,
}

/// Parses a JSON feed body by walking a dotted path to an array, then pulling one field per
/// element.
pub struct JsonPathParser;

impl FeedParser for JsonPathParser {
    fn parse(&self, raw: &[u8], config: Option<&str>) -> Result<Vec<String>, ParseError> {
        let config_str = config.ok_or_else(|| {
            ParseError::InvalidConfig("JSON_PATH requires parser_config_json with an ip_field".to_owned())
        })?;
        let config: JsonPathConfig = serde_json::from_str(config_str)
            .map_err(|e| ParseError::InvalidConfig(format!("invalid parser_config_json: {e}")))?;

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

        let mut results = Vec::new();
        for item in items {
            let Some(candidate) = item.get(&config.ip_field).and_then(Value::as_str) else {
                continue;
            };
            if let Some(normalized) = normalize_ip_or_cidr(candidate) {
                results.push(normalized);
            }
        }
        Ok(results)
    }
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
}
