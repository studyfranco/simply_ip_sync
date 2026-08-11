//! Extensible feed-parsing engine. [`FeedParser`] is the trait every parser algorithm implements;
//! new formats (CSV, XML, STIX/TAXII) are added by implementing it, not by branching inside the
//! ingestion job.

pub mod json_path;
pub mod regex_line;

/// Failure modes when parsing a fetched feed body.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// `parser_config_json` was present but not valid JSON, or missing a required key.
    #[error("invalid parser configuration: {0}")]
    InvalidConfig(String),
    /// The feed body was not valid UTF-8 (`REGEX_LINE`) or not valid JSON (`JSON_PATH`).
    #[error("malformed feed body: {0}")]
    MalformedBody(String),
}

/// A pluggable algorithm turning a raw fetched feed body into a list of normalized IP/CIDR
/// strings.
pub trait FeedParser {
    /// Parses `raw`, using `config` (the source's `parser_config_json`, if any) to steer
    /// extraction. Returns normalized IP/CIDR strings; duplicates are not required to be removed
    /// by the parser (callers deduplicate).
    fn parse(&self, raw: &[u8], config: Option<&str>) -> Result<Vec<String>, ParseError>;
}

/// Normalizes a bare IP address or CIDR subnet to a canonical string form (`/32`/`/128` singles
/// stored without a prefix, everything else keeps its prefix length). Returns `None` if `input`
/// is not a valid IP address or CIDR subnet.
pub fn normalize_ip_or_cidr(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if let Ok(net) = trimmed.parse::<ipnetwork::IpNetwork>() {
        let max_prefixlen = match net.ip() {
            std::net::IpAddr::V4(_) => 32,
            std::net::IpAddr::V6(_) => 128,
        };
        return Some(if net.prefix() == max_prefixlen {
            net.ip().to_string()
        } else {
            net.to_string()
        });
    }
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    None
}

/// Selects the parser implementation for `parser_type` (`"REGEX_LINE"` or `"JSON_PATH"`).
pub fn for_type(parser_type: &str) -> Result<Box<dyn FeedParser + Send + Sync>, ParseError> {
    match parser_type {
        "REGEX_LINE" => Ok(Box::new(regex_line::RegexLineParser)),
        "JSON_PATH" => Ok(Box::new(json_path::JsonPathParser)),
        other => Err(ParseError::InvalidConfig(format!("unknown parser_type '{other}'"))),
    }
}
