//! `REGEX_LINE` parser: line-by-line text feeds (Spamhaus DROP lists, FireHOL, plain IP lists).
//! Strips comment lines and extracts IPv4/IPv6 addresses and CIDR subnets.

use std::sync::OnceLock;

use regex::Regex;

use super::{normalize_ip_or_cidr, FeedParser, ParseError};

fn ip_token_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        // IPv4 (optionally /N), or IPv6 (optionally /N). Deliberately permissive at the token
        // level — validity is decided by `normalize_ip_or_cidr` parsing the matched text, not by
        // this pattern, since a byte-perfect IP regex is both hard to get right and unnecessary
        // when every match is re-validated immediately after extraction.
        Regex::new(r"(?:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:/[0-9]{1,2})?)|(?:[0-9a-fA-F:]{2,}(?:/[0-9]{1,3})?)")
            .expect("static regex is valid")
    })
}

/// Parses newline-delimited text, stripping comment lines (starting with `#`, `;`, or `//` after
/// trimming) and extracting one or more IP/CIDR tokens per remaining line.
pub struct RegexLineParser;

impl FeedParser for RegexLineParser {
    fn parse(&self, raw: &[u8], _config: Option<&str>) -> Result<Vec<String>, ParseError> {
        let text = std::str::from_utf8(raw).map_err(|e| ParseError::MalformedBody(e.to_string()))?;
        let pattern = ip_token_pattern();
        let mut results = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with(';')
                || trimmed.starts_with("//")
            {
                continue;
            }
            for candidate in pattern.find_iter(trimmed) {
                if let Some(normalized) = normalize_ip_or_cidr(candidate.as_str()) {
                    results.push(normalized);
                }
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_comment_lines() {
        let parser = RegexLineParser;
        let body = b"# comment\n; also comment\n// js style\n1.2.3.4\n";
        let out = parser.parse(body, None).expect("parse");
        assert_eq!(out, vec!["1.2.3.4".to_owned()]);
    }

    #[test]
    fn extracts_cidr_and_bare_ip() {
        let parser = RegexLineParser;
        let body = b"10.0.0.0/8\n192.168.1.1\n";
        let out = parser.parse(body, None).expect("parse");
        assert_eq!(out, vec!["10.0.0.0/8".to_owned(), "192.168.1.1".to_owned()]);
    }

    #[test]
    fn extracts_ipv6() {
        let parser = RegexLineParser;
        let body = b"2001:db8::1\n";
        let out = parser.parse(body, None).expect("parse");
        assert_eq!(out, vec!["2001:db8::1".to_owned()]);
    }

    #[test]
    fn ignores_blank_and_non_ip_lines() {
        let parser = RegexLineParser;
        let body = b"\n   \nnot an ip at all\n1.2.3.4\n";
        let out = parser.parse(body, None).expect("parse");
        assert_eq!(out, vec!["1.2.3.4".to_owned()]);
    }

    #[test]
    fn rejects_non_utf8_body() {
        let parser = RegexLineParser;
        let body: &[u8] = &[0xff, 0xfe, 0x00];
        assert!(parser.parse(body, None).is_err());
    }
}
