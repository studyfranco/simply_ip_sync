//! `REGEX_LINE` parser: line-by-line text feeds (Spamhaus DROP lists, FireHOL, plain IP lists).
//! Strips comment lines and extracts IPv4/IPv6 addresses and CIDR subnets.
//!
//! Decoded with [`String::from_utf8_lossy`], not a hard UTF-8 validation — a feed host serving
//! ISO-8859-1/Windows-1252 text, or a body corrupted in transit, must degrade gracefully (any
//! byte sequence that isn't valid UTF-8 becomes `U+FFFD` replacement characters, which can never
//! form an IP-shaped token and so simply extracts nothing from that stretch of text) rather than
//! failing the entire feed over a single encoding mismatch elsewhere in an otherwise-good body.

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
        let text = String::from_utf8_lossy(raw);
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

    /// Task 3: invalid UTF-8 must degrade gracefully (lossy decoding), not fail the whole feed —
    /// changed from an earlier version of this parser that hard-rejected non-UTF-8 bodies. Pure
    /// garbage bytes containing no line breaks and no IP-shaped substrings still parse cleanly to
    /// zero entries; `mixed_encoding_body_still_extracts_the_valid_utf8_portions` below is the
    /// more realistic "one bad line among good ones" case.
    #[test]
    fn non_utf8_body_degrades_to_zero_entries_instead_of_erroring() {
        let parser = RegexLineParser;
        let body: &[u8] = &[0xff, 0xfe, 0x00];
        let out = parser.parse(body, None).expect("must not error on invalid UTF-8");
        assert!(out.is_empty());
    }

    /// A body mixing a genuinely invalid UTF-8 byte sequence (simulating e.g. a stray
    /// Windows-1252/Latin-1 line, or transit corruption) with otherwise well-formed lines must
    /// still extract every valid IP from the good lines — the encoding fault must stay local to
    /// the byte range it actually corrupted, not poison the entire body.
    #[test]
    fn mixed_encoding_body_still_extracts_the_valid_utf8_portions() {
        let parser = RegexLineParser;
        let mut body = b"1.2.3.4\n".to_vec();
        body.extend_from_slice(&[0xff, 0xfe]); // invalid UTF-8, no line break around it
        body.extend_from_slice(b"\n5.6.7.8\n");
        let out = parser.parse(&body, None).expect("must not error on invalid UTF-8");
        assert_eq!(out, vec!["1.2.3.4".to_owned(), "5.6.7.8".to_owned()]);
    }

    /// A raw Latin-1 (ISO-8859-1) byte, e.g. `0xE9` ("é"), is not valid UTF-8 on its own but is
    /// exactly the shape a mis-encoded feed host commonly sends. It must not corrupt extraction of
    /// IP addresses on the same or neighboring lines.
    #[test]
    fn latin1_byte_in_a_comment_does_not_prevent_extraction() {
        let parser = RegexLineParser;
        let mut body = b"# Th".to_vec();
        body.push(0xE9); // Latin-1 'é', invalid as a lone UTF-8 byte
        body.extend_from_slice(b" liste\n10.0.0.0/8\n");
        let out = parser.parse(&body, None).expect("must not error on invalid UTF-8");
        assert_eq!(out, vec!["10.0.0.0/8".to_owned()]);
    }
}
