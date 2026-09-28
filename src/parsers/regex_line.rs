//! `REGEX_LINE` parser: line-by-line text feeds (Spamhaus DROP lists, FireHOL, plain IP lists,
//! SANS ISC's `block.txt`). Strips comments and extracts IPv4/IPv6 addresses and CIDR subnets.
//!
//! Decoded with [`String::from_utf8_lossy`], not a hard UTF-8 validation — a feed host serving
//! ISO-8859-1/Windows-1252 text, or a body corrupted in transit, must degrade gracefully (any
//! byte sequence that isn't valid UTF-8 becomes `U+FFFD` replacement characters, which can never
//! form an IP-shaped token and so simply extracts nothing from that stretch of text) rather than
//! failing the entire feed over a single encoding mismatch elsewhere in an otherwise-good body.
//!
//! # Tab/space-separated netblock + prefix-length columns
//!
//! SANS ISC's `block.txt` lists a "top attacking /24s" table, tab-delimited:
//! `<start-of-netblock>\t<end-of-netblock>\t<prefix-length>\t<targets>\t<network name>\t<country>\t<contact>`
//! (e.g. `45.74.28.0\t45.74.28.255\t24\t345\tM247\tRO\tabuse@m247.com`). A plain whole-line regex
//! scan gets this wrong: it would independently match both the start *and* end address as two
//! bogus `/32` entries and never notice the `24` is a prefix length meant to combine with the
//! first column, not an unrelated token. Before falling back to the generic scan, each line is
//! split on whitespace and checked against two specific shapes:
//! - `<ip>\t<n>` (two fields, `n` a bare small integer) → `<ip>/<n>` — the simpler shape the
//!   destination-group UI's own help text shows.
//! - `<ip>\t<ip-or-anything>\t<n>\t...` (three or more fields, first a bare IP, third a bare small
//!   integer) → `<ip>/<n>` — SANS ISC's actual on-the-wire shape, ignoring every other column.
//!
//! A bare integer can never itself parse as an IP (no dots, no colons), so there is no ambiguity
//! with an ordinary line listing two independent whitespace-separated addresses (FireHOL-style);
//! that shape falls through to the generic scan exactly as before, extracting both as independent
//! entries.
//!
//! # Inline comments
//!
//! A line-*starting* comment (`#`, `;`, `//`, matched at the earlier version of this parser) is
//! still stripped, but so is a comment appearing *after* real content on the same line — the first
//! occurrence of any of the three markers truncates the line from that point on before any other
//! processing. None of the three marker characters/sequences can appear inside a valid IPv4
//! address, CIDR suffix, or IPv6 address, so this never truncates real data.

use std::sync::OnceLock;

use regex::Regex;

use super::{normalize_ip_or_cidr, FeedParser, ParseError, ParsedRecord};

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

/// Truncates `line` at the first inline comment marker (`#`, `;`, or `//`), if any.
fn strip_inline_comment(line: &str) -> &str {
    let mut cut = line.len();
    if let Some(i) = line.find('#') {
        cut = cut.min(i);
    }
    if let Some(i) = line.find(';') {
        cut = cut.min(i);
    }
    if let Some(i) = line.find("//") {
        cut = cut.min(i);
    }
    &line[..cut]
}

/// Tries the `<ip> <prefix>` and `<ip> <end-ip-or-anything> <prefix> ...` netblock+prefix shapes
/// described in the module doc comment. Returns `None` (falls through to the generic scan) when
/// the line doesn't match either shape.
fn netblock_and_prefix(trimmed: &str) -> Option<String> {
    let fields: Vec<&str> = trimmed.split_whitespace().collect();
    let base = *fields.first()?;
    if base.parse::<std::net::IpAddr>().is_err() {
        return None; // first field isn't a bare IP -- not this shape at all.
    }
    let prefix_field = match fields.len() {
        2 => fields[1],
        n if n >= 3 => fields[2],
        _ => return None,
    };
    let prefix: u8 = prefix_field.parse().ok()?;
    normalize_ip_or_cidr(&format!("{base}/{prefix}"))
}

/// Parses newline-delimited text, stripping full-line and inline comments (`#`, `;`, `//`) and
/// extracting one or more IP/CIDR/netblock+prefix tokens per remaining line.
pub struct RegexLineParser;

impl FeedParser for RegexLineParser {
    fn parse(&self, raw: &[u8], _config: Option<&str>) -> Result<Vec<ParsedRecord>, ParseError> {
        let text = String::from_utf8_lossy(raw);
        let pattern = ip_token_pattern();
        let mut results = Vec::new();
        for line in text.lines() {
            let trimmed = strip_inline_comment(line).trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(combined) = netblock_and_prefix(trimmed) {
                results.push(ParsedRecord { address: combined, last_seen_at: None });
                continue;
            }
            for candidate in pattern.find_iter(trimmed) {
                if let Some(normalized) = normalize_ip_or_cidr(candidate.as_str()) {
                    results.push(ParsedRecord { address: normalized, last_seen_at: None });
                }
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs(parser: &RegexLineParser, body: &[u8]) -> Vec<String> {
        parser.parse(body, None).expect("parse").into_iter().map(|r| r.address).collect()
    }

    #[test]
    fn strips_comment_lines() {
        let parser = RegexLineParser;
        let body = b"# comment\n; also comment\n// js style\n1.2.3.4\n";
        assert_eq!(addrs(&parser, body), vec!["1.2.3.4".to_owned()]);
    }

    #[test]
    fn extracts_cidr_and_bare_ip() {
        let parser = RegexLineParser;
        let body = b"10.0.0.0/8\n192.168.1.1\n";
        assert_eq!(addrs(&parser, body), vec!["10.0.0.0/8".to_owned(), "192.168.1.1".to_owned()]);
    }

    #[test]
    fn extracts_ipv6() {
        let parser = RegexLineParser;
        let body = b"2001:db8::1\n";
        assert_eq!(addrs(&parser, body), vec!["2001:db8::1".to_owned()]);
    }

    #[test]
    fn ignores_blank_and_non_ip_lines() {
        let parser = RegexLineParser;
        let body = b"\n   \nnot an ip at all\n1.2.3.4\n";
        assert_eq!(addrs(&parser, body), vec!["1.2.3.4".to_owned()]);
    }

    /// Task 3 (historical): invalid UTF-8 must degrade gracefully (lossy decoding), not fail the
    /// whole feed. Pure garbage bytes containing no line breaks and no IP-shaped substrings still
    /// parse cleanly to zero entries.
    #[test]
    fn non_utf8_body_degrades_to_zero_entries_instead_of_erroring() {
        let parser = RegexLineParser;
        let body: &[u8] = &[0xff, 0xfe, 0x00];
        assert!(parser.parse(body, None).expect("must not error on invalid UTF-8").is_empty());
    }

    #[test]
    fn mixed_encoding_body_still_extracts_the_valid_utf8_portions() {
        let parser = RegexLineParser;
        let mut body = b"1.2.3.4\n".to_vec();
        body.extend_from_slice(&[0xff, 0xfe]); // invalid UTF-8, no line break around it
        body.extend_from_slice(b"\n5.6.7.8\n");
        assert_eq!(addrs(&parser, &body), vec!["1.2.3.4".to_owned(), "5.6.7.8".to_owned()]);
    }

    #[test]
    fn latin1_byte_in_a_comment_does_not_prevent_extraction() {
        let parser = RegexLineParser;
        let mut body = b"# Th".to_vec();
        body.push(0xE9); // Latin-1 'é', invalid as a lone UTF-8 byte
        body.extend_from_slice(b" liste\n10.0.0.0/8\n");
        assert_eq!(addrs(&parser, &body), vec!["10.0.0.0/8".to_owned()]);
    }

    /// Task 5: the simpler two-column shape the destination-group UI's help text shows.
    #[test]
    fn two_field_ip_and_prefix_combine_into_one_cidr() {
        let parser = RegexLineParser;
        let body = b"185.220.101.0\t24\n";
        assert_eq!(addrs(&parser, body), vec!["185.220.101.0/24".to_owned()]);
    }

    /// Task 5: the real SANS ISC `block.txt` shape (start, end, prefix, targets, org, country,
    /// contact) — verified against a live fetch of the actual feed during development. Only the
    /// first and third columns matter; the rest (including the second column, itself a full IP)
    /// must not also be picked up by the generic scan as a spurious extra `/32`.
    #[test]
    fn sans_isc_block_txt_shape_combines_start_and_prefix_ignoring_other_columns() {
        let parser = RegexLineParser;
        let body = b"45.74.28.0\t45.74.28.255\t24\t345\tM247\tRO\tabuse@m247.com\n\
                     66.132.186.0\t66.132.186.255\t24\t345\t-\t-\t-\n";
        assert_eq!(addrs(&parser, body), vec!["45.74.28.0/24".to_owned(), "66.132.186.0/24".to_owned()]);
    }

    /// Task 5: an inline comment after real content (not just a full-line comment) is stripped.
    #[test]
    fn inline_comment_after_content_is_stripped() {
        let parser = RegexLineParser;
        let body = b"1.2.3.4 # known scanner\n5.6.7.8 ; also flagged\n9.9.9.9 // noted\n";
        assert_eq!(addrs(&parser, body), vec!["1.2.3.4".to_owned(), "5.6.7.8".to_owned(), "9.9.9.9".to_owned()]);
    }

    /// Two independent whitespace-separated addresses on one line (no bare-integer third/second
    /// field) must still both be extracted via the generic scan — the netblock+prefix shape must
    /// not swallow this case.
    #[test]
    fn two_independent_addresses_on_one_line_are_not_mistaken_for_netblock_plus_prefix() {
        let parser = RegexLineParser;
        let body = b"1.2.3.4 5.6.7.8\n";
        assert_eq!(addrs(&parser, body), vec!["1.2.3.4".to_owned(), "5.6.7.8".to_owned()]);
    }
}
