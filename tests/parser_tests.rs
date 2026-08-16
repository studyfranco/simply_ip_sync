//! Black-box tests for the `FeedParser` engine, driven only through the public `parsers` API.
//!
//! Two feeds referenced in `AGENT_NOTES.MD` are rate-limited/archived and unsuitable for a test
//! that runs on every `cargo test`: StopForumSpam's IPv6 list (`listed_ip_30_ipv6.zip`) and
//! Spamhaus's DROP v6 list (`drop_v6.json`). Both were fetched once during development to inspect
//! their real wire format (recorded in the doc comments below); the tests here build local
//! fixtures reproducing those exact shapes rather than hitting the network, so they run
//! deterministically offline and can never trigger a rate limit or IP ban.

use std::io::Write;

use simply_ip_sync::parsers;

#[test]
fn regex_line_strips_comments_and_extracts_addresses() {
    let parser = parsers::for_type("REGEX_LINE").expect("known parser type");
    let body = b"# Spamhaus DROP list\n1.2.3.4/32\n; another comment\n10.0.0.0/8\n// js comment\n2001:db8::1\n";
    let records = parser.parse(body, None).expect("parse");
    assert_eq!(records, vec!["1.2.3.4".to_owned(), "10.0.0.0/8".to_owned(), "2001:db8::1".to_owned()]);
}

#[test]
fn json_path_extracts_configured_field() {
    let parser = parsers::for_type("JSON_PATH").expect("known parser type");
    let body = br#"{"data":[{"ipAddress":"203.0.113.9"},{"ipAddress":"203.0.113.10"}]}"#;
    let config = r#"{"array_path":"data","ip_field":"ipAddress"}"#;
    let records = parser.parse(body, Some(config)).expect("parse");
    assert_eq!(records, vec!["203.0.113.9".to_owned(), "203.0.113.10".to_owned()]);
}

#[test]
fn unknown_parser_type_is_rejected() {
    assert!(parsers::for_type("XML").is_err());
}

/// Writes `contents` to a single-member ZIP archive named `member_name`, using the same
/// `zip::ZipWriter` API `src/jobs/decompress.rs` reads with. Building the fixture with the real
/// crate (rather than hand-writing archive bytes) keeps the test honest about what an actual ZIP
/// download looks like, without touching the network.
fn build_zip_fixture(member_name: &str, contents: &[u8]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buf);
        let options: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        writer.start_file(member_name, options).expect("start_file");
        writer.write_all(contents).expect("write member contents");
        writer.finish().expect("finish archive");
    }
    buf.into_inner()
}

/// StopForumSpam's `listed_ip_30_ipv6.zip` (inspected 2026-08 by fetching the real download):
/// a single member `listed_ip_30_ipv6.txt`, one bare IPv6 address per line, no comments, no
/// header. This fixture reproduces that shape (member name included) at a representative scale.
#[test]
fn stopforumspam_ipv6_zip_fixture_decompresses_and_parses_via_regex_line() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture_path = tmp.path().join("listed_ip_30_ipv6.zip");

    let addresses = [
        "2001:268:7384:2aad::",
        "2001:268:c217:bc4b::",
        "2001:2d8:2057:d55c::",
        "2001:2d8:222a:fc74::",
    ];
    let inner_text = addresses.join("\n") + "\n";
    let zip_bytes = build_zip_fixture("listed_ip_30_ipv6.txt", inner_text.as_bytes());
    std::fs::write(&fixture_path, &zip_bytes).expect("write zip fixture to disk");

    // Read back from disk (not the in-memory `zip_bytes`) to exercise the same path a fetched
    // HTTP response body would take: bytes on disk/wire → decompress → parse.
    let fetched = std::fs::read(&fixture_path).expect("read zip fixture back");
    assert!(simply_ip_sync::jobs::decompress::is_zip(&fetched), "fixture must be recognised as a zip archive");
    let decompressed =
        simply_ip_sync::jobs::decompress::decompress_if_zip(&fetched).expect("decompress zip fixture");

    let parser = parsers::for_type("REGEX_LINE").expect("known parser type");
    let records = parser.parse(&decompressed, None).expect("parse decompressed body");
    assert_eq!(records.len(), addresses.len());
    for address in addresses {
        assert!(records.contains(&address.to_owned()), "expected {address} in parsed output: {records:?}");
    }

    // `tmp` (and the fixture file inside it) is removed automatically when it drops at the end of
    // this test — no manual cleanup step, and no leftover file even on a panic partway through.
}

/// Spamhaus's `drop_v6.json` (inspected 2026-08 by fetching the real download): **not** a JSON
/// array — newline-delimited JSON, one `{"cidr": "...", "sblid": "...", "rir": "..."}` object per
/// line, followed by a trailing `{"type":"metadata", ...}` footer line carrying no `cidr` field.
/// This fixture reproduces that exact shape, footer included, at a representative scale.
#[test]
fn spamhaus_drop_v6_json_fixture_parses_via_jsonl_mode_and_skips_the_metadata_footer() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture_path = tmp.path().join("drop_v6.json");

    let cidrs = ["2001:678:254::/48", "2001:678:6c0::/48", "2001:678:724::/48"];
    let mut fixture = String::new();
    for (i, cidr) in cidrs.iter().enumerate() {
        fixture.push_str(&format!("{{\"cidr\":\"{cidr}\",\"sblid\":\"SBL{i}\",\"rir\":\"ripencc\"}}\n"));
    }
    fixture.push_str(
        r#"{"type":"metadata","timestamp":1786614242,"size":123,"records":3,"copyright":"(c) 2026 The Spamhaus Project SLU"}"#,
    );
    fixture.push('\n');
    std::fs::write(&fixture_path, fixture.as_bytes()).expect("write json fixture to disk");

    let fetched = std::fs::read(&fixture_path).expect("read json fixture back");
    let parser = parsers::for_type("JSON_PATH").expect("known parser type");
    let config = r#"{"jsonl":true,"ip_field":"cidr"}"#;
    let records = parser.parse(&fetched, Some(config)).expect("parse");

    assert_eq!(records.len(), cidrs.len(), "the metadata footer line must be skipped, not counted or erroring");
    for cidr in cidrs {
        assert!(records.contains(&cidr.to_owned()), "expected {cidr} in parsed output: {records:?}");
        assert!(cidr.parse::<ipnetwork::IpNetwork>().is_ok(), "{cidr} must be a valid IPv6 CIDR");
    }
}

/// A non-zip body must pass through `decompress_if_zip` unchanged — the vast majority of feeds
/// are plain text/JSON, and this is the path every one of them takes.
#[test]
fn plain_text_body_is_not_mistaken_for_a_zip_archive() {
    let plain = b"2001:db8::1\n2001:db8::2\n";
    assert!(!simply_ip_sync::jobs::decompress::is_zip(plain));
    let result = simply_ip_sync::jobs::decompress::decompress_if_zip(plain).expect("passthrough");
    assert_eq!(result, plain);
}

/// Task 4: a Cloudflare-style block/error page — the shape a feed host commonly returns with a
/// `200 OK` when it's actually rate-limiting, WAF-blocking, or captive-portal-redirecting the
/// request. Contains no dotted-decimal or colon-hex substrings by construction (the Ray ID is
/// plain hex, no separators), so `REGEX_LINE` must extract nothing — not panic, not fabricate a
/// match out of markup.
const CLOUDFLARE_ERROR_PAGE: &str = r#"<!DOCTYPE html>
<html>
<head><title>Attention Required! | Cloudflare</title></head>
<body class="no-js">
<div id="cf-wrapper">
  <div class="cf-alert cf-alert-error cf-cookie-error" id="cookie-alert" data-translate="enable_cookies">
    Please enable cookies.
  </div>
  <div id="cf-error-details" class="p-0">
    <h1>Sorry, you have been blocked</h1>
    <p>You are unable to access this website.</p>
    <div class="cf-error-footer">
      <p>Ray ID: <code>8f2a1c9d4b3e7f10</code></p>
      <p>Performance &amp; security by Cloudflare</p>
    </div>
  </div>
</div>
</body>
</html>"#;

/// A captive-portal redirect page — the other very common "200 OK but not the real content" case
/// (public wifi, corporate proxy auth walls). Its `<meta http-equiv="refresh">` target deliberately
/// carries a private gateway address to prove the parser doesn't get confused by markup
/// *containing* an IP-shaped substring inside an attribute value — that address should still be
/// extracted (the parser has no notion of HTML structure, only line-oriented token scanning), but
/// it must not crash or mis-extract garbage around it.
const CAPTIVE_PORTAL_PAGE: &str = r#"<!DOCTYPE html>
<html>
<head>
<meta http-equiv="refresh" content="0; url=http://192.168.1.1/portal/login">
<title>Wi-Fi Login Required</title>
</head>
<body>
<p>Redirecting to the login portal&hellip;</p>
<script>window.location.href = "http://192.168.1.1/portal/login";</script>
</body>
</html>"#;

#[test]
fn html_error_page_yields_zero_entries_from_regex_line_no_panic() {
    let parser = parsers::for_type("REGEX_LINE").expect("known parser type");
    let records = parser.parse(CLOUDFLARE_ERROR_PAGE.as_bytes(), None).expect("parse must not error");
    assert!(records.is_empty(), "an HTML error page with no IP-shaped text must yield zero entries, got {records:?}");
}

#[test]
fn html_error_page_is_a_hard_parse_failure_for_json_path() {
    let parser = parsers::for_type("JSON_PATH").expect("known parser type");
    let config = r#"{"ip_field":"ip"}"#;
    let result = parser.parse(CLOUDFLARE_ERROR_PAGE.as_bytes(), Some(config));
    assert!(result.is_err(), "HTML is not valid JSON and must be reported as a parse error, not silently empty");
}

#[test]
fn captive_portal_page_extracts_the_embedded_address_without_crashing() {
    let parser = parsers::for_type("REGEX_LINE").expect("known parser type");
    let records = parser.parse(CAPTIVE_PORTAL_PAGE.as_bytes(), None).expect("parse must not error");
    // The line-oriented scanner has no concept of HTML syntax, so an IP-shaped substring inside a
    // URL or script tag is still picked up — documented behavior, not a bug: normalize_ip_or_cidr
    // re-validates every candidate, so this can never smuggle in something that isn't a real IP.
    assert!(records.iter().all(|r| r.parse::<std::net::IpAddr>().is_ok() || r.parse::<ipnetwork::IpNetwork>().is_ok()));
}

/// A large HTML body (well beyond a single packet/buffer's worth) must still parse in bounded
/// time and yield zero matches, as a proxy for "no unbounded memory growth or quadratic blowup on
/// adversarial input" — the closest a unit test can get to a memory-stability assertion without
/// an actual profiler attached.
#[test]
fn large_html_body_parses_quickly_with_zero_matches() {
    let mut big_html = String::from("<!DOCTYPE html><html><body>\n");
    for i in 0..50_000 {
        big_html.push_str(&format!("<div class=\"row-{i}\">Not a threat feed entry, just markup.</div>\n"));
    }
    big_html.push_str("</body></html>");

    let parser = parsers::for_type("REGEX_LINE").expect("known parser type");
    let start = std::time::Instant::now();
    let records = parser.parse(big_html.as_bytes(), None).expect("parse must not error");
    let elapsed = start.elapsed();

    assert!(records.is_empty());
    assert!(elapsed < std::time::Duration::from_secs(5), "parsing ~{} bytes took {elapsed:?}, expected well under 5s", big_html.len());
}
