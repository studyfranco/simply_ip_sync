//! Black-box tests for the `FeedParser` engine, driven only through the public `parsers` API.

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
