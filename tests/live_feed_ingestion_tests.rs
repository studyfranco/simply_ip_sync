//! Live network tests against real, public threat-intelligence feeds.
//!
//! `#[ignore]`d so `cargo test` stays offline and fast by default; run explicitly with
//! `cargo test -- --ignored` (or `cargo test --test live_feed_ingestion_tests -- --ignored`) when
//! network access is available. These exist to catch a feed's *actual* format drifting away from
//! what `REGEX_LINE` expects — something no local fixture can ever detect, by definition.

use simply_ip_sync::parsers;

const MASS_SCANNER_URL: &str = "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt";
const DOH_IPV4_URL: &str = "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv4.txt";
const VPN_IPV4_URL: &str = "https://raw.githubusercontent.com/NazgulCoder/IPLists/refs/heads/main/output/vpn-ipv4.txt";
const DOH_IPV6_URL: &str = "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv6.txt";

/// Fetches `url` and parses it with `REGEX_LINE`, asserting a non-empty set of syntactically
/// valid IPv4/IPv6/CIDR entries. Panics (failing the test) on a network error or a non-2xx
/// response, rather than skipping — a `#[ignore]`d test that silently passes when the network is
/// unreachable would stop meaning anything the first time someone actually needed it to fail.
async fn assert_feed_yields_valid_entries(url: &str) {
    let response = reqwest::get(url).await.unwrap_or_else(|e| panic!("GET {url} failed: {e}"));
    let status = response.status();
    assert!(status.is_success(), "GET {url} returned {status}");
    let body = response.bytes().await.unwrap_or_else(|e| panic!("failed to read body from {url}: {e}"));

    let parser = parsers::for_type("REGEX_LINE").expect("REGEX_LINE is a known parser type");
    let entries = parser.parse(&body, None).unwrap_or_else(|e| panic!("REGEX_LINE failed to parse {url}: {e}"));

    assert!(!entries.is_empty(), "{url} yielded zero parsed entries — the feed format may have changed");
    for entry in &entries {
        assert!(
            entry.parse::<ipnetwork::IpNetwork>().is_ok() || entry.parse::<std::net::IpAddr>().is_ok(),
            "{url} yielded an entry that is not a valid IP/CIDR: '{entry}'"
        );
    }
    println!("{url}: {} valid entries", entries.len());
}

#[tokio::test]
#[ignore = "hits a live network endpoint; run with `cargo test -- --ignored`"]
async fn mass_scanner_feed_parses_to_valid_entries() {
    assert_feed_yields_valid_entries(MASS_SCANNER_URL).await;
}

#[tokio::test]
#[ignore = "hits a live network endpoint; run with `cargo test -- --ignored`"]
async fn doh_ipv4_blocklist_parses_to_valid_entries() {
    assert_feed_yields_valid_entries(DOH_IPV4_URL).await;
}

#[tokio::test]
#[ignore = "hits a live network endpoint; run with `cargo test -- --ignored`"]
async fn vpn_ipv4_feed_parses_to_valid_entries() {
    assert_feed_yields_valid_entries(VPN_IPV4_URL).await;
}

#[tokio::test]
#[ignore = "hits a live network endpoint; run with `cargo test -- --ignored`"]
async fn doh_ipv6_blocklist_parses_to_valid_entries() {
    assert_feed_yields_valid_entries(DOH_IPV6_URL).await;

    // This feed is IPv6-specific; confirm the parser actually extracted v6 addresses and not just
    // an empty pass — a parser that silently extracted zero v6 addresses from a v6-only feed
    // while still reporting "non-empty" (e.g. by matching something else on the line) would slip
    // through the generic check above.
    let response = reqwest::get(DOH_IPV6_URL).await.expect("re-fetch for v6-specific assertion");
    let body = response.bytes().await.expect("read body");
    let parser = parsers::for_type("REGEX_LINE").expect("known parser type");
    let entries = parser.parse(&body, None).expect("parse");
    let v6_count = entries.iter().filter(|e| e.parse::<std::net::Ipv6Addr>().is_ok()).count();
    assert!(v6_count > 0, "doh-ipv6.txt yielded no actual IPv6 addresses among its {} entries", entries.len());
}

/// End-to-end through the real ingestion pipeline (not just the parser in isolation): an
/// `external_source` pointed at a live feed, triggered through `jobs::external_ingestion::run`,
/// must report a `SUCCESS` summary with `items_processed > 0`.
#[tokio::test]
#[ignore = "hits a live network endpoint; run with `cargo test -- --ignored`"]
async fn live_feed_ingests_successfully_through_the_full_job_pipeline() {
    use chrono::Utc;
    use sea_orm::{ActiveModelTrait, Set};
    use simply_ip_sync::entities::external_source;
    use uuid::Uuid;

    let conn = sea_orm::Database::connect("sqlite::memory:").await.expect("connect");
    simply_ip_sync::db::run_migrations(&conn).await.expect("migrate");
    let master_id = Uuid::new_v4();
    let now = Utc::now();
    let master = simply_ip_sync::entities::api_key::ActiveModel {
        id: Set(master_id),
        name: Set("Master".to_owned()),
        key_hash: Set("unused".to_owned()),
        signing_secret: Set(None),
        prefix: Set("unused".to_owned()),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_sources: Set(true),
        can_manage_vaults: Set(true),
        parent_key_id: Set(None),
        bound_ips: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    master.insert(&conn).await.expect("insert master");
    let state = simply_ip_sync::state::AppState::for_tests(conn.clone(), master_id).await;

    let source_id = Uuid::new_v4();
    let source = external_source::ActiveModel {
        id: Set(source_id),
        name: Set("live-doh-ipv4".to_owned()),
        source_url: Set(DOH_IPV4_URL.to_owned()),
        parser_type: Set("REGEX_LINE".to_owned()),
        parser_config_json: Set(None),
        cron_schedule: Set("0 0 * * *".to_owned()),
        target_group_name: Set("group".to_owned()),
        mode: Set("upsert".to_owned()),
        is_active: Set(true),
        last_run_at: Set(None),
        owner_key_id: Set(Some(master_id)),
        created_at: Set(now),
        updated_at: Set(now),
    };
    source.insert(&conn).await.expect("insert source");

    // No targets configured: the job still fetches and parses, it just has nothing to push to —
    // exactly what's needed to prove ingestion itself works without standing up a mock vault.
    let summary = simply_ip_sync::jobs::external_ingestion::run(&state, source_id).await.expect("job runs");
    assert_eq!(summary.status, "SUCCESS");
    assert!(summary.items_processed > 0, "expected at least one parsed entry from a live feed");
}
