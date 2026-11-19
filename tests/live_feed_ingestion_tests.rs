//! Offline HTTP tests using representative threat-feed payloads.

use std::time::Duration;

use simply_ip_sync::parsers::{self, ParsedRecord};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const MASS_SCANNER_FEED: &str = "# Mass scanners\n\n192.0.2.14\n198.51.100.26 # scanner\n";
const DOH_IPV4_FEED: &str = "1.1.1.1\n8.8.8.8\n9.9.9.9\n";
const VPN_IPV4_FEED: &str = "# VPN provider networks\n192.0.2.0/24\n198.51.100.64/26\n";
const DOH_IPV6_FEED: &str = "2001:4860:4860::8888\n2606:4700:4700::1111\n2620:fe::fe\n";

async fn mock_feed(feed_path: &str, payload: &str) -> (MockServer, String) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(feed_path))
        .respond_with(ResponseTemplate::new(200).set_body_string(payload))
        .expect(1)
        .mount(&server)
        .await;
    let url = format!("{}{feed_path}", server.uri());
    (server, url)
}

fn local_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build loopback HTTP client")
}

/// Fetches a fixture and checks that `REGEX_LINE` yields valid IP or CIDR records.
async fn assert_feed_yields_valid_entries(feed_path: &str, payload: &str) -> Vec<ParsedRecord> {
    let (_server, url) = mock_feed(feed_path, payload).await;
    let response = local_http_client()
        .get(&url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {url} failed: {e}"));
    let status = response.status();
    assert!(status.is_success(), "GET {url} returned {status}");
    let body = response
        .bytes()
        .await
        .unwrap_or_else(|e| panic!("failed to read body from {url}: {e}"));

    let parser = parsers::for_type("REGEX_LINE").expect("REGEX_LINE is a known parser type");
    let entries = parser
        .parse(&body, None)
        .unwrap_or_else(|e| panic!("REGEX_LINE failed to parse {url}: {e}"));

    assert!(
        !entries.is_empty(),
        "{url} yielded zero parsed entries — expected IP/CIDR records in the fixture"
    );
    for entry in &entries {
        assert!(
            entry.address.parse::<ipnet::IpNet>().is_ok()
                || entry.address.parse::<std::net::IpAddr>().is_ok(),
            "{url} yielded an entry that is not a valid IP/CIDR: '{}'",
            entry.address
        );
    }
    entries
}

#[tokio::test]
async fn mass_scanner_feed_parses_to_valid_entries() {
    assert_feed_yields_valid_entries("/mass_scanner.txt", MASS_SCANNER_FEED).await;
}

#[tokio::test]
async fn doh_ipv4_blocklist_parses_to_valid_entries() {
    assert_feed_yields_valid_entries("/doh-ipv4.txt", DOH_IPV4_FEED).await;
}

#[tokio::test]
async fn vpn_ipv4_feed_parses_to_valid_entries() {
    assert_feed_yields_valid_entries("/vpn-ipv4.txt", VPN_IPV4_FEED).await;
}

#[tokio::test]
async fn doh_ipv6_blocklist_parses_to_valid_entries() {
    let entries = assert_feed_yields_valid_entries("/doh-ipv6.txt", DOH_IPV6_FEED).await;
    assert!(
        entries
            .iter()
            .any(|entry| entry.address.parse::<std::net::Ipv6Addr>().is_ok()),
        "doh-ipv6.txt yielded no actual IPv6 addresses among its {} entries",
        entries.len()
    );
}

/// Exercises the external ingestion job with one destination group and one mock feed.
#[tokio::test]
async fn mock_feed_ingests_successfully_through_the_full_job_pipeline() {
    use chrono::Utc;
    use sea_orm::{ActiveModelTrait, Set};
    use simply_ip_sync::entities::{destination_group, external_source};
    use uuid::Uuid;

    let (_server, url) = mock_feed("/doh-ipv4.txt", DOH_IPV4_FEED).await;
    let conn = sea_orm::Database::connect("sqlite::memory:")
        .await
        .expect("connect");
    simply_ip_sync::db::run_migrations(&conn)
        .await
        .expect("migrate");
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
    let mut state = simply_ip_sync::state::AppState::for_tests(conn.clone(), master_id)
        .await
        .expect("build test state");
    state.http = local_http_client();

    let group_id = Uuid::new_v4();
    let group = destination_group::ActiveModel {
        id: Set(group_id),
        name: Set("mock-doh-ipv4-group".to_owned()),
        target_group_name: Set("group".to_owned()),
        cron_schedule: Set("0 0 * * *".to_owned()),
        mode: Set("upsert".to_owned()),
        is_active: Set(true),
        skip_bogon_filtering: Set(false),
        last_run_at: Set(None),
        owner_key_id: Set(Some(master_id)),
        created_at: Set(now),
        updated_at: Set(now),
    };
    group.insert(&conn).await.expect("insert destination group");

    let source = external_source::ActiveModel {
        id: Set(Uuid::new_v4()),
        destination_group_id: Set(group_id),
        name: Set("mock-doh-ipv4".to_owned()),
        source_url: Set(url),
        parser_type: Set("REGEX_LINE".to_owned()),
        parser_config_json: Set(None),
        max_age_days: Set(None),
        skip_bogon_filtering: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    source.insert(&conn).await.expect("insert feed");

    // No targets configured: the job still fetches and parses, it just has nothing to push to —
    // exactly what's needed to prove ingestion itself works without standing up a mock vault.
    let summary = simply_ip_sync::jobs::external_ingestion::run(&state, group_id)
        .await
        .expect("job runs");
    assert_eq!(summary.status, "SUCCESS");
    assert!(
        summary.items_processed > 0,
        "expected at least one parsed entry from the mock feed"
    );
}
