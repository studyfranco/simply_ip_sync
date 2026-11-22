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

    assert_ne!(
        entries,
        [] as [ParsedRecord; 0],
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
    let now = time::OffsetDateTime::now_utc();
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

struct CuratedFeedCase {
    name: &'static str,
    path: &'static str,
    parser_type: &'static str,
    parser_config: Option<&'static str>,
    payload: &'static str,
    expected_normalized: &'static [&'static str],
    expected_after_bogon: &'static [&'static str],
    expected_removed_bogons: usize,
}

const CURATED_FEEDS: &[CuratedFeedCase] = &[
    CuratedFeedCase {
        name: "feodo_tracker",
        path: "/downloads/ipblocklist_recommended.txt",
        parser_type: "REGEX_LINE",
        parser_config: None,
        payload: "# abuse.ch Feodo Tracker Botnet C2 IP Blocklist\n1.1.1.1\n8.8.8.8 # inline comment\n192.0.2.10\n",
        expected_normalized: &["1.1.1.1", "8.8.8.8", "192.0.2.10"],
        expected_after_bogon: &["1.1.1.1", "8.8.8.8"],
        expected_removed_bogons: 1,
    },
    CuratedFeedCase {
        name: "sans_isc_block",
        path: "/block.txt",
        parser_type: "REGEX_LINE",
        parser_config: None,
        payload: "# SANS ISC Top Attacking /24s\n1.1.1.0\t1.1.1.255\t24\t100\tExampleNet\tUS\n198.51.100.0\t198.51.100.255\t24\t50\tTestNet\tZZ\n",
        expected_normalized: &["1.1.1.0/24", "198.51.100.0/24"],
        expected_after_bogon: &["1.1.1.0/24"],
        expected_removed_bogons: 1,
    },
    CuratedFeedCase {
        name: "sans_isc_shodan",
        path: "/api/threatlist/shodan?json",
        parser_type: "JSON_PATH",
        parser_config: Some(
            r#"{"target_address":"$.ipv4","last_seen_at":"$.lastseen","user_agent":"simply_ip_sync/1.0"}"#,
        ),
        payload: r#"[{"ipv4":"8.8.4.4","lastseen":"2026-11-20"},{"ipv4":"203.0.113.5","lastseen":"2026-11-21T12:00:00Z"}]"#,
        expected_normalized: &["8.8.4.4", "203.0.113.5"],
        expected_after_bogon: &["8.8.4.4"],
        expected_removed_bogons: 1,
    },
    CuratedFeedCase {
        name: "ipsum_level3",
        path: "/levels/3.txt",
        parser_type: "REGEX_LINE",
        parser_config: None,
        payload: "# IPsum threat intelligence feed (level 3)\n9.9.9.9\t5\n10.0.0.1\t3\n",
        expected_normalized: &["9.9.9.9", "10.0.0.1"],
        expected_after_bogon: &["9.9.9.9"],
        expected_removed_bogons: 1,
    },
    CuratedFeedCase {
        name: "binarydefense",
        path: "/banlist.txt",
        parser_type: "REGEX_LINE",
        parser_config: None,
        payload: "# Binary Defense Systems Banlist\n1.1.1.1\n8.8.8.8\n192.168.1.50\n",
        expected_normalized: &["1.1.1.1", "8.8.8.8", "192.168.1.50"],
        expected_after_bogon: &["1.1.1.1", "8.8.8.8"],
        expected_removed_bogons: 1,
    },
    CuratedFeedCase {
        name: "dataplane_sshclient",
        path: "/sshclient.txt",
        parser_type: "REGEX_LINE",
        parser_config: None,
        payload: "# DataPlane.org sshclient\n# ASN | IP | Last Seen | Description\n13335 | 1.1.1.1 | 2026-11-22 00:00:00 | sshclient\n64512 | 192.0.2.42 | 2026-11-22 00:01:00 | sshclient\n",
        expected_normalized: &["1.1.1.1", "192.0.2.42"],
        expected_after_bogon: &["1.1.1.1"],
        expected_removed_bogons: 1,
    },
    CuratedFeedCase {
        name: "dataplane_sshpwauth",
        path: "/sshpwauth.txt",
        parser_type: "REGEX_LINE",
        parser_config: None,
        payload: "# DataPlane.org sshpwauth\n15169 | 8.8.8.8 | 2026-11-22 00:00:00 | sshpwauth\n64512 | 10.1.2.3 | 2026-11-22 00:01:00 | sshpwauth\n",
        expected_normalized: &["8.8.8.8", "10.1.2.3"],
        expected_after_bogon: &["8.8.8.8"],
        expected_removed_bogons: 1,
    },
    CuratedFeedCase {
        name: "dataplane_dnsrd",
        path: "/dnsrd.txt",
        parser_type: "REGEX_LINE",
        parser_config: None,
        payload: "# DataPlane.org dnsrd\n19281 | 9.9.9.9 | 2026-11-22 00:00:00 | dnsrd\n64512 | 172.16.0.5 | 2026-11-22 00:01:00 | dnsrd\n",
        expected_normalized: &["9.9.9.9", "172.16.0.5"],
        expected_after_bogon: &["9.9.9.9"],
        expected_removed_bogons: 1,
    },
    CuratedFeedCase {
        name: "dataplane_vncrfb",
        path: "/vncrfb.txt",
        parser_type: "REGEX_LINE",
        parser_config: None,
        payload: "# DataPlane.org vncrfb\n15169 | 8.8.4.4 | 2026-11-22 00:00:00 | vncrfb\n64512 | 127.0.0.1 | 2026-11-22 00:01:00 | vncrfb\n",
        expected_normalized: &["8.8.4.4", "127.0.0.1"],
        expected_after_bogon: &["8.8.4.4"],
        expected_removed_bogons: 1,
    },
];

#[tokio::test]
async fn all_nine_curated_threat_intel_feeds_parse_and_filter_bogons_offline() {
    assert_eq!(CURATED_FEEDS.len(), 9);
    let client = local_http_client();

    for feed in CURATED_FEEDS {
        let bare_path = feed.path.split('?').next().unwrap_or(feed.path);
        let (_server, url) = mock_feed(bare_path, feed.payload).await;
        let response = client
            .get(&url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {url} for {} failed: {e}", feed.name));
        assert!(
            response.status().is_success(),
            "{} returned {}",
            feed.name,
            response.status()
        );
        let body = response.bytes().await.expect("read body");

        let parser = parsers::for_type(feed.parser_type)
            .unwrap_or_else(|e| panic!("unknown parser for {}: {e}", feed.name));
        let parsed = parser
            .parse(&body, feed.parser_config)
            .unwrap_or_else(|e| panic!("{} failed to parse: {e}", feed.name));

        let normalized: Vec<String> = parsed.iter().map(|r| r.address.clone()).collect();
        let expected_norm: Vec<String> = feed
            .expected_normalized
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(
            normalized, expected_norm,
            "{}: normalized mismatch",
            feed.name
        );

        if feed.name == "sans_isc_shodan" {
            assert!(
                parsed.iter().all(|r| r.last_seen_at.is_some()),
                "sans_isc_shodan must extract last_seen_at timestamps"
            );
        }

        let (kept, removed) = simply_ip_sync::bogon::sanitize(normalized);
        let expected_kept: Vec<String> = feed
            .expected_after_bogon
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(kept, expected_kept, "{}: bogon-kept mismatch", feed.name);
        assert_eq!(
            removed, feed.expected_removed_bogons,
            "{}: bogon-removed count mismatch",
            feed.name
        );
    }
}

#[tokio::test]
async fn sans_isc_shodan_sends_configured_user_agent_header() {
    use sea_orm::{ActiveModelTrait, Set};
    use simply_ip_sync::entities::{destination_group, external_source};
    use uuid::Uuid;
    use wiremock::matchers::header;

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/threatlist/shodan"))
        .and(header("user-agent", "simply_ip_sync/1.0"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"[{"ipv4":"8.8.4.4","lastseen":"2026-11-20"},{"ipv4":"203.0.113.5","lastseen":"2026-11-21T12:00:00Z"}]"#,
        ))
        .expect(1)
        .mount(&server)
        .await;

    let conn = sea_orm::Database::connect("sqlite::memory:")
        .await
        .expect("connect");
    simply_ip_sync::db::run_migrations(&conn)
        .await
        .expect("migrate");
    let master_id = Uuid::new_v4();
    let now = time::OffsetDateTime::now_utc();
    simply_ip_sync::entities::api_key::ActiveModel {
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
    }
    .insert(&conn)
    .await
    .expect("insert master");

    let mut state = simply_ip_sync::state::AppState::for_tests(conn.clone(), master_id)
        .expect("build test state")
        .with_allow_private_ingest_urls(true);
    state.http = local_http_client();

    let group_id = Uuid::new_v4();
    destination_group::ActiveModel {
        id: Set(group_id),
        name: Set("shodan-ua-group".to_owned()),
        target_group_name: Set("problematics_ips".to_owned()),
        cron_schedule: Set("0 1 * * *".to_owned()),
        mode: Set("upsert".to_owned()),
        is_active: Set(true),
        skip_bogon_filtering: Set(false),
        last_run_at: Set(None),
        owner_key_id: Set(Some(master_id)),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&conn)
    .await
    .expect("insert group");

    external_source::ActiveModel {
        id: Set(Uuid::new_v4()),
        destination_group_id: Set(group_id),
        name: Set("sans_isc_shodan".to_owned()),
        source_url: Set(format!("{}/api/threatlist/shodan?json", server.uri())),
        parser_type: Set("JSON_PATH".to_owned()),
        parser_config_json: Set(Some(
            r#"{"target_address":"$.ipv4","last_seen_at":"$.lastseen","user_agent":"simply_ip_sync/1.0"}"#
                .to_owned(),
        )),
        max_age_days: Set(None),
        skip_bogon_filtering: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&conn)
    .await
    .expect("insert feed");

    let summary = simply_ip_sync::jobs::external_ingestion::run(&state, group_id)
        .await
        .expect("job runs");
    assert_eq!(summary.status, "SUCCESS");
    assert_eq!(summary.items_processed, 1);
}
