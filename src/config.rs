//! Environment parsing and client-address resolution.
//!
//! Everything here is pure enough to unit-test without a process or a database. Two variables are
//! security boundaries and fail hard at startup on a malformed value (`TRUSTED_PROXIES`,
//! `INITIAL_MASTER_KEY`); the rest are operational tuning and fail soft to a default with a
//! logged warning, because refusing to boot over a tuning typo trades a real outage for a small
//! one.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;

use ipnetwork::IpNetwork;

/// Hard requirement on `INITIAL_MASTER_KEY`: exactly this many hex characters, matching what
/// `crypto::generate_signing_secret` itself emits.
pub const MASTER_KEY_HEX_LEN: usize = 64;

/// Environment variable carrying an operator-supplied bootstrap Master key.
pub const INITIAL_MASTER_KEY_ENV: &str = "INITIAL_MASTER_KEY";

/// Environment variable carrying an operator-supplied bootstrap Master HMAC signing secret.
/// Optional: when unset, one is generated randomly and logged once at boot (see
/// `main.rs::bootstrap_master_key`). Setting this deterministically is useful for test harnesses
/// (e.g. `scripts/test_e2e.sh`) that need to sign requests as Master without scraping a
/// buffered/redirected server log — the same reasoning `INITIAL_MASTER_KEY` itself exists for.
pub const INITIAL_MASTER_SIGNING_SECRET_ENV: &str = "INITIAL_MASTER_SIGNING_SECRET";

/// Default maximum request body size, in mebibytes, when `MAX_BODY_SIZE_MIB` is unset.
pub const DEFAULT_MAX_BODY_MIB: usize = 10;

/// `TRUSTED_PROXIES` failed to parse as a comma-separated list of CIDRs/IP addresses.
#[derive(Debug, thiserror::Error)]
#[error("invalid TRUSTED_PROXIES entry: {0}")]
pub struct InvalidTrustedProxies(pub String);

/// `INITIAL_MASTER_KEY` was set but is not exactly `MASTER_KEY_HEX_LEN` hex characters.
#[derive(Debug, thiserror::Error)]
#[error("INITIAL_MASTER_KEY must be exactly {MASTER_KEY_HEX_LEN} hex characters")]
pub struct InvalidInitialMasterKey;

/// `INITIAL_MASTER_SIGNING_SECRET` was set but is not exactly `MASTER_KEY_HEX_LEN` hex characters.
#[derive(Debug, thiserror::Error)]
#[error("INITIAL_MASTER_SIGNING_SECRET must be exactly {MASTER_KEY_HEX_LEN} hex characters")]
pub struct InvalidInitialMasterSigningSecret;

/// Parses `TRUSTED_PROXIES` into a list of CIDR networks. Malformed entries are a hard error —
/// this is a security boundary, not a tuning knob.
pub fn parse_trusted_proxies(raw: &str) -> Result<Vec<IpNetwork>, InvalidTrustedProxies> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|entry| {
            entry
                .parse::<IpNetwork>()
                .map_err(|_| InvalidTrustedProxies(entry.to_owned()))
        })
        .collect()
}

/// Loads and parses `TRUSTED_PROXIES` from the environment. An unset variable yields an empty
/// (nothing trusted) list.
pub fn trusted_proxies_from_env() -> Result<Vec<IpNetwork>, InvalidTrustedProxies> {
    match std::env::var("TRUSTED_PROXIES") {
        Ok(raw) if !raw.trim().is_empty() => parse_trusted_proxies(&raw),
        _ => Ok(Vec::new()),
    }
}

/// Unwraps an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its IPv4 form. Several `is_*` checks
/// on `Ipv6Addr` (e.g. `is_loopback`) are false for the mapped form even when the underlying
/// address is loopback.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// True if `ip` falls within any network in `trusted`.
pub fn is_trusted(ip: IpAddr, trusted: &[IpNetwork]) -> bool {
    trusted.iter().any(|net| net.contains(ip))
}

/// Resolves the real client address for `peer` given the inbound headers and the configured
/// trusted-proxy list.
///
/// `X-Forwarded-For` is honoured **only** when the immediate TCP peer is itself a trusted proxy;
/// otherwise a client could simply forge the header. When trusted, the chain is walked
/// right-to-left (the entry closest to the trusted proxy is the one it actually observed),
/// skipping any further trusted hops, so a chain of trusted proxies still resolves to the real
/// originating address. Falls back to `X-Real-IP`, then the raw peer address.
pub fn resolve_client_ip(peer: IpAddr, headers: &axum::http::HeaderMap, trusted: &[IpNetwork]) -> IpAddr {
    let peer = normalize_ip(peer);
    if !is_trusted(peer, trusted) {
        return peer;
    }
    if let Some(forwarded) = headers.get("X-Forwarded-For").and_then(|h| h.to_str().ok()) {
        let client = forwarded
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .map(normalize_ip)
            .rev()
            .find(|ip| !is_trusted(*ip, trusted));
        if let Some(client) = client {
            return client;
        }
    }
    if let Some(real_ip) = headers
        .get("X-Real-IP")
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .and_then(|s| s.parse::<IpAddr>().ok())
    {
        return normalize_ip(real_ip);
    }
    peer
}

/// Validates an operator-supplied `INITIAL_MASTER_KEY`. Fatal on failure: this credential
/// administers every other credential in the service.
pub fn validate_initial_master_key(raw: &str) -> Result<(), InvalidInitialMasterKey> {
    if raw.len() == MASTER_KEY_HEX_LEN && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(InvalidInitialMasterKey)
    }
}

/// Validates an operator-supplied `INITIAL_MASTER_SIGNING_SECRET`. Fatal on failure, for the same
/// reason as `validate_initial_master_key`: a malformed value here would otherwise boot with a
/// broken Master identity that can never sign a request, and rotation is refused for the Master
/// key through the API (RBAC §5), so there would be no recovery path short of deleting the row.
pub fn validate_initial_master_signing_secret(raw: &str) -> Result<(), InvalidInitialMasterSigningSecret> {
    if raw.len() == MASTER_KEY_HEX_LEN && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(InvalidInitialMasterSigningSecret)
    }
}

/// Parses a `BIND_HOST`/`HOST` value combined with `PORT` into a `SocketAddr`. Defaults to
/// `0.0.0.0:3003`.
pub fn resolve_bind_addr() -> SocketAddr {
    let host = std::env::var("BIND_HOST")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "0.0.0.0".to_owned());
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3003);
    match host.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, port),
        Err(_) => {
            tracing::warn!("BIND_HOST '{host}' is not a valid IP address, defaulting to 0.0.0.0");
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
        }
    }
}

fn max_body_bytes_cell() -> &'static OnceLock<usize> {
    static CELL: OnceLock<usize> = OnceLock::new();
    &CELL
}

/// Maximum accepted request body size, in bytes. Read once from `MAX_BODY_SIZE_MIB` (default
/// [`DEFAULT_MAX_BODY_MIB`], clamped to at least 1 MiB). Called by both the router's
/// `DefaultBodyLimit` and the inbound auth middleware's signed-body buffer cap, so the two layers
/// can never drift into a band of sizes one accepts and the other refuses.
pub fn max_body_bytes() -> usize {
    *max_body_bytes_cell().get_or_init(|| {
        let mib = std::env::var("MAX_BODY_SIZE_MIB")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v >= 1)
            .unwrap_or_else(|| {
                if std::env::var("MAX_BODY_SIZE_MIB").is_ok() {
                    tracing::warn!(
                        "MAX_BODY_SIZE_MIB is not a valid positive integer, using default of {DEFAULT_MAX_BODY_MIB} MiB"
                    );
                }
                DEFAULT_MAX_BODY_MIB
            });
        mib * 1024 * 1024
    })
}

/// Default outbound HTTP timeout, in seconds, when `OUTBOUND_HTTP_TIMEOUT_SECS` is unset.
pub const DEFAULT_OUTBOUND_HTTP_TIMEOUT_SECS: u64 = 60;

fn outbound_http_timeout_cell() -> &'static OnceLock<u64> {
    static CELL: OnceLock<u64> = OnceLock::new();
    &CELL
}

/// Total per-request timeout, in seconds, for outbound calls to remote vault endpoints
/// (`client::build_http_client`). Read once from `OUTBOUND_HTTP_TIMEOUT_SECS` (default
/// [`DEFAULT_OUTBOUND_HTTP_TIMEOUT_SECS`], clamped to at least 1s) — a tuning value, not a
/// security boundary, so a malformed setting fails soft to the default with a logged warning
/// rather than refusing to boot. A hung remote target must never stall a scheduled job
/// indefinitely; this is the bound that guarantees it eventually gives up and reports `FAILED`.
pub fn outbound_http_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(*outbound_http_timeout_cell().get_or_init(|| {
        std::env::var("OUTBOUND_HTTP_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v >= 1)
            .unwrap_or_else(|| {
                if std::env::var("OUTBOUND_HTTP_TIMEOUT_SECS").is_ok() {
                    tracing::warn!(
                        "OUTBOUND_HTTP_TIMEOUT_SECS is not a valid positive integer, using default of {DEFAULT_OUTBOUND_HTTP_TIMEOUT_SECS}s"
                    );
                }
                DEFAULT_OUTBOUND_HTTP_TIMEOUT_SECS
            })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn parse_trusted_proxies_accepts_cidr_and_bare_ip() {
        let parsed = parse_trusted_proxies("10.0.0.0/8, 192.168.1.5").expect("parses");
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn parse_trusted_proxies_rejects_garbage() {
        assert!(parse_trusted_proxies("not-an-ip").is_err());
    }

    #[test]
    fn resolve_client_ip_ignores_xff_from_untrusted_peer() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "1.2.3.4".parse().unwrap());
        let peer: IpAddr = "203.0.113.7".parse().unwrap();
        let resolved = resolve_client_ip(peer, &headers, &[]);
        assert_eq!(resolved, peer);
    }

    #[test]
    fn resolve_client_ip_walks_xff_right_to_left_skipping_trusted_hops() {
        let trusted: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        let mut headers = HeaderMap::new();
        // real client, intermediate trusted proxy, edge trusted proxy (closest to us)
        headers.insert("X-Forwarded-For", "198.51.100.9, 10.0.0.5, 10.0.0.1".parse().unwrap());
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let resolved = resolve_client_ip(peer, &headers, &trusted);
        assert_eq!(resolved, "198.51.100.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn validate_initial_master_key_accepts_64_hex_chars() {
        let key = "a".repeat(64);
        assert!(validate_initial_master_key(&key).is_ok());
    }

    #[test]
    fn validate_initial_master_key_rejects_wrong_length() {
        assert!(validate_initial_master_key("abcd").is_err());
    }

    #[test]
    fn validate_initial_master_key_rejects_non_hex() {
        let key = "z".repeat(64);
        assert!(validate_initial_master_key(&key).is_err());
    }

    #[test]
    fn validate_initial_master_signing_secret_accepts_64_hex_chars() {
        let secret = "b".repeat(64);
        assert!(validate_initial_master_signing_secret(&secret).is_ok());
    }

    #[test]
    fn validate_initial_master_signing_secret_rejects_wrong_length() {
        assert!(validate_initial_master_signing_secret("abcd").is_err());
    }

    #[test]
    fn normalize_ip_unwraps_v4_mapped_v6() {
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert_eq!(normalize_ip(mapped), "127.0.0.1".parse::<IpAddr>().unwrap());
    }
}
