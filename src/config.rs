//! Environment parsing and client-address resolution.
//!
//! Everything here is pure enough to unit-test without a process or a database. Two variables are
//! security boundaries and fail hard at startup on a malformed value (`TRUSTED_PROXIES`,
//! `INITIAL_MASTER_KEY`); the rest are operational tuning and fail soft to a default with a
//! logged warning, because refusing to boot over a tuning typo trades a real outage for a small
//! one.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use ipnetwork::IpNetwork;
use tokio::sync::RwLock;

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

/// `INITIAL_MASTER_KEY_ENV` was set to something that is not a 32-byte hex key.
///
/// # Why this is fatal rather than a warning
///
/// The credential this guards administers every other credential in the service, so there is no
/// legitimate deployment that needs a short or non-hex master key: an operator who wants a
/// *deterministic* one still gets it (they supply 64 hex characters), and one who wants a *strong*
/// one leaves the variable unset. A warning in a startup log is not read by whoever set
/// `INITIAL_MASTER_KEY=changeme` in a compose file — refusing to start is the only objection that
/// actually stops it. Checked before any of it reaches the database, so a rejected key never
/// becomes the Master row.
#[derive(Debug, thiserror::Error)]
#[error(
    "{INITIAL_MASTER_KEY_ENV} must be exactly {MASTER_KEY_HEX_LEN} hexadecimal characters (32 bytes \
     of entropy) — the same shape this service generates for itself. Got {got} character(s){detail}. \
     Generate one with `openssl rand -hex 32`, or unset the variable to have one generated. \
     Refusing to start: a weak master key is the single credential that can administer everything."
)]
pub struct InvalidInitialMasterKey {
    /// How many characters were supplied.
    pub got: usize,
    /// `", and it contains non-hexadecimal characters"` when that is also true, else empty.
    pub detail: &'static str,
}

/// `INITIAL_MASTER_SIGNING_SECRET_ENV` was set to something that is not a 32-byte hex key. Same
/// rationale as [`InvalidInitialMasterKey`]: rotation is refused for the Master key through the
/// API (RBAC §5), so a malformed value here would boot with a Master identity that can never sign
/// a request and has no recovery path short of deleting the row.
#[derive(Debug, thiserror::Error)]
#[error(
    "{INITIAL_MASTER_SIGNING_SECRET_ENV} must be exactly {MASTER_KEY_HEX_LEN} hexadecimal \
     characters (32 bytes of entropy). Got {got} character(s){detail}. Generate one with \
     `openssl rand -hex 32`, or unset the variable to have one generated. Refusing to start."
)]
pub struct InvalidInitialMasterSigningSecret {
    /// How many characters were supplied.
    pub got: usize,
    /// `", and it contains non-hexadecimal characters"` when that is also true, else empty.
    pub detail: &'static str,
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

// ─────────────────────────────────────────────────────────────
// TRUSTED_PROXIES — hostnames as well as IPs/CIDRs
// ─────────────────────────────────────────────────────────────
//
// A container orchestrator (Docker Compose, Kubernetes) routinely gives a reverse proxy a stable
// *name* (`traefik`, `traefik_tomidejetsu`) rather than a stable address — the address changes on
// every recreate, the name does not. `TRUSTED_PROXIES` therefore accepts a hostname alongside a
// CIDR/IP, resolved at request time (not once at startup) so a proxy container's restart-and-new-IP
// never silently stops it from being trusted.

/// Comma-separated list of IPs, CIDRs, or **hostnames** whose members are allowed to set
/// `X-Forwarded-For` and `X-Real-IP` (e.g. `TRUSTED_PROXIES=10.0.0.0/8,192.168.1.5,traefik`).
pub const TRUSTED_PROXIES_ENV: &str = "TRUSTED_PROXIES";

/// How long a successful hostname resolution is reused before being looked up again.
///
/// Short on purpose. A container that is recreated keeps its name and gets a new address, and
/// until this expires the old address is still trusted while the new one is not — the first is a
/// brief over-trust of an address the orchestrator has probably already reassigned, the second a
/// visible `403`. 30s keeps both windows small without turning every request into a DNS lookup.
const POSITIVE_TTL: Duration = Duration::from_secs(30);

/// How long a *failed* resolution is remembered before being retried — negative caching.
///
/// Deliberately much shorter than [`POSITIVE_TTL`] but deliberately non-zero: without it, every
/// request arriving while a configured hostname is unresolvable triggers its own DNS lookup, which
/// turns a dead name behind a hot path into a resolution amplifier (one inbound request becomes one
/// outbound query at whatever rate the caller chooses). With it, the cost is bounded to one query
/// per name per interval no matter how much traffic arrives.
const NEGATIVE_TTL: Duration = Duration::from_secs(5);

/// How long after boot an initially-unresolvable hostname is given before the failure is reported
/// as persistent.
///
/// A daemon and its reverse proxy usually start together, and the proxy's DNS record may not exist
/// for the first few seconds of the daemon's life. Aborting startup over that would turn an
/// ordinary boot race into a crash loop, which is strictly worse than running: a service that is up
/// with one proxy entry disabled still serves every other caller correctly. The entry stays
/// untrusted for the duration (fail closed, for that entry only), and the outcome is logged either
/// way.
const BOOT_GRACE_PERIOD: Duration = Duration::from_secs(60);

/// A `TRUSTED_PROXIES` entry that is not a valid spelling of anything, and why.
///
/// Distinct from a hostname that merely fails to resolve *right now*: this is a value that can
/// never become usable no matter what DNS does, so it is a configuration error rather than a
/// transient one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidProxyEntry {
    /// The entry exactly as written, so the operator can find it in their configuration.
    pub entry: String,
    /// Why it was refused, phrased to name the mistake rather than the rule.
    pub reason: &'static str,
}

/// Startup refusal: at least one `TRUSTED_PROXIES` entry was syntactically impossible.
///
/// This aborts rather than dropping the entry, unlike every other malformed override in this
/// module: `TRUSTED_PROXIES` is the list of peers permitted to rewrite the client address every
/// authorization decision is made against, and a silently-dropped entry fails closed for itself but
/// leaves every request through that proxy attributed to the proxy's own address — an outage whose
/// cause is one `warn!` line nobody reads until the incident. It is safe to be this strict because
/// the check is purely syntactic: a hostname that is well-formed but currently unresolvable is not
/// an error here at all (see [`BOOT_GRACE_PERIOD`]).
#[derive(Debug, thiserror::Error)]
#[error(
    "{} invalid {TRUSTED_PROXIES_ENV} entr{}: {}",
    entries.len(),
    if entries.len() == 1 { "y" } else { "ies" },
    entries.iter().map(|e| format!("{:?} ({})", e.entry, e.reason)).collect::<Vec<_>>().join("; ")
)]
pub struct InvalidTrustedProxies {
    /// Every rejected entry, so one restart surfaces all of the typos rather than the first.
    pub entries: Vec<InvalidProxyEntry>,
}

/// A `TRUSTED_PROXIES` entry: either a fixed network or a name resolved at request time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyMatcher {
    /// A literal address or CIDR range, matched directly.
    Network(IpNetwork),
    /// A hostname (`traefik`, `proxy.internal`) resolved via DNS.
    ///
    /// Kept as a name rather than resolved once at startup because that is the entire point: in
    /// Docker and Kubernetes a service name outlives the address behind it, and a container
    /// restart that changes the IP must not silently stop the proxy from being trusted.
    Hostname(String),
}

impl std::fmt::Display for ProxyMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(network) => write!(f, "{network}"),
            Self::Hostname(name) => write!(f, "{name}"),
        }
    }
}

/// One hostname's last resolution attempt.
#[derive(Clone)]
struct HostnameState {
    /// What the name resolved to, empty when the lookup failed.
    addresses: Vec<IpNetwork>,
    /// When the attempt ran.
    attempted_at: Instant,
    /// Whether it produced at least one address.
    resolved: bool,
}

impl HostnameState {
    /// Whether this attempt may still be reused, per the positive/negative TTL split.
    fn is_fresh(&self, positive: Duration, negative: Duration) -> bool {
        let ttl = if self.resolved { positive } else { negative };
        self.attempted_at.elapsed() < ttl
    }
}

/// The merged view every request is matched against, plus the per-hostname state behind it.
#[derive(Default)]
struct ResolutionCache {
    /// Literal networks merged with whatever the hostnames currently resolve to.
    snapshot: Arc<Vec<IpNetwork>>,
    /// Per-hostname attempt state, which is what makes negative caching per-name rather than
    /// all-or-nothing: one dead entry must not force the healthy ones to be re-resolved on its
    /// short retry interval.
    hosts: HashMap<String, HostnameState>,
    /// Whether `snapshot` reflects the current `hosts` map.
    built: bool,
}

impl std::fmt::Debug for ResolutionCache {
    /// Renders nothing of substance: a `{:?}` of application state should describe what the
    /// operator configured, not which addresses a name happened to resolve to a moment ago.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<resolution cache>")
    }
}

/// The set of peers whose forwarding headers are believed.
///
/// Holds the parsed `TRUSTED_PROXIES` specification plus a short-lived cache of resolved hostnames.
/// Cloning shares the cache, so every clone of `AppState` sees one resolution rather than each
/// maintaining its own — the same reason every other security-relevant field in `AppState` is
/// `Arc`-backed.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies {
    /// The configuration exactly as written, for logging.
    matchers: Arc<Vec<ProxyMatcher>>,
    /// Literal entries, precomputed. Also the complete answer when no hostnames are configured —
    /// the common case, served for the cost of an `Arc` clone and no lock at all.
    networks: Arc<Vec<IpNetwork>>,
    /// Hostname entries awaiting resolution.
    hostnames: Arc<Vec<String>>,
    /// Reuse window for a successful lookup.
    positive_ttl: Duration,
    /// Reuse window for a failed lookup.
    negative_ttl: Duration,
    cache: Arc<RwLock<ResolutionCache>>,
}

impl TrustedProxies {
    /// Builds from an already-parsed matcher list.
    pub fn new(matchers: Vec<ProxyMatcher>) -> Self {
        let networks: Vec<IpNetwork> = matchers
            .iter()
            .filter_map(|m| match m {
                ProxyMatcher::Network(net) => Some(*net),
                ProxyMatcher::Hostname(_) => None,
            })
            .collect();
        let hostnames: Vec<String> = matchers
            .iter()
            .filter_map(|m| match m {
                ProxyMatcher::Hostname(name) => Some(name.clone()),
                ProxyMatcher::Network(_) => None,
            })
            .collect();

        Self {
            matchers: Arc::new(matchers),
            networks: Arc::new(networks),
            hostnames: Arc::new(hostnames),
            positive_ttl: POSITIVE_TTL,
            negative_ttl: NEGATIVE_TTL,
            cache: Arc::new(RwLock::new(ResolutionCache::default())),
        }
    }

    /// Reads and parses [`TRUSTED_PROXIES_ENV`], refusing to build if any entry is malformed.
    ///
    /// Every rejected entry is logged on its own `FATAL:` line before the error is returned, so an
    /// operator with three typos sees three lines naming three entries, not one line naming the
    /// first. This runs before any DNS resolution or grace-period logic — the check is syntactic,
    /// so there is nothing to wait for.
    ///
    /// An **unset** variable is not an error. That is the zero-configuration case, and it means
    /// "trust nothing", which is the safe posture rather than an ambiguous one.
    pub fn from_env() -> Result<Self, InvalidTrustedProxies> {
        let Ok(raw) = std::env::var(TRUSTED_PROXIES_ENV) else {
            return Ok(Self::default());
        };
        if raw.trim().is_empty() {
            return Ok(Self::default());
        }

        match parse_trusted_proxies(&raw) {
            Ok(matchers) => Ok(Self::new(matchers)),
            Err(entries) => {
                for invalid in &entries {
                    tracing::error!(
                        "FATAL: {} entry '{}' is not a valid IP address, CIDR range, or hostname \
                         ({}). Refusing to start with an ambiguous trust boundary.",
                        TRUSTED_PROXIES_ENV,
                        invalid.entry,
                        invalid.reason
                    );
                }
                Err(InvalidTrustedProxies { entries })
            }
        }
    }

    /// Overrides both DNS reuse windows. Test-facing: a suite cannot wait 30 seconds to observe
    /// that a re-resolution happened, nor 5 to observe that one was suppressed.
    #[cfg(test)]
    pub fn with_ttls(mut self, positive: Duration, negative: Duration) -> Self {
        self.positive_ttl = positive;
        self.negative_ttl = negative;
        self
    }

    /// Whether anything at all is trusted. An empty configuration ignores forwarding headers.
    pub fn is_empty(&self) -> bool {
        self.matchers.is_empty()
    }

    /// The configured matchers, for startup logging.
    pub fn matchers(&self) -> &[ProxyMatcher] {
        &self.matchers
    }

    /// The networks to match this request against, resolving hostnames when their cache entry has
    /// expired.
    ///
    /// Returns an [`Arc`] rather than a fresh `Vec` so the steady-state cost is a refcount bump.
    /// The no-hostname case — every deployment that names its proxies by address — never touches
    /// the lock or the resolver at all.
    ///
    /// Resolving the *whole set* into one flat list, rather than testing hostnames lazily on a
    /// per-address basis, is what lets [`resolve_client_ip`] treat a hostname-identified proxy
    /// exactly like a CIDR one while walking the `X-Forwarded-For` chain.
    pub async fn resolved(&self) -> Arc<Vec<IpNetwork>> {
        if self.hostnames.is_empty() {
            return Arc::clone(&self.networks);
        }

        {
            let cache = self.cache.read().await;
            if cache.built
                && self.hostnames.iter().all(|name| {
                    cache.hosts.get(name).is_some_and(|s| s.is_fresh(self.positive_ttl, self.negative_ttl))
                })
            {
                return Arc::clone(&cache.snapshot);
            }
        }

        // Re-check under the write lock: several requests can queue behind one expiry, and only
        // the first should pay for the lookup.
        let mut cache = self.cache.write().await;
        self.refresh_locked(&mut cache).await;
        Arc::clone(&cache.snapshot)
    }

    /// Re-resolves every hostname whose cached attempt has expired, then rebuilds the snapshot.
    async fn refresh_locked(&self, cache: &mut ResolutionCache) {
        for name in self.hostnames.iter() {
            if cache.hosts.get(name).is_some_and(|s| s.is_fresh(self.positive_ttl, self.negative_ttl)) {
                continue;
            }

            let addresses = resolve_hostname(name).await;
            let resolved = !addresses.is_empty();
            cache
                .hosts
                .insert(name.clone(), HostnameState { addresses, attempted_at: Instant::now(), resolved });
        }

        let mut merged = (*self.networks).clone();
        for name in self.hostnames.iter() {
            if let Some(state) = cache.hosts.get(name) {
                merged.extend(state.addresses.iter().copied());
            }
        }
        cache.snapshot = Arc::new(merged);
        cache.built = true;
    }

    /// Resolves every configured hostname once at boot, reporting the names that failed.
    ///
    /// Never returns an error and never panics: a name that does not resolve is simply not
    /// trusted, which is the safe direction, and is a per-entry outcome rather than a service-wide
    /// one.
    pub async fn prime(&self) -> Vec<String> {
        if self.hostnames.is_empty() {
            return Vec::new();
        }

        let mut cache = self.cache.write().await;
        // Force a real attempt rather than reusing whatever a concurrent request just cached.
        cache.hosts.clear();
        self.refresh_locked(&mut cache).await;

        self.hostnames.iter().filter(|name| !cache.hosts.get(*name).is_some_and(|s| s.resolved)).cloned().collect()
    }

    /// Primes the set at boot and, if anything failed to resolve, retries once after
    /// [`BOOT_GRACE_PERIOD`] on a detached task.
    ///
    /// The service is fully operational throughout — the unresolved entries are simply untrusted
    /// until they resolve, and normal per-request refresh will pick them up whenever they start
    /// working. The grace retry exists so the *logs* distinguish a boot race that healed itself
    /// from a genuine misconfiguration, without an operator having to correlate timestamps.
    pub fn prime_with_grace(&self) {
        let proxies = self.clone();
        tokio::spawn(async move {
            let failed = proxies.prime().await;
            if failed.is_empty() {
                if !proxies.hostnames.is_empty() {
                    tracing::info!(
                        "All {} {} hostname entr{} resolved at startup.",
                        proxies.hostnames.len(),
                        TRUSTED_PROXIES_ENV,
                        if proxies.hostnames.len() == 1 { "y" } else { "ies" }
                    );
                }
                return;
            }

            tracing::error!(
                "{} hostname entr{} did not resolve at startup: {:?}. Those peers are NOT trusted \
                 and their forwarding headers will be ignored; every other entry is unaffected and \
                 the service is serving normally. Retrying in {}s.",
                TRUSTED_PROXIES_ENV,
                if failed.len() == 1 { "y" } else { "ies" },
                failed,
                BOOT_GRACE_PERIOD.as_secs()
            );

            tokio::time::sleep(BOOT_GRACE_PERIOD).await;
            let still_failing = proxies.prime().await;
            if still_failing.is_empty() {
                tracing::info!(
                    "All {} hostname entries resolved after the {}s grace period; they are trusted \
                     from now on.",
                    TRUSTED_PROXIES_ENV,
                    BOOT_GRACE_PERIOD.as_secs()
                );
            } else {
                tracing::error!(
                    "{} hostname entr{} still unresolvable after the {}s grace period: {:?}. \
                     Continuing to serve with {} entr{} disabled — check the name and the \
                     resolver. Resolution is retried automatically; no restart is required.",
                    TRUSTED_PROXIES_ENV,
                    if still_failing.len() == 1 { "y" } else { "ies" },
                    BOOT_GRACE_PERIOD.as_secs(),
                    still_failing,
                    still_failing.len(),
                    if still_failing.len() == 1 { "y" } else { "ies" }
                );
            }
        });
    }
}

/// Resolves one hostname to the host routes it currently names.
///
/// A failure yields nothing rather than propagating: an unresolvable name means "this proxy is not
/// currently trusted", which is the safe direction to fail in. A DNS outage must never be able to
/// *widen* what the daemon believes.
async fn resolve_hostname(hostname: &str) -> Vec<IpNetwork> {
    // Port 0: `lookup_host` wants a socket address, but only the address half is used.
    match tokio::net::lookup_host((hostname, 0u16)).await {
        Ok(addrs) => {
            let networks: Vec<IpNetwork> = addrs.map(|addr| IpNetwork::from(normalize_ip(addr.ip()))).collect();
            if networks.is_empty() {
                tracing::warn!(
                    "TRUSTED_PROXIES hostname {hostname:?} resolved to no addresses; it is not \
                     trusted until it does."
                );
            } else {
                tracing::debug!(
                    "TRUSTED_PROXIES hostname {hostname:?} resolved to {}",
                    networks.iter().map(|n| n.ip().to_string()).collect::<Vec<_>>().join(", ")
                );
            }
            networks
        }
        Err(e) => {
            tracing::warn!(
                "Could not resolve TRUSTED_PROXIES hostname {hostname:?}: {e}. It is not trusted \
                 until resolution succeeds."
            );
            Vec::new()
        }
    }
}

/// Parses a `TRUSTED_PROXIES` value into matchers, or reports every entry that is unusable.
///
/// Three spellings are accepted, tried in order: a CIDR range (`172.16.0.0/12`), a bare address
/// (`127.0.0.1`, promoted to a single-host network so nobody has to remember `/32`), and otherwise
/// a hostname (`traefik`) resolved at request time.
///
/// Anything else is a **hard error** rather than a dropped entry — see [`InvalidTrustedProxies`].
/// Every bad entry is collected rather than the first, so an operator fixing a mistyped list needs
/// one restart and not one per typo.
///
/// The check is purely syntactic and does no I/O: a well-formed hostname is accepted here whether
/// or not it currently resolves, which is what keeps a DNS outage from becoming a refusal to boot.
pub fn parse_trusted_proxies(raw: &str) -> Result<Vec<ProxyMatcher>, Vec<InvalidProxyEntry>> {
    let mut matchers = Vec::new();
    let mut invalid = Vec::new();

    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        if let Ok(net) = entry.parse::<IpNetwork>() {
            matchers.push(ProxyMatcher::Network(net));
        } else if let Ok(addr) = entry.parse::<IpAddr>() {
            matchers.push(ProxyMatcher::Network(IpNetwork::from(addr)));
        } else {
            match hostname_rejection(entry) {
                None => matchers.push(ProxyMatcher::Hostname(entry.to_owned())),
                Some(reason) => invalid.push(InvalidProxyEntry { entry: entry.to_owned(), reason }),
            }
        }
    }

    if invalid.is_empty() { Ok(matchers) } else { Err(invalid) }
}

/// Why `entry` cannot be a DNS name, or `None` when it is shaped like one.
///
/// Returns the *reason* rather than a bool because the reason is the entire value of this check to
/// an operator: "not a valid hostname" sends them to the manual, "made only of digits and dots"
/// sends them to the typo.
///
/// Deliberately strict about the two shapes that are *nearly* addresses. An entry reaching this
/// point already failed to parse as an address and as a CIDR, and the ways that happens are a typo
/// and a hostname:
///
/// - Anything containing `/` or `:` is refused, since those characters appear only in prefix and
///   IPv6 syntax — so a near-miss CIDR like `10.0.0.0/99` surfaces as the configuration error it is
///   rather than a name that silently never matches.
/// - Anything made only of digits and dots is refused for the same reason: `10.0.0.256` is a
///   mistyped IPv4 literal, not a hostname, and treating it as one would hide the typo behind a
///   perfectly quiet non-match.
/// - The first and last characters must be alphanumeric. That is stricter than the RFC, which
///   permits a trailing `.` to mark a fully-qualified name, and the strictness is the point: a
///   trailing separator is far more often a stray comma-splice than a deliberate root anchor, and
///   `tokio::net::lookup_host` treats `proxy.` and `proxy` identically anyway.
fn hostname_rejection(entry: &str) -> Option<&'static str> {
    if entry.is_empty() {
        return Some("empty");
    }
    if entry.len() > 253 {
        return Some("longer than the 253-character limit on a DNS name");
    }
    if entry.contains('/') || entry.contains(':') {
        return Some(
            "contains '/' or ':', which appear only in CIDR and IPv6 syntax, so this is a \
             malformed address rather than a hostname",
        );
    }
    let bytes = entry.as_bytes();
    let edges_are_alphanumeric = bytes
        .first()
        .zip(bytes.last())
        .is_some_and(|(first, last)| first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric());
    if !edges_are_alphanumeric {
        return Some("a hostname must begin and end with a letter or a digit");
    }
    if entry.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Some("made only of digits and dots, so this is a malformed IPv4 literal");
    }
    if !entry.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_') {
        return Some("contains characters that cannot appear in a DNS name");
    }
    None
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
    let is_hex = raw.chars().all(|c| c.is_ascii_hexdigit());
    if raw.len() == MASTER_KEY_HEX_LEN && is_hex {
        return Ok(());
    }
    Err(InvalidInitialMasterKey {
        got: raw.chars().count(),
        detail: if is_hex { "" } else { ", and it contains non-hexadecimal characters" },
    })
}

/// Validates an operator-supplied `INITIAL_MASTER_SIGNING_SECRET`. Fatal on failure, for the same
/// reason as `validate_initial_master_key`: a malformed value here would otherwise boot with a
/// broken Master identity that can never sign a request, and rotation is refused for the Master
/// key through the API (RBAC §5), so there would be no recovery path short of deleting the row.
pub fn validate_initial_master_signing_secret(raw: &str) -> Result<(), InvalidInitialMasterSigningSecret> {
    let is_hex = raw.chars().all(|c| c.is_ascii_hexdigit());
    if raw.len() == MASTER_KEY_HEX_LEN && is_hex {
        return Ok(());
    }
    Err(InvalidInitialMasterSigningSecret {
        got: raw.chars().count(),
        detail: if is_hex { "" } else { ", and it contains non-hexadecimal characters" },
    })
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

/// Default maximum retry attempts for a transient (429/502/503/504) outbound failure, when
/// `OUTBOUND_MAX_RETRIES` is unset.
pub const DEFAULT_OUTBOUND_MAX_RETRIES: u32 = 3;

/// Default base retry backoff, in milliseconds, when `OUTBOUND_RETRY_BACKOFF_MS` is unset.
pub const DEFAULT_OUTBOUND_RETRY_BACKOFF_MS: u64 = 500;

/// Maximum retry attempts for a transient outbound failure (`retry::is_transient_status`) before
/// giving up. Read from `OUTBOUND_MAX_RETRIES` (default [`DEFAULT_OUTBOUND_MAX_RETRIES`]) **fresh
/// on every call, deliberately not cached in a `OnceLock`** unlike this module's other tuning
/// values: retries are the exceptional, rarely-taken path (most requests never hit them), so the
/// extra `env::var` read is immaterial, and staying uncached is what lets a test set this value
/// and see it take effect immediately rather than being stuck with whatever the first caller in
/// the process happened to observe.
pub fn outbound_max_retries() -> u32 {
    std::env::var("OUTBOUND_MAX_RETRIES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or_else(|| {
            if std::env::var("OUTBOUND_MAX_RETRIES").is_ok() {
                tracing::warn!(
                    "OUTBOUND_MAX_RETRIES is not a valid non-negative integer, using default of {DEFAULT_OUTBOUND_MAX_RETRIES}"
                );
            }
            DEFAULT_OUTBOUND_MAX_RETRIES
        })
}

/// Base delay before the first retry of a transient outbound failure; subsequent attempts back
/// off exponentially from this (see `retry::backoff_with_jitter`). Read from
/// `OUTBOUND_RETRY_BACKOFF_MS` (default [`DEFAULT_OUTBOUND_RETRY_BACKOFF_MS`], clamped to at
/// least 1ms) fresh on every call — see `outbound_max_retries`'s doc comment for why this
/// deliberately isn't `OnceLock`-cached.
pub fn outbound_retry_backoff() -> std::time::Duration {
    let ms = std::env::var("OUTBOUND_RETRY_BACKOFF_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v >= 1)
        .unwrap_or_else(|| {
            if std::env::var("OUTBOUND_RETRY_BACKOFF_MS").is_ok() {
                tracing::warn!(
                    "OUTBOUND_RETRY_BACKOFF_MS is not a valid positive integer, using default of {DEFAULT_OUTBOUND_RETRY_BACKOFF_MS}ms"
                );
            }
            DEFAULT_OUTBOUND_RETRY_BACKOFF_MS
        });
    std::time::Duration::from_millis(ms)
}

/// Default ceiling, in bytes, on a decompressed feed body before ingestion aborts, when
/// `MAX_DECOMPRESSED_BYTES` is unset.
pub const DEFAULT_MAX_DECOMPRESSED_BYTES: u64 = 50 * 1024 * 1024;

fn max_decompressed_bytes_cell() -> &'static OnceLock<u64> {
    static CELL: OnceLock<u64> = OnceLock::new();
    &CELL
}

/// Hard ceiling on decompressed feed body size — the defense against a decompression bomb (a
/// small compressed payload, whether via an HTTP `Content-Encoding` reqwest decodes transparently
/// or an internal ZIP member, that expands to gigabytes and exhausts memory before anything gets a
/// chance to reject it). Read once from `MAX_DECOMPRESSED_BYTES` (default
/// [`DEFAULT_MAX_DECOMPRESSED_BYTES`], clamped to at least 1 byte) — a tuning value, not a
/// fail-hard security boundary, so a malformed setting fails soft to the default with a logged
/// warning rather than refusing to boot. Enforced incrementally, never after the fact, by
/// `jobs::decompress::read_capped_body` (streaming the HTTP response body) and
/// `jobs::decompress::decompress_if_zip` (streaming each ZIP member) — both abort as soon as the
/// running total crosses this ceiling, so the oversized remainder is never actually materialized.
pub fn max_decompressed_bytes() -> u64 {
    *max_decompressed_bytes_cell().get_or_init(|| {
        std::env::var("MAX_DECOMPRESSED_BYTES")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v >= 1)
            .unwrap_or_else(|| {
                if std::env::var("MAX_DECOMPRESSED_BYTES").is_ok() {
                    tracing::warn!(
                        "MAX_DECOMPRESSED_BYTES is not a valid positive integer, using default of {DEFAULT_MAX_DECOMPRESSED_BYTES} bytes"
                    );
                }
                DEFAULT_MAX_DECOMPRESSED_BYTES
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn parse_trusted_proxies_accepts_cidr_and_bare_ip() {
        let parsed = parse_trusted_proxies("10.0.0.0/8, 192.168.1.5").expect("parses");
        assert_eq!(parsed.len(), 2);
        assert!(parsed.iter().all(|m| matches!(m, ProxyMatcher::Network(_))));
    }

    /// The exact case the bug report named: a Docker Compose service name containing an
    /// underscore (`traefik_tomidejetsu`). Must parse as a hostname, not be refused as garbage.
    #[test]
    fn parse_trusted_proxies_accepts_docker_style_hostnames() {
        let parsed = parse_trusted_proxies("traefik_tomidejetsu, proxy, traefik.internal").expect("parses");
        assert_eq!(parsed.len(), 3);
        assert!(parsed.iter().all(|m| matches!(m, ProxyMatcher::Hostname(_))));
    }

    #[test]
    fn parse_trusted_proxies_accepts_a_mix_of_cidr_and_hostname() {
        let parsed = parse_trusted_proxies("172.16.0.0/12, traefik").expect("parses");
        assert_eq!(parsed.len(), 2);
        assert!(matches!(parsed[0], ProxyMatcher::Network(_)));
        assert!(matches!(parsed[1], ProxyMatcher::Hostname(_)));
    }

    /// A near-miss CIDR (`/` present, but not a valid prefix) must surface as the configuration
    /// error it is, not be silently reinterpreted as a hostname — `hostname_rejection` refuses
    /// anything containing `/` or `:` for exactly this reason.
    #[test]
    fn parse_trusted_proxies_rejects_a_malformed_cidr_rather_than_treating_it_as_a_hostname() {
        let err = parse_trusted_proxies("10.0.0.0/99").expect_err("not a valid CIDR");
        assert_eq!(err.len(), 1);
        assert_eq!(err[0].entry, "10.0.0.0/99");
    }

    /// A mistyped IPv4 literal (digits and dots only) must be reported as such, not accepted as a
    /// hostname that will then silently never match anything.
    #[test]
    fn parse_trusted_proxies_rejects_a_malformed_ipv4_literal() {
        let err = parse_trusted_proxies("10.0.0.256").expect_err("not a valid address");
        assert_eq!(err.len(), 1);
    }

    #[test]
    fn parse_trusted_proxies_rejects_characters_that_cannot_appear_in_a_dns_name() {
        assert!(parse_trusted_proxies("!!!not-valid!!!").is_err());
    }

    #[test]
    fn parse_trusted_proxies_collects_every_bad_entry_not_just_the_first() {
        let err = parse_trusted_proxies("10.0.0.0/99, good-hostname, !!!bad!!!").expect_err("two bad entries");
        assert_eq!(err.len(), 2, "one restart should surface both typos: {err:?}");
    }

    /// `localhost` resolves on every platform this runs on, so it exercises the real DNS path.
    #[tokio::test]
    async fn a_hostname_entry_is_resolved_and_matched() {
        let trusted = TrustedProxies::new(vec![ProxyMatcher::Hostname("localhost".to_owned())]);
        let resolved = trusted.resolved().await;

        assert!(
            is_trusted("127.0.0.1".parse().unwrap(), &resolved)
                || is_trusted("::1".parse().unwrap(), &resolved),
            "localhost should resolve to a loopback address: {resolved:?}"
        );
        assert!(!is_trusted("203.0.113.9".parse().unwrap(), &resolved), "an unrelated address must not match");
    }

    /// Docker/Traefik shape: a container name alongside the bridge network CIDR. Either may match.
    #[tokio::test]
    async fn docker_style_configuration_matches_by_cidr_or_by_hostname() {
        let trusted =
            TrustedProxies::new(vec!["172.16.0.0/12".parse().map(ProxyMatcher::Network).unwrap(), ProxyMatcher::Hostname("localhost".to_owned())])
                .resolved()
                .await;

        assert!(is_trusted("172.17.0.5".parse().unwrap(), &trusted), "docker bridge CIDR matches");
        assert!(is_trusted("127.0.0.1".parse().unwrap(), &trusted), "the named service matches");
        assert!(!is_trusted("192.0.2.7".parse().unwrap(), &trusted), "anything else does not");
    }

    /// Failing closed matters: a DNS outage must never be able to *widen* what is trusted, and it
    /// must not take the healthy literal entries down with it.
    #[tokio::test]
    async fn an_unresolvable_hostname_trusts_nobody_but_disables_only_itself() {
        // `.invalid` is reserved by RFC 2606 and is guaranteed to never resolve.
        let trusted = TrustedProxies::new(vec![
            ProxyMatcher::Hostname("this-host-does-not-exist.invalid".to_owned()),
            "10.0.0.0/8".parse().map(ProxyMatcher::Network).unwrap(),
        ]);
        let resolved = trusted.resolved().await;

        assert!(is_trusted("10.1.2.3".parse().unwrap(), &resolved), "the literal entry still applies");
        assert_eq!(resolved.len(), 1, "the unresolvable name contributes nothing: {resolved:?}");
    }

    /// A resolution is reused rather than re-queried on every request within the TTL window —
    /// `resolved()` hands back the same `Arc` when nothing has expired.
    #[tokio::test]
    async fn a_fresh_resolution_is_served_from_cache_not_re_queried() {
        let trusted = TrustedProxies::new(vec![ProxyMatcher::Hostname("localhost".to_owned())])
            .with_ttls(Duration::from_secs(30), Duration::from_secs(30));
        let first = trusted.resolved().await;
        let second = trusted.resolved().await;
        assert!(Arc::ptr_eq(&first, &second), "an unexpired resolution must be reused, not re-queried");
    }

    /// The no-hostname path (every deployment naming its proxies by address) must never touch the
    /// resolution lock at all — the common case pays nothing for hostname support existing.
    #[tokio::test]
    async fn no_hostnames_never_touches_the_cache() {
        let trusted = TrustedProxies::new(vec!["10.0.0.0/8".parse().map(ProxyMatcher::Network).unwrap()]);
        let first = trusted.resolved().await;
        let second = trusted.resolved().await;
        assert!(Arc::ptr_eq(&first, &second), "same allocation each time: nothing was rebuilt");
    }

    #[test]
    fn hostname_syntax_accepts_container_names_and_rejects_near_miss_addresses() {
        for name in ["traefik", "traefik_tomidejetsu", "proxy-1", "traefik.internal", "a", "a1"] {
            assert!(hostname_rejection(name).is_none(), "{name:?} must be accepted as a hostname");
        }
        for garbage in ["10.0.0.0/8", "::1", "10.0.0.256", "-leading-hyphen", "trailing-hyphen-", ""] {
            assert!(hostname_rejection(garbage).is_some(), "{garbage:?} must be refused");
        }
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

    /// The error must name the actual character count so an operator can tell "too short" from
    /// "too long" without counting it themselves.
    #[test]
    fn invalid_initial_master_key_reports_the_actual_length_supplied() {
        let err = validate_initial_master_key("abcd").unwrap_err();
        assert_eq!(err.got, 4);
        assert_eq!(err.detail, "");
        assert!(err.to_string().contains("Got 4 character"), "{err}");
    }

    #[test]
    fn invalid_initial_master_key_reports_non_hex_characters() {
        let key = "z".repeat(64);
        let err = validate_initial_master_key(&key).unwrap_err();
        assert_eq!(err.got, 64);
        assert!(err.detail.contains("non-hexadecimal"));
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

    #[test]
    fn outbound_max_retries_defaults_when_unset() {
        // SAFETY: test-only env mutation; this key is not read anywhere else concurrently within
        // this single-threaded assertion.
        unsafe {
            std::env::remove_var("OUTBOUND_MAX_RETRIES");
        }
        assert_eq!(outbound_max_retries(), DEFAULT_OUTBOUND_MAX_RETRIES);
    }

    #[test]
    fn outbound_retry_backoff_defaults_when_unset() {
        unsafe {
            std::env::remove_var("OUTBOUND_RETRY_BACKOFF_MS");
        }
        assert_eq!(outbound_retry_backoff(), std::time::Duration::from_millis(DEFAULT_OUTBOUND_RETRY_BACKOFF_MS));
    }
}
