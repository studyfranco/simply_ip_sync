//! Pre-push IP sanitization: filters loopback, unspecified, private (RFC 1918), link-local, and
//! other non-routable/reserved ("bogon") addresses out of a record set before it is pushed to a
//! target vault.
//!
//! Modeled on `example/simply_ip_exporter`'s `src/ipfilter.rs` — same hand-rolled CIDR literal
//! tables (not `std::net`'s or `ipnetwork`'s built-in `.is_private()`/`.is_loopback()` methods,
//! which classify individual addresses but don't cleanly express "does this CIDR *overlap* a
//! reserved range" for a supplied subnet rather than a single IP), but applied at a different
//! pipeline stage: `simply_ip_exporter` filters at serve-time, per output endpoint, with three
//! independently toggleable flags; here it is one combined `skip_bogon_filtering` toggle applied
//! before a batch push, since the concern here is "don't hand a target vault garbage it will
//! reject with a `400`," not "let an operator choose which categories to redact from a public
//! feed."
//!
//! Deliberately conservative like the peer: any overlap between a candidate CIDR and a reserved
//! range drops the candidate entirely, even a supernet only partially overlapping one bogon
//! range — a record this pipeline lets through must be *entirely* outside every reserved range.

use std::sync::LazyLock;

use ipnetwork::IpNetwork;

/// RFC 1918 private IPv4 ranges.
const RFC1918_LITERALS: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

/// Loopback, both address families.
const LOOPBACK_LITERALS: &[&str] = &["127.0.0.0/8", "::1/128"];

/// Everything else non-routable/reserved that a real threat-intelligence feed occasionally lists
/// by mistake (a misconfigured honeypot logging its own interface, a scanner artifact, a
/// documentation example copy-pasted into a live list). Not exhaustive of every IANA
/// special-purpose registry entry, but covers the ranges that matter for a feed meant to be
/// banned at a real perimeter. Excludes RFC 1918 and loopback, governed by their own tables above.
const BOGON_LITERALS: &[&str] = &[
    "0.0.0.0/8",       // "this network" / unspecified
    "100.64.0.0/10",   // carrier-grade NAT (RFC 6598)
    "169.254.0.0/16",  // link-local / APIPA
    "192.0.0.0/24",    // IETF protocol assignments
    "192.0.2.0/24",    // TEST-NET-1 (documentation)
    "192.88.99.0/24",  // former 6to4 relay anycast
    "198.18.0.0/15",   // benchmarking
    "198.51.100.0/24", // TEST-NET-2 (documentation)
    "203.0.113.0/24",  // TEST-NET-3 (documentation)
    "224.0.0.0/4",     // multicast
    "240.0.0.0/4",     // reserved / future use
    "255.255.255.255/32", // limited broadcast
    "::/128",          // unspecified (v6)
    "::ffff:0:0/96",   // IPv4-mapped v6
    "100::/64",        // discard-only
    "2001:db8::/32",   // documentation (v6)
    "fc00::/7",        // unique local (ULA)
    "fe80::/10",       // link-local (v6)
    "ff00::/8",        // multicast (v6)
];

fn parse_literals(literals: &[&str]) -> Vec<IpNetwork> {
    literals.iter().map(|s| s.parse().expect("static bogon literal is a valid CIDR")).collect()
}

static RESERVED_RANGES: LazyLock<Vec<IpNetwork>> = LazyLock::new(|| {
    let mut all = Vec::new();
    all.extend(parse_literals(RFC1918_LITERALS));
    all.extend(parse_literals(LOOPBACK_LITERALS));
    all.extend(parse_literals(BOGON_LITERALS));
    all
});

/// Two networks "overlap" for this purpose if either contains the other's base address, which
/// `IpNetwork` doesn't expose as a single method — computed from `contains()` in both directions
/// so a `/8` reserved range correctly catches a more specific `/24` candidate, and vice versa (a
/// candidate supernet that happens to swallow a reserved range is just as unbannable).
fn overlaps(a: &IpNetwork, b: &IpNetwork) -> bool {
    a.contains(b.ip()) || b.contains(a.ip())
}

/// Returns `true` if `candidate` overlaps any reserved (loopback/private/bogon) range at all —
/// the address or CIDR is not safe to hand to a target vault as a real, bannable entry.
pub fn is_bogon(candidate: &IpNetwork) -> bool {
    RESERVED_RANGES.iter().any(|reserved| overlaps(candidate, reserved))
}

/// Splits `records` into `(kept, removed_count)`: `kept` holds every entry that parses as a valid
/// IP/CIDR and does not overlap a reserved range; anything else (including a string that fails to
/// parse as an IP/CIDR at all — already-invalid data that has no business surviving this stage
/// either) is dropped and counted. `records` are expected already-normalized (see
/// `parsers::normalize_ip_or_cidr`), so the parse here is just re-establishing the typed
/// `IpNetwork` needed for the overlap check, not re-validating shape.
pub fn sanitize(records: Vec<String>) -> (Vec<String>, usize) {
    let mut kept = Vec::with_capacity(records.len());
    let mut removed = 0usize;
    for record in records {
        match record.parse::<IpNetwork>() {
            Ok(net) if !is_bogon(&net) => kept.push(record),
            _ => removed += 1,
        }
    }
    (kept, removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_v4_and_v6_are_bogons() {
        assert!(is_bogon(&"127.0.0.1/32".parse().unwrap()));
        assert!(is_bogon(&"::1/128".parse().unwrap()));
    }

    #[test]
    fn unspecified_v4_is_a_bogon() {
        assert!(is_bogon(&"0.0.0.0/32".parse().unwrap()));
    }

    #[test]
    fn rfc1918_private_ranges_are_bogons() {
        assert!(is_bogon(&"10.1.2.3/32".parse().unwrap()));
        assert!(is_bogon(&"172.16.0.5/32".parse().unwrap()));
        assert!(is_bogon(&"192.168.1.1/32".parse().unwrap()));
    }

    #[test]
    fn link_local_v4_and_v6_are_bogons() {
        assert!(is_bogon(&"169.254.1.1/32".parse().unwrap()));
        assert!(is_bogon(&"fe80::1/128".parse().unwrap()));
    }

    #[test]
    fn a_real_public_address_is_not_a_bogon() {
        assert!(!is_bogon(&"8.8.8.8/32".parse().unwrap()));
        assert!(!is_bogon(&"1.1.1.1/32".parse().unwrap()));
        assert!(!is_bogon(&"2001:4860:4860::8888/128".parse().unwrap()));
    }

    /// The TEST-NET-3 documentation range is itself a bogon — used throughout this codebase's own
    /// examples/tests (e.g. `203.0.113.9`), so worth pinning explicitly that it is correctly
    /// classified as one, not accidentally treated as "public just because it looks routable."
    #[test]
    fn the_documentation_ranges_this_codebase_uses_as_examples_are_themselves_bogons() {
        assert!(is_bogon(&"203.0.113.9/32".parse().unwrap()));
        assert!(is_bogon(&"198.51.100.4/32".parse().unwrap()));
        assert!(is_bogon(&"192.0.2.1/32".parse().unwrap()));
    }

    /// Matches `simply_ip_exporter`'s own pinned behavior: a supernet only *partially* overlapping
    /// a reserved range is dropped entirely, not silently narrowed. A `/8` candidate that happens
    /// to contain a `/16` private block inside it is exactly this case.
    #[test]
    fn a_supernet_only_partially_overlapping_a_bogon_is_dropped_entirely() {
        assert!(is_bogon(&"10.0.0.0/6".parse().unwrap()), "10.0.0.0/6 spans 8.0.0.0-11.255.255.255, overlapping 10.0.0.0/8");
    }

    #[test]
    fn sanitize_separates_kept_from_removed_and_counts_correctly() {
        let (kept, removed) = sanitize(vec![
            "8.8.8.8".to_owned(),
            "1.1.1.1".to_owned(),
            "10.0.0.5".to_owned(),
            "127.0.0.1".to_owned(),
            "not-an-ip".to_owned(),
        ]);
        assert_eq!(kept, vec!["8.8.8.8".to_owned(), "1.1.1.1".to_owned()]);
        assert_eq!(removed, 3);
    }
}
