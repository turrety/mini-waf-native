//! Client-IP helpers for dual-stack (IPv4 / IPv6 / IPv4-mapped) handling.
//! Prefer these over ad-hoc string compares so rate-limit keys and `equals`
//! rules see one canonical form per address.

use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
};
use std::sync::{
    LazyLock,
    Mutex,
};

use crate::utils::lru::LruCache;

const IP_CACHE_MAX: usize = 2_048;

/// Process-wide memo of normalized addresses.
static IP_CACHE: LazyLock<Mutex<LruCache<String>>> =
    LazyLock::new(|| Mutex::new(LruCache::new(IP_CACHE_MAX, None)));

/// Strip surrounding whitespace and optional URI brackets (`[addr]`).
fn strip_brackets(raw: &str) -> &str {
    let trimmed = raw.trim();
    trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(trimmed)
}

/// Drop an IPv6 zone / scope id (`fe80::1%eth0`, `fe80::1%25eth0`).
fn strip_zone_id(address: &str) -> &str {
    address.split_once('%').map_or(address, |(head, _)| head)
}

fn canonicalize(raw: &str) -> String {
    let prepared = strip_zone_id(strip_brackets(raw));
    if let Ok(v4) = prepared.parse::<Ipv4Addr>() {
        return v4.to_string();
    }
    if let Ok(v6) = prepared.parse::<Ipv6Addr>() {
        return match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            // `Ipv6Addr`'s Display is RFC 5952: lowercase, longest zero run
            // compressed.
            None => v6.to_string(),
        };
    }
    prepared.to_owned()
}

/// Normalize a client IP for equality checks and rate-limit keys.
///
/// - trims whitespace and strips `[brackets]`
/// - strips IPv6 zone ids
/// - collapses IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to dotted IPv4
/// - compresses equivalent IPv6 forms to one canonical lowercase value
/// - leaves non-IP opaque strings intact after trim / bracket strip
///
/// Results are memoized in a small process-wide LRU (2048 entries).
pub fn normalize_client_ip(raw: &str) -> String {
    if let Ok(mut cache) = IP_CACHE.lock() {
        if let Some(hit) = cache.get(raw, Some(0)) {
            return hit.clone();
        }
    }
    let normalized = canonicalize(raw);
    if let Ok(mut cache) = IP_CACHE.lock() {
        cache.set(raw, normalized.clone(), Some(0));
    }
    normalized
}

/// Clear the IP normalization memo (tests / ops).
pub fn clear_ip_normalize_cache() {
    if let Ok(mut cache) = IP_CACHE.lock() {
        cache.clear();
    }
}

/// Current size of the IP normalization memo.
pub fn ip_normalize_cache_size() -> usize {
    IP_CACHE.lock().map(|cache| cache.size()).unwrap_or(0)
}

/// First hop from an `X-Forwarded-For` value (comma-separated), trimmed and
/// passed through [`normalize_client_ip`].
pub fn pick_client_ip_from_xff(forwarded_for: &str) -> String {
    normalize_client_ip(forwarded_for.split(',').next().unwrap_or(""))
}

fn is_ip(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok()
}

fn is_port(value: &str) -> bool {
    (1..=5).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// True when a `Host` header value is a raw IP literal (IPv4 or bracketed
/// IPv6), optionally with a port. Backs the `preset-protocol-host-ip` rule.
pub fn is_host_ip_literal(host_header: &str) -> bool {
    let host = host_header.trim();
    if host.is_empty() {
        return false;
    }
    if let Some(bracketed) = host.strip_prefix('[') {
        return is_bracketed_ip_host(bracketed);
    }
    if let Some((without_port, port)) = host.rsplit_once(':') {
        if !without_port.is_empty() && is_port(port) {
            return without_port.parse::<Ipv4Addr>().is_ok();
        }
    }
    is_ip(host)
}

/// `addr]` or `addr]:port`, the part of a `[addr]` host after the `[`.
fn is_bracketed_ip_host(bracketed: &str) -> bool {
    let Some((literal, after)) = bracketed.split_once(']') else {
        return false;
    };
    let port_ok =
        after.is_empty() || after.strip_prefix(':').is_some_and(is_port);
    port_ok && is_ip(strip_zone_id(literal))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_and_keeps_ipv4() {
        assert_eq!(normalize_client_ip("  127.0.0.1  "), "127.0.0.1");
    }

    #[test]
    fn strips_brackets_around_ipv6() {
        assert_eq!(normalize_client_ip("[2001:db8::1]"), "2001:db8::1");
    }

    #[test]
    fn unifies_ipv4_mapped_ipv6() {
        assert_eq!(normalize_client_ip("::ffff:127.0.0.1"), "127.0.0.1");
        assert_eq!(normalize_client_ip("::FFFF:7f00:1"), "127.0.0.1");
        assert_eq!(normalize_client_ip("[::ffff:192.0.2.10]"), "192.0.2.10");
    }

    #[test]
    fn collapses_equivalent_ipv6_forms() {
        assert_eq!(
            normalize_client_ip("2001:0db8:0000:0000:0000:0000:0000:0001"),
            "2001:db8::1"
        );
        assert_eq!(normalize_client_ip("::1"), "::1");
        assert_eq!(normalize_client_ip("0:0:0:0:0:0:0:1"), "::1");
    }

    #[test]
    fn strips_ipv6_zone_identifiers() {
        assert_eq!(normalize_client_ip("fe80::1%eth0"), "fe80::1");
        assert_eq!(normalize_client_ip("[fe80::1%25eth0]"), "fe80::1");
    }

    #[test]
    fn keeps_opaque_values() {
        assert_eq!(normalize_client_ip(" unix-socket "), "unix-socket");
        assert_eq!(normalize_client_ip(""), "");
    }

    #[test]
    fn picks_the_first_forwarded_hop() {
        assert_eq!(
            pick_client_ip_from_xff("  ::ffff:127.0.0.1  , 10.0.0.1"),
            "127.0.0.1"
        );
        assert_eq!(
            pick_client_ip_from_xff(" [2001:db8::1] , 10.0.0.1"),
            "2001:db8::1"
        );
    }

    #[test]
    fn detects_host_ip_literals() {
        assert!(is_host_ip_literal("127.0.0.1"));
        assert!(is_host_ip_literal("127.0.0.1:8080"));
        assert!(!is_host_ip_literal("example.com"));
        assert!(!is_host_ip_literal("example.com:443"));
        assert!(is_host_ip_literal("[2001:db8::1]"));
        assert!(is_host_ip_literal("[2001:db8::1]:443"));
        assert!(is_host_ip_literal("[::ffff:127.0.0.1]"));
        assert!(!is_host_ip_literal("[2001:db8::1]:abc"));
    }
}
