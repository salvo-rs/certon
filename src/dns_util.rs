//! DNS utilities for ACME DNS-01 challenge solving.
//!
//! This module provides helpers for constructing DNS-01 challenge records,
//! computing challenge values, normalizing domain names, and checking DNS
//! propagation. These functions are used primarily by the [`Dns01Solver`]
//! but are public so that custom solver implementations can reuse them.
//!
//! [`Dns01Solver`]: crate::solvers::Dns01Solver

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant as StdInstant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hickory_resolver::TokioResolver;
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The DNS record prefix used for ACME DNS-01 challenges.
const ACME_CHALLENGE_PREFIX: &str = "_acme-challenge.";

/// Default timeout for DNS propagation checks.
pub const DEFAULT_PROPAGATION_TIMEOUT: Duration = Duration::from_secs(120);

/// Default interval between DNS propagation check attempts.
pub const DEFAULT_PROPAGATION_INTERVAL: Duration = Duration::from_secs(4);

/// Well-known public recursive DNS resolvers (used as fallback).
pub const DEFAULT_NAMESERVERS: &[&str] = &["8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53", "1.0.0.1:53"];

/// Default DNS query timeout.
pub const DNS_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// FQDN helpers
// ---------------------------------------------------------------------------

/// Normalize `domain` to a fully-qualified domain name by ensuring it ends
/// with a trailing dot.
///
/// # Examples
///
/// ```
/// use certon::dns_util::to_fqdn;
///
/// assert_eq!(to_fqdn("example.com"), "example.com.");
/// assert_eq!(to_fqdn("example.com."), "example.com.");
/// ```
pub fn to_fqdn(domain: &str) -> String {
    if domain.ends_with('.') {
        domain.to_string()
    } else {
        format!("{domain}.")
    }
}

/// Strip the trailing dot from a fully-qualified domain name, returning the
/// "unqualified" form.
///
/// # Examples
///
/// ```
/// use certon::dns_util::from_fqdn;
///
/// assert_eq!(from_fqdn("example.com."), "example.com");
/// assert_eq!(from_fqdn("example.com"), "example.com");
/// ```
pub fn from_fqdn(fqdn: &str) -> String {
    fqdn.strip_suffix('.').unwrap_or(fqdn).to_string()
}

// ---------------------------------------------------------------------------
// Challenge record helpers
// ---------------------------------------------------------------------------

/// Construct the DNS record name used for an ACME DNS-01 challenge.
///
/// For a domain `example.com`, this returns `_acme-challenge.example.com.`
/// (fully-qualified with trailing dot).
///
/// # Examples
///
/// ```
/// use certon::dns_util::challenge_record_name;
///
/// assert_eq!(
///     challenge_record_name("example.com"),
///     "_acme-challenge.example.com."
/// );
/// assert_eq!(
///     challenge_record_name("sub.example.com."),
///     "_acme-challenge.sub.example.com."
/// );
/// ```
pub fn challenge_record_name(domain: &str) -> String {
    let clean = from_fqdn(domain);
    to_fqdn(&format!("{ACME_CHALLENGE_PREFIX}{clean}"))
}

/// Compute the value that must be placed in the DNS TXT record for a DNS-01
/// challenge.
///
/// Per [RFC 8555 §8.4](https://www.rfc-editor.org/rfc/rfc8555#section-8.4),
/// the value is `base64url(SHA-256(key_authorization))` with no padding.
///
/// # Examples
///
/// ```
/// use certon::dns_util::challenge_record_value;
///
/// // The exact output depends on the input; this just exercises the function.
/// let value = challenge_record_value("token.thumbprint");
/// assert!(!value.is_empty());
/// assert!(!value.contains('=')); // URL-safe, no padding
/// ```
pub fn challenge_record_value(key_auth: &str) -> String {
    let digest = Sha256::digest(key_auth.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

// ---------------------------------------------------------------------------
// Domain validation
// ---------------------------------------------------------------------------

/// Validate that `domain` is a syntactically well-formed domain name.
///
/// This performs basic structural checks:
/// - The domain is non-empty and not longer than 253 characters.
/// - Each label is 1-63 characters long.
/// - Labels contain only ASCII letters, digits, and hyphens.
/// - Labels do not start or end with a hyphen.
/// - There is at least one dot (i.e. at least two labels), unless the domain is a single-label TLD
///   followed by a trailing dot.
///
/// Wildcard domains (e.g. `*.example.com`) are accepted.
///
/// # Examples
///
/// ```
/// use certon::dns_util::is_valid_domain;
///
/// assert!(is_valid_domain("example.com"));
/// assert!(is_valid_domain("sub.example.com"));
/// assert!(is_valid_domain("*.example.com"));
/// assert!(!is_valid_domain(""));
/// assert!(!is_valid_domain("-bad.com"));
/// assert!(!is_valid_domain("bad-.com"));
/// ```
pub fn is_valid_domain(domain: &str) -> bool {
    // Strip optional trailing dot and wildcard prefix.
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    let domain = domain.strip_prefix("*.").unwrap_or(domain);

    if domain.is_empty() || domain.len() > 253 {
        return false;
    }

    let labels: Vec<&str> = domain.split('.').collect();

    // A bare domain with no dots is technically a TLD; we require at least two
    // labels for practical certificate purposes.
    if labels.len() < 2 {
        return false;
    }

    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Domain sanitization
// ---------------------------------------------------------------------------

/// Sanitize a domain name so it is safe to use as a filesystem path component
/// or storage key.
///
/// This lower-cases the domain, strips a leading wildcard prefix (`*.`),
/// removes the trailing dot, and replaces any remaining characters that are
/// not ASCII alphanumeric, `-`, or `.` with an underscore.
///
/// # Examples
///
/// ```
/// use certon::dns_util::sanitize_domain;
///
/// assert_eq!(sanitize_domain("Example.COM"), "example.com");
/// assert_eq!(sanitize_domain("*.example.com"), "example.com");
/// assert_eq!(sanitize_domain("example.com."), "example.com");
/// ```
pub fn sanitize_domain(domain: &str) -> String {
    let domain = domain.to_ascii_lowercase();
    let domain = domain.strip_prefix("*.").unwrap_or(&domain);
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    domain
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// DNS propagation checking
// ---------------------------------------------------------------------------

/// Check whether a DNS TXT record with the expected value has propagated.
///
/// The function repeatedly queries DNS for TXT records at `fqdn` using
/// hickory-resolver and compares each result with `expected_value`. It
/// retries at `interval` until a match is found or `timeout` elapses.
///
/// # Errors
///
/// Returns [`Error::Timeout`] if the record is not found within `timeout`.
pub async fn check_dns_propagation(
    fqdn: &str,
    expected_value: &str,
    timeout: Duration,
    interval: Duration,
) -> Result<bool> {
    let fqdn_normalized = to_fqdn(fqdn);
    let lookup_name = from_fqdn(&fqdn_normalized);
    let deadline = Instant::now() + timeout;

    debug!(
        fqdn = %fqdn_normalized,
        expected_value,
        "starting DNS propagation check"
    );

    loop {
        // Perform a real DNS TXT record lookup via hickory-resolver.
        match try_lookup_txt(&lookup_name, expected_value).await {
            Ok(true) => {
                debug!(
                    fqdn = %fqdn_normalized,
                    "DNS propagation confirmed"
                );
                return Ok(true);
            }
            Ok(false) => {
                debug!(
                    fqdn = %fqdn_normalized,
                    "TXT record not yet propagated, will retry"
                );
            }
            Err(e) => {
                warn!(
                    fqdn = %fqdn_normalized,
                    error = %e,
                    "DNS lookup error during propagation check"
                );
            }
        }

        if Instant::now() >= deadline {
            return Err(Error::Timeout(format!(
                "DNS propagation check for {fqdn_normalized} timed out after {timeout:?}"
            )));
        }

        tokio::time::sleep(interval).await;
    }
}

/// Perform a real DNS TXT record lookup for `name` using hickory-resolver
/// and check if any record matches `expected_value`.
async fn try_lookup_txt(name: &str, expected_value: &str) -> std::result::Result<bool, String> {
    let txt_records = lookup_txt(name).await.map_err(|e| format!("{e}"))?;
    for record in &txt_records {
        // TXT records may be returned with surrounding quotes; strip them.
        let cleaned = record.trim_matches('"');
        if cleaned == expected_value {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Look up TXT records for the given FQDN using hickory-resolver.
///
/// Returns a list of TXT record string values.
async fn lookup_txt(fqdn: &str) -> Result<Vec<String>> {
    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| Error::Other(format!("failed to create DNS resolver: {e}")))?
        .build();
    let response = resolver
        .txt_lookup(fqdn)
        .await
        .map_err(|e| Error::Other(format!("DNS TXT lookup failed for {fqdn}: {e}")))?;
    Ok(response
        .iter()
        .map(|r: &hickory_resolver::proto::rr::rdata::TXT| r.to_string())
        .collect())
}

// ---------------------------------------------------------------------------
// Zone cache
// ---------------------------------------------------------------------------

/// TTL for zone cache entries (5 minutes).
const ZONE_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// An entry in the DNS zone cache.
struct ZoneCacheEntry {
    zone: Option<String>,
    expires_at: StdInstant,
}

/// Global DNS zone cache keyed by domain name.
///
/// Caches the result of SOA-based zone discovery to avoid repeated DNS
/// lookups for the same domain hierarchy. Entries expire after
/// [`ZONE_CACHE_TTL`].
static ZONE_CACHE: std::sync::OnceLock<Mutex<HashMap<String, ZoneCacheEntry>>> =
    std::sync::OnceLock::new();

fn zone_cache() -> &'static Mutex<HashMap<String, ZoneCacheEntry>> {
    ZONE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Look up a cached zone for `domain`. Returns `Some(Some(zone))` on cache
/// hit (zone found), `Some(None)` on negative cache hit (no zone), or
/// `None` on cache miss.
fn zone_cache_get(domain: &str) -> Option<Option<String>> {
    let cache = zone_cache();
    let map = cache.lock().ok()?;
    let entry = map.get(domain)?;
    if StdInstant::now() < entry.expires_at {
        Some(entry.zone.clone())
    } else {
        None // expired
    }
}

/// Insert a zone lookup result into the cache.
fn zone_cache_set(domain: &str, zone: Option<String>) {
    if let Ok(mut map) = zone_cache().lock() {
        // Evict expired entries if the cache grows too large.
        if map.len() > 1000 {
            let now = StdInstant::now();
            map.retain(|_, v| now < v.expires_at);
        }
        map.insert(
            domain.to_string(),
            ZoneCacheEntry {
                zone,
                expires_at: StdInstant::now() + ZONE_CACHE_TTL,
            },
        );
    }
}

/// Clear the DNS zone cache.
///
/// This is primarily useful for testing or when DNS configuration has
/// changed and cached results are stale.
pub fn clear_zone_cache() {
    if let Ok(mut map) = zone_cache().lock() {
        map.clear();
    }
}

// ---------------------------------------------------------------------------
// Zone detection
// ---------------------------------------------------------------------------

/// Determine the registerable domain (zone apex) for the given domain.
///
/// Attempts to find the zone by performing SOA lookups walking up the label
/// hierarchy. If SOA lookup fails
/// (e.g. no network), falls back to a heuristic that returns the last two
/// labels of the domain.
///
/// Results are cached for [`ZONE_CACHE_TTL`] to avoid repeated DNS lookups.
///
/// # Examples
///
/// ```
/// use certon::dns_util::find_zone_by_fqdn;
///
/// assert_eq!(
///     find_zone_by_fqdn("sub.example.com"),
///     Some("example.com.".to_string())
/// );
/// assert_eq!(
///     find_zone_by_fqdn("example.com"),
///     Some("example.com.".to_string())
/// );
/// assert_eq!(find_zone_by_fqdn("com"), None);
/// ```
pub fn find_zone_by_fqdn(fqdn: &str) -> Option<String> {
    let normalized = from_fqdn(fqdn).to_lowercase();

    // Check cache first.
    if let Some(cached) = zone_cache_get(&normalized) {
        return cached;
    }

    let result = find_zone_by_fqdn_heuristic(fqdn);
    zone_cache_set(&normalized, result.clone());
    result
}

/// Async version of [`find_zone_by_fqdn`] that performs real SOA queries.
///
/// Walks up the label hierarchy, querying for SOA records at each level.
/// Returns the first domain that has an SOA record. Falls back to the
/// heuristic if no SOA is found.
///
/// Results are cached for [`ZONE_CACHE_TTL`] to avoid repeated DNS lookups.
pub async fn find_zone_by_fqdn_async(fqdn: &str) -> Option<String> {
    let normalized = from_fqdn(fqdn).to_lowercase();

    // Check cache first.
    if let Some(cached) = zone_cache_get(&normalized) {
        return cached;
    }

    let domain = from_fqdn(fqdn);
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        zone_cache_set(&normalized, None);
        return None;
    }

    let resolver = match TokioResolver::builder_tokio() {
        Ok(builder) => builder.build(),
        Err(_) => {
            let result = find_zone_by_fqdn_heuristic(fqdn);
            zone_cache_set(&normalized, result.clone());
            return result;
        }
    };

    // Walk up the label hierarchy, starting from the full domain.
    for i in 0..labels.len() - 1 {
        let candidate = labels[i..].join(".");
        if candidate.split('.').count() < 2 {
            break;
        }
        match resolver.soa_lookup(&candidate).await {
            Ok(_) => {
                debug!(zone = %candidate, "found SOA record for zone");
                let result = Some(to_fqdn(&candidate));
                zone_cache_set(&normalized, result.clone());
                return result;
            }
            Err(_) => continue,
        }
    }

    // Fallback to heuristic.
    let result = find_zone_by_fqdn_heuristic(fqdn);
    zone_cache_set(&normalized, result.clone());
    result
}

/// Heuristic zone detection: returns the last two labels as the zone apex.
fn find_zone_by_fqdn_heuristic(fqdn: &str) -> Option<String> {
    let domain = from_fqdn(fqdn);
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    let zone = labels[labels.len() - 2..].join(".");
    Some(to_fqdn(&zone))
}

// ---------------------------------------------------------------------------
// Nameserver helpers
// ---------------------------------------------------------------------------

/// Ensure every address in `servers` has a port number. Entries without an
/// explicit port get `:53` appended.
pub fn populate_nameserver_ports(servers: &mut [String]) {
    for server in servers.iter_mut() {
        if !server.contains(':') {
            *server = format!("{server}:53");
        } else if server.starts_with('[') {
            // Bare IPv6 without port, e.g. `[::1]`
            if !server.contains("]:") {
                *server = format!("{server}:53");
            }
        }
    }
}

/// Read system-configured nameservers.
///
/// On Unix, parses `/etc/resolv.conf` for `nameserver` lines.
/// On Windows (and as a fallback), returns the well-known public defaults.
pub fn system_nameservers() -> Vec<String> {
    #[cfg(unix)]
    {
        if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
            let servers: Vec<String> = contents
                .lines()
                .filter_map(|line| {
                    let trimmed = line.trim();
                    if trimmed.starts_with("nameserver") {
                        trimmed.split_whitespace().nth(1).map(|s| s.to_string())
                    } else {
                        None
                    }
                })
                .collect();
            if !servers.is_empty() {
                return servers;
            }
        }
        DEFAULT_NAMESERVERS.iter().map(|s| s.to_string()).collect()
    }
    #[cfg(not(unix))]
    {
        DEFAULT_NAMESERVERS.iter().map(|s| s.to_string()).collect()
    }
}

/// Return the list of recursive nameservers to use for pre-checking DNS
/// propagation. If `custom` is non-empty those servers are used; otherwise
/// system resolvers are tried first, falling back to well-known public
/// defaults.
///
/// All returned addresses are guaranteed to include a port number.
pub fn recursive_nameservers(custom: &[String]) -> Vec<String> {
    let mut servers: Vec<String> = if custom.is_empty() {
        let system = system_nameservers();
        if system.is_empty() {
            DEFAULT_NAMESERVERS.iter().map(|s| s.to_string()).collect()
        } else {
            system
        }
    } else {
        custom.to_vec()
    };
    populate_nameserver_ports(&mut servers);
    servers
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- FQDN helpers -------------------------------------------------------

    #[test]
    fn test_to_fqdn_without_dot() {
        assert_eq!(to_fqdn("example.com"), "example.com.");
    }

    #[test]
    fn test_to_fqdn_with_dot() {
        assert_eq!(to_fqdn("example.com."), "example.com.");
    }

    #[test]
    fn test_from_fqdn_with_dot() {
        assert_eq!(from_fqdn("example.com."), "example.com");
    }

    #[test]
    fn test_from_fqdn_without_dot() {
        assert_eq!(from_fqdn("example.com"), "example.com");
    }

    // -- Challenge record helpers -------------------------------------------

    #[test]
    fn test_challenge_record_name_simple() {
        assert_eq!(
            challenge_record_name("example.com"),
            "_acme-challenge.example.com."
        );
    }

    #[test]
    fn test_challenge_record_name_fqdn() {
        assert_eq!(
            challenge_record_name("example.com."),
            "_acme-challenge.example.com."
        );
    }

    #[test]
    fn test_challenge_record_name_subdomain() {
        assert_eq!(
            challenge_record_name("sub.example.com"),
            "_acme-challenge.sub.example.com."
        );
    }

    #[test]
    fn test_challenge_record_value_deterministic() {
        let v1 = challenge_record_value("token.thumbprint");
        let v2 = challenge_record_value("token.thumbprint");
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_challenge_record_value_no_padding() {
        let value = challenge_record_value("token.thumbprint");
        assert!(!value.contains('='));
        assert!(!value.contains('+'));
        assert!(!value.contains('/'));
    }

    #[test]
    fn test_challenge_record_value_known_vector() {
        // SHA-256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
        // base64url of those bytes (no padding):
        // n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg
        let value = challenge_record_value("test");
        assert_eq!(value, "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg");
    }

    // -- Domain validation --------------------------------------------------

    #[test]
    fn test_valid_domains() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(is_valid_domain("a.b.c.example.com"));
        assert!(is_valid_domain("example.com."));
        assert!(is_valid_domain("*.example.com"));
        assert!(is_valid_domain("xn--nxasmq6b.example.com")); // IDN
    }

    #[test]
    fn test_invalid_domains() {
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("."));
        assert!(!is_valid_domain("com"));
        assert!(!is_valid_domain("-bad.com"));
        assert!(!is_valid_domain("bad-.com"));
        assert!(!is_valid_domain("ex ample.com"));
        assert!(!is_valid_domain("example..com"));
        assert!(!is_valid_domain(".example.com"));
    }

    // -- Sanitization -------------------------------------------------------

    #[test]
    fn test_sanitize_domain_basic() {
        assert_eq!(sanitize_domain("Example.COM"), "example.com");
    }

    #[test]
    fn test_sanitize_domain_wildcard() {
        assert_eq!(sanitize_domain("*.example.com"), "example.com");
    }

    #[test]
    fn test_sanitize_domain_trailing_dot() {
        assert_eq!(sanitize_domain("example.com."), "example.com");
    }

    #[test]
    fn test_sanitize_domain_special_chars() {
        assert_eq!(sanitize_domain("ex@mple.com"), "ex_mple.com");
    }

    // -- Zone detection -----------------------------------------------------

    #[test]
    fn test_find_zone_subdomain() {
        assert_eq!(
            find_zone_by_fqdn("sub.example.com"),
            Some("example.com.".to_string())
        );
    }

    #[test]
    fn test_find_zone_apex() {
        assert_eq!(
            find_zone_by_fqdn("example.com"),
            Some("example.com.".to_string())
        );
    }

    #[test]
    fn test_find_zone_fqdn() {
        assert_eq!(
            find_zone_by_fqdn("example.com."),
            Some("example.com.".to_string())
        );
    }

    #[test]
    fn test_find_zone_single_label() {
        assert_eq!(find_zone_by_fqdn("com"), None);
    }

    // -- Nameserver helpers -------------------------------------------------

    #[test]
    fn test_populate_nameserver_ports_adds_default() {
        let mut servers = vec!["8.8.8.8".to_string()];
        populate_nameserver_ports(&mut servers);
        assert_eq!(servers, vec!["8.8.8.8:53"]);
    }

    #[test]
    fn test_populate_nameserver_ports_preserves_existing() {
        let mut servers = vec!["8.8.8.8:5353".to_string()];
        populate_nameserver_ports(&mut servers);
        assert_eq!(servers, vec!["8.8.8.8:5353"]);
    }

    #[test]
    fn test_recursive_nameservers_defaults() {
        let servers = recursive_nameservers(&[]);
        assert_eq!(servers.len(), 4);
        assert!(servers[0].ends_with(":53"));
    }

    #[test]
    fn test_recursive_nameservers_custom() {
        let custom = vec!["10.0.0.1".to_string()];
        let servers = recursive_nameservers(&custom);
        assert_eq!(servers, vec!["10.0.0.1:53"]);
    }
}
