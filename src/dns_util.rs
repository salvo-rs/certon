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
    check_dns_propagation_with_resolvers(fqdn, expected_value, timeout, interval, None).await
}

/// Check propagation using explicitly selected IP address and port pairs.
pub async fn check_dns_propagation_with_resolvers(
    fqdn: &str,
    expected_value: &str,
    timeout: Duration,
    interval: Duration,
    resolvers: Option<&[String]>,
) -> Result<bool> {
    let resolver = propagation_resolver(resolvers)?;
    let fqdn_normalized = to_fqdn(fqdn);
    let lookup_name = from_fqdn(&fqdn_normalized);
    let deadline = Instant::now() + timeout;

    debug!(
        fqdn = %fqdn_normalized,
        expected_value,
        "starting DNS propagation check"
    );

    loop {
        // Propagation checks must observe new authoritative data rather than
        // retaining the previous TXT value or NXDOMAIN for its full TTL.
        resolver.clear_cache();
        // Perform a real DNS TXT record lookup via hickory-resolver.
        let lookup = async {
            let response = resolver
                .txt_lookup(&lookup_name)
                .await
                .map_err(|e| Error::Other(format!("DNS TXT lookup failed: {e}")))?;
            Ok::<_, Error>(response.answers().iter().any(|record| {
                match &record.data {
                    hickory_resolver::proto::rr::RData::TXT(txt) => txt
                        .txt_data
                        .iter()
                        .flat_map(|part| part.iter().copied())
                        .eq(expected_value.bytes()),
                    _ => false,
                }
            }))
        };
        match tokio::time::timeout_at(deadline, lookup).await {
            Err(_) => {
                return Err(Error::Timeout(format!(
                    "DNS propagation check for {fqdn_normalized} timed out"
                )));
            }
            Ok(result) => match result {
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
            },
        }

        if Instant::now() >= deadline {
            return Err(Error::Timeout(format!(
                "DNS propagation check for {fqdn_normalized} timed out after {timeout:?}"
            )));
        }

        tokio::time::sleep_until(std::cmp::min(Instant::now() + interval, deadline)).await;
    }
}

/// Perform a real DNS TXT record lookup for `name` using hickory-resolver
/// and check if any record matches `expected_value`.
fn propagation_resolver(resolvers: Option<&[String]>) -> Result<TokioResolver> {
    if let Some(addresses) = resolvers {
        use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
        if addresses.is_empty() {
            return Err(Error::Config("DNS resolver list cannot be empty".into()));
        }
        let servers = addresses
            .iter()
            .map(|address| {
                let address: std::net::SocketAddr = address
                    .parse()
                    .map_err(|e| Error::Config(format!("invalid DNS resolver {address:?}: {e}")))?;
                let mut udp = ConnectionConfig::udp();
                udp.port = address.port();
                let mut tcp = ConnectionConfig::tcp();
                tcp.port = address.port();
                Ok(NameServerConfig::new(address.ip(), true, vec![udp, tcp]))
            })
            .collect::<Result<Vec<_>>>()?;
        return TokioResolver::builder_with_config(
            ResolverConfig::from_parts(None, Vec::new(), servers),
            hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
        )
        .build()
        .map_err(|e| Error::Config(format!("failed to build DNS resolver: {e}")));
    }
    TokioResolver::builder_tokio()
        .map_err(|e| Error::Other(format!("failed to create DNS resolver: {e}")))?
        .build()
        .map_err(|e| Error::Other(format!("failed to build DNS resolver: {e}")))
}

// ---------------------------------------------------------------------------
// Zone cache
// ---------------------------------------------------------------------------

/// TTL for zone cache entries (5 minutes).
const ZONE_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Maximum retained domains and the number of slots inspected per operation.
const ZONE_CACHE_CAPACITY: usize = 1024;
const ZONE_CACHE_SWEEP_BUDGET: usize = 2;
const MAX_ZONE_CACHE_KEY_BYTES: usize = 253;
const MAX_ZONE_CACHE_VALUE_BYTES: usize = 254; // A fully qualified zone may end in a dot.

struct ZoneCacheEntry {
    zone: Option<String>,
    expires_at: StdInstant,
    slot: usize,
}

/// Fixed slots bound both entries and expiry bookkeeping. Hits and updates
/// inspect only a small sweep budget; a full cache evicts one round-robin slot.
/// Repeated updates do not append expiry tickets or grow auxiliary queues.
struct ZoneCache {
    entries: HashMap<String, ZoneCacheEntry>,
    slots: Vec<Option<String>>,
    free: Vec<usize>,
    hand: usize,
}

impl ZoneCache {
    fn new() -> Self {
        Self {
            entries: HashMap::with_capacity(ZONE_CACHE_CAPACITY),
            slots: vec![None; ZONE_CACHE_CAPACITY],
            free: (0..ZONE_CACHE_CAPACITY).rev().collect(),
            hand: 0,
        }
    }

    fn key(domain: &str) -> Option<String> {
        let domain = domain.strip_suffix('.').unwrap_or(domain);
        // Reject oversized input before allocating its lowercased copy. The
        // second check also bounds Unicode lowercase expansions.
        if domain.len() > MAX_ZONE_CACHE_KEY_BYTES {
            return None;
        }
        let key = domain.to_lowercase();
        (key.len() <= MAX_ZONE_CACHE_KEY_BYTES).then_some(key)
    }

    fn remove_slot(&mut self, slot: usize) {
        if let Some(key) = self.slots[slot].take() {
            let removed = self.entries.remove(&key);
            debug_assert!(removed.is_some_and(|entry| entry.slot == slot));
            self.free.push(slot);
        }
    }

    fn sweep(&mut self, now: StdInstant) {
        for _ in 0..ZONE_CACHE_SWEEP_BUDGET {
            let slot = self.hand;
            self.hand = (self.hand + 1) % ZONE_CACHE_CAPACITY;
            if self.slots[slot].as_ref().is_some_and(|key| {
                self.entries
                    .get(key)
                    .is_some_and(|entry| now >= entry.expires_at)
            }) {
                self.remove_slot(slot);
            }
        }
    }

    fn get(&mut self, domain: &str, now: StdInstant) -> Option<Option<String>> {
        let key = Self::key(domain)?;
        self.sweep(now);
        let entry = self.entries.get(&key)?;
        if now >= entry.expires_at {
            let slot = entry.slot;
            self.remove_slot(slot);
            return None;
        }
        Some(entry.zone.clone())
    }

    fn set(&mut self, domain: &str, zone: Option<&str>, now: StdInstant) {
        if zone.is_some_and(|value| value.len() > MAX_ZONE_CACHE_VALUE_BYTES) {
            return;
        }
        let Some(key) = Self::key(domain) else {
            return;
        };
        self.sweep(now);
        let expires_at = now + ZONE_CACHE_TTL;
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.zone = zone.map(str::to_owned);
            entry.expires_at = expires_at;
            return;
        }
        if self.free.is_empty() {
            self.remove_slot(self.hand);
            self.hand = (self.hand + 1) % ZONE_CACHE_CAPACITY;
        }
        let slot = self
            .free
            .pop()
            .expect("zone cache has a vacant or evicted slot");
        self.slots[slot] = Some(key.clone());
        self.entries.insert(
            key,
            ZoneCacheEntry {
                zone: zone.map(str::to_owned),
                expires_at,
                slot,
            },
        );
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.slots.fill(None);
        self.free.clear();
        self.free.extend((0..ZONE_CACHE_CAPACITY).rev());
        self.hand = 0;
    }
}

/// Global DNS zone cache with five-minute positive and negative entries.
static ZONE_CACHE: std::sync::OnceLock<Mutex<ZoneCache>> = std::sync::OnceLock::new();

fn zone_cache() -> &'static Mutex<ZoneCache> {
    ZONE_CACHE.get_or_init(|| Mutex::new(ZoneCache::new()))
}

/// `Some(Some(zone))` is a positive hit; `Some(None)` is a negative hit.
fn zone_cache_get(domain: &str) -> Option<Option<String>> {
    zone_cache().lock().ok()?.get(domain, StdInstant::now())
}

fn zone_cache_set(domain: &str, zone: Option<&str>) {
    if let Ok(mut cache) = zone_cache().lock() {
        cache.set(domain, zone, StdInstant::now());
    }
}

/// Clear the DNS zone cache, including all expiry and eviction bookkeeping.
///
/// This is primarily useful for testing or when DNS configuration has
/// changed and cached results are stale.
/// At most 1024 domains are retained for five minutes; capacity eviction may
/// remove an entry sooner. Oversized keys or zone values are not cached.
pub fn clear_zone_cache() {
    if let Ok(mut cache) = zone_cache().lock() {
        cache.clear();
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
/// Results use a shared cache of at most 1024 domains, with a five-minute
/// `ZONE_CACHE_TTL`. Capacity eviction may remove entries sooner.
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
    // Check cache first.
    if let Some(cached) = zone_cache_get(fqdn) {
        return cached;
    }

    let result = find_zone_by_fqdn_heuristic(fqdn);
    zone_cache_set(fqdn, result.as_deref());
    result
}

/// Async version of [`find_zone_by_fqdn`] that performs real SOA queries.
///
/// Walks up the label hierarchy, querying for SOA records at each level.
/// Returns the first domain that has an SOA record. Falls back to the
/// heuristic if no SOA is found.
///
/// Results use a shared cache of at most 1024 domains, with a five-minute
/// `ZONE_CACHE_TTL`. Capacity eviction may remove entries sooner.
pub async fn find_zone_by_fqdn_async(fqdn: &str) -> Option<String> {
    // Check cache first.
    if let Some(cached) = zone_cache_get(fqdn) {
        return cached;
    }

    let domain = from_fqdn(fqdn);
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        zone_cache_set(fqdn, None);
        return None;
    }

    let resolver = match TokioResolver::builder_tokio().and_then(|builder| builder.build()) {
        Ok(resolver) => resolver,
        Err(_) => {
            let result = find_zone_by_fqdn_heuristic(fqdn);
            zone_cache_set(fqdn, result.as_deref());
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
                zone_cache_set(fqdn, result.as_deref());
                return result;
            }
            Err(_) => continue,
        }
    }

    // Fallback to heuristic.
    let result = find_zone_by_fqdn_heuristic(fqdn);
    zone_cache_set(fqdn, result.as_deref());
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
        assert!(!servers.is_empty());
        assert!(servers.iter().all(|s| s.ends_with(":53")));
    }

    #[test]
    fn test_recursive_nameservers_custom() {
        let custom = vec!["10.0.0.1".to_string()];
        let servers = recursive_nameservers(&custom);
        assert_eq!(servers, vec!["10.0.0.1:53"]);
    }

    #[test]
    fn zone_cache_enforces_hard_capacity_under_unique_insertions() {
        let mut cache = ZoneCache::new();
        let now = StdInstant::now();
        for index in 0..10_000 {
            cache.set(
                &format!("cache-capacity-{index}.example.test"),
                Some("example.test."),
                now,
            );
            assert!(cache.entries.len() <= ZONE_CACHE_CAPACITY);
            if index % 64 == 0 {
                assert_zone_cache_slots(&cache);
            }
        }
        assert_zone_cache_slots(&cache);
        assert_eq!(cache.entries.len(), ZONE_CACHE_CAPACITY);
        assert_eq!(cache.slots.len(), ZONE_CACHE_CAPACITY);
        assert!(cache.free.is_empty());
        assert_eq!(
            cache.get("cache-capacity-9999.example.test", now),
            Some(Some("example.test.".into()))
        );
        assert!(cache.get("cache-capacity-0.example.test", now).is_none());
    }

    fn assert_zone_cache_slots(cache: &ZoneCache) {
        use std::collections::HashSet;
        let free: HashSet<_> = cache.free.iter().copied().collect();
        assert_eq!(free.len(), cache.free.len(), "duplicate vacant slot");
        assert_eq!(cache.slots.len(), ZONE_CACHE_CAPACITY);
        assert_eq!(cache.entries.len() + cache.free.len(), ZONE_CACHE_CAPACITY);
        for (slot, key) in cache.slots.iter().enumerate() {
            if let Some(key) = key {
                assert!(!free.contains(&slot));
                assert_eq!(cache.entries[key].slot, slot);
            } else {
                assert!(free.contains(&slot));
            }
        }
        for (key, entry) in &cache.entries {
            assert_eq!(cache.slots[entry.slot].as_deref(), Some(key.as_str()));
        }
    }

    #[test]
    fn zone_cache_preserves_positive_negative_and_exact_ttl_boundaries() {
        let now = StdInstant::now();
        let mut cache = ZoneCache::new();
        cache.set("example.com", Some("example.com."), now);
        cache.set("com", None, now);
        let before = now + ZONE_CACHE_TTL - Duration::from_nanos(1);
        assert_eq!(
            cache.get("example.com", before),
            Some(Some("example.com.".into()))
        );
        assert_eq!(cache.get("com", before), Some(None));
        assert_eq!(cache.get("example.com", now + ZONE_CACHE_TTL), None);
        assert_eq!(cache.get("com", now + ZONE_CACHE_TTL), None);
        assert!(cache.entries.is_empty());
        assert_zone_cache_slots(&cache);
    }

    #[test]
    fn zone_cache_repeated_updates_refresh_ttl_without_growing_bookkeeping() {
        let now = StdInstant::now();
        let mut cache = ZoneCache::new();
        cache.set("example.com", Some("old.example."), now);
        let slot = cache.entries["example.com"].slot;
        let allocations = (
            cache.entries.capacity(),
            cache.slots.capacity(),
            cache.free.capacity(),
        );
        for index in 0..10_000 {
            let at = now + Duration::from_millis(index);
            cache.set(
                "EXAMPLE.COM.",
                (index % 2 == 0).then_some("new.example."),
                at,
            );
            assert_eq!(cache.entries.len(), 1);
            assert_eq!(cache.entries["example.com"].slot, slot);
        }
        assert_eq!(
            allocations,
            (
                cache.entries.capacity(),
                cache.slots.capacity(),
                cache.free.capacity()
            )
        );
        assert_zone_cache_slots(&cache);
        assert_eq!(
            cache.get("example.com", now + ZONE_CACHE_TTL),
            Some(None),
            "an earlier expiry must not discard the latest update"
        );
        assert_eq!(
            cache.get(
                "example.com",
                now + Duration::from_millis(9999) + ZONE_CACHE_TTL
            ),
            None
        );
        assert_zone_cache_slots(&cache);
    }

    #[test]
    fn zone_cache_sweeps_expired_slots_incrementally_and_keeps_refreshed_entries() {
        let now = StdInstant::now();
        let mut cache = ZoneCache::new();
        for index in 0..ZONE_CACHE_CAPACITY {
            cache.set(&format!("host-{index}.example.com"), None, now);
        }
        let update = now + ZONE_CACHE_TTL - Duration::from_secs(1);
        cache.set("host-0.example.com", Some("example.com."), update);
        for _ in 0..ZONE_CACHE_CAPACITY.div_ceil(ZONE_CACHE_SWEEP_BUDGET) {
            assert_eq!(
                cache.get("not-cached.example.com", now + ZONE_CACHE_TTL),
                None
            );
        }
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(
            cache.get("host-0.example.com", now + ZONE_CACHE_TTL),
            Some(Some("example.com.".into()))
        );
        assert_zone_cache_slots(&cache);
    }

    #[test]
    fn zone_cache_clear_resets_slots_and_expiry_bookkeeping() {
        let now = StdInstant::now();
        let mut cache = ZoneCache::new();
        for index in 0..ZONE_CACHE_CAPACITY {
            cache.set(&format!("host-{index}.example.com"), None, now);
        }
        cache.clear();
        assert!(cache.entries.is_empty());
        assert_eq!(cache.hand, 0);
        assert_zone_cache_slots(&cache);
        cache.set(
            "fresh.example.com",
            Some("example.com."),
            now + ZONE_CACHE_TTL,
        );
        assert_eq!(cache.get("host-0.example.com", now + ZONE_CACHE_TTL), None);
        assert_eq!(
            cache.get("fresh.example.com", now + ZONE_CACHE_TTL),
            Some(Some("example.com.".into()))
        );
        assert_zone_cache_slots(&cache);
    }

    #[test]
    fn zone_cache_normalizes_keys_and_skips_oversized_keys_and_values() {
        let now = StdInstant::now();
        let mut cache = ZoneCache::new();
        cache.set("MiXeD.Example.Com.", Some("example.com."), now);
        assert_eq!(
            cache.get("MIXED.EXAMPLE.COM", now),
            Some(Some("example.com.".into()))
        );
        cache.set("mixed.example.com", None, now);
        assert_eq!(cache.get("mixed.example.com.", now), Some(None));
        assert_eq!(cache.entries.len(), 1);
        assert!(cache.entries.contains_key("mixed.example.com"));
        let oversized = "A".repeat(1_000_000);
        cache.set(&oversized, None, now);
        assert!(cache.get(&oversized, now).is_none());
        let expansion = format!("{}.example", "İ".repeat(83));
        assert!(expansion.len() <= MAX_ZONE_CACHE_KEY_BYTES);
        assert!(expansion.to_lowercase().len() > MAX_ZONE_CACHE_KEY_BYTES);
        cache.set(&expansion, None, now);
        cache.set(
            "mixed.example.com",
            Some(&"x".repeat(MAX_ZONE_CACHE_VALUE_BYTES + 1)),
            now,
        );
        assert_eq!(cache.get("mixed.example.com", now), Some(None));
        assert_eq!(cache.entries.len(), 1);
        assert_zone_cache_slots(&cache);
        let longest = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        assert_eq!(longest.len(), MAX_ZONE_CACHE_KEY_BYTES);
        let zone = format!("{longest}.");
        assert_eq!(zone.len(), MAX_ZONE_CACHE_VALUE_BYTES);
        cache.set(&longest, Some(&zone), now);
        assert_eq!(cache.get(&format!("{longest}."), now), Some(Some(zone)));
        assert_zone_cache_slots(&cache);
        // Cache admission must not change the existing discovery result.
        assert_eq!(
            find_zone_by_fqdn(&format!("{oversized}.example.com")),
            Some("example.com.".into())
        );
    }

    #[test]
    fn zone_cache_keeps_repeated_root_dots_separate_from_normal_keys() {
        let now = StdInstant::now();
        let mut cache = ZoneCache::new();
        cache.set("example.com", Some("example.com."), now);
        cache.set("example.com..", Some("com."), now);
        assert_eq!(
            cache.get("EXAMPLE.COM.", now),
            Some(Some("example.com.".into()))
        );
        assert_eq!(cache.get("example.com..", now), Some(Some("com.".into())));
        assert_eq!(cache.entries.len(), 2);
        assert_zone_cache_slots(&cache);
        // Preserve the discovery function's existing malformed-input result
        // without letting that result poison an otherwise normal DNS name.
        assert_eq!(
            find_zone_by_fqdn("root-dot-cache.example.com.."),
            Some("com.".into())
        );
        assert_eq!(
            find_zone_by_fqdn("root-dot-cache.example.com."),
            Some("example.com.".into())
        );
        assert_eq!(
            find_zone_by_fqdn("root-dot-cache.example.com"),
            Some("example.com.".into())
        );
    }

    #[test]
    fn zone_cache_concurrent_positive_and_negative_hits_preserve_slots() {
        let now = StdInstant::now();
        let cache = std::sync::Arc::new(Mutex::new(ZoneCache::new()));
        for index in 0..128 {
            cache.lock().unwrap().set(
                &format!("host-{index}.example.com"),
                (index % 7 != 0).then_some("example.com."),
                now,
            );
        }
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let workers: Vec<_> = (0..8)
            .map(|worker| {
                let cache = cache.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    for iteration in 0..2000 {
                        let index = (iteration + worker) % 128;
                        let name = format!("HOST-{index}.EXAMPLE.COM.");
                        let expected = (index % 7 != 0).then_some("example.com.");
                        let mut cache = cache.lock().unwrap();
                        assert_eq!(
                            cache.get(&name, now + Duration::from_secs(1)),
                            Some(expected.map(str::to_owned))
                        );
                        if iteration % 16 == 0 {
                            cache.set(&name, expected, now + Duration::from_secs(1));
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        let cache = cache.lock().unwrap();
        assert_eq!(cache.entries.len(), 128);
        assert_zone_cache_slots(&cache);
    }
}
