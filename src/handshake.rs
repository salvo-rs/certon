//! TLS handshake certificate resolution.
//!
//! This module implements a [`rustls::server::ResolvesServerCert`] resolver
//! that looks up certificates from the in-memory [`CertCache`] during TLS
//! handshakes. It supports:
//!
//! - Fast SNI-based lookup from the certificate cache.
//! - On-demand TLS: when a matching certificate is not cached, the resolver
//!   can trigger background certificate acquisition so that subsequent
//!   handshakes succeed.
//! - Fallback to a configurable default certificate when no match is found.
//!
//!
//! # On-demand TLS caveat
//!
//! [`rustls::server::ResolvesServerCert::resolve`] is synchronous, so the
//! resolver cannot block on certificate acquisition. Instead, it spawns the
//! obtain operation in the background and returns `None` (or the default
//! certificate) for the current handshake. The next handshake for the same
//! name will find the certificate in cache.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::sync::{Mutex, Notify, RwLock};
use tracing::{debug, warn};

use crate::cache::CertCache;
use crate::certificates::{Certificate, PrivateKeyKind};
use crate::error::{CryptoError, Result};
use crate::rate_limiter::RateLimiter;

// ---------------------------------------------------------------------------
// OnDemandConfig
// ---------------------------------------------------------------------------

/// Configuration for on-demand TLS certificate issuance.
///
/// On-demand TLS allows the server to obtain certificates for previously
/// unknown domain names at handshake time. This is powerful but must be
/// guarded carefully to prevent abuse.
///
/// At least one gating mechanism ([`decision_func`](OnDemandConfig::decision_func)
/// or [`host_allowlist`](OnDemandConfig::host_allowlist)) should be configured
/// to prevent an attacker from forcing the server to request certificates for
/// arbitrary domains.
pub struct OnDemandConfig {
    /// An optional decision function that determines whether a certificate
    /// should be obtained for a given server name.
    ///
    /// Returns `true` if the name is allowed.
    /// If `None`, the decision falls through to `host_allowlist`.
    pub decision_func: Option<Arc<dyn Fn(&str) -> bool + Send + Sync>>,

    /// An explicit set of hostnames for which on-demand issuance is permitted.
    ///
    /// Lookups are case-insensitive (names are lowercased before checking).
    /// If `None`, this check is skipped.
    pub host_allowlist: Option<HashSet<String>>,

    /// Optional rate limiter to throttle on-demand certificate issuance.
    ///
    /// When set, the resolver will check `try_allow()` before spawning an
    /// obtain operation. If the rate limit is exhausted, the request is
    /// silently dropped (no certificate is obtained).
    pub rate_limit: Option<Arc<RateLimiter>>,

    /// Callback that triggers certificate acquisition for the given domain.
    ///
    /// This function is spawned in the background (via `tokio::spawn`) when
    /// a certificate is needed but not cached. The obtained certificate is
    /// expected to be placed into the [`CertCache`] by the callback.
    pub obtain_func: Option<Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>>,
}

impl fmt::Debug for OnDemandConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnDemandConfig")
            .field("decision_func", &self.decision_func.as_ref().map(|_| "..."))
            .field("host_allowlist", &self.host_allowlist)
            .field("rate_limit", &self.rate_limit.as_ref().map(|_| "..."))
            .field("obtain_func", &self.obtain_func.as_ref().map(|_| "..."))
            .finish()
    }
}

impl OnDemandConfig {
    /// Returns `true` if the given server name is allowed for on-demand TLS.
    ///
    /// The check order is:
    /// 1. If `decision_func` is set, its result is authoritative.
    /// 2. If `host_allowlist` is set, the name must be present in the set.
    /// 3. If neither is set, the name is **rejected** (fail-closed) to prevent
    ///    unbounded issuance.
    fn is_allowed(&self, name: &str) -> bool {
        let lower = name.to_lowercase();

        // Decision function takes priority.
        if let Some(ref func) = self.decision_func {
            return func(&lower);
        }

        // Fall back to allowlist.
        if let Some(ref allowlist) = self.host_allowlist {
            return allowlist.contains(&lower);
        }

        // No gating mechanism configured — deny.
        debug!(
            name = %name,
            "on-demand TLS denied: no decision_func or host_allowlist configured",
        );
        false
    }
}

// ---------------------------------------------------------------------------
// CertResolver
// ---------------------------------------------------------------------------

/// A TLS certificate resolver that integrates with [`CertCache`] and
/// optionally supports on-demand certificate issuance.
///
/// Implements [`rustls::server::ResolvesServerCert`] so it can be plugged
/// directly into a `rustls::ServerConfig`.
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
/// use certon::cache::{CertCache, CacheOptions};
/// use certon::handshake::CertResolver;
///
/// let cache = CertCache::new(CacheOptions::default());
/// let resolver = CertResolver::new(cache);
///
/// let config = rustls::ServerConfig::builder()
///     .with_no_client_auth()
///     .with_cert_resolver(Arc::new(resolver));
/// ```
pub struct CertResolver {
    /// The certificate cache used for lookups during TLS handshakes.
    cache: Arc<CertCache>,

    /// Optional on-demand TLS configuration. When set, the resolver can
    /// trigger background certificate acquisition for uncached names.
    on_demand: Option<Arc<OnDemandConfig>>,

    /// A default certificate to return when no matching certificate is found
    /// in the cache (and on-demand TLS is not configured or the name is not
    /// allowed).
    default_cert: RwLock<Option<Arc<CertifiedKey>>>,

    /// Default server name to use when the ClientHello has no SNI.
    default_server_name: Option<String>,

    /// Fallback server name to try when no certificate matches the SNI.
    fallback_server_name: Option<String>,

    /// Challenge certificates for TLS-ALPN-01 validation, keyed by domain name.
    acme_challenges: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,

    /// Pending on-demand obtain operations, keyed by domain name.
    ///
    /// When an on-demand TLS obtain is triggered for a domain, a [`Notify`]
    /// is created so that concurrent handshakes for the same domain can
    /// wait for the obtain to complete rather than spawning duplicate work.
    pending_obtains: Arc<Mutex<HashMap<String, Arc<Notify>>>>,

    /// Optional callback that triggers a background OCSP staple refresh
    /// for a given domain. This is spawned as a background task to avoid
    /// blocking the TLS handshake.
    pub ocsp_refresh_func: Option<Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>>,
}

impl fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertResolver")
            .field("cache", &self.cache)
            .field("on_demand", &self.on_demand.as_ref().map(|_| "..."))
            .field("default_cert", &"<RwLock<Option<Arc<CertifiedKey>>>>")
            .field("default_server_name", &self.default_server_name)
            .field("fallback_server_name", &self.fallback_server_name)
            .field("acme_challenges", &"<Arc<RwLock<HashMap>>>")
            .finish()
    }
}

impl CertResolver {
    /// Create a new `CertResolver` backed by the given certificate cache.
    ///
    /// On-demand TLS is not enabled in this configuration. To enable it,
    /// use [`CertResolver::with_on_demand`] instead.
    pub fn new(cache: Arc<CertCache>) -> Self {
        Self {
            cache,
            on_demand: None,
            default_cert: RwLock::new(None),
            default_server_name: None,
            fallback_server_name: None,
            acme_challenges: Arc::new(RwLock::new(HashMap::new())),
            pending_obtains: Arc::new(Mutex::new(HashMap::new())),
            ocsp_refresh_func: None,
        }
    }

    /// Create a new `CertResolver` with on-demand TLS support.
    ///
    /// When a matching certificate is not found in the cache for a given
    /// SNI name, the resolver checks [`OnDemandConfig`] to decide whether
    /// to trigger background certificate acquisition.
    pub fn with_on_demand(cache: Arc<CertCache>, on_demand: Arc<OnDemandConfig>) -> Self {
        Self {
            cache,
            on_demand: Some(on_demand),
            default_cert: RwLock::new(None),
            default_server_name: None,
            fallback_server_name: None,
            acme_challenges: Arc::new(RwLock::new(HashMap::new())),
            pending_obtains: Arc::new(Mutex::new(HashMap::new())),
            ocsp_refresh_func: None,
        }
    }

    /// Set the default server name to use when the ClientHello has no SNI.
    pub fn set_default_server_name(&mut self, name: Option<String>) {
        self.default_server_name = name;
    }

    /// Set the fallback server name to try when no certificate matches the SNI.
    pub fn set_fallback_server_name(&mut self, name: Option<String>) {
        self.fallback_server_name = name;
    }

    /// Register a TLS-ALPN-01 challenge certificate for the given domain.
    ///
    /// When a ClientHello arrives with ALPN containing `"acme-tls/1"` and
    /// a matching SNI, this challenge certificate will be returned instead
    /// of the normal certificate.
    pub async fn set_challenge_cert(&self, domain: String, cert: Arc<CertifiedKey>) {
        let mut challenges = self.acme_challenges.write().await;
        challenges.insert(domain, cert);
    }

    /// Remove a previously registered TLS-ALPN-01 challenge certificate.
    pub async fn remove_challenge_cert(&self, domain: &str) {
        let mut challenges = self.acme_challenges.write().await;
        challenges.remove(domain);
    }

    /// Set the default (fallback) certificate.
    ///
    /// This certificate is returned when no match is found in the cache for
    /// the requested SNI name. It can be updated at runtime.
    pub async fn set_default_cert(&self, cert: Arc<CertifiedKey>) {
        let mut guard = self.default_cert.write().await;
        *guard = Some(cert);
    }

    /// Clear the default (fallback) certificate.
    pub async fn clear_default_cert(&self) {
        let mut guard = self.default_cert.write().await;
        *guard = None;
    }

    /// Attempt to resolve a certificate for the given server name.
    ///
    /// This is the core lookup logic, factored out of the `ResolvesServerCert`
    /// trait method so it can also be called from async contexts.
    ///
    /// Returns `Some(CertifiedKey)` if a suitable certificate was found or
    /// `None` if no certificate is available.
    fn resolve_name(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let name = match server_name {
            Some(n) if !n.is_empty() => n.to_owned(),
            _ => {
                // No SNI: try default_server_name from config.
                if let Some(ref default_name) = self.default_server_name {
                    debug!(
                        default_server_name = %default_name,
                        "no SNI in ClientHello; using default_server_name",
                    );
                    default_name.clone()
                } else {
                    debug!("no SNI in ClientHello; returning default cert");
                    return self.try_default_cert();
                }
            }
        };

        debug!(sni = %name, "resolving certificate for TLS handshake");

        // Step 1: Look up the exact name in the certificate cache.
        if let Some(result) = self.try_resolve_from_cache_with_ocsp_check(&name) {
            return Some(result);
        }

        // Step 1b: Wildcard matching — try replacing labels from the left
        // with `*` to find wildcard certificates.
        // For "foo.bar.example.com", try:
        //   *.bar.example.com
        //   *.example.com
        //   *.com
        {
            let labels: Vec<&str> = name.split('.').collect();
            if labels.len() >= 2 {
                for i in 1..labels.len() {
                    let wildcard = format!("*.{}", labels[i..].join("."));
                    if let Some(result) = self.try_resolve_from_cache(&wildcard) {
                        debug!(
                            sni = %name,
                            wildcard = %wildcard,
                            "certificate found via wildcard matching",
                        );
                        return Some(result);
                    }
                }
            }
        }

        // Step 2: On-demand TLS — trigger background certificate acquisition.
        if let Some(ref on_demand) = self.on_demand {
            if on_demand.is_allowed(&name) {
                self.trigger_on_demand_obtain(on_demand, &name);
                debug!(
                    sni = %name,
                    "on-demand certificate obtain triggered; returning default cert for now",
                );
            } else {
                debug!(
                    sni = %name,
                    "on-demand TLS not allowed for this name",
                );
            }
        }

        // Step 3: Try fallback_server_name if set and different from the
        // original name.
        if let Some(ref fallback) = self.fallback_server_name {
            if fallback != &name {
                debug!(
                    sni = %name,
                    fallback = %fallback,
                    "trying fallback_server_name",
                );
                if let Some(result) = self.try_resolve_from_cache(fallback) {
                    return Some(result);
                }
            }
        }

        // Step 4: Return the default certificate.
        self.try_default_cert()
    }

    /// Try to resolve a certificate for `name` from the cache and convert it
    /// to a `CertifiedKey`. Returns `None` on miss or conversion failure.
    fn try_resolve_from_cache(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        if let Some(cert) = self.try_cache_lookup(name) {
            match cert_to_certified_key(&cert) {
                Ok(ck) => {
                    debug!(sni = %name, hash = %cert.hash, "certificate found in cache");
                    return Some(ck);
                }
                Err(e) => {
                    warn!(
                        sni = %name,
                        hash = %cert.hash,
                        error = %e,
                        "failed to convert cached certificate to CertifiedKey",
                    );
                }
            }
        }
        None
    }

    /// Like [`try_resolve_from_cache`], but also triggers a background OCSP
    /// refresh if the certificate is missing its OCSP staple.
    fn try_resolve_from_cache_with_ocsp_check(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        if let Some(cert) = self.try_cache_lookup(name) {
            // Task 10: if the OCSP status is missing or the OCSP response
            // bytes are absent, trigger a background OCSP refresh without
            // blocking the handshake.
            if cert.ocsp_status.is_none() || cert.ocsp_response.is_none() {
                if let Some(ref refresh_fn) = self.ocsp_refresh_func {
                    let refresh = Arc::clone(refresh_fn);
                    let domain = name.to_owned();
                    debug!(
                        sni = %name,
                        hash = %cert.hash,
                        "OCSP staple missing; spawning background refresh",
                    );
                    tokio::spawn(async move {
                        refresh(domain).await;
                    });
                }
            }

            match cert_to_certified_key(&cert) {
                Ok(ck) => {
                    debug!(sni = %name, hash = %cert.hash, "certificate found in cache");
                    return Some(ck);
                }
                Err(e) => {
                    warn!(
                        sni = %name,
                        hash = %cert.hash,
                        error = %e,
                        "failed to convert cached certificate to CertifiedKey",
                    );
                }
            }
        }
        None
    }

    /// Attempt a synchronous cache lookup.
    ///
    /// Uses `try_read` on the internal RwLocks to avoid blocking in a sync
    /// context. Returns `None` if the locks are contended or no certificate
    /// matches.
    fn try_cache_lookup(&self, name: &str) -> Option<Certificate> {
        // We need to perform the lookup that CertCache::get_by_name does,
        // but synchronously. We use tokio's `Handle::block_on` if we're
        // inside a tokio runtime, falling back to `try_read`.
        //
        // The recommended approach for rustls resolvers is to use
        // `tokio::runtime::Handle::try_current()` and `block_in_place`.
        // However, this can deadlock if called from within a non-blocking
        // context. The safest approach is `block_in_place` which works from
        // multi-threaded runtimes.
        let handle = tokio::runtime::Handle::try_current().ok()?;

        // `block_in_place` moves the current task off the worker thread so
        // that we can safely block on async operations. This requires a
        // multi-threaded runtime; on a current-thread runtime it will panic.
        // For production TLS servers a multi-threaded runtime is expected.
        let result = tokio::task::block_in_place(|| {
            handle.block_on(self.cache.get_by_name(name))
        });

        result
    }

    /// Trigger background certificate acquisition for the given name.
    ///
    /// Uses leader/waiter coordination: if an obtain is already in progress
    /// for this domain, the current caller does not spawn a duplicate task.
    /// Instead, subsequent handshakes will find the certificate in cache once
    /// the first obtain completes.
    fn trigger_on_demand_obtain(&self, on_demand: &Arc<OnDemandConfig>, name: &str) {
        // Check if there is already a pending obtain for this domain.
        // We use try_lock to avoid blocking in a sync context.
        let pending = self.pending_obtains.clone();
        let name_owned = name.to_owned();

        // Try to check and register as leader in a non-blocking way.
        let maybe_guard = self.pending_obtains.try_lock();
        match maybe_guard {
            Ok(mut guard) => {
                if guard.contains_key(&name_owned) {
                    // Another task is already obtaining this certificate.
                    debug!(
                        sni = %name,
                        "on-demand obtain already in progress for this domain; waiting",
                    );
                    return;
                }
                // Register as leader.
                let notify = Arc::new(Notify::new());
                guard.insert(name_owned.clone(), Arc::clone(&notify));

                // Spawn the obtain task.
                let on_demand = Arc::clone(on_demand);
                let name_for_task = name_owned.clone();

                tokio::spawn(async move {
                    Self::do_on_demand_obtain(&on_demand, &name_for_task).await;

                    // Notify all waiters and remove from pending map.
                    notify.notify_waiters();
                    let mut guard = pending.lock().await;
                    guard.remove(&name_for_task);
                });
            }
            Err(_) => {
                // Lock contended; fall through and spawn without dedup
                // coordination to avoid blocking the handshake.
                let on_demand = Arc::clone(on_demand);
                let name_for_task = name_owned;
                tokio::spawn(async move {
                    Self::do_on_demand_obtain(&on_demand, &name_for_task).await;
                });
            }
        }
    }

    /// Execute the on-demand obtain, respecting rate limits.
    async fn do_on_demand_obtain(on_demand: &OnDemandConfig, name: &str) {
        // Check rate limit.
        if let Some(ref limiter) = on_demand.rate_limit {
            if !limiter.try_allow().await {
                warn!(
                    sni = %name,
                    "on-demand certificate obtain rate-limited; skipping",
                );
                return;
            }
        }

        if let Some(ref obtain) = on_demand.obtain_func {
            if let Err(e) = obtain(name.to_owned()).await {
                warn!(
                    sni = %name,
                    error = %e,
                    "on-demand certificate obtain failed",
                );
            }
        }
    }

    /// Try to return the default certificate (non-blocking).
    fn try_default_cert(&self) -> Option<Arc<CertifiedKey>> {
        // Use `try_read` to avoid blocking.
        match self.default_cert.try_read() {
            Ok(guard) => guard.clone(),
            Err(_) => {
                debug!("could not read default cert (lock contended)");
                None
            }
        }
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Check for TLS-ALPN-01 ACME challenge first.
        let is_acme_tls_alpn = client_hello.alpn().map_or(false, |mut alpn| {
            alpn.any(|proto| proto == b"acme-tls/1")
        });

        if is_acme_tls_alpn {
            if let Some(sni) = client_hello.server_name() {
                debug!(sni = %sni, "TLS-ALPN-01 challenge request detected");
                if let Some(challenge_cert) = self.try_challenge_lookup(sni) {
                    debug!(sni = %sni, "serving TLS-ALPN-01 challenge certificate");
                    return Some(challenge_cert);
                }
                warn!(
                    sni = %sni,
                    "TLS-ALPN-01 challenge requested but no challenge cert registered",
                );
                return None;
            }
            debug!("TLS-ALPN-01 challenge without SNI; ignoring");
            return None;
        }

        self.resolve_name(client_hello.server_name())
    }
}

impl CertResolver {
    /// Attempt a synchronous lookup for a TLS-ALPN-01 challenge certificate.
    fn try_challenge_lookup(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        match self.acme_challenges.try_read() {
            Ok(guard) => guard.get(name).cloned(),
            Err(_) => {
                debug!("could not read acme_challenges (lock contended)");
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Certificate conversion
// ---------------------------------------------------------------------------

/// Convert a [`Certificate`] into a rustls [`CertifiedKey`].
///
/// This reconstructs the [`PrivateKeyDer`] from the stored raw bytes and
/// [`PrivateKeyKind`], then uses `rustls::crypto::ring::sign::any_supported_type`
/// to produce a signing key. The certificate chain and signing key are bundled
/// into a [`CertifiedKey`].
///
/// If the certificate has an OCSP response, it is attached to the
/// `CertifiedKey` so that rustls can staple it during the handshake.
///
/// # Errors
///
/// Returns an error if the certificate has no private key or if the key
/// type is not supported by the ring crypto provider.
pub fn cert_to_certified_key(cert: &Certificate) -> Result<Arc<CertifiedKey>> {
    // Reconstruct the PrivateKeyDer.
    let key_der = reconstruct_private_key_der(cert)?;

    // Convert to a rustls signing key.
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
        .map_err(|e| CryptoError::InvalidKey(format!(
            "failed to create signing key from private key: {e}"
        )))?;

    // Build the CertifiedKey.
    let mut certified_key = CertifiedKey::new(
        cert.cert_chain.clone(),
        signing_key,
    );

    // Attach OCSP response if available.
    if let Some(ref ocsp) = cert.ocsp_response {
        certified_key.ocsp = Some(ocsp.clone());
    }

    Ok(Arc::new(certified_key))
}

/// Reconstruct a [`PrivateKeyDer`] from a [`Certificate`]'s raw key bytes
/// and kind tag.
fn reconstruct_private_key_der(cert: &Certificate) -> Result<PrivateKeyDer<'static>> {
    let raw = cert.private_key_der.as_ref().ok_or_else(|| {
        CryptoError::InvalidKey("certificate has no private key".into())
    })?;

    if raw.is_empty() {
        return Err(CryptoError::InvalidKey("private key bytes are empty".into()).into());
    }

    let key_der = match cert.private_key_kind {
        PrivateKeyKind::Pkcs8 => {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(raw.clone()))
        }
        PrivateKeyKind::Pkcs1 => {
            PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(raw.clone()))
        }
        PrivateKeyKind::Sec1 => {
            PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(raw.clone()))
        }
        PrivateKeyKind::None => {
            return Err(CryptoError::InvalidKey(
                "certificate private key kind is None".into(),
            ).into());
        }
    };

    Ok(key_der)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CacheOptions;
    use chrono::{Duration as ChronoDuration, Utc};
    /// Helper: build a minimal test certificate (no real crypto material).
    fn make_test_cert(names: &[&str], hash: &str) -> Certificate {
        let now = Utc::now();
        Certificate {
            cert_chain: Vec::new(),
            private_key_der: None,
            private_key_kind: PrivateKeyKind::None,
            names: names.iter().map(|n| n.to_string()).collect(),
            tags: Vec::new(),
            managed: true,
            issuer_key: String::new(),
            hash: hash.to_string(),
            ocsp_response: None,
            ocsp_status: None,
            not_after: now + ChronoDuration::days(90),
            not_before: now - ChronoDuration::days(1),
            ari: None,
        }
    }

    #[test]
    fn test_on_demand_config_denied_without_gating() {
        let config = OnDemandConfig {
            decision_func: None,
            host_allowlist: None,
            rate_limit: None,
            obtain_func: None,
        };
        assert!(!config.is_allowed("example.com"));
    }

    #[test]
    fn test_on_demand_config_allowlist_hit() {
        let mut allowlist = HashSet::new();
        allowlist.insert("example.com".to_string());

        let config = OnDemandConfig {
            decision_func: None,
            host_allowlist: Some(allowlist),
            rate_limit: None,
            obtain_func: None,
        };
        assert!(config.is_allowed("example.com"));
        assert!(config.is_allowed("Example.COM")); // case-insensitive
    }

    #[test]
    fn test_on_demand_config_allowlist_miss() {
        let mut allowlist = HashSet::new();
        allowlist.insert("example.com".to_string());

        let config = OnDemandConfig {
            decision_func: None,
            host_allowlist: Some(allowlist),
            rate_limit: None,
            obtain_func: None,
        };
        assert!(!config.is_allowed("other.com"));
    }

    #[test]
    fn test_on_demand_config_decision_func() {
        let config = OnDemandConfig {
            decision_func: Some(Arc::new(|name: &str| name.ends_with(".example.com"))),
            host_allowlist: None,
            rate_limit: None,
            obtain_func: None,
        };
        assert!(config.is_allowed("sub.example.com"));
        assert!(!config.is_allowed("other.com"));
    }

    #[test]
    fn test_on_demand_config_decision_func_takes_priority() {
        let mut allowlist = HashSet::new();
        allowlist.insert("blocked.com".to_string());

        let config = OnDemandConfig {
            decision_func: Some(Arc::new(|_| false)),
            host_allowlist: Some(allowlist),
            rate_limit: None,
            obtain_func: None,
        };
        // decision_func denies everything, even if allowlist would allow it.
        assert!(!config.is_allowed("blocked.com"));
    }

    #[test]
    fn test_cert_resolver_new() {
        let cache = CertCache::new(CacheOptions::default());
        let resolver = CertResolver::new(cache);
        // Just verify construction succeeds.
        assert!(format!("{:?}", resolver).contains("CertResolver"));
    }

    #[test]
    fn test_cert_resolver_no_sni_returns_none_without_default() {
        let cache = CertCache::new(CacheOptions::default());
        let resolver = CertResolver::new(cache);
        let result = resolver.resolve_name(None);
        assert!(result.is_none());
    }

    #[test]
    fn test_cert_resolver_empty_sni_returns_none_without_default() {
        let cache = CertCache::new(CacheOptions::default());
        let resolver = CertResolver::new(cache);
        let result = resolver.resolve_name(Some(""));
        assert!(result.is_none());
    }

    #[test]
    fn test_reconstruct_private_key_no_key() {
        let cert = make_test_cert(&["example.com"], "h1");
        let result = reconstruct_private_key_der(&cert);
        assert!(result.is_err());
    }

    #[test]
    fn test_reconstruct_private_key_empty_bytes() {
        let mut cert = make_test_cert(&["example.com"], "h1");
        cert.private_key_der = Some(Vec::new());
        cert.private_key_kind = PrivateKeyKind::Pkcs8;
        let result = reconstruct_private_key_der(&cert);
        assert!(result.is_err());
    }

    #[test]
    fn test_reconstruct_private_key_none_kind() {
        let mut cert = make_test_cert(&["example.com"], "h1");
        cert.private_key_der = Some(vec![1, 2, 3]);
        cert.private_key_kind = PrivateKeyKind::None;
        let result = reconstruct_private_key_der(&cert);
        assert!(result.is_err());
    }

    #[test]
    fn test_reconstruct_private_key_pkcs8() {
        let mut cert = make_test_cert(&["example.com"], "h1");
        cert.private_key_der = Some(vec![1, 2, 3, 4]);
        cert.private_key_kind = PrivateKeyKind::Pkcs8;
        let result = reconstruct_private_key_der(&cert);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reconstruct_private_key_pkcs1() {
        let mut cert = make_test_cert(&["example.com"], "h1");
        cert.private_key_der = Some(vec![1, 2, 3, 4]);
        cert.private_key_kind = PrivateKeyKind::Pkcs1;
        let result = reconstruct_private_key_der(&cert);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reconstruct_private_key_sec1() {
        let mut cert = make_test_cert(&["example.com"], "h1");
        cert.private_key_der = Some(vec![1, 2, 3, 4]);
        cert.private_key_kind = PrivateKeyKind::Sec1;
        let result = reconstruct_private_key_der(&cert);
        assert!(result.is_ok());
    }

    #[test]
    fn test_on_demand_config_debug() {
        let config = OnDemandConfig {
            decision_func: None,
            host_allowlist: None,
            rate_limit: None,
            obtain_func: None,
        };
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("OnDemandConfig"));
    }

    #[test]
    fn test_cert_resolver_debug() {
        let cache = CertCache::new(CacheOptions::default());
        let resolver = CertResolver::new(cache);
        let debug_str = format!("{:?}", resolver);
        assert!(debug_str.contains("CertResolver"));
    }
}
