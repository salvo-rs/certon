//! TLS handshake certificate resolution.
//!
//! This module implements a [`rustls::server::ResolvesServerCert`] resolver
//! that looks up certificates from the in-memory [`CertCache`] during TLS
//! handshakes. It supports:
//!
//! - Fast SNI-based lookup from the certificate cache.
//! - On-demand TLS: when a matching certificate is not cached, the resolver can trigger background
//!   certificate acquisition so that subsequent handshakes succeed.
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
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use rustls::SignatureScheme;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// Decision function that determines whether on-demand TLS is allowed for a name.
type DecisionFunc = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Async callback that triggers certificate acquisition for a domain.
type ObtainFunc =
    Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;

/// Async callback that triggers a background OCSP staple refresh for a domain.
type OcspRefreshFunc =
    Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;
use tracing::{debug, warn};

use crate::cache::CertCache;
use crate::certificates::{Certificate, PrivateKeyKind};
use crate::error::{CryptoError, Result};
use crate::policy::CertificateSelector;
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
    pub decision_func: Option<DecisionFunc>,

    /// An explicit set of hostnames for which on-demand issuance is permitted.
    ///
    /// Lookups are case-insensitive (names are lowercased before checking).
    /// If `None`, this check is skipped.
    pub host_allowlist: Option<HashSet<String>>,

    /// Optional rate limiter to throttle on-demand certificate issuance.
    ///
    /// When set, admitted background work checks `try_allow()` before calling
    /// the obtain callback. If the rate limit is exhausted, the request is
    /// silently dropped (no certificate is obtained).
    pub rate_limit: Option<Arc<RateLimiter>>,

    /// Callback that triggers certificate acquisition for the given domain.
    ///
    /// This function is spawned in the background (via `tokio::spawn`) when
    /// a certificate is needed but not cached. The obtained certificate is
    /// expected to be placed into the [`CertCache`] by the callback.
    /// Work is deduplicated by domain, with at most 32 concurrent obtains and
    /// a 60-second cooldown after completion or failure. The cooldown registry
    /// retains at most 256 domains. Acquisition requires an active Tokio runtime.
    pub obtain_func: Option<ObtainFunc>,
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
    /// 3. If neither is set, the name is **rejected** (fail-closed) to prevent unbounded issuance.
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

    cert_selection: Option<Arc<dyn CertificateSelector>>,

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

    /// Bounded, single-flight background work with retry cooldowns.
    pending_obtains: Arc<Mutex<BackgroundTasks>>,
    pending_ocsp: Arc<Mutex<BackgroundTasks>>,

    /// Optional callback that triggers a background OCSP staple refresh
    /// for a given domain. This is spawned as a background task to avoid
    /// blocking the TLS handshake. Refreshes are deduplicated by certificate
    /// hash, limited to 32 concurrent tasks, with a 60-second retry cooldown.
    /// Without an active Tokio runtime, cached certificates are served without
    /// scheduling a refresh.
    pub ocsp_refresh_func: Option<OcspRefreshFunc>,
}

impl fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertResolver")
            .field("cache", &self.cache)
            .field("on_demand", &self.on_demand.as_ref().map(|_| "..."))
            .field("cert_selection", &self.cert_selection.is_some())
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
            cert_selection: None,
            default_cert: RwLock::new(None),
            default_server_name: None,
            fallback_server_name: None,
            acme_challenges: Arc::new(RwLock::new(HashMap::new())),
            pending_obtains: Arc::new(Mutex::new(BackgroundTasks::default())),
            pending_ocsp: Arc::new(Mutex::new(BackgroundTasks::default())),
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
            cert_selection: None,
            default_cert: RwLock::new(None),
            default_server_name: None,
            fallback_server_name: None,
            acme_challenges: Arc::new(RwLock::new(HashMap::new())),
            pending_obtains: Arc::new(Mutex::new(BackgroundTasks::default())),
            pending_ocsp: Arc::new(Mutex::new(BackgroundTasks::default())),
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

    pub(crate) fn set_certificate_selector(&mut self, selector: Arc<dyn CertificateSelector>) {
        self.cert_selection = Some(selector);
    }

    /// Register a TLS-ALPN-01 challenge certificate for the given domain.
    ///
    /// When a ClientHello arrives with ALPN containing `"acme-tls/1"` and
    /// a matching SNI, this challenge certificate will be returned instead
    /// of the normal certificate.
    pub async fn set_challenge_cert(&self, domain: String, cert: Arc<CertifiedKey>) {
        let mut challenges = self
            .acme_challenges
            .write()
            .unwrap_or_else(|e| e.into_inner());
        challenges.insert(domain.to_lowercase(), cert);
    }

    /// Remove a previously registered TLS-ALPN-01 challenge certificate.
    pub async fn remove_challenge_cert(&self, domain: &str) {
        let mut challenges = self
            .acme_challenges
            .write()
            .unwrap_or_else(|e| e.into_inner());
        challenges.remove(&domain.to_lowercase());
    }

    /// Set the default (fallback) certificate.
    ///
    /// This certificate is returned when no match is found in the cache for
    /// the requested SNI name. It can be updated at runtime.
    pub async fn set_default_cert(&self, cert: Arc<CertifiedKey>) {
        let mut guard = self.default_cert.write().unwrap_or_else(|e| e.into_inner());
        *guard = Some(cert);
    }

    /// Clear the default (fallback) certificate.
    pub async fn clear_default_cert(&self) {
        let mut guard = self.default_cert.write().unwrap_or_else(|e| e.into_inner());
        *guard = None;
    }

    /// Attempt to resolve a certificate for the given server name.
    ///
    /// This is the core lookup logic, factored out of the `ResolvesServerCert`
    /// trait method so it can also be called from async contexts.
    ///
    /// Returns `Some(CertifiedKey)` if a suitable certificate was found or
    /// `None` if no certificate is available.
    #[cfg(test)]
    fn resolve_name(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        self.resolve_name_for_client(server_name, None)
    }

    fn resolve_name_for_client(
        &self,
        server_name: Option<&str>,
        hello: Option<&ClientHello<'_>>,
    ) -> Option<Arc<CertifiedKey>> {
        let schemes = hello.map(ClientHello::signature_schemes);
        let name = match server_name {
            Some(n) if !n.is_empty() => n.to_lowercase(),
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
                    return self.try_default_cert(schemes);
                }
            }
        };

        debug!(sni = %name, "resolving certificate for TLS handshake");

        // Step 1: Look up the exact name in the certificate cache.
        let (cached_match, selected) = self.try_resolve_from_cache_with_ocsp_check(&name, hello);
        if let Some(result) = selected {
            return Some(result);
        }

        // Step 2: Obtain only for a true cache miss. A client advertising an
        // incompatible algorithm must not spend the issuance rate-limit budget.
        if !cached_match && let Some(ref on_demand) = self.on_demand {
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
        if let Some(ref fallback) = self.fallback_server_name
            && fallback != &name
        {
            debug!(
                sni = %name,
                fallback = %fallback,
                "trying fallback_server_name",
            );
            if let Some(result) = self.try_resolve_from_cache(fallback, hello) {
                return Some(result);
            }
        }

        // Step 4: Return the default certificate.
        self.try_default_cert(schemes)
    }

    /// The cache owns the prebuilt signing key; a handshake only clones its Arc.
    fn try_resolve_from_cache(
        &self,
        name: &str,
        hello: Option<&ClientHello<'_>>,
    ) -> Option<Arc<CertifiedKey>> {
        self.resolve_cached_key(name, hello)
            .selected
            .map(|cached| cached.key)
    }

    fn resolve_cached_key(
        &self,
        name: &str,
        hello: Option<&ClientHello<'_>>,
    ) -> crate::cache::CachedKeyLookup {
        let schemes = hello.map(ClientHello::signature_schemes);
        if let (Some(selector), Some(hello)) = (&self.cert_selection, hello) {
            let (matched, mut candidates) = self
                .cache
                .selection_candidates(name, |key| accepts_schemes(key, schemes));
            let selected = if candidates.is_empty() {
                None
            } else {
                let choices: Vec<_> = candidates
                    .iter()
                    .map(|candidate| candidate.certificate.as_ref())
                    .collect();
                let index = selector
                    .select_certificate(hello, &choices)
                    .filter(|index| *index < candidates.len())
                    .unwrap_or(0);
                Some(candidates.swap_remove(index).key)
            };
            return crate::cache::CachedKeyLookup { matched, selected };
        }
        match schemes {
            Some(schemes) => self
                .cache
                .resolve_with_filter(name, |key| key.key.choose_scheme(schemes).is_some()),
            None => {
                let selected = self.cache.resolve(name);
                crate::cache::CachedKeyLookup {
                    matched: selected.is_some(),
                    selected,
                }
            }
        }
    }

    fn try_resolve_from_cache_with_ocsp_check(
        &self,
        name: &str,
        hello: Option<&ClientHello<'_>>,
    ) -> (bool, Option<Arc<CertifiedKey>>) {
        let lookup = self.resolve_cached_key(name, hello);
        let refresh_hash = if self.ocsp_refresh_func.is_some() {
            match lookup.selected.as_ref() {
                Some(key) => key.needs_ocsp.then(|| key.hash.clone()),
                None => self.cache.ocsp_refresh_candidate(name, |key| {
                    accepts_schemes(key, hello.map(ClientHello::signature_schemes))
                }),
            }
        } else {
            None
        };
        if let Some(hash) = refresh_hash
            && let Some(refresh_fn) = &self.ocsp_refresh_func
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
            && let Some(work) = BackgroundWork::try_start(&self.pending_ocsp, hash)
        {
            let refresh = Arc::clone(refresh_fn);
            let domain = name.to_owned();
            runtime.spawn(async move {
                let _work = work;
                refresh(domain).await;
            });
        }
        (lookup.matched, lookup.selected.map(|cached| cached.key))
    }

    fn trigger_on_demand_obtain(&self, on_demand: &Arc<OnDemandConfig>, name: &str) {
        // Plain synchronous rustls users can serve cached/default certificates
        // without a runtime. Async acquisition requires one, so skip it there.
        if on_demand.obtain_func.is_none() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let Some(work) = BackgroundWork::try_start(&self.pending_obtains, name.to_lowercase())
        else {
            return;
        };
        let on_demand = Arc::clone(on_demand);
        let domain = name.to_owned();
        runtime.spawn(async move {
            let _work = work;
            Self::do_on_demand_obtain(&on_demand, &domain).await;
        });
    }

    /// Execute the on-demand obtain, respecting rate limits.
    async fn do_on_demand_obtain(on_demand: &OnDemandConfig, name: &str) {
        // Check rate limit.
        if let Some(ref limiter) = on_demand.rate_limit
            && !limiter.try_allow().await
        {
            warn!(
                sni = %name,
                "on-demand certificate obtain rate-limited; skipping",
            );
            return;
        }

        if let Some(ref obtain) = on_demand.obtain_func
            && let Err(e) = obtain(name.to_owned()).await
        {
            warn!(
                sni = %name,
                error = %e,
                "on-demand certificate obtain failed",
            );
        }
    }

    /// Short synchronous reads do not turn contention into a false cache miss.
    fn try_default_cert(&self, schemes: Option<&[SignatureScheme]>) -> Option<Arc<CertifiedKey>> {
        let key = self
            .default_cert
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()?;
        accepts_schemes(&key, schemes).then_some(key)
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Check for TLS-ALPN-01 ACME challenge first.
        let is_acme_tls_alpn = client_hello
            .alpn()
            .is_some_and(|mut alpn| alpn.any(|proto| proto == b"acme-tls/1"));

        if is_acme_tls_alpn {
            if let Some(sni) = client_hello.server_name() {
                debug!(sni = %sni, "TLS-ALPN-01 challenge request detected");
                if let Some(challenge_cert) = self.try_challenge_lookup(sni) {
                    debug!(sni = %sni, "serving TLS-ALPN-01 challenge certificate");
                    return accepts_schemes(
                        &challenge_cert,
                        Some(client_hello.signature_schemes()),
                    )
                    .then_some(challenge_cert);
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

        self.resolve_name_for_client(client_hello.server_name(), Some(&client_hello))
    }
}

fn accepts_schemes(key: &CertifiedKey, schemes: Option<&[SignatureScheme]>) -> bool {
    schemes.is_none_or(|schemes| key.key.choose_scheme(schemes).is_some())
}

impl CertResolver {
    /// Attempt a synchronous lookup for a TLS-ALPN-01 challenge certificate.
    fn try_challenge_lookup(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        self.acme_challenges
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&name.to_lowercase())
            .cloned()
    }
}

// A handshake never queues unlimited work. The per-key cooldown also covers
// failed refreshes, unavailable OCSP responders and rapidly failing issuers.
const MAX_BACKGROUND_TASKS: usize = 32;
const MAX_BACKGROUND_KEYS: usize = 256;
const BACKGROUND_RETRY_DELAY: Duration = Duration::from_secs(60);

#[derive(Default)]
struct BackgroundTasks {
    // None means running; Some is the earliest permitted retry time.
    entries: HashMap<String, Option<Instant>>,
}

struct BackgroundWork {
    tasks: Arc<Mutex<BackgroundTasks>>,
    key: String,
}

impl BackgroundWork {
    fn try_start(tasks: &Arc<Mutex<BackgroundTasks>>, key: String) -> Option<Self> {
        let now = Instant::now();
        let mut state = tasks.lock().unwrap_or_else(|e| e.into_inner());
        state
            .entries
            .retain(|_, retry| retry.is_none_or(|at| at > now));
        if state.entries.contains_key(&key)
            || state.entries.len() >= MAX_BACKGROUND_KEYS
            || state.entries.values().filter(|at| at.is_none()).count() >= MAX_BACKGROUND_TASKS
        {
            return None;
        }
        state.entries.insert(key.clone(), None);
        Some(Self {
            tasks: Arc::clone(tasks),
            key,
        })
    }
}

impl Drop for BackgroundWork {
    fn drop(&mut self) {
        let mut state = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        state.entries.insert(
            self.key.clone(),
            Some(Instant::now() + BACKGROUND_RETRY_DELAY),
        );
    }
}

// ---------------------------------------------------------------------------
// Certificate conversion
// ---------------------------------------------------------------------------

/// Create a rustls signing key from a [`PrivateKeyDer`].
///
/// Uses the crypto provider selected by the `aws-lc-rs` or `ring` feature.
pub fn signing_key_from_der(
    key_der: &PrivateKeyDer<'_>,
) -> std::result::Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
    #[cfg(feature = "aws-lc-rs")]
    {
        rustls::crypto::aws_lc_rs::sign::any_supported_type(key_der)
    }
    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    {
        rustls::crypto::ring::sign::any_supported_type(key_der)
    }
}

/// Convert a [`Certificate`] into a rustls [`CertifiedKey`].
///
/// This reconstructs the [`PrivateKeyDer`] from the stored raw bytes and
/// [`PrivateKeyKind`], then uses the feature-selected crypto provider
/// to produce a signing key. The certificate chain and signing key are bundled
/// into a [`CertifiedKey`].
///
/// If the certificate has an OCSP response, it is attached to the
/// `CertifiedKey` so that rustls can staple it during the handshake.
///
/// # Errors
///
/// Returns an error if the certificate has no private key or if the key
/// type is not supported by the crypto provider.
pub fn cert_to_certified_key(cert: &Certificate) -> Result<Arc<CertifiedKey>> {
    // Reconstruct the PrivateKeyDer.
    let key_der = reconstruct_private_key_der(cert)?;

    // Convert to a rustls signing key.
    let signing_key = signing_key_from_der(&key_der).map_err(|e| {
        CryptoError::InvalidKey(format!(
            "failed to create signing key from private key: {e}"
        ))
    })?;

    // Build the CertifiedKey.
    let mut certified_key = CertifiedKey::new(cert.cert_chain.clone(), signing_key);

    // Attach OCSP response if available.
    if let Some(ref ocsp) = cert.ocsp_response {
        certified_key.ocsp = Some(ocsp.clone());
    }

    Ok(Arc::new(certified_key))
}

/// Reconstruct a [`PrivateKeyDer`] from a [`Certificate`]'s raw key bytes
/// and kind tag.
fn reconstruct_private_key_der(cert: &Certificate) -> Result<PrivateKeyDer<'static>> {
    let raw = cert
        .private_key_der
        .as_ref()
        .ok_or_else(|| CryptoError::InvalidKey("certificate has no private key".into()))?;

    if raw.is_empty() {
        return Err(CryptoError::InvalidKey("private key bytes are empty".into()).into());
    }

    let key_der = match cert.private_key_kind {
        PrivateKeyKind::Pkcs8 => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(raw.clone())),
        PrivateKeyKind::Pkcs1 => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(raw.clone())),
        PrivateKeyKind::Sec1 => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(raw.clone())),
        PrivateKeyKind::None => {
            return Err(
                CryptoError::InvalidKey("certificate private key kind is None".into()).into(),
            );
        }
    };

    Ok(key_der)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::{Duration as ChronoDuration, Utc};

    use super::*;
    use crate::cache::CacheOptions;
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

    async fn cached_real_certificate(names: &[&str]) -> (Arc<CertCache>, Certificate) {
        let generated = rcgen::generate_simple_self_signed(
            names.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        let cert = Certificate::from_pem(
            generated.cert.pem().as_bytes(),
            generated.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let cache = CertCache::new(CacheOptions::default());
        cache.add(cert.clone()).await;
        (cache, cert)
    }

    fn complete_rustls_handshake(cache: Arc<CertCache>, cert: &Certificate) {
        crate::http::install_crypto_provider();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert_chain[0].clone()).unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver::new(cache)));
        let mut client = rustls::ClientConnection::new(
            Arc::new(client_config),
            "example.com".try_into().unwrap(),
        )
        .unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
        for _ in 0..10 {
            let mut bytes = Vec::new();
            client.write_tls(&mut bytes).unwrap();
            server.read_tls(&mut std::io::Cursor::new(bytes)).unwrap();
            server.process_new_packets().unwrap();
            let mut bytes = Vec::new();
            server.write_tls(&mut bytes).unwrap();
            client.read_tls(&mut std::io::Cursor::new(bytes)).unwrap();
            client.process_new_packets().unwrap();
            if !client.is_handshaking() && !server.is_handshaking() {
                return;
            }
        }
        panic!("TLS handshake did not finish");
    }

    #[tokio::test]
    async fn real_handshake_on_current_thread_runtime() {
        let (cache, cert) = cached_real_certificate(&["example.com"]).await;
        complete_rustls_handshake(cache, &cert);
    }

    #[test]
    fn real_handshake_without_tokio_runtime() {
        let (cache, cert) = {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(cached_real_certificate(&["example.com"]))
        };
        assert!(tokio::runtime::Handle::try_current().is_err());
        complete_rustls_handshake(cache, &cert);
    }

    #[tokio::test]
    async fn serving_key_is_reused_and_replaced_with_ocsp() {
        let (cache, mut cert) = cached_real_certificate(&["*.example.com"]).await;
        let resolver = CertResolver::new(Arc::clone(&cache));
        let first = resolver.resolve_name(Some("a.example.com")).unwrap();
        for _ in 0..100 {
            assert!(Arc::ptr_eq(
                &first,
                &resolver.resolve_name(Some("b.example.com")).unwrap()
            ));
        }
        assert!(resolver.resolve_name(Some("deep.a.example.com")).is_none());
        assert!(resolver.resolve_name(Some("example.com")).is_none());
        cert.ocsp_response = Some(vec![1, 2, 3]);
        cache.replace(&cert.hash.clone(), cert).await;
        let updated = resolver.resolve_name(Some("a.example.com")).unwrap();
        assert!(!Arc::ptr_eq(&first, &updated));
        assert_eq!(
            updated.ocsp, None,
            "unverified raw bytes must not be served"
        );
        assert!(Arc::ptr_eq(
            &updated,
            &resolver.resolve_name(Some("b.example.com")).unwrap()
        ));
        assert_eq!(first.ocsp, None);
    }

    #[tokio::test]
    async fn expired_signed_staple_triggers_the_configured_handshake_refresh() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (mut cert, issuer) = crate::cache::tests::signed_certificate();
        cert.ocsp_status = Some(crate::ocsp::OcspStatus::Good);
        cert.ocsp_response = Some(crate::cache::tests::signed_staple(&cert, &issuer, 4));
        let name = cert.names[0].clone();
        let cache = CertCache::new(crate::cache::CacheOptions::default());
        cache.add(cert).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut resolver = CertResolver::new(cache);
        resolver.ocsp_refresh_func = Some(Arc::new({
            let calls = calls.clone();
            move |_| {
                let calls = calls.clone();
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                })
            }
        }));
        assert!(resolver.resolve_name(Some(&name)).unwrap().ocsp.is_some());
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert!(resolver.resolve_name(Some(&name)).unwrap().ocsp.is_none());
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn expired_must_staple_yields_to_usable_siblings_and_recovers_only_for_compatible_clients()
     {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Selector {
            expected: String,
            calls: Arc<AtomicUsize>,
        }
        impl crate::policy::CertificateSelector for Selector {
            fn select_certificate(
                &self,
                _: &ClientHello<'_>,
                choices: &[&Certificate],
            ) -> Option<usize> {
                assert_eq!(choices.len(), 1);
                assert_eq!(choices[0].hash, self.expected);
                self.calls.fetch_add(1, Ordering::SeqCst);
                Some(0)
            }
        }
        async fn connect(
            resolver: CertResolver,
            root: rustls::pki_types::CertificateDer<'static>,
            scheme: SignatureScheme,
        ) -> Option<Vec<u8>> {
            crate::install_default_crypto_provider();
            let mut provider = rustls::crypto::CryptoProvider::get_default()
                .unwrap()
                .as_ref()
                .clone();
            provider.signature_verification_algorithms.mapping = std::slice::from_ref(
                provider
                    .signature_verification_algorithms
                    .mapping
                    .iter()
                    .find(|(supported, _)| *supported == scheme)
                    .unwrap(),
            );
            let mut roots = rustls::RootCertStore::empty();
            roots.add(root).unwrap();
            let client = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let server = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(resolver));
            let (server_io, client_io) = tokio::io::duplex(16384);
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
            let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
            let (server, client) = tokio::join!(
                acceptor.accept(server_io),
                connector.connect("ocsp.example.com".try_into().unwrap(), client_io)
            );
            match (server, client) {
                (Ok(_), Ok(client)) => {
                    Some(client.get_ref().1.peer_certificates().unwrap()[0].to_vec())
                }
                _ => None,
            }
        }
        let (mut must, issuer) = crate::ocsp::tests::short_lived_certificate(Some(5));
        must.managed = true; // Prefer this leaf while its staple is usable.
        must.ocsp_status = Some(crate::ocsp::OcspStatus::Good);
        must.ocsp_response = Some(crate::cache::tests::signed_staple(&must, &issuer, 3));
        let must_hash = must.hash.clone();
        let (ordinary, _) = crate::ocsp::tests::short_lived_certificate(None);
        let root = ordinary.cert_chain[1].clone();
        let leaf = ordinary.cert_chain[0].to_vec();
        let cache = CertCache::new(CacheOptions::default());
        cache.add(ordinary.clone()).await;
        cache.add(must).await;
        assert_eq!(cache.resolve("ocsp.example.com").unwrap().hash, must_hash);
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(
            cache.resolve("ocsp.example.com").unwrap().hash,
            ordinary.hash
        );
        for custom in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let mut resolver = CertResolver::new(cache.clone());
            if custom {
                resolver.set_certificate_selector(Arc::new(Selector {
                    expected: ordinary.hash.clone(),
                    calls: calls.clone(),
                }));
            }
            assert_eq!(
                connect(
                    resolver,
                    root.clone(),
                    SignatureScheme::ECDSA_NISTP256_SHA256
                )
                .await,
                Some(leaf.clone())
            );
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(custom));
        }
        cache.remove(&ordinary.hash).await;
        for (scheme, refreshed) in [
            (SignatureScheme::RSA_PSS_SHA256, 0),
            (SignatureScheme::ECDSA_NISTP256_SHA256, 1),
        ] {
            let obtains = Arc::new(AtomicUsize::new(0));
            let refreshes = Arc::new(AtomicUsize::new(0));
            let config = Arc::new(OnDemandConfig {
                decision_func: Some(Arc::new(|_| true)),
                host_allowlist: None,
                rate_limit: None,
                obtain_func: Some(Arc::new({
                    let obtains = obtains.clone();
                    move |_| {
                        let obtains = obtains.clone();
                        Box::pin(async move {
                            obtains.fetch_add(1, Ordering::SeqCst);
                            Ok(())
                        })
                    }
                })),
            });
            let mut resolver = CertResolver::with_on_demand(cache.clone(), config);
            resolver.ocsp_refresh_func = Some(Arc::new({
                let refreshes = refreshes.clone();
                move |_| {
                    let refreshes = refreshes.clone();
                    Box::pin(async move {
                        refreshes.fetch_add(1, Ordering::SeqCst);
                    })
                }
            }));
            assert!(connect(resolver, root.clone(), scheme).await.is_none());
            tokio::task::yield_now().await;
            assert_eq!(refreshes.load(Ordering::SeqCst), refreshed);
            assert_eq!(
                obtains.load(Ordering::SeqCst),
                0,
                "missing Must-Staple response must not trigger duplicate issuance"
            );
        }
    }

    #[tokio::test]
    async fn on_demand_is_single_flight_and_cools_down() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let config = Arc::new(OnDemandConfig {
            decision_func: Some(Arc::new(|_| true)),
            host_allowlist: None,
            rate_limit: None,
            obtain_func: Some(Arc::new({
                let calls = Arc::clone(&calls);
                let started = Arc::clone(&started);
                let release = Arc::clone(&release);
                move |_| {
                    let calls = Arc::clone(&calls);
                    let started = Arc::clone(&started);
                    let release = Arc::clone(&release);
                    Box::pin(async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        started.notify_one();
                        release.notified().await;
                        Ok(())
                    })
                }
            })),
        });
        let resolver =
            CertResolver::with_on_demand(CertCache::new(CacheOptions::default()), config);
        for _ in 0..100 {
            assert!(
                resolver
                    .resolve_name(Some("customer.example.com"))
                    .is_none()
            );
        }
        started.notified().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        release.notify_one();
        tokio::task::yield_now().await;
        resolver.resolve_name(Some("customer.example.com"));
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ocsp_refresh_is_deduplicated_by_certificate_hash() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (cache, _) = cached_real_certificate(&["*.example.com"]).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut resolver = CertResolver::new(cache);
        resolver.ocsp_refresh_func = Some(Arc::new({
            let calls = Arc::clone(&calls);
            move |_| {
                let calls = Arc::clone(&calls);
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                })
            }
        }));
        for domain in ["a.example.com", "b.example.com", "c.example.com"] {
            assert!(resolver.resolve_name(Some(domain)).is_some());
        }
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        resolver.resolve_name(Some("d.example.com"));
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn background_work_has_task_and_memory_bounds_and_retry_cooldown() {
        let tasks = Arc::new(Mutex::new(BackgroundTasks::default()));
        let permits: Vec<_> = (0..MAX_BACKGROUND_TASKS)
            .map(|i| BackgroundWork::try_start(&tasks, i.to_string()).unwrap())
            .collect();
        assert!(BackgroundWork::try_start(&tasks, "overflow".into()).is_none());
        drop(permits);
        assert!(BackgroundWork::try_start(&tasks, "0".into()).is_none());
        for i in MAX_BACKGROUND_TASKS..MAX_BACKGROUND_KEYS {
            drop(BackgroundWork::try_start(&tasks, i.to_string()).unwrap());
        }
        assert!(BackgroundWork::try_start(&tasks, "overflow".into()).is_none());
        tasks
            .lock()
            .unwrap()
            .entries
            .insert("0".into(), Some(Instant::now() - Duration::from_secs(1)));
        assert!(BackgroundWork::try_start(&tasks, "0".into()).is_some());
    }

    #[tokio::test]
    async fn aborted_background_work_releases_single_flight_slot() {
        let tasks = Arc::new(Mutex::new(BackgroundTasks::default()));
        let work = BackgroundWork::try_start(&tasks, "example.com".into()).unwrap();
        let task = tokio::spawn(async move {
            let _work = work;
            std::future::pending::<()>().await;
        });
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(tasks.lock().unwrap().entries["example.com"].is_some());
    }

    #[test]
    fn background_acquisition_without_runtime_does_not_panic() {
        let config = Arc::new(OnDemandConfig {
            decision_func: Some(Arc::new(|_| true)),
            host_allowlist: None,
            rate_limit: None,
            obtain_func: Some(Arc::new(|_| Box::pin(async { Ok(()) }))),
        });
        let resolver =
            CertResolver::with_on_demand(CertCache::new(CacheOptions::default()), config);
        assert!(resolver.resolve_name(Some("example.com")).is_none());
    }
}
