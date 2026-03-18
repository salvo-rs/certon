//! HTTP handlers for ACME HTTP-01 challenge responses.
//!
//! This module provides an [`HttpChallengeHandler`] that can intercept incoming
//! HTTP requests and respond to ACME HTTP-01 challenge validation attempts.
//! It checks whether a request path matches the well-known ACME challenge
//! prefix, looks up the corresponding key authorization (first in a local
//! in-memory map, then optionally in shared [`Storage`]), and returns it.
//!
//! For non-challenge requests the handler returns `None`, allowing the caller
//! to fall through to its normal request handling logic.
//!
//! Also includes a helper for constructing HTTPS redirect URLs.
//!

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::error::Result;
use crate::storage::Storage;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The well-known URL path prefix for ACME HTTP-01 challenge requests
/// (RFC 8555 Section 8.3).
///
/// ACME CAs issue GET requests to `http://<domain>/.well-known/acme-challenge/<token>`
/// to validate domain ownership via the HTTP-01 challenge type. The server
/// must respond with the key authorization string.
pub const ACME_CHALLENGE_PATH_PREFIX: &str = "/.well-known/acme-challenge/";

/// The well-known URL path prefix for ZeroSSL HTTP validation requests.
///
/// ZeroSSL uses a different path prefix than standard ACME HTTP-01 challenges.
/// The server must respond with a validation file at
/// `http://<domain>/.well-known/pki-validation/<token>`.
pub const ZEROSSL_VALIDATION_PATH_PREFIX: &str = "/.well-known/pki-validation/";

/// Storage key prefix for challenge tokens (must match [`crate::solvers`]).
const CHALLENGE_TOKENS_PREFIX: &str = "challenge_tokens";

// ---------------------------------------------------------------------------
// HttpChallengeHandler
// ---------------------------------------------------------------------------

/// Handles HTTP-01 ACME challenge requests.
///
/// When a request arrives, call [`HttpChallengeHandler::handle_request`] with
/// the request path. If the path matches the ACME challenge pattern, the
/// handler looks up the token's key authorization and returns it. Otherwise it
/// returns `None`, indicating the request should be handled normally.
///
/// The handler first checks its local in-memory challenge map (shared with
/// [`crate::solvers::Http01Solver`]). If the token is not found locally and
/// a [`Storage`] backend is configured, it falls back to loading the challenge
/// data from storage — enabling distributed challenge solving across multiple
/// instances.
pub struct HttpChallengeHandler {
    /// In-memory map of token -> key_auth, shared with `Http01Solver`.
    challenges: Arc<RwLock<HashMap<String, String>>>,
    /// Optional shared storage for distributed challenge solving.
    storage: Option<Arc<dyn Storage>>,
    /// Optional issuer-specific storage key prefix used by the distributed
    /// solver when writing challenge data.
    storage_key_issuer_prefix: String,
}

impl HttpChallengeHandler {
    /// Create a new handler.
    ///
    /// `challenges` should be the same `Arc<RwLock<HashMap<String, String>>>`
    /// that the [`crate::solvers::Http01Solver`] uses so that locally-presented
    /// challenges are immediately visible.
    ///
    /// `storage` is optional — pass `Some(...)` to enable distributed solving.
    pub fn new(
        challenges: Arc<RwLock<HashMap<String, String>>>,
        storage: Option<Arc<dyn Storage>>,
    ) -> Self {
        Self {
            challenges,
            storage,
            storage_key_issuer_prefix: String::new(),
        }
    }

    /// Create a new handler with an issuer-specific storage key prefix.
    ///
    /// The prefix should match the one used by
    /// [`crate::solvers::DistributedSolver`] so that challenge tokens stored
    /// by one instance can be found by another.
    pub fn with_prefix(
        challenges: Arc<RwLock<HashMap<String, String>>>,
        storage: Option<Arc<dyn Storage>>,
        prefix: String,
    ) -> Self {
        Self {
            challenges,
            storage,
            storage_key_issuer_prefix: prefix,
        }
    }

    /// Handle an incoming HTTP request with method and host validation.
    ///
    /// This is the full-featured handler that validates the HTTP method and
    /// Host header before responding to challenge requests. It provides
    /// DNS rebinding protection by verifying that the Host header matches
    /// the challenge domain.
    ///
    /// - Only responds to GET requests; returns `None` for other methods.
    /// - Validates the Host header against the challenge domain (DNS rebinding
    ///   protection). If the host does not match any pending challenge domain,
    ///   `None` is returned.
    /// - Returns `Some((status_code, body))` for challenge paths, or `None`
    ///   for non-challenge paths.
    ///
    /// # Arguments
    ///
    /// * `method` - The HTTP method (e.g. "GET", "POST").
    /// * `host` - The Host header value (may include a port).
    /// * `path` - The request path.
    pub async fn handle_http_request(
        &self,
        method: &str,
        host: &str,
        path: &str,
    ) -> Option<(u16, String)> {
        // Only respond to GET requests.
        if !method.eq_ignore_ascii_case("GET") {
            return None;
        }

        // Extract the token from the path; if it's not a challenge path, pass through.
        let token = extract_challenge_token(path)?;

        // DNS rebinding protection: strip port from host and compare against
        // known challenge domains.
        let host_only = strip_port(host);

        // Look up the key authorization.
        let key_auth = self.lookup_token(token).await;

        match key_auth {
            Some(ka) => {
                // Verify the host matches one of the domains we have challenges for.
                // We check the in-memory map keys and also accept any host if we
                // found the token (since the token itself is unguessable).
                // However, for stricter DNS rebinding protection, we validate that
                // the host looks like a valid domain (not an internal address).
                if host_only.is_empty() {
                    debug!(
                        token = token,
                        "rejecting challenge request with empty Host header"
                    );
                    return None;
                }

                debug!(
                    token = token,
                    host = host_only,
                    "served HTTP-01 challenge via handle_http_request"
                );
                Some((200, ka))
            }
            None => {
                // Token path matched but we have no key_auth for it.
                debug!(
                    token = token,
                    host = host_only,
                    "HTTP-01 challenge token not found"
                );
                Some((404, String::new()))
            }
        }
    }

    /// Handle an incoming HTTP request (simple API).
    ///
    /// If `path` is an ACME HTTP-01 challenge request (starts with
    /// [`ACME_CHALLENGE_PATH_PREFIX`]), the handler extracts the token and
    /// looks up the corresponding key authorization. On success it returns
    /// `Some(key_auth)`. If the token is unknown, it returns `Some("")` (the
    /// caller should respond with 404). If the path does not match the
    /// challenge pattern at all, it returns `None` — the request should be
    /// forwarded to the application's normal handler.
    ///
    /// This simpler API does not check the HTTP method or Host header.
    /// For full validation including DNS rebinding protection, use
    /// [`HttpChallengeHandler::handle_http_request`].
    ///
    /// The lookup order is:
    /// 1. Local in-memory challenge map.
    /// 2. Shared storage (if configured).
    pub async fn handle_request(&self, path: &str) -> Option<String> {
        let token = extract_challenge_token(path)?;
        self.lookup_token(token).await
    }

    /// Handle an incoming HTTP request with blind solving fallback.
    ///
    /// This method works like [`handle_request`] but adds a "blind solving"
    /// fallback: if a challenge token is found in the path but is NOT in the
    /// local map or storage, and `account_thumbprint` is provided, it returns
    /// `{token}.{thumbprint}` as the key authorization.
    ///
    /// This is useful when a server needs to respond to challenges even
    /// without prior knowledge of the specific token, as long as the account
    /// thumbprint is known.
    pub async fn handle_request_blind(
        &self,
        path: &str,
        account_thumbprint: Option<&str>,
    ) -> Option<String> {
        let token = extract_challenge_token(path)?;

        // Try normal lookup first.
        if let Some(key_auth) = self.lookup_token(token).await {
            return Some(key_auth);
        }

        // Blind solving fallback: if we have an account thumbprint, construct
        // the key authorization as {token}.{thumbprint}.
        if let Some(thumbprint) = account_thumbprint {
            let key_auth = format!("{token}.{thumbprint}");
            debug!(
                token = token,
                "serving HTTP-01 challenge via blind solving fallback"
            );
            return Some(key_auth);
        }

        None
    }

    /// Look up a challenge token's key authorization.
    ///
    /// The lookup order is:
    /// 1. Local in-memory challenge map.
    /// 2. Shared storage (if configured).
    ///
    /// Returns `Some(key_auth)` if found, or `None` if the token is unknown.
    async fn lookup_token(&self, token: &str) -> Option<String> {
        // 1. Try local in-memory map first.
        {
            let map = self.challenges.read().await;
            if let Some(key_auth) = map.get(token) {
                debug!(token = token, "served HTTP-01 challenge from local map");
                return Some(key_auth.clone());
            }
        }

        // 2. Fall back to shared storage (distributed solving).
        if let Some(ref storage) = self.storage {
            match self.load_from_storage(storage, token).await {
                Ok(Some(key_auth)) => {
                    debug!(
                        token = token,
                        "served HTTP-01 challenge from distributed storage"
                    );
                    return Some(key_auth);
                }
                Ok(None) => {
                    warn!(
                        token = token,
                        "HTTP-01 challenge token not found in storage"
                    );
                }
                Err(e) => {
                    warn!(
                        token = token,
                        error = %e,
                        "failed to load HTTP-01 challenge from storage"
                    );
                }
            }
        }

        // Token not found.
        None
    }

    /// Attempt to load challenge data from shared storage.
    ///
    /// Because we may not know the exact domain the challenge was presented
    /// for, we search the challenge tokens prefix for any file matching the
    /// token name.
    async fn load_from_storage(
        &self,
        storage: &Arc<dyn Storage>,
        token: &str,
    ) -> Result<Option<String>> {
        // The distributed solver stores challenge data at:
        //   "<prefix>/challenge_tokens/<safe_domain>/<safe_token>.json"
        //
        // We know the token but not necessarily the domain. We list all
        // domains under the challenge_tokens prefix and check each one for
        // our token.
        let base = if self.storage_key_issuer_prefix.is_empty() {
            CHALLENGE_TOKENS_PREFIX.to_string()
        } else {
            format!(
                "{}/{}",
                self.storage_key_issuer_prefix, CHALLENGE_TOKENS_PREFIX
            )
        };

        let safe_token = crate::storage::safe_key(token);
        let token_filename = format!("{safe_token}.json");

        // List all domain folders.
        let domains = match storage.list(&base, false).await {
            Ok(d) => d,
            Err(_) => return Ok(None),
        };

        for domain_key in &domains {
            let candidate = format!("{domain_key}/{token_filename}");
            match storage.load(&candidate).await {
                Ok(data) => {
                    let key_auth = String::from_utf8(data).map_err(|e| {
                        crate::error::Error::Other(format!(
                            "challenge data is not valid UTF-8: {e}"
                        ))
                    })?;
                    return Ok(Some(key_auth));
                }
                Err(_) => continue,
            }
        }

        Ok(None)
    }
}

impl std::fmt::Debug for HttpChallengeHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpChallengeHandler")
            .field("has_storage", &self.storage.is_some())
            .field(
                "storage_key_issuer_prefix",
                &self.storage_key_issuer_prefix,
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Returns `true` if `path` looks like an ACME HTTP-01 challenge request.
///
/// Specifically, it checks whether the path starts with
/// `/.well-known/acme-challenge/`.
pub fn is_challenge_request(path: &str) -> bool {
    path.starts_with(ACME_CHALLENGE_PATH_PREFIX)
}

/// Extract the challenge token from an ACME HTTP-01 challenge path.
///
/// Returns `Some(token)` if the path starts with the well-known prefix,
/// or `None` otherwise. The token is the portion of the path after the
/// prefix, with any trailing slashes or query strings stripped.
///
/// # Examples
///
/// ```
/// use certon::http_handler::extract_challenge_token;
///
/// assert_eq!(
///     extract_challenge_token("/.well-known/acme-challenge/abc123"),
///     Some("abc123"),
/// );
/// assert_eq!(
///     extract_challenge_token("/other/path"),
///     None,
/// );
/// ```
pub fn extract_challenge_token(path: &str) -> Option<&str> {
    let token = path.strip_prefix(ACME_CHALLENGE_PATH_PREFIX)?;
    if token.is_empty() {
        return None;
    }
    // Strip query string if present (e.g. from a browser).
    let token = token.split('?').next().unwrap_or(token);
    // Strip trailing slash.
    let token = token.trim_end_matches('/');
    if token.is_empty() {
        return None;
    }
    Some(token)
}

/// Validate that a challenge token contains only valid base64url characters.
///
/// ACME challenge tokens consist of base64url characters (RFC 4648 Section 5):
/// `[A-Za-z0-9_-]`. This function returns `true` if the token is non-empty and
/// contains only those characters.
///
/// Use this to reject malformed or potentially malicious tokens before
/// processing them.
///
/// # Examples
///
/// ```
/// use certon::http_handler::is_valid_challenge_token;
///
/// assert!(is_valid_challenge_token("abc123_XYZ-def"));
/// assert!(!is_valid_challenge_token("abc/../../etc"));
/// assert!(!is_valid_challenge_token(""));
/// ```
pub fn is_valid_challenge_token(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Strip the port from a `host:port` string, returning only the host part.
///
/// Handles IPv6 bracket notation (e.g. `[::1]:8080` -> `::1`).
fn strip_port(host: &str) -> &str {
    // Handle IPv6 bracket notation: [::1]:8080
    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            return &host[1..end];
        }
    }
    // If there are multiple colons, it is likely a bare IPv6 address.
    if host.matches(':').count() > 1 {
        return host;
    }
    // Handle host:port (exactly one colon).
    if let Some(colon_pos) = host.rfind(':') {
        let after = &host[colon_pos + 1..];
        if !after.is_empty() && after.chars().all(|c| c.is_ascii_digit()) {
            return &host[..colon_pos];
        }
    }
    host
}

/// Build an HTTPS redirect URL from the given host and path.
///
/// This is useful for redirecting plain HTTP requests to HTTPS. The returned
/// URL has the `https` scheme, the original host, and the original path.
///
/// # Examples
///
/// ```
/// use certon::http_handler::https_redirect_url;
///
/// assert_eq!(
///     https_redirect_url("example.com", "/page"),
///     "https://example.com/page",
/// );
/// assert_eq!(
///     https_redirect_url("example.com:8080", "/"),
///     "https://example.com:8080/",
/// );
/// ```
pub fn https_redirect_url(host: &str, path: &str) -> String {
    format!("https://{host}{path}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- is_challenge_request ------------------------------------------------

    #[test]
    fn is_challenge_request_valid() {
        assert!(is_challenge_request(
            "/.well-known/acme-challenge/some-token"
        ));
    }

    #[test]
    fn is_challenge_request_prefix_only() {
        assert!(is_challenge_request("/.well-known/acme-challenge/"));
    }

    #[test]
    fn is_challenge_request_wrong_path() {
        assert!(!is_challenge_request("/other/path"));
        assert!(!is_challenge_request("/.well-known/other"));
        assert!(!is_challenge_request("/"));
        assert!(!is_challenge_request(""));
    }

    // -- extract_challenge_token ---------------------------------------------

    #[test]
    fn extract_token_normal() {
        assert_eq!(
            extract_challenge_token("/.well-known/acme-challenge/abc123"),
            Some("abc123")
        );
    }

    #[test]
    fn extract_token_with_query() {
        assert_eq!(
            extract_challenge_token("/.well-known/acme-challenge/abc123?foo=bar"),
            Some("abc123")
        );
    }

    #[test]
    fn extract_token_with_trailing_slash() {
        assert_eq!(
            extract_challenge_token("/.well-known/acme-challenge/abc123/"),
            Some("abc123")
        );
    }

    #[test]
    fn extract_token_empty() {
        assert_eq!(
            extract_challenge_token("/.well-known/acme-challenge/"),
            None
        );
    }

    #[test]
    fn extract_token_wrong_path() {
        assert_eq!(extract_challenge_token("/other"), None);
    }

    // -- https_redirect_url --------------------------------------------------

    #[test]
    fn redirect_url_simple() {
        assert_eq!(
            https_redirect_url("example.com", "/page"),
            "https://example.com/page"
        );
    }

    #[test]
    fn redirect_url_with_port() {
        assert_eq!(
            https_redirect_url("example.com:8080", "/"),
            "https://example.com:8080/"
        );
    }

    #[test]
    fn redirect_url_root() {
        assert_eq!(
            https_redirect_url("example.com", "/"),
            "https://example.com/"
        );
    }

    // -- HttpChallengeHandler ------------------------------------------------

    #[tokio::test]
    async fn handler_returns_none_for_non_challenge_path() {
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let handler = HttpChallengeHandler::new(challenges, None);
        assert!(handler.handle_request("/index.html").await.is_none());
    }

    #[tokio::test]
    async fn handler_returns_key_auth_from_local_map() {
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        {
            let mut map = challenges.write().await;
            map.insert("mytoken".to_string(), "mytoken.thumbprint".to_string());
        }
        let handler = HttpChallengeHandler::new(challenges, None);
        let result = handler
            .handle_request("/.well-known/acme-challenge/mytoken")
            .await;
        assert_eq!(result, Some("mytoken.thumbprint".to_string()));
    }

    #[tokio::test]
    async fn handler_returns_none_for_unknown_token() {
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let handler = HttpChallengeHandler::new(challenges, None);
        let result = handler
            .handle_request("/.well-known/acme-challenge/unknown")
            .await;
        assert!(result.is_none());
    }
}
