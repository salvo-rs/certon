//! HTTP handlers for ACME HTTP-01 challenge responses.
//!
//! This module provides an [`HttpChallengeHandler`] that can intercept incoming
//! HTTP requests and respond to ACME HTTP-01 challenge validation attempts.
//! It checks whether a request path matches the well-known ACME challenge
//! prefix, looks up the corresponding key authorization (first in a local
//! in-memory map bound to a domain, then optionally in shared [`Storage`]), and returns it.
//!
//! For non-challenge requests the handler returns `None`, allowing the caller
//! to fall through to its normal request handling logic.
//!
//! Also includes a helper for constructing HTTPS redirect URLs.

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

// ---------------------------------------------------------------------------
// HttpChallengeHandler
// ---------------------------------------------------------------------------

/// Handles HTTP-01 ACME challenge requests.
///
/// When a request arrives, call [`HttpChallengeHandler::handle_http_request`]
/// with its method, Host header, and path. If the path matches the ACME challenge pattern, the
/// handler looks up the token's key authorization and returns it. Otherwise it
/// returns `None`, indicating the request should be handled normally.
///
/// The Host-aware handler checks its local in-memory challenge map only after
/// [`Self::with_domain`] binds it to a domain. If the token is not found locally and
/// a [`Storage`] backend is configured, it falls back to loading the challenge
/// data from storage — enabling distributed challenge solving across multiple
/// instances.
pub struct HttpChallengeHandler {
    /// In-memory map of token -> key_auth, shared with `Http01Solver`.
    challenges: Arc<RwLock<HashMap<String, String>>>,
    local_domain: Option<String>,
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
            local_domain: None,
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
            local_domain: None,
            storage,
            storage_key_issuer_prefix: prefix,
        }
    }

    /// Bind the unscoped local token map to a domain for Host-aware requests.
    /// Without this binding only shared storage is used by the Host-aware API.
    pub fn with_domain(mut self, domain: &str) -> Result<Self> {
        self.local_domain = Some(crate::challenge::domain(domain)?);
        Ok(self)
    }

    /// Handle a GET challenge for the exact Host and token. Backend failures
    /// produce 503; use [`Self::try_handle_http_request`] to inspect the error.
    pub async fn handle_http_request(
        &self,
        method: &str,
        host: &str,
        path: &str,
    ) -> Option<(u16, String)> {
        match self.try_handle_http_request(method, host, path).await {
            Ok(response) => response,
            Err(e) => {
                warn!(error = %e, "distributed challenge lookup failed");
                Some((503, String::new()))
            }
        }
    }

    /// Fallible Host-aware challenge handler. Invalid method, Host or token
    /// returns `Ok(None)` before accessing storage; an unknown token is 404.
    pub async fn try_handle_http_request(
        &self,
        method: &str,
        host: &str,
        path: &str,
    ) -> Result<Option<(u16, String)>> {
        if method != "GET" {
            return Ok(None);
        }
        let Some(token) = extract_challenge_token(path) else {
            return Ok(None);
        };
        let Ok(domain) = crate::challenge::host(host) else {
            return Ok(None);
        };
        if self.local_domain.as_deref() == Some(&domain)
            && let Some(auth) = self.challenges.read().await.get(token)
        {
            crate::challenge::validate_auth(token, auth)?;
            return Ok(Some((200, auth.clone())));
        }
        let auth = if let Some(storage) = &self.storage {
            crate::challenge::load(
                storage.as_ref(),
                &self.storage_key_issuer_prefix,
                &domain,
                token,
            )
            .await?
        } else {
            None
        };
        Ok(Some(
            auth.map_or_else(|| (404, String::new()), |auth| (200, auth)),
        ))
    }

    /// Handle an incoming HTTP request (simple API).
    ///
    /// If `path` is an ACME HTTP-01 challenge request (starts with
    /// [`ACME_CHALLENGE_PATH_PREFIX`]), the handler extracts the token and
    /// looks up the corresponding key authorization. On success it returns
    /// `Some(key_auth)`. If the token is unknown, it returns `None`. If the path does not match the
    /// challenge pattern at all, it returns `None` — the request should be
    /// forwarded to the application's normal handler.
    ///
    /// This simpler API does not check the HTTP method or Host header. Without
    /// [`Self::with_domain`] it reads only the local token map.
    /// For full validation including DNS rebinding protection, use
    /// [`HttpChallengeHandler::handle_http_request`].
    ///
    /// The lookup order is:
    /// 1. Local in-memory challenge map.
    /// 2. Shared storage for the explicitly bound domain (if configured).
    pub async fn handle_request(&self, path: &str) -> Option<String> {
        let token = extract_challenge_token(path)?;
        self.lookup_token(token).await
    }

    /// Handle an incoming HTTP request with blind solving fallback.
    ///
    /// This method works like [`Self::handle_request`] but adds a "blind solving"
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

    async fn lookup_token(&self, token: &str) -> Option<String> {
        if let Some(auth) = self.challenges.read().await.get(token) {
            return Some(auth.clone());
        }
        // A path alone cannot identify a distributed challenge domain.
        if let (Some(storage), Some(domain)) = (&self.storage, &self.local_domain) {
            match crate::challenge::load(
                storage.as_ref(),
                &self.storage_key_issuer_prefix,
                domain,
                token,
            )
            .await
            {
                Ok(auth) => return auth,
                Err(e) => warn!(error = %e, "distributed challenge lookup failed"),
            }
        }
        None
    }
}

impl std::fmt::Debug for HttpChallengeHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpChallengeHandler")
            .field("has_storage", &self.storage.is_some())
            .field("storage_key_issuer_prefix", &self.storage_key_issuer_prefix)
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
/// assert_eq!(extract_challenge_token("/other/path"), None,);
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
    is_valid_challenge_token(token).then_some(token)
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
    crate::challenge::valid_token(token)
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
