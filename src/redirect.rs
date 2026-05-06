//! HTTP to HTTPS redirect handler.
//!
//! This module provides a simple HTTP server that redirects all incoming
//! HTTP requests to their HTTPS equivalents. This is a common best practice
//! for production web servers: listen on port 80 only to redirect clients
//! to port 443.
//!
//! # Usage
//!
//! ```ignore
//! use certon::redirect::HttpsRedirectHandler;
//!
//! let handler = HttpsRedirectHandler::new(443)
//!     .with_canonical_host("example.com")?;
//! handler.start("0.0.0.0:80").await?;
//! ```

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// HttpsRedirectHandler
// ---------------------------------------------------------------------------

/// A simple HTTP server that responds to every request with a `301 Moved
/// Permanently` redirect to the HTTPS equivalent of the requested URL.
///
/// This handler also serves ACME HTTP-01 challenge responses if an
/// [`Http01Solver`](crate::solvers::Http01Solver) token map is provided,
/// allowing the same port-80 listener to handle both redirects and ACME
/// validation.
#[derive(Debug, Clone)]
pub struct HttpsRedirectHandler {
    /// The HTTPS port to redirect to. When set to `443` (default), the port
    /// is omitted from the `Location` header.
    pub https_port: u16,

    /// Canonical host to place in the `Location` header. When configured,
    /// the request `Host` header is not reflected.
    canonical_host: Option<String>,

    /// Accepted request hosts when no canonical host is configured.
    allowed_hosts: Vec<String>,
}

impl Default for HttpsRedirectHandler {
    fn default() -> Self {
        Self {
            https_port: 443,
            canonical_host: None,
            allowed_hosts: Vec::new(),
        }
    }
}

impl HttpsRedirectHandler {
    /// Create a new redirect handler that redirects to the given HTTPS port.
    pub fn new(https_port: u16) -> Self {
        Self {
            https_port,
            canonical_host: None,
            allowed_hosts: Vec::new(),
        }
    }

    /// Set the canonical HTTPS host used in every redirect response.
    pub fn with_canonical_host(mut self, host: &str) -> Result<Self> {
        self.canonical_host = Some(normalize_host(host)?);
        Ok(self)
    }

    /// Allow a request Host header when redirects should preserve the host.
    pub fn allow_host(mut self, host: &str) -> Result<Self> {
        self.allowed_hosts.push(normalize_host(host)?);
        Ok(self)
    }

    /// Start the redirect server on the given bind address (e.g.
    /// `"0.0.0.0:80"`).
    ///
    /// Returns a [`JoinHandle`] for the spawned server task. The server runs
    /// until the handle is dropped or aborted.
    pub async fn start(&self, bind_addr: &str) -> Result<JoinHandle<()>> {
        if self.canonical_host.is_none() && self.allowed_hosts.is_empty() {
            return Err(Error::Config(
                "HTTPS redirect requires a canonical host or explicit allowed hosts".to_owned(),
            ));
        }

        let listener = TcpListener::bind(bind_addr).await.map_err(|e| {
            Error::Other(format!(
                "failed to bind HTTP redirect listener on {bind_addr}: {e}"
            ))
        })?;

        let handler = self.clone();

        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        tokio::spawn(handle_redirect_connection(stream, handler.clone()));
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to accept HTTP connection for redirect");
                    }
                }
            }
        });

        Ok(handle)
    }

    /// Build the HTTPS redirect URL from the request's `Host` header and
    /// path.
    pub fn redirect_url(&self, host: &str, path: &str) -> String {
        let host = self
            .canonical_host
            .clone()
            .or_else(|| normalize_host(host).ok())
            .unwrap_or_else(|| "localhost".to_owned());
        self.format_redirect_url(&host, path)
    }

    /// Build a redirect URL while enforcing the configured Host policy.
    pub fn try_redirect_url(&self, host: &str, path: &str) -> Result<String> {
        let host = if let Some(canonical_host) = &self.canonical_host {
            canonical_host.clone()
        } else {
            let host = normalize_host(host)?;
            if !self.allowed_hosts.iter().any(|allowed| allowed == &host) {
                return Err(Error::Config(format!(
                    "request Host {host:?} is not allowed for HTTPS redirect"
                )));
            }
            host
        };

        Ok(self.format_redirect_url(&host, path))
    }

    fn format_redirect_url(&self, host: &str, path: &str) -> String {
        let path = sanitize_redirect_path(path);
        if self.https_port == 443 {
            format!("https://{host}{path}")
        } else {
            format!("https://{host}:{}{path}", self.https_port)
        }
    }
}

/// Handle a single HTTP connection: parse enough of the request to extract
/// the Host header and path, then send back a 301 redirect to HTTPS.
async fn handle_redirect_connection(
    mut stream: tokio::net::TcpStream,
    handler: HttpsRedirectHandler,
) {
    let mut buf = vec![0u8; 4096];
    let n = match stream.read(&mut buf).await {
        Ok(0) => return,
        Ok(n) => n,
        Err(e) => {
            debug!(error = %e, "error reading HTTP request for redirect");
            return;
        }
    };

    let request = String::from_utf8_lossy(&buf[..n]);

    // Parse the first line to get the request path.
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    // Parse the Host header.
    let host = request
        .lines()
        .find(|line| line.to_lowercase().starts_with("host:"))
        .map(|line| line[5..].trim())
        .unwrap_or("localhost");

    let location = match handler.try_redirect_url(host, path) {
        Ok(location) => location,
        Err(e) => {
            debug!(error = %e, "rejecting HTTP redirect request with invalid Host");
            let response = "HTTP/1.1 400 Bad Request\r\n\
                            Content-Length: 0\r\n\
                            Connection: close\r\n\
                            \r\n";
            let _ = stream.write_all(response.as_bytes()).await;
            return;
        }
    };

    let response = format!(
        "HTTP/1.1 301 Moved Permanently\r\n\
         Location: {location}\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\
         \r\n"
    );

    if let Err(e) = stream.write_all(response.as_bytes()).await {
        debug!(error = %e, "error writing HTTP redirect response");
    }
}

/// Convenience function: start an HTTP→HTTPS redirect server on `bind_addr`.
///
/// For public listeners, prefer [`start_https_redirect_to_host`] or
/// [`HttpsRedirectHandler::with_canonical_host`]. This helper returns a
/// configuration error unless an allowlist is added through the handler API.
pub async fn start_https_redirect(bind_addr: &str) -> Result<JoinHandle<()>> {
    HttpsRedirectHandler::default().start(bind_addr).await
}

/// Convenience function: start an HTTP→HTTPS redirect server on
/// `bind_addr`, redirecting to a custom HTTPS port.
///
/// For public listeners, prefer configuring a canonical host with
/// [`HttpsRedirectHandler::with_canonical_host`].
pub async fn start_https_redirect_with_port(
    bind_addr: &str,
    https_port: u16,
) -> Result<JoinHandle<()>> {
    HttpsRedirectHandler::new(https_port).start(bind_addr).await
}

/// Convenience function: start an HTTP→HTTPS redirect server with a fixed
/// canonical HTTPS host.
pub async fn start_https_redirect_to_host(
    bind_addr: &str,
    canonical_host: &str,
) -> Result<JoinHandle<()>> {
    HttpsRedirectHandler::new(443)
        .with_canonical_host(canonical_host)?
        .start(bind_addr)
        .await
}

fn normalize_host(host: &str) -> Result<String> {
    let host = host.trim();
    if host.is_empty() {
        return Err(Error::Config("Host header is empty".to_owned()));
    }
    if host
        .bytes()
        .any(|b| b.is_ascii_control() || matches!(b, b' ' | b'\t' | b'/' | b'\\' | b'@'))
    {
        return Err(Error::Config(
            "Host header contains invalid characters".to_owned(),
        ));
    }

    if let Some(rest) = host.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err(Error::Config(
                "IPv6 Host header is missing closing bracket".to_owned(),
            ));
        };
        let addr = &rest[..end];
        let tail = &rest[end + 1..];
        if !tail.is_empty()
            && !tail
                .strip_prefix(':')
                .is_some_and(|port| !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()))
        {
            return Err(Error::Config(
                "IPv6 Host header has invalid port".to_owned(),
            ));
        }
        if addr.is_empty() || addr.bytes().any(|b| b.is_ascii_control()) {
            return Err(Error::Config("IPv6 Host header is invalid".to_owned()));
        }
        return Ok(format!("[{}]", addr.to_ascii_lowercase()));
    }

    let host = if let Some(colon) = host.rfind(':') {
        let after = &host[colon + 1..];
        if !after.is_empty() && after.chars().all(|c| c.is_ascii_digit()) {
            &host[..colon]
        } else {
            host
        }
    } else {
        host
    };

    if host.contains(':') {
        return Err(Error::Config(
            "IPv6 Host headers must use bracket notation".to_owned(),
        ));
    }
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
    {
        return Err(Error::Config("Host header is invalid".to_owned()));
    }

    Ok(host.to_ascii_lowercase())
}

fn sanitize_redirect_path(path: &str) -> &str {
    if path.starts_with('/') && !path.bytes().any(|b| matches!(b, b'\r' | b'\n')) {
        path
    } else {
        "/"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redirect_url_default_port() {
        let handler = HttpsRedirectHandler::new(443);
        assert_eq!(
            handler.redirect_url("example.com", "/path"),
            "https://example.com/path"
        );
    }

    #[test]
    fn test_redirect_url_custom_port() {
        let handler = HttpsRedirectHandler::new(8443);
        assert_eq!(
            handler.redirect_url("example.com", "/path"),
            "https://example.com:8443/path"
        );
    }

    #[test]
    fn test_redirect_url_strips_port_from_host() {
        let handler = HttpsRedirectHandler::new(443);
        assert_eq!(
            handler.redirect_url("example.com:80", "/"),
            "https://example.com/"
        );
    }

    #[test]
    fn test_redirect_url_root_path() {
        let handler = HttpsRedirectHandler::new(443);
        assert_eq!(
            handler.redirect_url("example.com", "/"),
            "https://example.com/"
        );
    }

    #[test]
    fn test_try_redirect_url_uses_canonical_host() {
        let handler = HttpsRedirectHandler::new(443)
            .with_canonical_host("example.com")
            .unwrap();
        assert_eq!(
            handler
                .try_redirect_url("attacker.example", "/login")
                .unwrap(),
            "https://example.com/login"
        );
    }

    #[test]
    fn test_try_redirect_url_rejects_unallowed_host() {
        let handler = HttpsRedirectHandler::new(443)
            .allow_host("example.com")
            .unwrap();
        assert!(handler.try_redirect_url("attacker.example", "/").is_err());
    }

    #[test]
    fn test_try_redirect_url_accepts_allowed_host_without_port() {
        let handler = HttpsRedirectHandler::new(8443)
            .allow_host("example.com")
            .unwrap();
        assert_eq!(
            handler.try_redirect_url("example.com:80", "/").unwrap(),
            "https://example.com:8443/"
        );
    }

    #[test]
    fn test_try_redirect_url_rejects_invalid_host_characters() {
        let handler = HttpsRedirectHandler::new(443)
            .allow_host("example.com")
            .unwrap();
        assert!(
            handler
                .try_redirect_url("example.com\r\nx: y", "/")
                .is_err()
        );
        assert!(handler.try_redirect_url("example.com/path", "/").is_err());
    }

    #[tokio::test]
    async fn test_start_requires_host_policy() {
        let err = HttpsRedirectHandler::new(443)
            .start("127.0.0.1:0")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("canonical host"));
    }
}
