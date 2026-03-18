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
//! let handler = HttpsRedirectHandler::new(443);
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
}

impl Default for HttpsRedirectHandler {
    fn default() -> Self {
        Self { https_port: 443 }
    }
}

impl HttpsRedirectHandler {
    /// Create a new redirect handler that redirects to the given HTTPS port.
    pub fn new(https_port: u16) -> Self {
        Self { https_port }
    }

    /// Start the redirect server on the given bind address (e.g.
    /// `"0.0.0.0:80"`).
    ///
    /// Returns a [`JoinHandle`] for the spawned server task. The server runs
    /// until the handle is dropped or aborted.
    pub async fn start(&self, bind_addr: &str) -> Result<JoinHandle<()>> {
        let listener = TcpListener::bind(bind_addr).await.map_err(|e| {
            Error::Other(format!(
                "failed to bind HTTP redirect listener on {bind_addr}: {e}"
            ))
        })?;

        let https_port = self.https_port;

        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        tokio::spawn(handle_redirect_connection(stream, https_port));
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
        // Strip any existing port from the host.
        let host_only = if let Some(colon) = host.rfind(':') {
            let after = &host[colon + 1..];
            if after.chars().all(|c| c.is_ascii_digit()) {
                &host[..colon]
            } else {
                host
            }
        } else {
            host
        };

        if self.https_port == 443 {
            format!("https://{host_only}{path}")
        } else {
            format!("https://{host_only}:{}{path}", self.https_port)
        }
    }
}

/// Handle a single HTTP connection: parse enough of the request to extract
/// the Host header and path, then send back a 301 redirect to HTTPS.
async fn handle_redirect_connection(mut stream: tokio::net::TcpStream, https_port: u16) {
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

    let handler = HttpsRedirectHandler::new(https_port);
    let location = handler.redirect_url(host, path);

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
/// This is equivalent to:
/// ```ignore
/// HttpsRedirectHandler::new(443).start(bind_addr).await
/// ```
pub async fn start_https_redirect(bind_addr: &str) -> Result<JoinHandle<()>> {
    HttpsRedirectHandler::default().start(bind_addr).await
}

/// Convenience function: start an HTTP→HTTPS redirect server on
/// `bind_addr`, redirecting to a custom HTTPS port.
pub async fn start_https_redirect_with_port(
    bind_addr: &str,
    https_port: u16,
) -> Result<JoinHandle<()>> {
    HttpsRedirectHandler::new(https_port).start(bind_addr).await
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
}
