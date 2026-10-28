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

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, warn};

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// HttpsRedirectHandler
// ---------------------------------------------------------------------------

/// Resource limits for one redirect listener, shared by all its connections.
#[derive(Debug, Clone, Copy)]
pub struct RedirectLimits {
    /// Maximum admitted connections, including idle readers and blocked writers.
    /// Excess connections are closed immediately without spawning a task.
    pub max_connections: usize,
    /// Total wall-clock budget from acceptance through the final response write.
    /// Incoming bytes do not reset this deadline.
    pub connection_timeout: Duration,
    /// Maximum request-header bytes, including the terminating CRLF pair.
    pub max_header_bytes: usize,
}

impl Default for RedirectLimits {
    fn default() -> Self {
        Self {
            max_connections: 256,
            connection_timeout: Duration::from_secs(10),
            max_header_bytes: 16 * 1024,
        }
    }
}

/// A simple HTTP server that responds to every request with a `301 Moved
/// Permanently` redirect to the HTTPS equivalent of the requested URL.
///
/// Configure a canonical host or allowlist before starting the listener.
/// Each listener enforces [`RedirectLimits`] and owns all child connections.
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
    limits: RedirectLimits,
}

impl Default for HttpsRedirectHandler {
    fn default() -> Self {
        Self {
            https_port: 443,
            canonical_host: None,
            allowed_hosts: Vec::new(),
            limits: RedirectLimits::default(),
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
            limits: RedirectLimits::default(),
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

    /// Set the connection budget, total request/response deadline and header cap.
    /// Limits must be nonzero; at least four bytes are needed for the header terminator.
    pub fn with_limits(mut self, limits: RedirectLimits) -> Result<Self> {
        if limits.max_connections == 0
            || limits.max_header_bytes < 4
            || limits.connection_timeout.is_zero()
            || std::time::Instant::now()
                .checked_add(limits.connection_timeout)
                .is_none()
        {
            return Err(Error::Config("invalid HTTP redirect limits".into()));
        }
        self.limits = limits;
        Ok(self)
    }

    /// Start the redirect server on the given bind address (e.g.
    /// `"0.0.0.0:80"`).
    ///
    /// Returns a [`JoinHandle`] for the spawned server task. The server runs
    /// until the handle is aborted. Aborting also cancels all admitted
    /// connections; await the aborted handle to observe listener shutdown.
    /// Dropping a Tokio JoinHandle detaches the server and does not stop it.
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

        Ok(tokio::spawn(serve_redirect(listener, self.clone())))
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

async fn serve_redirect(listener: TcpListener, handler: HttpsRedirectHandler) {
    // JoinSet owns child futures. Dropping the server future aborts them even
    // while they are waiting for input or socket write capacity.
    let mut connections = JoinSet::new();
    let handler = Arc::new(handler);
    loop {
        tokio::select! {
            biased;
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(e)) = result { debug!(error = %e, "redirect connection task ended"); }
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    if connections.len() >= handler.limits.max_connections {
                        drop(stream);
                        continue;
                    }
                    let Some(deadline) = tokio::time::Instant::now().checked_add(handler.limits.connection_timeout) else {
                        drop(stream);
                        continue;
                    };
                    let handler = handler.clone();
                    connections.spawn(async move {
                        handle_redirect_io(stream, &handler, deadline).await;
                    });
                }
                Err(e) => {
                    warn!(error = %e, "failed to accept HTTP connection for redirect");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
}

#[cfg(test)]
async fn handle_redirect_connection(stream: tokio::net::TcpStream, handler: HttpsRedirectHandler) {
    let deadline = tokio::time::Instant::now() + handler.limits.connection_timeout;
    handle_redirect_io(stream, &handler, deadline).await;
}

async fn handle_redirect_io<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    handler: &HttpsRedirectHandler,
    deadline: tokio::time::Instant,
) {
    if tokio::time::timeout_at(deadline, redirect_exchange(&mut stream, handler))
        .await
        .is_err()
    {
        debug!("HTTP redirect connection deadline exceeded");
    }
}

async fn redirect_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    handler: &HttpsRedirectHandler,
) {
    let mut request = Vec::with_capacity(handler.limits.max_header_bytes.min(4096));
    let mut chunk = [0; 1024];
    let header_end = loop {
        // A read may also contain body bytes. Find the header terminator before
        // checking the cap, and never parse or count that body as header text.
        if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        let remaining = handler.limits.max_header_bytes - request.len();
        if remaining == 0 {
            let _ = stream.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
            return;
        }
        let count = remaining.min(chunk.len());
        match stream.read(&mut chunk[..count]).await {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&chunk[..n]),
        }
    };
    let location = parse_redirect_request(&request[..header_end], handler);
    let response = match location {
        Ok(location) => format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
        Err(_) => {
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
        }
    };
    if let Err(e) = stream.write_all(response.as_bytes()).await {
        debug!(error = %e, "error writing HTTP redirect response");
    }
}

fn parse_redirect_request(request: &[u8], handler: &HttpsRedirectHandler) -> Result<String> {
    let bad_request = || Error::Config("invalid HTTP redirect request".into());
    let header_end = request
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or_else(bad_request)?;
    let headers = &request[..header_end];
    // Require CRLF framing; splitting a bare LF must not create another field.
    if headers.iter().enumerate().any(|(index, byte)| match byte {
        b'\r' => headers.get(index + 1) != Some(&b'\n'),
        b'\n' => index == 0 || headers[index - 1] != b'\r',
        _ => false,
    }) {
        return Err(bad_request());
    }
    let is_token = |value: &[u8]| {
        !value.is_empty()
            && value
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte))
    };
    let mut lines = headers
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    let mut first = lines
        .next()
        .ok_or_else(bad_request)?
        .split(|byte| *byte == b' ');
    let method = first.next().ok_or_else(bad_request)?;
    let target = first.next().ok_or_else(bad_request)?;
    let version = first.next().ok_or_else(bad_request)?;
    if !is_token(method)
        || target.is_empty()
        || target.iter().any(u8::is_ascii_control)
        || first.next().is_some()
        || (version != b"HTTP/1.0" && version != b"HTTP/1.1")
    {
        return Err(bad_request());
    }
    let path = std::str::from_utf8(target).map_err(|_| bad_request())?;
    let mut host = None;
    for line in lines {
        let separator = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(bad_request)?;
        let (name, value) = line.split_at(separator);
        let value = &value[1..];
        // HTTP field values allow obs-text and horizontal tabs, but not other
        // controls, DEL or folded lines. Unused fields need no UTF-8 decoding.
        if !is_token(name)
            || value
                .iter()
                .any(|byte| matches!(byte, 0..=8 | 10..=31 | 127))
        {
            return Err(bad_request());
        }
        if name.eq_ignore_ascii_case(b"host") {
            if host.is_some() {
                return Err(bad_request());
            }
            let value = value.trim_ascii();
            if !value.is_ascii() {
                return Err(bad_request());
            }
            let value = std::str::from_utf8(value).map_err(|_| bad_request())?;
            // Validate the required field even with a canonical redirect host.
            // URL parsing also rejects invalid bracketed IPs and port overflow.
            normalize_host(value)?;
            url::Url::parse(&format!("http://{value}/")).map_err(|_| bad_request())?;
            host = Some(value);
        }
    }
    if version == b"HTTP/1.1" && host.is_none() {
        return Err(bad_request());
    }
    handler.try_redirect_url(host.unwrap_or(""), path)
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
    // A DNS root dot is optional. Remove at most one after stripping the port;
    // repeated trailing dots must still fail the normal hostname validation.
    let host = host.strip_suffix('.').unwrap_or(host);
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

    fn limited_handler(timeout: Duration, max_connections: usize) -> HttpsRedirectHandler {
        HttpsRedirectHandler::default()
            .with_canonical_host("example.com")
            .unwrap()
            .with_limits(RedirectLimits {
                max_connections,
                connection_timeout: timeout,
                max_header_bytes: 8192,
            })
            .unwrap()
    }

    async fn test_server(handler: HttpsRedirectHandler) -> (std::net::SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        (address, tokio::spawn(serve_redirect(listener, handler)))
    }

    async fn read_closed(stream: &mut tokio::net::TcpStream) {
        let mut byte = [0];
        let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
            .await
            .expect("connection must close");
        match result {
            Ok(0) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) => {}
            other => panic!("unexpected connection result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn idle_connections_expire() {
        let (address, task) = test_server(limited_handler(Duration::from_millis(60), 2)).await;
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        read_closed(&mut client).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn connection_limit_rejects_excess_and_releases_capacity() {
        let (address, task) = test_server(limited_handler(Duration::from_secs(5), 1)).await;
        let mut first = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut excess = tokio::net::TcpStream::connect(address).await.unwrap();
        read_closed(&mut excess).await;
        first
            .write_all(b"GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(2), first.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 301"));
        let mut next = tokio::net::TcpStream::connect(address).await.unwrap();
        next.write_all(b"GET /next HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        response.clear();
        tokio::time::timeout(Duration::from_secs(2), next.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.contains("https://example.com/next"));
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn aborting_listener_cancels_admitted_idle_connections() {
        let (address, task) = test_server(limited_handler(Duration::from_secs(60), 1)).await;
        let mut first = tokio::net::TcpStream::connect(address).await.unwrap();
        // Rejection of the second connection proves the first was admitted.
        let mut excess = tokio::net::TcpStream::connect(address).await.unwrap();
        read_closed(&mut excess).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        read_closed(&mut first).await;
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
    }

    #[tokio::test]
    async fn trickled_bytes_do_not_extend_total_deadline() {
        let handler = limited_handler(Duration::from_millis(100), 2);
        let (mut client, server) = tokio::io::duplex(64);
        let deadline = tokio::time::Instant::now() + handler.limits.connection_timeout;
        let task = tokio::spawn(async move {
            handle_redirect_io(server, &handler, deadline).await;
        });
        let writer = tokio::spawn(async move {
            for _ in 0..30 {
                if client.write_all(b"G").await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            panic!("slow request was allowed to reset its deadline");
        });
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), writer)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn blocked_response_write_uses_the_same_deadline() {
        let handler = limited_handler(Duration::from_millis(100), 2);
        let (mut client, server) = tokio::io::duplex(16);
        let deadline = tokio::time::Instant::now() + handler.limits.connection_timeout;
        let task = tokio::spawn(async move {
            handle_redirect_io(server, &handler, deadline).await;
        });
        let request = format!(
            "GET /{} HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "p".repeat(4096)
        );
        client.write_all(&request.as_bytes()[..16]).await.unwrap();
        tokio::time::advance(Duration::from_millis(80)).await;
        client.write_all(&request.as_bytes()[16..]).await.unwrap();
        // Observe one response byte to prove the read phase really completed.
        // Then stop reading: the 16-byte buffer still forces writing to wait.
        let mut first = [0];
        client.read_exact(&mut first).await.unwrap();
        assert_eq!(
            tokio::time::Instant::now(),
            deadline - Duration::from_millis(20)
        );
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tokio::time::Instant::now(), deadline);
        let mut response = first.to_vec();
        client.read_to_end(&mut response).await.unwrap();
        assert!(!response.is_empty());
        assert!(!response.windows(4).any(|w| w == b"\r\n\r\n"));
    }

    #[tokio::test]
    async fn oversized_headers_are_rejected_within_budget() {
        let handler = limited_handler(Duration::from_secs(2), 2)
            .with_limits(RedirectLimits {
                max_header_bytes: 64,
                ..RedirectLimits::default()
            })
            .unwrap();
        let (mut client, server) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            handle_redirect_io(
                server,
                &handler,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await;
        });
        client.write_all(&[b'X'; 128]).await.unwrap();
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 431"));
        task.await.unwrap();
    }

    /// Deterministic read boundaries model coalesced and fragmented TCP data.
    struct FragmentedIo {
        input: std::collections::VecDeque<Vec<u8>>,
        offset: usize,
        output: Vec<u8>,
    }

    impl AsyncRead for FragmentedIo {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if let Some(fragment) = this.input.front() {
                let count = buffer.remaining().min(fragment.len() - this.offset);
                buffer.put_slice(&fragment[this.offset..this.offset + count]);
                this.offset += count;
                if this.offset == fragment.len() {
                    this.input.pop_front();
                    this.offset = 0;
                }
            }
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for FragmentedIo {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.get_mut().output.extend_from_slice(bytes);
            std::task::Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    async fn fragmented_response(
        request: &[u8],
        split: Option<usize>,
        header_cap: usize,
    ) -> String {
        let handler = limited_handler(Duration::from_secs(1), 1)
            .with_limits(RedirectLimits {
                max_header_bytes: header_cap,
                ..RedirectLimits::default()
            })
            .unwrap();
        fragmented_response_for_handler(request, split, &handler).await
    }

    async fn fragmented_response_for_handler(
        request: &[u8],
        split: Option<usize>,
        handler: &HttpsRedirectHandler,
    ) -> String {
        let input = match split {
            Some(split) => [request[..split].to_vec(), request[split..].to_vec()]
                .into_iter()
                .collect(),
            None => [request.to_vec()].into_iter().collect(),
        };
        let mut stream = FragmentedIo {
            input,
            offset: 0,
            output: Vec::new(),
        };
        redirect_exchange(&mut stream, handler).await;
        String::from_utf8(stream.output).unwrap()
    }

    #[tokio::test]
    async fn single_dns_root_dot_redirects_under_both_host_policies() {
        let canonical = HttpsRedirectHandler::default()
            .with_canonical_host("canonical.example.com")
            .unwrap();
        let allowlist = HttpsRedirectHandler::default()
            .allow_host("example.com")
            .unwrap();
        for (handler, destination) in [
            (&canonical, "canonical.example.com"),
            (&allowlist, "example.com"),
        ] {
            for host in [
                "example.com.",
                "EXAMPLE.COM.",
                "example.com.:8080",
                "EXAMPLE.COM.:8080",
            ] {
                let request = format!("GET /path HTTP/1.1\r\nHost: {host}\r\n\r\n");
                for split in [None, Some(request.len() / 2), Some(request.len() - 5)] {
                    let response =
                        fragmented_response_for_handler(request.as_bytes(), split, handler).await;
                    assert!(
                        response.starts_with("HTTP/1.1 301"),
                        "host={host} split={split:?}: {response}"
                    );
                    assert!(
                        response.contains(&format!("Location: https://{destination}/path\r\n"))
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn root_dot_normalization_still_rejects_invalid_hosts() {
        let canonical = HttpsRedirectHandler::default()
            .with_canonical_host("canonical.example.com")
            .unwrap();
        let allowlist = HttpsRedirectHandler::default()
            .allow_host("example.com")
            .unwrap();
        for handler in [&canonical, &allowlist] {
            for host in [
                "example.com..",
                "EXAMPLE.COM..:8080",
                ".",
                ".:8080",
                "example.com.:65536",
                "example.com.\0",
            ] {
                let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
                for split in [None, Some(request.len() / 2)] {
                    let response =
                        fragmented_response_for_handler(request.as_bytes(), split, handler).await;
                    assert!(
                        response.starts_with("HTTP/1.1 400"),
                        "host={host:?} split={split:?}: {response}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn binary_body_is_independent_of_read_fragmentation() {
        let header = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\n\r\n";
        let mut request = header.to_vec();
        request.push(0xff);
        let coalesced = fragmented_response(&request, None, 8192).await;
        let fragmented = fragmented_response(&request, Some(header.len()), 8192).await;
        assert!(
            coalesced.starts_with("HTTP/1.1 301"),
            "coalesced: {coalesced}"
        );
        assert_eq!(coalesced, fragmented);
        assert!(coalesced.contains("Location: https://example.com/upload\r\n"));
    }

    #[tokio::test]
    async fn header_limit_counts_only_headers_at_every_fragment_boundary() {
        for cap in [128, 1024, 1025] {
            for header_length in [cap - 1, cap, cap + 1] {
                let prefix = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4096\r\nX-Pad: ";
                let mut request = prefix.to_vec();
                request.extend(std::iter::repeat_n(b'a', header_length - prefix.len() - 4));
                request.extend_from_slice(b"\r\n\r\n");
                assert_eq!(request.len(), header_length);
                request.extend_from_slice(&[0xff; 4096]);
                let expected = if header_length <= cap {
                    "HTTP/1.1 301"
                } else {
                    "HTTP/1.1 431"
                };
                for split in [
                    None,
                    Some(header_length - 3),
                    Some(header_length - 1),
                    Some(header_length),
                    Some(header_length + 1),
                    Some(1024),
                ] {
                    let response = fragmented_response(&request, split, cap).await;
                    assert!(
                        response.starts_with(expected),
                        "cap={cap} header={header_length} split={split:?}: {response}"
                    );
                }
            }
        }
    }

    #[test]
    fn parsing_headers_ignores_non_utf8_body_bytes() {
        let handler = limited_handler(Duration::from_secs(1), 1);
        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\n\r\n\xff";
        assert_eq!(
            parse_redirect_request(request, &handler).unwrap(),
            "https://example.com/upload"
        );
    }

    #[tokio::test]
    async fn unrelated_obs_text_headers_are_independent_of_fragmentation() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Label: \xff\t\x80\r\n\r\n";
        let obs_text = request.iter().position(|byte| *byte == 0xff).unwrap();
        for split in [
            None,
            Some(obs_text),
            Some(obs_text + 1),
            Some(request.len() - 2),
        ] {
            let response = fragmented_response(request, split, 8192).await;
            assert!(
                response.starts_with("HTTP/1.1 301"),
                "split={split:?}: {response}"
            );
            assert!(response.contains("Location: https://example.com/\r\n"));
        }
    }

    #[tokio::test]
    async fn invalid_required_fields_and_control_bytes_are_still_rejected() {
        let requests: &[&[u8]] = &[
            b"G\xffT / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"GET /\xff HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: examp\xffle.com\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: example.com bad\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: [not-an-ip]\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: example.com:65536\r\n\r\n",
            b"GET / HTTP/1.1\r\nX-Label: present\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: example.com\r\nHost: evil.com\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: example.com\r\nX Label: value\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Label: value\0bad\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Label: value\rbad\r\n\r\n",
            b"GET / HTTP/1.1\nHost: example.com\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: example.com\r\n X-Fold: value\r\n\r\n",
        ];
        for request in requests {
            for split in [None, Some(request.len() / 2)] {
                let response = fragmented_response(request, split, 8192).await;
                assert!(
                    response.starts_with("HTTP/1.1 400"),
                    "request={request:?} split={split:?}: {response}"
                );
            }
        }
    }

    #[test]
    fn invalid_limits_are_rejected() {
        for limits in [
            RedirectLimits {
                max_connections: 0,
                ..RedirectLimits::default()
            },
            RedirectLimits {
                connection_timeout: Duration::ZERO,
                ..RedirectLimits::default()
            },
            RedirectLimits {
                max_header_bytes: 3,
                ..RedirectLimits::default()
            },
        ] {
            assert!(HttpsRedirectHandler::default().with_limits(limits).is_err());
        }
    }

    #[tokio::test]
    async fn fragmented_request_waits_for_complete_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let handler = HttpsRedirectHandler::default()
            .with_canonical_host("example.com")
            .unwrap();
        let task = tokio::spawn(handle_redirect_connection(stream, handler));
        client.write_all(b"GET /path HTTP/1.1\r\nHo").await.unwrap();
        let mut byte = [0];
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), client.read(&mut byte))
                .await
                .is_err(),
            "must wait for the full headers"
        );
        client.write_all(b"st: example.com\r\n\r\n").await.unwrap();
        let mut response = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_to_string(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(response.contains("Location: https://example.com/path\r\n"));
        task.await.unwrap();
    }

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
