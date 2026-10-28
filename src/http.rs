//! The one HTTP client.
//!
//! Every request certon makes goes through here: fetching an ACME directory,
//! posting a signed order, asking an OCSP responder, calling the ZeroSSL API.
//!
//! It is one client rather than four because four had three consequences, and
//! the first of them was a panic.
//!
//! `reqwest` built against rustls with no provider selected refuses to guess
//! one — constructing a client with no process-wide provider installed aborts
//! the process with a message telling you to install one. Two of the four
//! places that built a client installed a provider first. The other two, the
//! OCSP fetcher and the ZeroSSL API client, did not, and worked only when
//! something else happened to have run before them. A program that reached
//! OCSP without first building an [`AcmeClient`](crate::acme_client::AcmeClient)
//! or a `Config` died.
//!
//! The second is that a client owns a connection pool, so four clients meant
//! four pools and no reuse between them. The OCSP path built a fresh one for
//! every request, which is a TLS stack and a pool per certificate checked.
//!
//! The third is that the user agent reached Let's Encrypt but not ZeroSSL and
//! not any OCSP responder, so certon identified itself to one of the three
//! parties it talks to.
//!
//! A caller wanting different transport behaviour has one place to look
//! rather than three modules to search, which is the point.

use std::sync::OnceLock;
use std::time::Duration;

use crate::error::{Error, Result};

/// How long any single request may take: an ACME POST, an OCSP round trip, a
/// ZeroSSL API call. Every caller used the same value before this module
/// existed; now they use it because there is one.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum JSON document accepted from an ACME or ZeroSSL endpoint.
pub(crate) const MAX_JSON_BODY_BYTES: usize = 1024 * 1024;
/// Error details are diagnostic data, so they have a smaller memory/log budget.
pub(crate) const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// Read a response incrementally, enforcing the limit even for chunked bodies.
/// `context` must be a static operation label, never a URL containing credentials.
pub(crate) async fn read_body_limited(
    mut response: reqwest::Response,
    limit: usize,
    context: &'static str,
) -> Result<Vec<u8>> {
    let too_large = || Error::Other(format!("{context} response body exceeds {limit} bytes"));
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        Error::Other(format!(
            "failed to read {context} response: {}",
            error.without_url()
        ))
    })? {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Default identification, when the embedder has not chosen one.
const DEFAULT_USER_AGENT: &str = concat!("certon/", env!("CARGO_PKG_VERSION"));

static USER_AGENT: OnceLock<String> = OnceLock::new();

/// Set the user agent certon sends.
///
/// Must be called before the first client is created, because the client is built once
/// and shared. Calling it afterwards is ignored rather than an error, which is
/// what a `OnceLock` gives; there is nothing useful to do about it.
///
/// A certificate authority reads this. Setting it to something that names your
/// service is how you get told about a problem instead of rate-limited for it.
pub fn set_user_agent(agent: impl Into<String>) {
    USER_AGENT.set(agent.into()).ok();
}

/// What certon currently identifies itself as.
pub fn user_agent() -> &'static str {
    USER_AGENT
        .get()
        .map(String::as_str)
        .unwrap_or(DEFAULT_USER_AGENT)
}

/// The client every module shares.
///
/// Built on first use and kept. `reqwest::Client` is a handle to a shared
/// pool, so this hands back a reference rather than cloning: callers that want
/// an owned handle can clone it themselves.
pub fn client() -> Result<&'static reqwest::Client> {
    static CLIENT: OnceLock<std::result::Result<reqwest::Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(build)
        .as_ref()
        .map_err(|reason| Error::Other(format!("could not build the HTTP client: {reason}")))
}

fn build() -> std::result::Result<reqwest::Client, String> {
    install_crypto_provider();
    reqwest::Client::builder()
        .user_agent(
            USER_AGENT
                .get_or_init(|| DEFAULT_USER_AGENT.to_owned())
                .as_str(),
        )
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|error| error.to_string())
}

/// Make sure rustls has a process-wide provider, because `reqwest` requires
/// one and will not choose.
///
/// A provider the embedder installed first wins. That is deliberate — a host
/// that has already chosen is not overruled by a library.
pub(crate) fn install_crypto_provider() {
    #[cfg(feature = "aws-lc-rs")]
    {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    async fn wire_response(
        wire: Vec<u8>,
        hold_open: bool,
    ) -> (reqwest::Response, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/?access_key=secret-for-redaction",
            listener.local_addr().unwrap()
        );
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            let _ = stream.write_all(&wire).await;
            if hold_open {
                std::future::pending::<()>().await;
            }
        });
        (client().unwrap().get(url).send().await.unwrap(), task)
    }

    #[tokio::test]
    async fn declared_oversize_is_rejected_without_waiting_for_the_body() {
        let (response, task) = wire_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n".to_vec(),
            true,
        )
        .await;
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            read_body_limited(response, 4, "test"),
        )
        .await
        .expect("declared size must be checked before reading the body");
        task.abort();
        assert!(result.unwrap_err().to_string().contains("exceeds 4 bytes"));
    }

    #[tokio::test]
    async fn chunked_limits_accept_the_boundary_and_reject_the_next_byte() {
        for (chunks, expected) in [
            ("2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n", Some(b"abcd".as_slice())),
            ("3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n", None),
        ] {
            let wire = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{chunks}");
            let (response, task) = wire_response(wire.into_bytes(), false).await;
            let result = read_body_limited(response, 4, "test").await;
            task.await.unwrap();
            match expected {
                Some(bytes) => assert_eq!(result.unwrap(), bytes),
                None => assert!(result.unwrap_err().to_string().contains("exceeds 4 bytes")),
            }
        }
    }

    #[tokio::test]
    async fn malformed_response_errors_do_not_expose_request_credentials() {
        let (response, task) = wire_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nNOT-HEX\r\n".to_vec(),
            false,
        )
        .await;
        let error = read_body_limited(response, 64, "test")
            .await
            .unwrap_err()
            .to_string();
        task.await.unwrap();
        assert!(error.contains("failed to read test response"));
        assert!(!error.contains("secret-for-redaction"));
        assert!(!error.contains("access_key"));
    }

    #[test]
    fn the_default_user_agent_carries_the_real_version() {
        // It used to say `certon/0.1` at every version, which is worse than
        // saying nothing: a CA reading it learns something untrue.
        assert!(DEFAULT_USER_AGENT.starts_with("certon/"));
        assert!(DEFAULT_USER_AGENT.contains(env!("CARGO_PKG_VERSION")));
        assert_ne!(DEFAULT_USER_AGENT, "certon/0.1");
    }

    #[test]
    fn the_client_is_one_client() {
        // Every caller shares the same connection pool.
        let first = client().expect("a client");
        let second = client().expect("a client");
        assert!(std::ptr::eq(first, second));
    }
}
