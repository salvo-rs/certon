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

/// Default identification, when the embedder has not chosen one.
const DEFAULT_USER_AGENT: &str = concat!("certon/", env!("CARGO_PKG_VERSION"));

static USER_AGENT: OnceLock<String> = OnceLock::new();

/// Set the user agent certon sends.
///
/// Must be called before the first request, because the client is built once
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
        .user_agent(user_agent())
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|error| error.to_string())
}

/// Make sure rustls has a process-wide provider, because `reqwest` requires
/// one and will not choose.
///
/// This is the one place certon touches process-global state, and it is here
/// rather than anywhere else because this is the only thing that needs it:
/// certon's own rustls configurations go through `rustls`'s builders, which
/// select the provider from the crate features it was compiled with.
///
/// A provider the embedder installed first wins. That is deliberate — a host
/// that has already chosen is not overruled by a library.
fn install_crypto_provider() {
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
    use super::*;

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
        // Two callers must get the same connection pool. Two pools is how a
        // rate limit gets hit twice as fast.
        let first = client().expect("a client");
        let second = client().expect("a client");
        assert!(std::ptr::eq(first, second));
    }
}
