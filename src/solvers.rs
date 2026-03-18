//! ACME challenge solvers.
//!
//! This module provides trait-based abstractions and concrete implementations
//! for solving ACME challenges (HTTP-01, TLS-ALPN-01, DNS-01) as well as a
//! distributed solver wrapper for clustered deployments.
//!
//!
//! # Challenge types
//!
//! | Solver | Port | How it works |
//! |---|---|---|
//! | [`Http01Solver`] | 80 | Serves `key_auth` at `/.well-known/acme-challenge/{token}` |
//! | [`TlsAlpn01Solver`] | 443 | Presents a self-signed cert with the `acmeIdentifier` extension via `acme-tls/1` ALPN |
//! | [`Dns01Solver`] | n/a | Creates a `_acme-challenge` TXT record via a [`DnsProvider`] |
//!
//! # Distributed deployments
//!
//! In a cluster, wrap any solver with [`DistributedSolver`] so that challenge
//! data is persisted to shared [`Storage`]. This
//! allows any cluster member to respond to the CA's validation request, not
//! just the instance that initiated the certificate order.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use rcgen::{
    CertificateParams, CustomExtension, KeyPair as RcgenKeyPair, PKCS_ECDSA_P256_SHA256,
};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

use crate::dns_util::{
    challenge_record_name, challenge_record_value, check_dns_propagation, from_fqdn,
    find_zone_by_fqdn, DEFAULT_PROPAGATION_INTERVAL, DEFAULT_PROPAGATION_TIMEOUT,
};
use crate::error::{Error, Result};
use crate::storage::{safe_key, Storage};

// ---------------------------------------------------------------------------
// Active challenges global tracking
// ---------------------------------------------------------------------------

/// Global map of active challenge identifiers to their key authorizations.
///
/// When an [`Http01Solver`] or [`TlsAlpn01Solver`] presents a challenge, it
/// registers the identifier (token or domain) and key authorization here.
/// On cleanup, the entry is removed. This allows looking up active
/// challenges globally without direct access to a specific solver instance.
static ACTIVE_CHALLENGES: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

fn active_challenges() -> &'static RwLock<HashMap<String, String>> {
    ACTIVE_CHALLENGES.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Look up the key authorization for an active challenge by its identifier.
///
/// Returns `Some(key_auth)` if a challenge is currently active for the given
/// identifier (token for HTTP-01, domain for TLS-ALPN-01), or `None`
/// otherwise.
pub fn get_active_challenge(identifier: &str) -> Option<String> {
    let rt = tokio::runtime::Handle::try_current();
    match rt {
        Ok(_handle) => {
            // Cannot block_on inside async; try_read instead.
            let map = active_challenges().try_read().ok()?;
            map.get(identifier).cloned()
        }
        Err(_) => None,
    }
}

/// Register an active challenge in the global map.
async fn register_active_challenge(identifier: &str, key_auth: &str) {
    let mut map = active_challenges().write().await;
    map.insert(identifier.to_string(), key_auth.to_string());
}

/// Remove an active challenge from the global map.
async fn unregister_active_challenge(identifier: &str) {
    let mut map = active_challenges().write().await;
    map.remove(identifier);
}

// ---------------------------------------------------------------------------
// Solver trait
// ---------------------------------------------------------------------------

/// An ACME challenge solver.
///
/// Implementations of this trait know how to present (make solvable),
/// optionally wait for readiness, and clean up after an ACME challenge.
///
/// The typical call sequence during certificate issuance is:
///
/// 1. [`Solver::present`] -- make the challenge solvable.
/// 2. [`Solver::wait`] -- optionally block until the challenge is ready
///    (e.g. DNS propagation).
/// 3. *(ACME CA validates the challenge)*
/// 4. [`Solver::cleanup`] -- remove the challenge artifacts.
#[async_trait]
pub trait Solver: Send + Sync {
    /// Present the challenge — make it solvable by the ACME CA's validation
    /// server (e.g. start an HTTP server, create a DNS record, or install a
    /// TLS certificate).
    async fn present(&self, domain: &str, token: &str, key_auth: &str) -> Result<()>;

    /// Optionally wait until the challenge is ready to be verified by the CA.
    ///
    /// The default implementation is a no-op. DNS solvers typically override
    /// this to wait for TXT record propagation.
    async fn wait(&self, _domain: &str, _token: &str, _key_auth: &str) -> Result<()> {
        Ok(())
    }

    /// Clean up after the challenge (e.g. stop the server, delete the DNS
    /// record, remove the certificate from the cache).
    async fn cleanup(&self, domain: &str, token: &str, key_auth: &str) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Challenge token storage key helpers
// ---------------------------------------------------------------------------

/// Storage key prefix for challenge tokens used by the distributed solver.
const CHALLENGE_TOKENS_PREFIX: &str = "challenge_tokens";

/// Build the storage key for challenge data.
///
/// The key format is: `"<issuer_prefix>/challenge_tokens/<safe_domain>.json"`.
/// The stored value is a JSON object mapping tokens to key authorizations.
fn challenge_tokens_key(issuer_prefix: &str, domain: &str) -> String {
    let safe_domain = safe_key(domain);
    if issuer_prefix.is_empty() {
        format!("{CHALLENGE_TOKENS_PREFIX}/{safe_domain}.json")
    } else {
        format!("{issuer_prefix}/{CHALLENGE_TOKENS_PREFIX}/{safe_domain}.json")
    }
}

// ===========================================================================
// HTTP-01 Solver
// ===========================================================================

/// Solves ACME HTTP-01 challenges by serving the key authorization string
/// at `GET /.well-known/acme-challenge/{token}` on a simple HTTP server.
///
/// The solver lazily starts a TCP listener on the configured port (default: 80)
/// when the first challenge is presented, and stops it when all challenges have
/// been cleaned up. Multiple concurrent challenges share the same server.
///
/// **Important**: Port 80 must be reachable from the internet for the ACME
/// CA's validation server to reach this solver.
pub struct Http01Solver {
    /// In-memory map of token -> key_auth for currently active challenges.
    challenges: Arc<RwLock<HashMap<String, String>>>,
    /// The port to listen on (default: 80).
    pub port: u16,
    /// Handle to the background HTTP server task, if running.
    server_handle: Mutex<Option<JoinHandle<()>>>,
}

impl Http01Solver {
    /// Create a new HTTP-01 solver that will listen on the given port.
    ///
    /// The server is not started until [`Solver::present`] is called for
    /// the first time.
    pub fn new(port: u16) -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            port,
            server_handle: Mutex::new(None),
        }
    }

    /// Start the challenge HTTP server if it is not already running.
    ///
    /// If binding the TCP listener fails with "address already in use", the
    /// method retries once after 100ms. If binding still fails, a warning is
    /// logged and `Ok(())` is returned under the assumption that an existing
    /// listener (e.g. from a previous solver or external process) can handle
    /// the challenge requests.
    async fn ensure_server_running(&self) -> Result<()> {
        let mut handle = self.server_handle.lock().await;
        if handle.is_some() {
            return Ok(());
        }

        let addr = format!("0.0.0.0:{}", self.port);
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                debug!(addr = %addr, "address in use, retrying after 100ms");
                tokio::time::sleep(Duration::from_millis(100)).await;
                match TcpListener::bind(&addr).await {
                    Ok(l) => l,
                    Err(e2) => {
                        warn!(
                            addr = %addr,
                            error = %e2,
                            "failed to bind HTTP-01 challenge server after retry; \
                             assuming an existing listener can handle it"
                        );
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                return Err(Error::Other(format!(
                    "failed to bind HTTP-01 challenge server on {addr}: {e}"
                )));
            }
        };

        debug!(addr = %addr, "HTTP-01 challenge server started");

        let challenges = Arc::clone(&self.challenges);
        let jh = tokio::spawn(async move {
            loop {
                let accept_result = listener.accept().await;
                let (mut stream, peer) = match accept_result {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "HTTP-01 server accept error");
                        continue;
                    }
                };

                let challenges = Arc::clone(&challenges);
                tokio::spawn(async move {
                    // Apply a 10-second connection timeout.
                    let handler = async {
                        // Read until we find the end of headers (\r\n\r\n) or
                        // hit a size limit.
                        let mut buf = Vec::with_capacity(8192);
                        let mut tmp = [0u8; 1024];
                        let headers_end;
                        loop {
                            let n = match stream.read(&mut tmp).await {
                                Ok(0) => return,
                                Ok(n) => n,
                                Err(_) => return,
                            };
                            buf.extend_from_slice(&tmp[..n]);

                            // Check for end-of-headers marker.
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                headers_end = pos;
                                break;
                            }

                            // Prevent unbounded reads (64 KB limit for headers).
                            if buf.len() > 65536 {
                                return;
                            }
                        }

                        let request = String::from_utf8_lossy(&buf[..headers_end]);
                        // Parse the request line: "METHOD PATH VERSION".
                        let request_line = match request.lines().next() {
                            Some(line) => line,
                            None => return,
                        };
                        let mut parts = request_line.split_whitespace();
                        let method = parts.next().unwrap_or("");
                        let path = parts.next().unwrap_or("");

                        // Only respond to GET requests.
                        if !method.eq_ignore_ascii_case("GET") {
                            let response = "HTTP/1.1 405 Method Not Allowed\r\n\
                                            Content-Length: 0\r\n\
                                            Content-Type: text/plain\r\n\
                                            Connection: close\r\n\
                                            \r\n";
                            let _ = stream.write_all(response.as_bytes()).await;
                            return;
                        }

                        const CHALLENGE_PATH_PREFIX: &str = "/.well-known/acme-challenge/";

                        if let Some(token) = path.strip_prefix(CHALLENGE_PATH_PREFIX) {
                            let challenges = challenges.read().await;
                            if let Some(key_auth) = challenges.get(token) {
                                let body = key_auth.as_bytes();
                                let response = format!(
                                    "HTTP/1.1 200 OK\r\n\
                                     Content-Type: text/plain\r\n\
                                     Content-Length: {}\r\n\
                                     Connection: close\r\n\
                                     \r\n",
                                    body.len()
                                );
                                let _ = stream.write_all(response.as_bytes()).await;
                                let _ = stream.write_all(body).await;
                                debug!(token = token, peer = %peer, "served HTTP-01 challenge");
                            } else {
                                let response = "HTTP/1.1 404 Not Found\r\n\
                                                Content-Length: 0\r\n\
                                                Content-Type: text/plain\r\n\
                                                Connection: close\r\n\
                                                \r\n";
                                let _ = stream.write_all(response.as_bytes()).await;
                            }
                        } else {
                            let response = "HTTP/1.1 404 Not Found\r\n\
                                            Content-Length: 0\r\n\
                                            Content-Type: text/plain\r\n\
                                            Connection: close\r\n\
                                            \r\n";
                            let _ = stream.write_all(response.as_bytes()).await;
                        }
                    };

                    // Wrap the handler in a 10-second timeout.
                    let _ = tokio::time::timeout(
                        Duration::from_secs(10),
                        handler,
                    )
                    .await;
                });
            }
        });

        *handle = Some(jh);
        Ok(())
    }
}

impl Default for Http01Solver {
    fn default() -> Self {
        Self::new(80)
    }
}

impl std::fmt::Debug for Http01Solver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http01Solver")
            .field("port", &self.port)
            .finish()
    }
}

#[async_trait]
impl Solver for Http01Solver {
    async fn present(&self, _domain: &str, token: &str, key_auth: &str) -> Result<()> {
        {
            let mut challenges = self.challenges.write().await;
            challenges.insert(token.to_string(), key_auth.to_string());
        }
        register_active_challenge(token, key_auth).await;
        self.ensure_server_running().await?;
        debug!(token = token, "HTTP-01 challenge presented");
        Ok(())
    }

    async fn cleanup(&self, _domain: &str, token: &str, _key_auth: &str) -> Result<()> {
        let should_stop = {
            let mut challenges = self.challenges.write().await;
            challenges.remove(token);
            challenges.is_empty()
        };
        unregister_active_challenge(token).await;

        if should_stop {
            let mut handle = self.server_handle.lock().await;
            if let Some(jh) = handle.take() {
                jh.abort();
                debug!("HTTP-01 challenge server stopped (no more challenges)");
            }
        }
        Ok(())
    }
}

// ===========================================================================
// TLS-ALPN-01 Solver
// ===========================================================================

/// OID for the `acmeIdentifier` extension: `1.3.6.1.5.5.7.1.31`.
///
/// This is the extension OID specified in RFC 8737 that carries the SHA-256
/// digest of the key authorization in the self-signed challenge certificate.
/// The extension must be marked as critical.
const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

/// The ALPN protocol identifier for TLS-ALPN-01 challenges (`"acme-tls/1"`).
///
/// During the TLS handshake the client and server negotiate this protocol
/// via the ALPN extension, signaling that the connection is for ACME
/// challenge validation rather than normal application traffic.
const ACME_TLS_ALPN_PROTOCOL: &[u8] = b"acme-tls/1";

/// Solves ACME TLS-ALPN-01 challenges by presenting a self-signed certificate
/// with the `acmeIdentifier` extension during the TLS handshake, negotiated
/// via the `acme-tls/1` ALPN protocol (RFC 8737).
///
/// Like [`Http01Solver`], the TLS server is started lazily and shared across
/// concurrent challenges. The default port is 443.
///
/// **Important**: Port 443 must be reachable from the internet, and the
/// client's SNI value must match the domain being validated.
pub struct TlsAlpn01Solver {
    /// In-memory map of domain -> (cert chain DER, private key DER) for
    /// currently active challenges.
    challenges: Arc<RwLock<HashMap<String, (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>>>,
    /// The port to listen on (default: 443).
    pub port: u16,
    /// Handle to the background TLS server task, if running.
    server_handle: Mutex<Option<JoinHandle<()>>>,
}

impl TlsAlpn01Solver {
    /// Create a new TLS-ALPN-01 solver that will listen on the given port.
    ///
    /// The server is not started until [`Solver::present`] is called for
    /// the first time.
    pub fn new(port: u16) -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            port,
            server_handle: Mutex::new(None),
        }
    }

    /// Generate a self-signed challenge certificate for the TLS-ALPN-01
    /// challenge.
    ///
    /// The certificate contains:
    /// - A single SAN matching `domain`
    /// - The `acmeIdentifier` extension (OID 1.3.6.1.5.5.7.1.31) containing
    ///   the DER-encoded ASN.1 value: `OCTET STRING { SHA-256(key_auth) }`
    /// - Marked as critical per RFC 8737
    fn generate_challenge_cert(
        domain: &str,
        key_auth: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        // Generate an ephemeral ECDSA P-256 key for the challenge certificate.
        let rng = SystemRandom::new();
        let pkcs8_doc =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).map_err(|e| {
                Error::Other(format!(
                    "failed to generate ephemeral key for TLS-ALPN-01: {e}"
                ))
            })?;
        let pkcs8_bytes = pkcs8_doc.as_ref().to_vec();

        let key_pair =
            RcgenKeyPair::from_pkcs8_der_and_sign_algo(
                &PrivatePkcs8KeyDer::from(pkcs8_bytes.clone()),
                &PKCS_ECDSA_P256_SHA256,
            )
            .map_err(|e| {
                Error::Other(format!("failed to create rcgen key pair: {e}"))
            })?;

        let mut params = CertificateParams::new(vec![domain.to_string()]).map_err(|e| {
            Error::Other(format!("failed to create certificate params: {e}"))
        })?;

        // Compute SHA-256(key_auth) for the acmeIdentifier extension value.
        let digest = Sha256::digest(key_auth.as_bytes());

        // The extension value is a DER-encoded ASN.1 OCTET STRING wrapping the
        // 32-byte SHA-256 digest:
        //   OCTET STRING (32 bytes) { <digest> }
        let mut ext_value = Vec::with_capacity(2 + 32);
        ext_value.push(0x04); // ASN.1 OCTET STRING tag
        ext_value.push(0x20); // length = 32
        ext_value.extend_from_slice(&digest);

        let oid_vec: Vec<u64> = ACME_IDENTIFIER_OID.to_vec();
        let mut ext = CustomExtension::from_oid_content(&oid_vec, ext_value);
        ext.set_criticality(true);
        params.custom_extensions.push(ext);

        // Self-sign the certificate.
        let cert = params.self_signed(&key_pair).map_err(|e| {
            Error::Other(format!(
                "failed to self-sign TLS-ALPN-01 challenge certificate: {e}"
            ))
        })?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_bytes));

        Ok((vec![cert_der], key_der))
    }

    /// Start the TLS-ALPN challenge server if not already running.
    async fn ensure_server_running(&self) -> Result<()> {
        let mut handle = self.server_handle.lock().await;
        if handle.is_some() {
            return Ok(());
        }

        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr).await.map_err(|e| {
            Error::Other(format!(
                "failed to bind TLS-ALPN-01 challenge server on {addr}: {e}"
            ))
        })?;

        debug!(addr = %addr, "TLS-ALPN-01 challenge server started");

        let challenges = Arc::clone(&self.challenges);
        let jh = tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "TLS-ALPN-01 server accept error");
                        continue;
                    }
                };

                let challenges = Arc::clone(&challenges);
                tokio::spawn(async move {
                    // Build a rustls ServerConfig that selects the challenge cert
                    // based on the SNI value.
                    let challenges_snapshot = challenges.read().await;
                    if challenges_snapshot.is_empty() {
                        return;
                    }

                    // We need a custom cert resolver. For simplicity, we build a
                    // new TLS config per connection using the SNI from the
                    // challenges we have. If the client's SNI doesn't match, the
                    // handshake will fail, which is fine for challenge purposes.

                    // Since we cannot peek at SNI before constructing the config,
                    // we use a resolver that picks the right cert dynamically.
                    let resolver = ChallengeCertResolver {
                        challenges: challenges_snapshot
                            .iter()
                            .map(|(domain, (certs, key))| {
                                (domain.clone(), (certs.clone(), key.clone_key()))
                            })
                            .collect(),
                    };

                    drop(challenges_snapshot);

                    let mut config = match rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_cert_resolver(Arc::new(resolver))
                    {
                        config => config,
                    };

                    config.alpn_protocols = vec![ACME_TLS_ALPN_PROTOCOL.to_vec()];

                    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
                    match acceptor.accept(stream).await {
                        Ok(_tls_stream) => {
                            debug!(peer = %peer, "TLS-ALPN-01 handshake completed");
                            // The handshake is all that matters; drop the connection.
                        }
                        Err(e) => {
                            debug!(peer = %peer, error = %e, "TLS-ALPN-01 handshake failed");
                        }
                    }
                });
            }
        });

        *handle = Some(jh);
        Ok(())
    }
}

impl Default for TlsAlpn01Solver {
    fn default() -> Self {
        Self::new(443)
    }
}

impl std::fmt::Debug for TlsAlpn01Solver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAlpn01Solver")
            .field("port", &self.port)
            .finish()
    }
}

#[async_trait]
impl Solver for TlsAlpn01Solver {
    async fn present(&self, domain: &str, _token: &str, key_auth: &str) -> Result<()> {
        let (cert_chain, key_der) = Self::generate_challenge_cert(domain, key_auth)?;
        {
            let mut challenges = self.challenges.write().await;
            challenges.insert(domain.to_string(), (cert_chain, key_der));
        }
        register_active_challenge(domain, key_auth).await;
        self.ensure_server_running().await?;
        debug!(domain = domain, "TLS-ALPN-01 challenge presented");
        Ok(())
    }

    async fn cleanup(&self, domain: &str, _token: &str, _key_auth: &str) -> Result<()> {
        let should_stop = {
            let mut challenges = self.challenges.write().await;
            challenges.remove(domain);
            challenges.is_empty()
        };
        unregister_active_challenge(domain).await;

        if should_stop {
            let mut handle = self.server_handle.lock().await;
            if let Some(jh) = handle.take() {
                jh.abort();
                debug!("TLS-ALPN-01 challenge server stopped (no more challenges)");
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ChallengeCertResolver — dynamic cert selection for TLS-ALPN-01
// ---------------------------------------------------------------------------

/// A [`rustls::server::ResolvesServerCert`] implementation that selects the
/// correct challenge certificate based on the client's SNI (Server Name
/// Indication) value.
///
/// Each active TLS-ALPN-01 challenge registers its domain and ephemeral
/// certificate here. When the ACME CA connects and sends an SNI matching
/// one of the registered domains, the corresponding challenge certificate
/// (containing the `acmeIdentifier` extension) is presented.
#[derive(Debug)]
struct ChallengeCertResolver {
    challenges: HashMap<String, (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
}

impl rustls::server::ResolvesServerCert for ChallengeCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni = client_hello.server_name()?;

        let (certs, key_der) = self.challenges.get(sni)?;

        let signing_key =
            rustls::crypto::ring::sign::any_supported_type(key_der).ok()?;

        Some(Arc::new(rustls::sign::CertifiedKey::new(
            certs.clone(),
            signing_key,
        )))
    }
}

// ===========================================================================
// DNS-01 Solver
// ===========================================================================

/// Abstraction over a DNS provider that can create and delete TXT records.
///
/// Implementations should be able to create and delete TXT records for
/// ACME DNS-01 challenges.
///
/// Implementations should be idempotent: calling [`DnsProvider::set_record`]
/// twice with the same arguments should not create duplicate records, and
/// calling [`DnsProvider::delete_record`] for a non-existent record should
/// not fail.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Create (or append) a TXT record in the given DNS zone.
    ///
    /// - `zone`: the DNS zone (e.g. `"example.com."`)
    /// - `name`: the relative record name within the zone (e.g.
    ///   `"_acme-challenge"`)
    /// - `value`: the TXT record value
    /// - `ttl`: the record TTL in seconds
    async fn set_record(&self, zone: &str, name: &str, value: &str, ttl: u32) -> Result<()>;

    /// Delete a TXT record matching `name` and `value` from the given zone.
    async fn delete_record(&self, zone: &str, name: &str, value: &str) -> Result<()>;
}

/// Solves ACME DNS-01 challenges by creating a TXT record via a
/// [`DnsProvider`] implementation and optionally waiting for propagation.
///
/// The DNS-01 challenge is the only challenge type that supports wildcard
/// certificates. It works by placing a TXT record at
/// `_acme-challenge.<domain>` containing a base64url-encoded SHA-256 digest
/// of the key authorization.
///
/// After presenting the record, the solver's [`Solver::wait`] implementation
/// polls DNS resolvers until the record propagates or the timeout is reached.
pub struct Dns01Solver {
    /// The DNS provider that creates and deletes TXT records.
    pub provider: Box<dyn DnsProvider>,
    /// Maximum time to wait for DNS propagation (default: 2 minutes).
    pub propagation_timeout: Duration,
    /// Interval between propagation check attempts (default: 4 seconds).
    pub propagation_check_interval: Duration,
    /// Optional fixed delay before starting propagation checks.
    ///
    /// Some DNS providers need a grace period after record creation before
    /// the record becomes visible. Set this to add a sleep at the start of
    /// [`Solver::wait`].
    pub propagation_delay: Option<Duration>,
    /// TTL for the temporary challenge TXT record (in seconds).
    pub ttl: u32,
    /// Optional domain override for CNAME delegation.
    ///
    /// If set, the TXT record is created on this domain instead of
    /// `_acme-challenge.<domain>`. This is useful when the challenge domain
    /// has a CNAME pointing to a different zone that this provider controls.
    pub override_domain: Option<String>,
    /// Optional custom DNS resolvers to use for propagation checks.
    ///
    /// If set, these resolvers are passed to the propagation check function
    /// instead of the system defaults. Each entry should be in the form
    /// `"host:port"` (e.g. `"8.8.8.8:53"`).
    pub resolvers: Option<Vec<String>>,
    /// Remembered records for efficient cleanup, keyed by (dns_name, value).
    records: RwLock<HashMap<(String, String), DnsRecordMemory>>,
}

/// Information remembered about a presented DNS record, used for cleanup.
struct DnsRecordMemory {
    zone: String,
    relative_name: String,
    value: String,
}

impl Dns01Solver {
    /// Create a new DNS-01 solver with the given provider and default timeouts.
    ///
    /// Default propagation timeout is 2 minutes with a 4-second check interval.
    /// The default TXT record TTL is 120 seconds.
    pub fn new(provider: Box<dyn DnsProvider>) -> Self {
        Self {
            provider,
            propagation_timeout: DEFAULT_PROPAGATION_TIMEOUT,
            propagation_check_interval: DEFAULT_PROPAGATION_INTERVAL,
            propagation_delay: None,
            ttl: 120,
            override_domain: None,
            resolvers: None,
            records: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new DNS-01 solver with custom propagation settings.
    pub fn with_timeouts(
        provider: Box<dyn DnsProvider>,
        propagation_timeout: Duration,
        propagation_check_interval: Duration,
    ) -> Self {
        Self {
            provider,
            propagation_timeout,
            propagation_check_interval,
            propagation_delay: None,
            ttl: 120,
            override_domain: None,
            resolvers: None,
            records: RwLock::new(HashMap::new()),
        }
    }

    /// Compute the FQDN for the challenge TXT record.
    fn dns_name(&self, domain: &str) -> String {
        if let Some(ref override_domain) = self.override_domain {
            override_domain.clone()
        } else {
            challenge_record_name(domain)
        }
    }
}

impl std::fmt::Debug for Dns01Solver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dns01Solver")
            .field("propagation_timeout", &self.propagation_timeout)
            .field("propagation_check_interval", &self.propagation_check_interval)
            .field("propagation_delay", &self.propagation_delay)
            .field("ttl", &self.ttl)
            .field("override_domain", &self.override_domain)
            .field("resolvers", &self.resolvers)
            .finish()
    }
}

#[async_trait]
impl Solver for Dns01Solver {
    async fn present(&self, domain: &str, _token: &str, key_auth: &str) -> Result<()> {
        let dns_name = self.dns_name(domain);
        let txt_value = challenge_record_value(key_auth);

        // Determine the zone for this domain.
        let zone = find_zone_by_fqdn(&dns_name).ok_or_else(|| {
            Error::Other(format!(
                "could not determine DNS zone for {dns_name}"
            ))
        })?;

        // Compute the relative record name within the zone.
        let dns_name_fqdn = if dns_name.ends_with('.') {
            dns_name.clone()
        } else {
            format!("{dns_name}.")
        };
        let relative_name = dns_name_fqdn
            .strip_suffix(&zone)
            .unwrap_or(&dns_name)
            .trim_end_matches('.')
            .to_string();

        debug!(
            dns_name = %dns_name,
            zone = %zone,
            relative_name = %relative_name,
            "creating DNS TXT record for ACME challenge"
        );

        self.provider
            .set_record(&zone, &relative_name, &txt_value, self.ttl)
            .await?;

        // Remember for cleanup.
        let memory = DnsRecordMemory {
            zone,
            relative_name,
            value: txt_value.clone(),
        };
        {
            let mut records = self.records.write().await;
            records.insert((dns_name, txt_value), memory);
        }

        Ok(())
    }

    async fn wait(&self, domain: &str, _token: &str, key_auth: &str) -> Result<()> {
        let dns_name = self.dns_name(domain);
        let txt_value = challenge_record_value(key_auth);
        let fqdn = from_fqdn(&dns_name);

        // If a propagation delay is configured, sleep before checking.
        if let Some(delay) = self.propagation_delay {
            debug!(
                fqdn = %fqdn,
                delay = ?delay,
                "sleeping for configured propagation delay before checking DNS"
            );
            tokio::time::sleep(delay).await;
        }

        debug!(
            fqdn = %fqdn,
            "waiting for DNS propagation of challenge TXT record"
        );

        check_dns_propagation(
            &fqdn,
            &txt_value,
            self.propagation_timeout,
            self.propagation_check_interval,
        )
        .await?;

        Ok(())
    }

    async fn cleanup(&self, domain: &str, _token: &str, key_auth: &str) -> Result<()> {
        let dns_name = self.dns_name(domain);
        let txt_value = challenge_record_value(key_auth);

        let memory = {
            let mut records = self.records.write().await;
            records.remove(&(dns_name.clone(), txt_value))
        };

        if let Some(mem) = memory {
            debug!(
                zone = %mem.zone,
                name = %mem.relative_name,
                "deleting DNS TXT record for ACME challenge"
            );
            self.provider
                .delete_record(&mem.zone, &mem.relative_name, &mem.value)
                .await?;
        } else {
            warn!(
                dns_name = %dns_name,
                "no memory of presenting DNS record (cleanup may be incomplete)"
            );
        }

        Ok(())
    }
}

// ===========================================================================
// Distributed Solver
// ===========================================================================

/// Wraps any [`Solver`] for clustered / distributed deployments.
///
/// Before delegating to the inner solver, the distributed solver stores the
/// challenge data (domain, token, key_auth) in shared [`Storage`] so that
/// other cluster members can read it and respond to validation requests.
///
/// During cleanup, the challenge data is removed from storage and the inner
/// solver's cleanup method is also called.
///
pub struct DistributedSolver {
    /// The underlying solver that actually presents the challenge.
    inner: Box<dyn Solver>,
    /// Shared storage for cross-instance coordination.
    storage: Arc<dyn Storage>,
    /// Optional issuer-specific storage key prefix.
    storage_key_issuer_prefix: String,
}

impl DistributedSolver {
    /// Create a new distributed solver wrapping `inner`, using `storage` for
    /// cross-instance coordination.
    ///
    /// Challenge tokens are stored under the default prefix
    /// (`challenge_tokens/`). Use [`DistributedSolver::with_prefix`] to
    /// specify an issuer-specific prefix.
    pub fn new(inner: Box<dyn Solver>, storage: Arc<dyn Storage>) -> Self {
        Self {
            inner,
            storage,
            storage_key_issuer_prefix: String::new(),
        }
    }

    /// Create a new distributed solver with an issuer-specific storage key
    /// prefix.
    ///
    /// The prefix is prepended to the challenge tokens storage path, e.g.
    /// `"<prefix>/challenge_tokens/<domain>/<token>.json"`.
    pub fn with_prefix(
        inner: Box<dyn Solver>,
        storage: Arc<dyn Storage>,
        prefix: String,
    ) -> Self {
        Self {
            inner,
            storage,
            storage_key_issuer_prefix: prefix,
        }
    }

    /// Build the storage key for a challenge identified by domain.
    fn challenge_key(&self, domain: &str) -> String {
        challenge_tokens_key(&self.storage_key_issuer_prefix, domain)
    }
}

impl std::fmt::Debug for DistributedSolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DistributedSolver")
            .field("storage_key_issuer_prefix", &self.storage_key_issuer_prefix)
            .finish()
    }
}

#[async_trait]
impl Solver for DistributedSolver {
    async fn present(&self, domain: &str, token: &str, key_auth: &str) -> Result<()> {
        // Store challenge data in shared storage so other instances can read it.
        // The storage key is per-domain; the value is a JSON object mapping
        // token -> key_auth.
        let storage_key = self.challenge_key(domain);

        // Load existing map (if any), merge the new token, then store.
        let mut token_map: HashMap<String, String> = match self.storage.load(&storage_key).await {
            Ok(data) => serde_json::from_slice(&data).unwrap_or_default(),
            Err(_) => HashMap::new(),
        };
        token_map.insert(token.to_string(), key_auth.to_string());

        let json_bytes = serde_json::to_vec(&token_map)
            .map_err(|e| Error::Other(format!("serializing challenge tokens: {e}")))?;
        self.storage.store(&storage_key, &json_bytes).await?;

        // Delegate to the inner solver.
        self.inner
            .present(domain, token, key_auth)
            .await
            .map_err(|e| Error::Other(format!("presenting with inner solver: {e}")))?;

        Ok(())
    }

    async fn wait(&self, domain: &str, token: &str, key_auth: &str) -> Result<()> {
        self.inner.wait(domain, token, key_auth).await
    }

    async fn cleanup(&self, domain: &str, token: &str, key_auth: &str) -> Result<()> {
        // Remove the token from the per-domain JSON map in shared storage.
        let storage_key = self.challenge_key(domain);
        match self.storage.load(&storage_key).await {
            Ok(data) => {
                let mut token_map: HashMap<String, String> =
                    serde_json::from_slice(&data).unwrap_or_default();
                token_map.remove(token);
                if token_map.is_empty() {
                    // No more tokens for this domain — delete the key entirely.
                    if let Err(e) = self.storage.delete(&storage_key).await {
                        error!(
                            key = %storage_key,
                            error = %e,
                            "failed to delete challenge token from storage during cleanup"
                        );
                    }
                } else {
                    // Store the updated map.
                    if let Ok(json_bytes) = serde_json::to_vec(&token_map) {
                        if let Err(e) = self.storage.store(&storage_key, &json_bytes).await {
                            error!(
                                key = %storage_key,
                                error = %e,
                                "failed to update challenge tokens in storage during cleanup"
                            );
                        }
                    }
                }
            }
            Err(e) => {
                error!(
                    key = %storage_key,
                    error = %e,
                    "failed to load challenge tokens from storage during cleanup"
                );
            }
        }

        // Delegate cleanup to the inner solver.
        self.inner
            .cleanup(domain, token, key_auth)
            .await
            .map_err(|e| Error::Other(format!("cleaning up inner solver: {e}")))?;

        Ok(())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // -- challenge_tokens_key -----------------------------------------------

    #[test]
    fn challenge_tokens_key_no_prefix() {
        let key = challenge_tokens_key("", "example.com");
        assert_eq!(key, "challenge_tokens/example.com.json");
    }

    #[test]
    fn challenge_tokens_key_with_prefix() {
        let key = challenge_tokens_key("acme/ca", "example.com");
        assert_eq!(key, "acme/ca/challenge_tokens/example.com.json");
    }

    #[test]
    fn challenge_tokens_key_sanitizes() {
        let key = challenge_tokens_key("", "*.Example.COM");
        // safe_key lowercases, replaces * with wildcard_
        assert!(key.contains("wildcard_"));
    }

    // -- Http01Solver -------------------------------------------------------

    #[test]
    fn http01_solver_default_port() {
        let solver = Http01Solver::default();
        assert_eq!(solver.port, 80);
    }

    #[test]
    fn http01_solver_custom_port() {
        let solver = Http01Solver::new(8080);
        assert_eq!(solver.port, 8080);
    }

    // -- TlsAlpn01Solver ---------------------------------------------------

    #[test]
    fn tls_alpn01_solver_default_port() {
        let solver = TlsAlpn01Solver::default();
        assert_eq!(solver.port, 443);
    }

    #[test]
    fn tls_alpn01_generate_challenge_cert() {
        // Verify that generating a challenge cert succeeds and produces valid
        // output.
        let (certs, key) = TlsAlpn01Solver::generate_challenge_cert(
            "example.com",
            "token.thumbprint",
        )
        .unwrap();
        assert_eq!(certs.len(), 1);
        assert!(!certs[0].as_ref().is_empty());
        match &key {
            PrivateKeyDer::Pkcs8(der) => {
                assert!(!der.secret_pkcs8_der().is_empty());
            }
            _ => panic!("expected PKCS#8 key"),
        }
    }

    // -- Dns01Solver --------------------------------------------------------

    /// A mock DNS provider that counts calls.
    struct MockDnsProvider {
        set_count: AtomicUsize,
        delete_count: AtomicUsize,
    }

    impl MockDnsProvider {
        fn new() -> Self {
            Self {
                set_count: AtomicUsize::new(0),
                delete_count: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl DnsProvider for MockDnsProvider {
        async fn set_record(
            &self,
            _zone: &str,
            _name: &str,
            _value: &str,
            _ttl: u32,
        ) -> Result<()> {
            self.set_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn delete_record(
            &self,
            _zone: &str,
            _name: &str,
            _value: &str,
        ) -> Result<()> {
            self.delete_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn dns01_solver_default_timeouts() {
        let provider = MockDnsProvider::new();
        let solver = Dns01Solver::new(Box::new(provider));
        assert_eq!(solver.propagation_timeout, DEFAULT_PROPAGATION_TIMEOUT);
        assert_eq!(
            solver.propagation_check_interval,
            DEFAULT_PROPAGATION_INTERVAL
        );
        assert_eq!(solver.ttl, 120);
    }

    #[test]
    fn dns01_solver_dns_name_default() {
        let provider = MockDnsProvider::new();
        let solver = Dns01Solver::new(Box::new(provider));
        let name = solver.dns_name("example.com");
        assert_eq!(name, "_acme-challenge.example.com.");
    }

    #[test]
    fn dns01_solver_dns_name_override() {
        let provider = MockDnsProvider::new();
        let mut solver = Dns01Solver::new(Box::new(provider));
        solver.override_domain = Some("delegated.example.net.".to_string());
        let name = solver.dns_name("example.com");
        assert_eq!(name, "delegated.example.net.");
    }

    #[tokio::test]
    async fn dns01_present_and_cleanup() {
        let provider = Arc::new(MockDnsProvider::new());
        let provider_ref = Arc::clone(&provider);

        let solver = Dns01Solver::new(Box::new(MockDnsProviderWrapper(provider_ref)));

        solver
            .present("example.com", "token", "key_auth")
            .await
            .unwrap();

        // Verify the record was remembered.
        {
            let records = solver.records.read().await;
            assert_eq!(records.len(), 1);
        }

        solver
            .cleanup("example.com", "token", "key_auth")
            .await
            .unwrap();

        // Record should be cleaned up.
        {
            let records = solver.records.read().await;
            assert!(records.is_empty());
        }

        assert_eq!(provider.set_count.load(Ordering::SeqCst), 1);
        assert_eq!(provider.delete_count.load(Ordering::SeqCst), 1);
    }

    /// Wrapper to allow using Arc<MockDnsProvider> as Box<dyn DnsProvider>.
    struct MockDnsProviderWrapper(Arc<MockDnsProvider>);

    #[async_trait]
    impl DnsProvider for MockDnsProviderWrapper {
        async fn set_record(
            &self,
            zone: &str,
            name: &str,
            value: &str,
            ttl: u32,
        ) -> Result<()> {
            self.0.set_record(zone, name, value, ttl).await
        }
        async fn delete_record(
            &self,
            zone: &str,
            name: &str,
            value: &str,
        ) -> Result<()> {
            self.0.delete_record(zone, name, value).await
        }
    }
}
