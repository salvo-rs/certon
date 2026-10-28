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
//! | `Dns01Solver` | n/a | Creates a `_acme-challenge` TXT record via a `DnsProvider` |
//!
//! # Distributed deployments
//!
//! In a cluster, wrap any solver with [`DistributedSolver`] so that challenge
//! data is persisted to shared [`Storage`]. This
//! allows any cluster member to respond to the CA's validation request, not
//! just the instance that initiated the certificate order.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock, RwLock as SyncRwLock};
use std::time::Duration;

use async_trait::async_trait;
#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs as crypto_provider;
use crypto_provider::rand::SystemRandom;
use crypto_provider::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
use rcgen::{CertificateParams, CustomExtension, KeyPair as RcgenKeyPair, PKCS_ECDSA_P256_SHA256};
#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
use ring as crypto_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use tracing::{debug, warn};

#[cfg(feature = "dns-01")]
use crate::dns_util::{
    DEFAULT_PROPAGATION_INTERVAL, DEFAULT_PROPAGATION_TIMEOUT, challenge_record_name,
    challenge_record_value, check_dns_propagation_with_resolvers, find_zone_by_fqdn, from_fqdn,
};
use crate::error::{Error, Result};
use crate::storage::Storage;

/// Prebuilt challenge signing keys shared by every connection.
type ChallengeMap = Arc<SyncRwLock<HashMap<String, Arc<rustls::sign::CertifiedKey>>>>;

#[derive(Clone, Copy)]
struct ChallengeLimits {
    max_connections: usize,
    connection_timeout: Duration,
}

impl Default for ChallengeLimits {
    fn default() -> Self {
        Self {
            max_connections: 128,
            connection_timeout: Duration::from_secs(10),
        }
    }
}

impl ChallengeLimits {
    fn checked(max_connections: usize, connection_timeout: Duration) -> Result<Self> {
        if max_connections == 0
            || connection_timeout.is_zero()
            || Instant::now().checked_add(connection_timeout).is_none()
        {
            return Err(Error::Config("invalid challenge server limits".into()));
        }
        Ok(Self {
            max_connections,
            connection_timeout,
        })
    }
}

/// The listener owns every accepted connection. Stopping it aborts and joins
/// all workers before its completion is acknowledged. Drop requests the same
/// shutdown; synchronous destructors cannot wait for the runtime to drain it.
struct ChallengeServer {
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl ChallengeServer {
    fn spawn<F, Fut>(listener: TcpListener, limits: ChallengeLimits, handler: F) -> Self
    where
        F: FnMut(TcpStream, SocketAddr) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let listener = Arc::new(listener);
        Self::spawn_with_accept(
            move || {
                let listener = Arc::clone(&listener);
                async move { listener.accept().await }
            },
            limits,
            handler,
        )
    }

    fn spawn_with_accept<A, Accepted, F, Fut>(
        mut accept: A,
        limits: ChallengeLimits,
        mut handler: F,
    ) -> Self
    where
        A: FnMut() -> Accepted + Send + 'static,
        Accepted: Future<Output = std::io::Result<(TcpStream, SocketAddr)>> + Send,
        F: FnMut(TcpStream, SocketAddr) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut workers = JoinSet::new();
            let mut retry_at = None;
            loop {
                tokio::select! {
                    biased;
                    _ = &mut stopped => break,
                    _ = workers.join_next(), if !workers.is_empty() => {},
                    accepted = async {
                        if let Some(retry_at) = retry_at {
                            tokio::time::sleep_until(retry_at).await;
                        }
                        accept().await
                    }, if workers.len() < limits.max_connections => {
                        let (stream, peer) = match accepted {
                            Ok(connection) => connection,
                            Err(error) => {
                                warn!(%error, "challenge listener accept failed; retrying");
                                retry_at = Some(Instant::now() + Duration::from_millis(100));
                                continue;
                            }
                        };
                        retry_at = None;
                        let deadline = Instant::now() + limits.connection_timeout;
                        let connection = handler(stream, peer);
                        workers.spawn(async move {
                            let _ = tokio::time::timeout_at(deadline, connection).await;
                        });
                    }
                }
            }
            drop(accept);
            workers.shutdown().await;
        });
        Self {
            stop: Some(stop),
            task,
        }
    }

    fn request_stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }

    fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    #[cfg(test)]
    fn id(&self) -> tokio::task::Id {
        self.task.id()
    }
}

impl Drop for ChallengeServer {
    fn drop(&mut self) {
        self.request_stop();
    }
}

// Retain the handle in its slot while awaiting. If a cleanup future is
// cancelled, the next publication still observes the stopping generation and
// waits for its listener and all accepted sockets to be released before bind.
async fn stop_challenge_server(handle: &mut Option<ChallengeServer>) {
    if let Some(server) = handle.as_mut() {
        server.request_stop();
        let _ = (&mut server.task).await;
    }
    *handle = None;
}

async fn finish_stopped_challenge_server(handle: &mut Option<ChallengeServer>) {
    if handle
        .as_ref()
        .is_some_and(|server| server.stop.is_none() || server.is_finished())
    {
        stop_challenge_server(handle).await;
    }
}

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
async fn register_active_challenge(identifier: &str, key_auth: &str) -> Option<String> {
    active_challenges()
        .write()
        .await
        .insert(identifier.to_string(), key_auth.to_string())
}

async fn restore_active_challenge(identifier: &str, attempted: &str, previous: Option<String>) {
    let mut map = active_challenges().write().await;
    if map.get(identifier).is_some_and(|auth| auth == attempted) {
        if let Some(previous) = previous {
            map.insert(identifier.to_owned(), previous);
        } else {
            map.remove(identifier);
        }
    }
}

/// Remove an active challenge from the global map.
async fn unregister_active_challenge(identifier: &str) {
    let mut map = active_challenges().write().await;
    map.remove(identifier);
}

/// Remove only the authorization owned by this HTTP cleanup operation.
async fn unregister_active_challenge_if_matching(identifier: &str, key_auth: &str) {
    let mut map = active_challenges().write().await;
    if map
        .get(identifier)
        .is_some_and(|current| current == key_auth)
    {
        map.remove(identifier);
    }
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
/// 2. [`Solver::wait`] -- optionally block until the challenge is ready (e.g. DNS propagation).
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

#[cfg(test)]
fn challenge_tokens_key(issuer_prefix: &str, domain: &str) -> String {
    crate::challenge::legacy_key(issuer_prefix, domain)
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
/// It handles at most 128 accepted connections, each with a total 10-second
/// read/write deadline; [`Self::with_limits`] overrides both limits. At capacity
/// peers wait in the operating system's accept backlog. Final cleanup waits for
/// all accepted connections to be released. Dropping the solver requests the
/// same shutdown without blocking for the runtime to finish it.
///
/// **Important**: Port 80 must be reachable from the internet for the ACME
/// CA's validation server to reach this solver.
pub struct Http01Solver {
    /// In-memory map of token -> key_auth for currently active challenges.
    challenges: Arc<RwLock<HashMap<String, String>>>,
    /// The port to listen on (default: 80).
    pub port: u16,
    /// Serializes HTTP challenge publication, cleanup and listener lifetime.
    /// Holds the background HTTP server task while it is running.
    server_handle: Mutex<Option<ChallengeServer>>,
    limits: ChallengeLimits,
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
            limits: ChallengeLimits::default(),
        }
    }

    /// Use a custom accepted-connection budget and total connection timeout.
    /// Defaults are 128 connections and 10 seconds. At capacity, new peers wait
    /// in the operating system's accept backlog. Zero values or a timeout that
    /// exceeds the monotonic clock range return a configuration error.
    pub fn with_limits(
        port: u16,
        max_connections: usize,
        connection_timeout: Duration,
    ) -> Result<Self> {
        let limits = ChallengeLimits::checked(max_connections, connection_timeout)?;
        Ok(Self {
            limits,
            ..Self::new(port)
        })
    }

    /// Start the challenge HTTP server if it is not already running.
    ///
    /// If binding the TCP listener fails with "address already in use", the
    /// method retries once after 100ms. If binding still fails, a warning is
    /// logged and `Ok(())` is returned under the assumption that an existing
    /// listener (e.g. from a previous solver or external process) can handle
    /// the challenge requests.
    async fn ensure_server_running(&self, handle: &mut Option<ChallengeServer>) -> Result<()> {
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
        *handle = Some(ChallengeServer::spawn(
            listener,
            self.limits,
            move |stream, peer| serve_http_challenge(stream, peer, Arc::clone(&challenges)),
        ));
        Ok(())
    }
}

async fn serve_http_challenge<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut stream: S,
    peer: SocketAddr,
    challenges: Arc<RwLock<HashMap<String, String>>>,
) {
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
        let key_auth = challenges.read().await.get(token).cloned();
        if let Some(key_auth) = key_auth {
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
        let mut handle = self.server_handle.lock().await;
        finish_stopped_challenge_server(&mut handle).await;
        let previous = self
            .challenges
            .write()
            .await
            .insert(token.to_owned(), key_auth.to_owned());
        let previous_global = register_active_challenge(token, key_auth).await;
        if let Err(error) = self.ensure_server_running(&mut handle).await {
            let mut challenges = self.challenges.write().await;
            if let Some(previous) = previous {
                challenges.insert(token.to_owned(), previous);
            } else {
                challenges.remove(token);
            }
            drop(challenges);
            restore_active_challenge(token, key_auth, previous_global).await;
            return Err(error);
        }
        debug!(token, "HTTP-01 challenge presented");
        Ok(())
    }

    async fn cleanup(&self, _domain: &str, token: &str, key_auth: &str) -> Result<()> {
        let mut handle = self.server_handle.lock().await;
        let should_stop = {
            let mut challenges = self.challenges.write().await;
            if challenges
                .get(token)
                .is_some_and(|current| current == key_auth)
            {
                challenges.remove(token);
            }
            challenges.is_empty()
        };
        unregister_active_challenge_if_matching(token, key_auth).await;

        if should_stop {
            stop_challenge_server(&mut handle).await;
            debug!("HTTP-01 challenge server stopped (no more challenges)");
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
/// The default budget is 128 accepted connections with a total 10-second
/// handshake deadline; [`Self::with_limits`] overrides both values. Final
/// cleanup awaits every accepted connection. Drop requests shutdown without
/// synchronously waiting for the runtime to release those connections.
///
/// **Important**: Port 443 must be reachable from the internet, and the
/// client's SNI value must match the domain being validated.
pub struct TlsAlpn01Solver {
    /// In-memory map of domain -> (cert chain DER, private key DER) for
    /// currently active challenges.
    challenges: ChallengeMap,
    /// The port to listen on (default: 443).
    pub port: u16,
    /// Handle to the background TLS server task, if running.
    server_handle: Mutex<Option<ChallengeServer>>,
    limits: ChallengeLimits,
}

impl TlsAlpn01Solver {
    /// Create a new TLS-ALPN-01 solver that will listen on the given port.
    ///
    /// The server is not started until [`Solver::present`] is called for
    /// the first time.
    pub fn new(port: u16) -> Self {
        Self {
            challenges: Arc::new(SyncRwLock::new(HashMap::new())),
            port,
            server_handle: Mutex::new(None),
            limits: ChallengeLimits::default(),
        }
    }

    /// Use a custom accepted-connection budget and total connection timeout.
    /// Defaults are 128 connections and 10 seconds. At capacity, new peers wait
    /// in the operating system's accept backlog. Zero values or a timeout that
    /// exceeds the monotonic clock range return a configuration error.
    pub fn with_limits(
        port: u16,
        max_connections: usize,
        connection_timeout: Duration,
    ) -> Result<Self> {
        let limits = ChallengeLimits::checked(max_connections, connection_timeout)?;
        Ok(Self {
            limits,
            ..Self::new(port)
        })
    }

    /// Generate a self-signed challenge certificate for the TLS-ALPN-01
    /// challenge.
    ///
    /// The certificate contains:
    /// - A single SAN matching `domain`
    /// - The `acmeIdentifier` extension (OID 1.3.6.1.5.5.7.1.31) containing the DER-encoded ASN.1
    ///   value: `OCTET STRING { SHA-256(key_auth) }`
    /// - Marked as critical per RFC 8737
    fn generate_challenge_cert(
        domain: &str,
        key_auth: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        // Generate an ephemeral ECDSA P-256 key for the challenge certificate.
        let rng = SystemRandom::new();
        let pkcs8_doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|e| {
                Error::Other(format!(
                    "failed to generate ephemeral key for TLS-ALPN-01: {e}"
                ))
            })?;
        let pkcs8_bytes = pkcs8_doc.as_ref().to_vec();

        let key_pair = RcgenKeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(pkcs8_bytes.clone()),
            &PKCS_ECDSA_P256_SHA256,
        )
        .map_err(|e| Error::Other(format!("failed to create rcgen key pair: {e}")))?;

        let mut params = CertificateParams::new(vec![domain.to_string()])
            .map_err(|e| Error::Other(format!("failed to create certificate params: {e}")))?;

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
    async fn ensure_server_running(&self, handle: &mut Option<ChallengeServer>) -> Result<()> {
        if handle.is_some() {
            return Ok(());
        }
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr).await.map_err(|e| {
            Error::Other(format!(
                "failed to bind TLS-ALPN-01 challenge server on {addr}: {e}"
            ))
        })?;
        let resolver = ChallengeCertResolver {
            challenges: Arc::clone(&self.challenges),
        };
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        config.alpn_protocols = vec![ACME_TLS_ALPN_PROTOCOL.to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        *handle = Some(ChallengeServer::spawn(
            listener,
            self.limits,
            move |stream, peer| {
                let acceptor = acceptor.clone();
                async move {
                    match acceptor.accept(stream).await {
                        Ok(_) => debug!(%peer, "TLS-ALPN-01 handshake completed"),
                        Err(error) => debug!(%peer, %error, "TLS-ALPN-01 handshake failed"),
                    }
                }
            },
        ));
        debug!(%addr, "TLS-ALPN-01 challenge server started");
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
        let (certs, key_der) = Self::generate_challenge_cert(domain, key_auth)?;
        let key = crate::handshake::signing_key_from_der(&key_der)
            .map_err(|e| Error::Other(format!("failed to load challenge signing key: {e}")))?;
        let prepared = Arc::new(rustls::sign::CertifiedKey::new(certs, key));
        let mut handle = self.server_handle.lock().await;
        finish_stopped_challenge_server(&mut handle).await;
        let previous = self
            .challenges
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(domain.to_owned(), prepared);
        let previous_global = register_active_challenge(domain, key_auth).await;
        if let Err(error) = self.ensure_server_running(&mut handle).await {
            {
                let mut challenges = self.challenges.write().unwrap_or_else(|e| e.into_inner());
                if let Some(previous) = previous {
                    challenges.insert(domain.to_owned(), previous);
                } else {
                    challenges.remove(domain);
                }
            }
            restore_active_challenge(domain, key_auth, previous_global).await;
            return Err(error);
        }
        debug!(domain, "TLS-ALPN-01 challenge presented");
        Ok(())
    }

    async fn cleanup(&self, domain: &str, _token: &str, _key_auth: &str) -> Result<()> {
        let mut handle = self.server_handle.lock().await;
        let should_stop = {
            let mut challenges = self.challenges.write().unwrap_or_else(|e| e.into_inner());
            challenges.remove(domain);
            challenges.is_empty()
        };
        unregister_active_challenge(domain).await;
        if should_stop {
            stop_challenge_server(&mut handle).await;
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
    challenges: ChallengeMap,
}

impl rustls::server::ResolvesServerCert for ChallengeCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni = client_hello.server_name()?;

        let challenges = self.challenges.read().unwrap_or_else(|e| e.into_inner());
        let key = challenges.get(sni)?;
        key.key.choose_scheme(client_hello.signature_schemes())?;
        Some(Arc::clone(key))
    }
}

// ===========================================================================
// DNS-01 Solver
// ===========================================================================
//
// Behind the `dns-01` feature: this is the only challenge type that needs a
// DNS resolver, and a resolver is the largest dependency certon has.

/// Abstraction over a DNS provider that can create and delete TXT records.
///
/// Implementations should be able to create and delete TXT records for
/// ACME DNS-01 challenges.
///
/// Implementations should be idempotent: calling [`DnsProvider::set_record`]
/// twice with the same arguments should not create duplicate records, and
/// calling [`DnsProvider::delete_record`] for a non-existent record should
/// not fail.
#[cfg(feature = "dns-01")]
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Create (or append) a TXT record in the given DNS zone.
    ///
    /// - `zone`: the DNS zone (e.g. `"example.com."`)
    /// - `name`: the relative record name within the zone (e.g. `"_acme-challenge"`)
    /// - `value`: the TXT record value
    /// - `ttl`: the record TTL in seconds
    async fn set_record(&self, zone: &str, name: &str, value: &str, ttl: u32) -> Result<()>;

    /// Delete a TXT record matching `name` and `value` from the given zone.
    async fn delete_record(&self, zone: &str, name: &str, value: &str) -> Result<()>;
}

/// Solves ACME DNS-01 challenges by creating a TXT record via a
/// `DnsProvider` implementation and optionally waiting for propagation.
///
/// The DNS-01 challenge is the only challenge type that supports wildcard
/// certificates. It works by placing a TXT record at
/// `_acme-challenge.<domain>` containing a base64url-encoded SHA-256 digest
/// of the key authorization.
///
/// After presenting the record, the solver's [`Solver::wait`] implementation
/// polls DNS resolvers until the record propagates or the timeout is reached.
#[cfg(feature = "dns-01")]
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
#[cfg(feature = "dns-01")]
#[derive(Clone)]
struct DnsRecordMemory {
    zone: String,
    relative_name: String,
    value: String,
}

#[cfg(feature = "dns-01")]
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

#[cfg(feature = "dns-01")]
impl std::fmt::Debug for Dns01Solver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dns01Solver")
            .field("propagation_timeout", &self.propagation_timeout)
            .field(
                "propagation_check_interval",
                &self.propagation_check_interval,
            )
            .field("propagation_delay", &self.propagation_delay)
            .field("ttl", &self.ttl)
            .field("override_domain", &self.override_domain)
            .field("resolvers", &self.resolvers)
            .finish()
    }
}

#[cfg(feature = "dns-01")]
#[async_trait]
impl Solver for Dns01Solver {
    async fn present(&self, domain: &str, _token: &str, key_auth: &str) -> Result<()> {
        let dns_name = self.dns_name(domain);
        let txt_value = challenge_record_value(key_auth);

        // Determine the zone for this domain.
        let zone = find_zone_by_fqdn(&dns_name)
            .ok_or_else(|| Error::Other(format!("could not determine DNS zone for {dns_name}")))?;

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

        // Remember the intended record before contacting the provider: a
        // cancelled request may already have created the remote TXT record.
        let memory = DnsRecordMemory {
            zone: zone.clone(),
            relative_name: relative_name.clone(),
            value: txt_value.clone(),
        };
        {
            let mut records = self.records.write().await;
            records.insert((dns_name, txt_value.clone()), memory);
        }

        self.provider
            .set_record(&zone, &relative_name, &txt_value, self.ttl)
            .await?;

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

        check_dns_propagation_with_resolvers(
            &fqdn,
            &txt_value,
            self.propagation_timeout,
            self.propagation_check_interval,
            self.resolvers.as_deref(),
        )
        .await?;

        Ok(())
    }

    async fn cleanup(&self, domain: &str, _token: &str, key_auth: &str) -> Result<()> {
        let dns_name = self.dns_name(domain);
        let txt_value = challenge_record_value(key_auth);

        let memory = {
            let records = self.records.read().await;
            records.get(&(dns_name.clone(), txt_value.clone())).cloned()
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
            // Retain the intent while deletion is in flight so cancellation
            // cleanup can retry an interrupted provider request.
            self.records.write().await.remove(&(dns_name, txt_value));
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
    /// `"<prefix>/challenge_tokens/v2/<domain-hash>/<token-hash>.json"`.
    /// Each entry binds the exact token to its canonical domain.
    pub fn with_prefix(inner: Box<dyn Solver>, storage: Arc<dyn Storage>, prefix: String) -> Self {
        Self {
            inner,
            storage,
            storage_key_issuer_prefix: prefix,
        }
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
        let canonical = crate::challenge::domain(domain)?;
        let data = crate::challenge::encode(&canonical, token, key_auth)?;
        let key = crate::challenge::key(&self.storage_key_issuer_prefix, &canonical, token);
        let _guard =
            crate::storage::acquire(self.storage.clone(), &crate::challenge::lock_key(&key))
                .await?;
        self.storage.store(&key, &data).await?;
        self.inner.present(domain, token, key_auth).await
    }

    async fn wait(&self, domain: &str, token: &str, key_auth: &str) -> Result<()> {
        self.inner.wait(domain, token, key_auth).await
    }

    async fn cleanup(&self, domain: &str, token: &str, key_auth: &str) -> Result<()> {
        let canonical = crate::challenge::domain(domain)?;
        crate::challenge::validate_auth(token, key_auth)?;
        let storage_result: Result<()> = async {
            let key = crate::challenge::key(&self.storage_key_issuer_prefix, &canonical, token);
            let _guard =
                crate::storage::acquire(self.storage.clone(), &crate::challenge::lock_key(&key))
                    .await?;
            // Retire legacy entries under a separate shared domain lock. New writers
            // never update the old map, so different v2 tokens remain independent.
            let legacy = crate::challenge::legacy_key(&self.storage_key_issuer_prefix, &canonical);
            let legacy_compatible = crate::challenge::legacy_compatible(&canonical);
            let _legacy_guard = if legacy_compatible {
                Some(
                    crate::storage::acquire(
                        self.storage.clone(),
                        &crate::challenge::lock_key(&legacy),
                    )
                    .await?,
                )
            } else {
                None
            };
            let current = crate::challenge::load(
                self.storage.as_ref(),
                &self.storage_key_issuer_prefix,
                &canonical,
                token,
            )
            .await?;
            if legacy_compatible {
                match self.storage.load(&legacy).await {
                    Ok(data) => {
                        let mut map = crate::challenge::legacy_map(&data)?;
                        if current.as_deref() == Some(key_auth)
                            || map.get(token).is_some_and(|auth| auth == key_auth)
                        {
                            map.remove(token);
                            if map.is_empty() {
                                self.storage.delete(&legacy).await?;
                            } else {
                                self.storage
                                    .store(
                                        &legacy,
                                        &serde_json::to_vec(&map)
                                            .map_err(|e| Error::Other(e.to_string()))?,
                                    )
                                    .await?;
                            }
                        }
                    }
                    Err(Error::Storage(crate::error::StorageError::NotFound(_))) => {}
                    Err(e) => return Err(e),
                }
            }
            if current.as_deref() == Some(key_auth) {
                match self.storage.delete(&key).await {
                    Ok(()) | Err(Error::Storage(crate::error::StorageError::NotFound(_))) => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }
        .await;
        let inner_result = self.inner.cleanup(domain, token, key_auth).await;
        storage_result.and(inner_result)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    #[cfg(feature = "dns-01")]
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

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

    #[tokio::test]
    async fn challenge_accept_error_backs_off_then_serves_a_real_peer() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let address = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        tokio::time::pause();
        let runnable = tokio::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        });
        let mut server = Some(ChallengeServer::spawn_with_accept(
            {
                let calls = calls.clone();
                move || {
                    let listener = listener.clone();
                    let attempt = calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if attempt == 0 {
                            Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted))
                        } else {
                            listener.accept().await
                        }
                    }
                }
            },
            ChallengeLimits::default(),
            |mut stream, _| async move {
                let mut byte = [0];
                stream.read_exact(&mut byte).await.unwrap();
                stream.write_all(&byte).await.unwrap();
            },
        ));
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        let mut peer = TcpStream::connect(address).await.unwrap();
        peer.write_all(b"x").await.unwrap();
        tokio::time::advance(Duration::from_millis(50)).await;
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "accept failures must not form a hot loop"
        );
        tokio::time::advance(Duration::from_millis(50)).await;
        tokio::time::resume();
        runnable.abort();
        let mut reply = [0];
        tokio::time::timeout(Duration::from_secs(2), peer.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"x");
        assert!(calls.load(Ordering::SeqCst) >= 2);
        stop_challenge_server(&mut server).await;
    }

    #[tokio::test]
    async fn challenge_deadline_includes_a_blocked_http_response_write() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let challenges = Arc::new(RwLock::new(HashMap::from([
            ("blocked".to_owned(), "blocked.thumb".to_owned()),
            ("fast".to_owned(), "ok".to_owned()),
        ])));
        tokio::time::pause();
        let runnable = tokio::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        });
        let (mut stalled, controlled_server) = tokio::io::duplex(16);
        let mut first = Some(controlled_server);
        let mut server = Some(ChallengeServer::spawn(
            listener,
            ChallengeLimits::checked(1, Duration::from_secs(10)).unwrap(),
            move |stream, peer| {
                let first = first.take();
                let challenges = challenges.clone();
                async move {
                    if let Some(controlled) = first {
                        // Retain the real accepted socket and its budget while
                        // the actual HTTP handler writes to a deterministic
                        // 16-byte transport instead of an OS-sized buffer.
                        serve_http_challenge(controlled, peer, challenges).await;
                        drop(stream);
                    } else {
                        serve_http_challenge(stream, peer, challenges).await;
                    }
                }
            },
        ));
        let _accepted = TcpStream::connect(address).await.unwrap();
        stalled
            .write_all(
                b"GET /.well-known/acme-challenge/blocked HTTP/1.1\r\nHost: example.com\r\n\r\n",
            )
            .await
            .unwrap();
        let mut byte = [0];
        stalled.read_exact(&mut byte).await.unwrap();
        assert_eq!(&byte, b"H", "prove the response write has started");
        let fast = tokio::spawn(async move {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream
                .write_all(
                    b"GET /.well-known/acme-challenge/fast HTTP/1.1\r\nHost: example.com\r\n\r\n",
                )
                .await
                .unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).await.unwrap();
            reply
        });
        tokio::time::advance(Duration::from_secs(9)).await;
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert!(
            !fast.is_finished(),
            "the unread response still owns the only connection slot"
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::time::resume();
        runnable.abort();
        let reply = tokio::time::timeout(Duration::from_secs(5), fast)
            .await
            .expect("a blocked writer starved the next challenge")
            .unwrap();
        assert!(reply.starts_with("HTTP/1.1 200"));
        assert!(reply.ends_with("ok"));
        stop_challenge_server(&mut server).await;
    }

    #[tokio::test]
    async fn dropping_an_unpolled_challenge_server_releases_its_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = ChallengeServer::spawn(listener, ChallengeLimits::default(), |_, _| async {});
        drop(server);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match TcpListener::bind(address).await {
                    Ok(_) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                        tokio::task::yield_now().await
                    }
                    Err(error) => panic!("unexpected bind failure: {error}"),
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_cleanup_keeps_the_stopping_generation_until_a_new_present_can_bind() {
        struct Release(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
        impl Release {
            fn open(&self) {
                *self.0.0.lock().unwrap() = true;
                self.0.1.notify_all();
            }
        }
        impl Drop for Release {
            fn drop(&mut self) {
                self.open();
            }
        }
        struct BlockOnDrop {
            entered: Arc<tokio::sync::Notify>,
            release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
        }
        impl Drop for BlockOnDrop {
            fn drop(&mut self) {
                self.entered.notify_one();
                let mut released = self.release.0.lock().unwrap();
                while !*released {
                    released = self.release.1.wait(released).unwrap();
                }
            }
        }
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let address = listener.local_addr().unwrap();
        let solver = Arc::new(Http01Solver::new(address.port()));
        solver
            .challenges
            .write()
            .await
            .insert("cancelled-old".into(), "old.thumb".into());
        register_active_challenge("cancelled-old", "old.thumb").await;
        let accepting_second = Arc::new(tokio::sync::Notify::new());
        let dropping_accept = Arc::new(tokio::sync::Notify::new());
        let release = Release(Arc::new((
            std::sync::Mutex::new(false),
            std::sync::Condvar::new(),
        )));
        let calls = Arc::new(AtomicUsize::new(0));
        *solver.server_handle.lock().await = Some(ChallengeServer::spawn_with_accept(
            {
                let accepting_second = accepting_second.clone();
                let dropping_accept = dropping_accept.clone();
                let release = release.0.clone();
                move || {
                    let listener = listener.clone();
                    let attempt = calls.fetch_add(1, Ordering::SeqCst);
                    let accepting_second = accepting_second.clone();
                    let entered = dropping_accept.clone();
                    let release = release.clone();
                    async move {
                        let _drop = if attempt == 1 {
                            accepting_second.notify_one();
                            Some(BlockOnDrop { entered, release })
                        } else {
                            None
                        };
                        listener.accept().await
                    }
                }
            },
            ChallengeLimits::default(),
            |mut stream, _| async move {
                let mut byte = [0];
                let _ = stream.read(&mut byte).await;
            },
        ));
        let mut peer = TcpStream::connect(address).await.unwrap();
        accepting_second.notified().await;
        let cleanup = tokio::spawn({
            let solver = solver.clone();
            async move {
                solver
                    .cleanup("example.com", "cancelled-old", "old.thumb")
                    .await
            }
        });
        dropping_accept.notified().await;
        cleanup.abort();
        let _ = cleanup.await;
        assert!(
            solver
                .server_handle
                .lock()
                .await
                .as_ref()
                .unwrap()
                .stop
                .is_none()
        );
        let mut present = Box::pin(solver.present("example.com", "cancelled-new", "new.thumb"));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(present.as_mut().poll(&mut context).is_pending());
        assert!(!solver.challenges.read().await.contains_key("cancelled-new"));
        release.open();
        tokio::time::timeout(Duration::from_secs(2), present)
            .await
            .unwrap()
            .unwrap();
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), peer.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        let mut peer = TcpStream::connect(address).await.unwrap();
        peer.write_all(
            b"GET /.well-known/acme-challenge/cancelled-new HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .await
        .unwrap();
        let mut response = String::new();
        peer.read_to_string(&mut response).await.unwrap();
        assert!(response.ends_with("new.thumb"));
        solver
            .cleanup("example.com", "cancelled-new", "new.thumb")
            .await
            .unwrap();
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

    #[tokio::test]
    async fn http01_stale_cleanup_preserves_new_local_authorization_and_listener() {
        let solver = Http01Solver::new(0);
        let token = "http-local-stale-cleanup";
        solver
            .present("example.com", token, "old-auth")
            .await
            .unwrap();
        let original_task = solver.server_handle.lock().await.as_ref().unwrap().id();
        solver
            .present("example.com", token, "new-auth")
            .await
            .unwrap();
        solver
            .cleanup("example.com", token, "old-auth")
            .await
            .unwrap();
        assert_eq!(
            solver
                .challenges
                .read()
                .await
                .get(token)
                .map(String::as_str),
            Some("new-auth")
        );
        assert_eq!(
            active_challenges()
                .read()
                .await
                .get(token)
                .map(String::as_str),
            Some("new-auth")
        );
        let handle = solver.server_handle.lock().await;
        let task = handle
            .as_ref()
            .expect("new challenge must keep its listener");
        assert_eq!(task.id(), original_task);
        assert!(!task.is_finished());
        drop(handle);
        solver
            .cleanup("example.com", token, "new-auth")
            .await
            .unwrap();
        assert!(solver.server_handle.lock().await.is_none());
        assert!(!active_challenges().read().await.contains_key(token));
    }

    #[tokio::test]
    async fn http01_cleanup_of_another_solver_preserves_new_global_registration() {
        let old = Http01Solver::new(0);
        let new = Http01Solver::new(0);
        let token = "http-global-stale-cleanup";
        old.present("example.com", token, "old-auth").await.unwrap();
        new.present("example.com", token, "new-auth").await.unwrap();
        old.cleanup("example.com", token, "old-auth").await.unwrap();
        assert_eq!(
            active_challenges()
                .read()
                .await
                .get(token)
                .map(String::as_str),
            Some("new-auth")
        );
        assert!(old.server_handle.lock().await.is_none());
        assert!(new.server_handle.lock().await.is_some());
        new.cleanup("example.com", token, "new-auth").await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http01_concurrent_last_cleanup_and_present_keep_new_listener() {
        let solver = Arc::new(Http01Solver::new(0));
        for iteration in 0..32 {
            let old = format!("http-lifetime-old-{iteration}");
            let new = format!("http-lifetime-new-{iteration}");
            solver
                .present("example.com", &old, "old-auth")
                .await
                .unwrap();
            let barrier = Arc::new(tokio::sync::Barrier::new(3));
            let cleanup = {
                let solver = solver.clone();
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    solver
                        .cleanup("example.com", &old, "old-auth")
                        .await
                        .unwrap();
                })
            };
            let present = {
                let solver = solver.clone();
                let barrier = barrier.clone();
                let new = new.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    solver
                        .present("example.com", &new, "new-auth")
                        .await
                        .unwrap();
                })
            };
            barrier.wait().await;
            cleanup.await.unwrap();
            present.await.unwrap();
            assert_eq!(
                solver.challenges.read().await.get(&new).map(String::as_str),
                Some("new-auth")
            );
            assert!(
                !solver
                    .server_handle
                    .lock()
                    .await
                    .as_ref()
                    .expect("new challenge requires a listener")
                    .is_finished()
            );
            solver
                .cleanup("example.com", &new, "new-auth")
                .await
                .unwrap();
        }
    }

    // -- TlsAlpn01Solver ---------------------------------------------------

    #[tokio::test]
    async fn tls_bind_failure_rolls_back_only_its_attempted_challenge() {
        crate::install_default_crypto_provider();
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let original = TlsAlpn01Solver::new(port);
        let failed = TlsAlpn01Solver::new(port);
        let domain = "tls-bind-rollback.example";
        original.present(domain, "old", "old.thumb").await.unwrap();
        let original_key = original.challenges.read().unwrap()[domain].clone();
        assert!(failed.present(domain, "new", "new.thumb").await.is_err());
        assert!(failed.challenges.read().unwrap().is_empty());
        assert!(failed.server_handle.lock().await.is_none());
        assert!(Arc::ptr_eq(
            &original_key,
            &original.challenges.read().unwrap()[domain]
        ));
        assert_eq!(
            active_challenges()
                .read()
                .await
                .get(domain)
                .map(String::as_str),
            Some("old.thumb")
        );
        assert!(
            !original
                .server_handle
                .lock()
                .await
                .as_ref()
                .unwrap()
                .is_finished()
        );
        original.cleanup(domain, "old", "old.thumb").await.unwrap();
    }

    #[test]
    fn tls_alpn01_solver_default_port() {
        let solver = TlsAlpn01Solver::default();
        assert_eq!(solver.port, 443);
    }

    #[test]
    fn tls_alpn01_generate_challenge_cert() {
        // Verify that generating a challenge cert succeeds and produces valid
        // output.
        let (certs, key) =
            TlsAlpn01Solver::generate_challenge_cert("example.com", "token.thumbprint").unwrap();
        assert_eq!(certs.len(), 1);
        assert!(!certs[0].as_ref().is_empty());
        match &key {
            PrivateKeyDer::Pkcs8(der) => {
                assert!(!der.secret_pkcs8_der().is_empty());
            }
            _ => panic!("expected PKCS#8 key"),
        }
    }

    // Behind the same feature as the solver they exercise.
    #[cfg(feature = "dns-01")]
    mod dns01 {
        use super::*;

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

            async fn delete_record(&self, _zone: &str, _name: &str, _value: &str) -> Result<()> {
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
            async fn delete_record(&self, zone: &str, name: &str, value: &str) -> Result<()> {
                self.0.delete_record(zone, name, value).await
            }
        }
    }
}
