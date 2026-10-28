//! Bounded TLS acceptance for the convenience listener API.

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

type Accepted = (TlsStream<TcpStream>, SocketAddr);

/// Admission and total handshake deadline for [`BoundTlsListener::accept`].
#[derive(Clone, Copy, Debug)]
pub struct TlsListenerLimits {
    /// Maximum admitted handshakes, including completed results awaiting delivery.
    pub max_handshakes: usize,
    /// Deadline starting when the TCP connection is accepted.
    pub handshake_timeout: Duration,
}

impl Default for TlsListenerLimits {
    fn default() -> Self {
        Self {
            max_handshakes: 256,
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

/// A bound TCP listener and its TLS acceptor, with owned handshake workers.
///
/// [`Self::accept`] drives multiple handshakes concurrently, so a peer that
/// does not send a ClientHello cannot block all subsequent connections. Failed
/// or timed-out handshakes are skipped. The limits apply to this convenience
/// method; direct use of the public listener/acceptor requires caller limits.
/// Dropping the listener aborts its owned handshake workers.
pub struct BoundTlsListener {
    /// The bound socket, available for custom accept loops.
    pub listener: TcpListener,
    /// TLS configuration for custom accept loops.
    pub acceptor: TlsAcceptor,
    limits: TlsListenerLimits,
    handshakes: Mutex<JoinSet<io::Result<Accepted>>>,
}

impl BoundTlsListener {
    /// Wrap an already-bound socket and acceptor with default limits.
    pub fn new(listener: TcpListener, acceptor: TlsAcceptor) -> Self {
        Self {
            listener,
            acceptor,
            limits: TlsListenerLimits::default(),
            handshakes: Mutex::new(JoinSet::new()),
        }
    }

    /// Wrap a socket with custom limits. Both values must be nonzero, and the
    /// timeout must fit the monotonic clock.
    pub fn with_limits(
        listener: TcpListener,
        acceptor: TlsAcceptor,
        limits: TlsListenerLimits,
    ) -> io::Result<Self> {
        if limits.max_handshakes == 0
            || limits.handshake_timeout.is_zero()
            || Instant::now()
                .checked_add(limits.handshake_timeout)
                .is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TLS listener limits",
            ));
        }
        Ok(Self {
            listener,
            acceptor,
            limits,
            handshakes: Mutex::new(JoinSet::new()),
        })
    }

    /// Return the next connection with a completed TLS handshake.
    ///
    /// TCP accepts and handshake completions progress together. At capacity,
    /// new peers wait in the operating system's accept backlog. TLS failures
    /// and handshake timeouts are logged at debug level and skipped; socket
    /// accept errors are returned to the caller.
    ///
    /// Cancelling this future retains already-admitted handshakes and their
    /// original deadlines for the next call. Concurrent callers share the
    /// same budget. Dropping this object or calling [`Self::into_parts`] aborts
    /// those workers, including completed connections not yet delivered.
    pub async fn accept(&self) -> io::Result<Accepted> {
        let mut handshakes = self.handshakes.lock().await;
        loop {
            tokio::select! {
                biased;
                completed = handshakes.join_next(), if !handshakes.is_empty() => {
                    match completed {
                        Some(Ok(Ok(connection))) => return Ok(connection),
                        Some(Ok(Err(error))) => tracing::debug!(%error, "TLS handshake rejected"),
                        Some(Err(error)) => tracing::debug!(%error, "TLS handshake worker stopped"),
                        None => {}
                    }
                }
                incoming = self.listener.accept(), if handshakes.len() < self.limits.max_handshakes => {
                    let (stream, address) = incoming?;
                    let acceptor = self.acceptor.clone();
                    let deadline = tokio::time::Instant::now() + self.limits.handshake_timeout;
                    handshakes.spawn(async move {
                        let stream = tokio::time::timeout_at(deadline, acceptor.accept(stream))
                            .await
                            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake deadline exceeded"))??;
                        Ok((stream, address))
                    });
                }
            }
        }
    }

    /// Take over TCP acceptance and TLS handshaking. Pending convenience
    /// handshakes are aborted; the caller must supply its own bounds/deadlines.
    pub fn into_parts(self) -> (TcpListener, TlsAcceptor) {
        (self.listener, self.acceptor)
    }
}
