use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use certon::{BoundTlsListener, CertCache, CertResolver, Certificate, TlsListenerLimits};
use chrono::Datelike;
use rustls::server::{ClientHello, ResolvesServerCert};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Debug)]
struct RecordingResolver {
    inner: CertResolver,
    calls: Arc<AtomicUsize>,
}

impl ResolvesServerCert for RecordingResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.resolve(hello)
    }
}

struct Fixture {
    bound: BoundTlsListener,
    client: Arc<rustls::ClientConfig>,
    calls: Arc<AtomicUsize>,
}

impl Fixture {
    async fn new(max_handshakes: usize, handshake_timeout: Duration) -> Self {
        certon::install_default_crypto_provider();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["example.com".into()]).unwrap();
        let year = chrono::Utc::now().year();
        params.not_before = rcgen::date_time_ymd(year - 1, 1, 1);
        params.not_after = rcgen::date_time_ymd(year + 2, 1, 1);
        let leaf = params.self_signed(&key).unwrap();
        let certificate =
            Certificate::from_pem(leaf.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap();
        let cache = CertCache::new(Default::default());
        cache.add(certificate).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(RecordingResolver {
                inner: CertResolver::new(cache),
                calls: calls.clone(),
            }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = BoundTlsListener::with_limits(
            listener,
            TlsAcceptor::from(Arc::new(server)),
            TlsListenerLimits {
                max_handshakes,
                handshake_timeout,
            },
        )
        .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(leaf.der().clone()).unwrap();
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            bound,
            client: Arc::new(client),
            calls,
        }
    }
}

#[tokio::test]
async fn idle_and_malformed_peers_do_not_block_a_normal_accept_loop() {
    let fixture = Fixture::new(4, Duration::from_secs(2)).await;
    let address = fixture.bound.listener.local_addr().unwrap();
    let idle = TcpStream::connect(address).await.unwrap();
    let mut accepted = Box::pin(fixture.bound.accept());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut accepted)
            .await
            .is_err()
    );
    let mut malformed = TcpStream::connect(address).await.unwrap();
    malformed
        .write_all(b"GET / HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let normal = TcpStream::connect(address).await.unwrap();
    let normal_address = normal.local_addr().unwrap();
    let connector = TlsConnector::from(fixture.client.clone());
    let (server, client) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            accepted,
            connector.connect("example.com".try_into().unwrap(), normal)
        )
    })
    .await
    .expect("an idle peer must not monopolize accept()");
    assert_eq!(server.unwrap().1, normal_address);
    assert!(client.is_ok());
    drop(idle);
}

#[tokio::test]
async fn admitted_handshakes_remain_bounded() {
    let fixture = Fixture::new(2, Duration::from_secs(3)).await;
    let address = fixture.bound.listener.local_addr().unwrap();
    let bound = Arc::new(fixture.bound);
    let server = tokio::spawn({
        let bound = bound.clone();
        async move { bound.accept().await }
    });
    let mut hello =
        rustls::ClientConnection::new(fixture.client.clone(), "example.com".try_into().unwrap())
            .unwrap();
    let mut bytes = Vec::new();
    hello.write_tls(&mut bytes).unwrap();
    let mut peers = Vec::new();
    for _ in 0..6 {
        let mut socket = TcpStream::connect(address).await.unwrap();
        socket.write_all(&bytes).await.unwrap();
        peers.push(socket);
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.calls.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), async {
            while fixture.calls.load(Ordering::SeqCst) < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_err(),
        "more handshakes than configured were admitted"
    );
    drop(peers);
    let socket = TcpStream::connect(address).await.unwrap();
    let connector = TlsConnector::from(fixture.client);
    let (server, client) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            server,
            connector.connect("example.com".try_into().unwrap(), socket)
        )
    })
    .await
    .unwrap();
    assert!(server.unwrap().is_ok());
    assert!(client.is_ok());
}

#[tokio::test]
async fn cancelling_accept_preserves_admission_and_the_original_work() {
    let fixture = Fixture::new(1, Duration::from_secs(2)).await;
    let address = fixture.bound.listener.local_addr().unwrap();
    let idle = TcpStream::connect(address).await.unwrap();
    let mut first = Box::pin(fixture.bound.accept());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut first)
            .await
            .is_err()
    );
    drop(first);
    let normal = TcpStream::connect(address).await.unwrap();
    let connector = TlsConnector::from(fixture.client.clone());
    let mut result = Box::pin(async {
        tokio::join!(
            fixture.bound.accept(),
            connector.connect("example.com".try_into().unwrap(), normal)
        )
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut result)
            .await
            .is_err(),
        "cancellation reset the occupied admission slot"
    );
    drop(idle);
    let (server, client) = tokio::time::timeout(Duration::from_secs(2), result)
        .await
        .unwrap();
    assert!(server.is_ok());
    assert!(client.is_ok());
}

#[tokio::test]
async fn handshake_deadline_releases_capacity_without_peer_cooperation() {
    let fixture = Fixture::new(1, Duration::from_millis(100)).await;
    let address = fixture.bound.listener.local_addr().unwrap();
    let mut idle = TcpStream::connect(address).await.unwrap();
    let mut first = Box::pin(fixture.bound.accept());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut first)
            .await
            .is_err()
    );
    let socket = TcpStream::connect(address).await.unwrap();
    let connector = TlsConnector::from(fixture.client.clone());
    let (server, client) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            first,
            connector.connect("example.com".try_into().unwrap(), socket)
        )
    })
    .await
    .unwrap();
    assert!(server.is_ok());
    assert!(client.is_ok());
    let mut byte = [0];
    let closed = tokio::time::timeout(Duration::from_secs(1), idle.read(&mut byte))
        .await
        .unwrap();
    assert!(closed.is_err() || closed.unwrap() == 0);
}

#[tokio::test]
async fn dropping_or_taking_parts_cancels_owned_handshakes() {
    for take_parts in [false, true] {
        let fixture = Fixture::new(1, Duration::from_secs(30)).await;
        let address = fixture.bound.listener.local_addr().unwrap();
        let mut idle = TcpStream::connect(address).await.unwrap();
        let mut first = Box::pin(fixture.bound.accept());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut first)
                .await
                .is_err()
        );
        drop(first);
        let parts = if take_parts {
            Some(fixture.bound.into_parts())
        } else {
            drop(fixture.bound);
            None
        };
        let mut byte = [0];
        let closed = tokio::time::timeout(Duration::from_secs(2), idle.read(&mut byte))
            .await
            .unwrap();
        assert!(closed.is_err() || closed.unwrap() == 0);
        if let Some((listener, _)) = parts {
            assert_eq!(listener.local_addr().unwrap(), address);
        }
    }
}

#[tokio::test]
async fn listener_limits_reject_zero_or_overflowing_deadlines() {
    for limits in [
        TlsListenerLimits {
            max_handshakes: 0,
            ..Default::default()
        },
        TlsListenerLimits {
            handshake_timeout: Duration::ZERO,
            ..Default::default()
        },
        TlsListenerLimits {
            handshake_timeout: Duration::MAX,
            ..Default::default()
        },
    ] {
        let fixture = Fixture::new(1, Duration::from_secs(2)).await;
        let (listener, acceptor) = fixture.bound.into_parts();
        let error = BoundTlsListener::with_limits(listener, acceptor, limits)
            .err()
            .unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}
