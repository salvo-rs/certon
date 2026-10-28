use std::sync::Arc;
use std::time::Duration;

use certon::solvers::{Http01Solver, Solver, TlsAlpn01Solver};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn idle_peer(kind: &str) -> (Arc<dyn Solver>, TcpStream) {
    certon::install_default_crypto_provider();
    let baseline = tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks();
    let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = reserved.local_addr().unwrap().port();
    drop(reserved);
    let solver: Arc<dyn Solver> = match kind {
        "http" => Arc::new(Http01Solver::new(port)),
        "tls" => Arc::new(TlsAlpn01Solver::new(port)),
        _ => unreachable!(),
    };
    solver
        .present(&format!("{kind}-bounds.example"), kind, "token.thumb")
        .await
        .unwrap();
    let peer = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
            < baseline + 2
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    (solver, peer)
}

async fn assert_closed(mut peer: TcpStream) {
    let mut byte = [0];
    let result = tokio::time::timeout(Duration::from_secs(2), peer.read(&mut byte)).await;
    assert!(
        matches!(result, Ok(Ok(0)) | Ok(Err(_))),
        "idle peer outlived solver shutdown: {result:?}"
    );
}

#[tokio::test]
async fn http_cleanup_waits_for_idle_connection_release() {
    let (solver, peer) = idle_peer("http").await;
    solver
        .cleanup("http-bounds.example", "http", "token.thumb")
        .await
        .unwrap();
    assert_closed(peer).await;
}

#[tokio::test]
async fn tls_cleanup_waits_for_idle_connection_release() {
    let (solver, peer) = idle_peer("tls").await;
    solver
        .cleanup("tls-bounds.example", "tls", "token.thumb")
        .await
        .unwrap();
    assert_closed(peer).await;
}

#[tokio::test]
async fn dropping_each_solver_cancels_its_idle_workers() {
    for kind in ["http", "tls"] {
        let (solver, peer) = idle_peer(kind).await;
        drop(solver);
        assert_closed(peer).await;
    }
}

#[derive(Debug)]
struct ChallengeVerifier;
impl rustls::client::danger::ServerCertVerifier for ChallengeVerifier {
    // Availability-only test: ACME leaves have a specialized critical
    // extension. This verifier does not assert certificate/signature safety.
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .unwrap()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn normal_request(port: u16, kind: &str) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    if kind == "tls" {
        let mut config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ChallengeVerifier))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tls = connector
            .connect("second-bounds.example".try_into().unwrap(), stream)
            .await
            .unwrap();
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(b"acme-tls/1".as_slice())
        );
        assert!(!tls.get_ref().1.peer_certificates().unwrap().is_empty());
    } else {
        stream.write_all(b"GET /.well-known/acme-challenge/second HTTP/1.1\r\nHost: second-bounds.example\r\n\r\n").await.unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        assert!(reply.ends_with("second.thumb"), "{reply}");
    }
}

async fn bounded_slow_peers(kind: &str) {
    certon::install_default_crypto_provider();
    let baseline = tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks();
    let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = reserved.local_addr().unwrap().port();
    drop(reserved);
    let solver: Arc<dyn Solver> = match kind {
        "http" => Arc::new(Http01Solver::with_limits(port, 2, Duration::from_secs(10)).unwrap()),
        "tls" => Arc::new(TlsAlpn01Solver::with_limits(port, 2, Duration::from_secs(10)).unwrap()),
        _ => unreachable!(),
    };
    // Keep paused time runnable while real loopback IO is scheduled. Otherwise
    // the runtime could auto-advance a deadline before the peer is connected.
    tokio::time::pause();
    let runnable = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    solver
        .present("first-bounds.example", "first", "first.thumb")
        .await
        .unwrap();
    // The same listener/configuration must see later challenges dynamically.
    solver
        .present("second-bounds.example", "second", "second.thumb")
        .await
        .unwrap();
    let mut slow = Vec::new();
    for _ in 0..2 {
        slow.push(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
    }
    while tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
        < baseline + 4
    {
        tokio::task::yield_now().await;
    }
    let owned_kind = kind.to_owned();
    let normal = tokio::spawn(async move { normal_request(port, &owned_kind).await });
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert!(
        !normal.is_finished(),
        "a full accepted-connection budget was bypassed"
    );
    assert!(
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
            <= baseline + 5,
        "queued peers must not create additional connection tasks"
    );
    tokio::time::advance(Duration::from_secs(9)).await;
    for stream in &mut slow {
        stream
            .write_all(if kind == "tls" { b"\x16" } else { b"G" })
            .await
            .unwrap();
    }
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert!(
        !normal.is_finished(),
        "slow peers must retain capacity before their deadline"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    // Resume real time for a bounded failure if a broken implementation never
    // releases the slow connections. This is not an elapsed-time assertion.
    tokio::time::resume();
    runnable.abort();
    let _ = runnable.await;
    tokio::time::timeout(Duration::from_secs(5), normal)
        .await
        .expect("slow peers starved a normal challenge connection")
        .unwrap();
    for peer in slow {
        assert_closed(peer).await;
    }
    solver
        .cleanup("first-bounds.example", "first", "first.thumb")
        .await
        .unwrap();
    solver
        .cleanup("second-bounds.example", "second", "second.thumb")
        .await
        .unwrap();
}

#[tokio::test]
async fn http_budget_and_total_deadline_release_slow_peers_for_normal_requests() {
    bounded_slow_peers("http").await;
}

#[tokio::test]
async fn tls_budget_and_total_deadline_release_slow_peers_for_normal_handshakes() {
    bounded_slow_peers("tls").await;
}

#[test]
fn invalid_connection_limits_are_rejected() {
    for (max, timeout) in [
        (0, Duration::from_secs(1)),
        (1, Duration::ZERO),
        (1, Duration::MAX),
    ] {
        assert!(Http01Solver::with_limits(0, max, timeout).is_err());
        assert!(TlsAlpn01Solver::with_limits(0, max, timeout).is_err());
    }
}
