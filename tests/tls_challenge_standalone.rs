#[path = "common/challenge_tls.rs"]
mod challenge_tls;

use certon::solvers::{Solver, TlsAlpn01Solver};
use tokio::net::{TcpListener, TcpStream};

// A separate integration-test process ensures no other fixture initializes
// rustls's provider before this public solver is used as the first TLS API.
#[tokio::test]
async fn standalone_tls_challenge_initializes_its_provider_and_serves_a_handshake() {
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = reserved.local_addr().unwrap().port();
    drop(reserved);
    let solver = TlsAlpn01Solver::new(port);
    solver
        .present("standalone.example", "token", "token.thumb")
        .await
        .unwrap();
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let certificate = challenge_tls::peer_certificate(stream, "standalone.example").await;
    assert!(!certificate.is_empty());
    solver
        .cleanup("standalone.example", "token", "token.thumb")
        .await
        .unwrap();
}
