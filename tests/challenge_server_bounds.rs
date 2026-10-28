#[path = "common/challenge_tls.rs"]
mod challenge_tls;
use std::sync::Arc;
use std::time::Duration;

use certon::solvers::{Http01Solver, Solver, TlsAlpn01Solver};
use challenge_tls::peer_certificate as tls_peer_certificate;
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

async fn normal_request(port: u16, kind: &str) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    if kind == "tls" {
        let _ = tls_peer_certificate(stream, "second-bounds.example").await;
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

#[tokio::test]
async fn stale_tls_cleanup_preserves_the_current_certificate_on_real_handshakes() {
    certon::install_default_crypto_provider();
    let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = reserved.local_addr().unwrap().port();
    drop(reserved);
    let solver = TlsAlpn01Solver::new(port);
    let domain = "network-owner.example";
    solver.present(domain, "old", "old.thumb").await.unwrap();
    let old = tls_peer_certificate(
        TcpStream::connect(("127.0.0.1", port)).await.unwrap(),
        domain,
    )
    .await;
    solver.present(domain, "new", "new.thumb").await.unwrap();
    let new = tls_peer_certificate(
        TcpStream::connect(("127.0.0.1", port)).await.unwrap(),
        domain,
    )
    .await;
    assert_ne!(old, new);
    for (token, auth) in [
        ("old", "old.thumb"),
        ("old", "new.thumb"),
        ("new", "old.thumb"),
    ] {
        solver.cleanup(domain, token, auth).await.unwrap();
        let current = tokio::time::timeout(Duration::from_secs(5), async {
            tls_peer_certificate(
                TcpStream::connect(("127.0.0.1", port)).await.unwrap(),
                domain,
            )
            .await
        })
        .await
        .unwrap();
        assert_eq!(
            current, new,
            "stale token={token} auth={auth} changed the serving certificate"
        );
    }
    solver.cleanup(domain, "new", "new.thumb").await.unwrap();
}
