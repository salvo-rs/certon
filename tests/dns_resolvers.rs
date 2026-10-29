#![cfg(feature = "dns-01")]

#[path = "common/dns_server.rs"]
mod dns_server;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use certon::Solver;

#[tokio::test]
async fn propagation_requeries_custom_resolver_despite_long_ttl_and_combines_txt_fragments() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        for attempt in 0..2 {
            let mut query = [0; 2048];
            let (length, peer) = server.recv_from(&mut query).await.unwrap();
            assert!(length > 16);
            let mut end = 12;
            while query[end] != 0 {
                end += query[end] as usize + 1;
            }
            end += 5;
            let mut response = query[..2].to_vec();
            response.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
            response.extend_from_slice(&query[12..end]);
            response.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 1, 44, 0, 13]);
            response.extend_from_slice(if attempt == 0 {
                b"\x05wrong\x06-world"
            } else {
                b"\x05hello\x06-world"
            });
            server.send_to(&response, peer).await.unwrap();
        }
    });
    let result = certon::dns_util::check_dns_propagation_with_resolvers(
        "_acme-challenge.review.example.com",
        "hello-world",
        Duration::from_secs(2),
        Duration::from_millis(10),
        Some(&[address]),
    )
    .await
    .unwrap();
    assert!(result);
    task.await.unwrap();
}

#[tokio::test]
async fn empty_or_invalid_custom_resolver_configuration_is_rejected() {
    for resolvers in [vec![], vec!["not-an-ip-and-port".into()]] {
        let result = certon::dns_util::check_dns_propagation_with_resolvers(
            "_acme-challenge.example.com",
            "value",
            Duration::from_millis(10),
            Duration::from_millis(1),
            Some(&resolvers),
        )
        .await;
        assert!(matches!(result, Err(certon::Error::Config(_))));
    }
}

struct CancellableProvider {
    exists: AtomicBool,
    block_set: AtomicBool,
    block_delete: AtomicBool,
    entered: tokio::sync::Notify,
}

struct ProviderHandle(Arc<CancellableProvider>);

#[async_trait::async_trait]
impl certon::DnsProvider for ProviderHandle {
    async fn set_record(&self, _: &str, _: &str, _: &str, _: u32) -> certon::Result<()> {
        self.0.exists.store(true, Ordering::SeqCst);
        self.0.entered.notify_one();
        if self.0.block_set.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        Ok(())
    }
    async fn delete_record(&self, _: &str, _: &str, _: &str) -> certon::Result<()> {
        self.0.entered.notify_one();
        if self.0.block_delete.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        self.0.exists.store(false, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn cancellation_during_dns_creation_and_deletion_retains_cleanup_intent() {
    for during_creation in [true, false] {
        let server = dns_server::Server::new("example.com.").await;
        let provider = Arc::new(CancellableProvider {
            exists: AtomicBool::new(false),
            block_set: AtomicBool::new(during_creation),
            block_delete: AtomicBool::new(!during_creation),
            entered: tokio::sync::Notify::new(),
        });
        let mut solver = certon::Dns01Solver::new(Box::new(ProviderHandle(Arc::clone(&provider))));
        solver.resolvers = Some(vec![server.address.clone()]);
        let solver = Arc::new(solver);
        if !during_creation {
            solver
                .present("example.com", "token", "key-auth")
                .await
                .unwrap();
            provider.entered.notified().await;
        }
        let owned = Arc::clone(&solver);
        let operation = tokio::spawn(async move {
            if during_creation {
                owned.present("example.com", "token", "key-auth").await
            } else {
                owned.cleanup("example.com", "token", "key-auth").await
            }
        });
        provider.entered.notified().await;
        assert!(provider.exists.load(Ordering::SeqCst));
        operation.abort();
        let _ = operation.await;
        provider.block_set.store(false, Ordering::SeqCst);
        provider.block_delete.store(false, Ordering::SeqCst);
        solver
            .cleanup("example.com", "token", "key-auth")
            .await
            .unwrap();
        assert!(!provider.exists.load(Ordering::SeqCst));
    }
}
