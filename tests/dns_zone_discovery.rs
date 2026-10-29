#![cfg(feature = "dns-01")]

#[path = "common/dns_server.rs"]
mod dns_server;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use certon::{Dns01Solver, DnsProvider, Solver};
use dns_server::{Server, State};
use hickory_resolver::proto::rr::RecordType;

struct Provider {
    state: Arc<State>,
    writes: AtomicUsize,
    deletes: AtomicUsize,
}

struct Handle(Arc<Provider>);

#[async_trait::async_trait]
impl DnsProvider for Handle {
    async fn set_record(&self, zone: &str, name: &str, value: &str, _: u32) -> certon::Result<()> {
        if zone != self.0.state.zone {
            return Err(certon::Error::Config(format!(
                "provider owns {}, received {zone}",
                self.0.state.zone
            )));
        }
        self.0.writes.fetch_add(1, Ordering::SeqCst);
        let fqdn = if name.is_empty() {
            zone.to_owned()
        } else {
            format!("{name}.{zone}")
        };
        self.0
            .state
            .records
            .lock()
            .unwrap()
            .entry(fqdn)
            .or_default()
            .push(value.into());
        Ok(())
    }

    async fn delete_record(&self, zone: &str, name: &str, value: &str) -> certon::Result<()> {
        assert_eq!(zone, self.0.state.zone);
        let fqdn = if name.is_empty() {
            zone.to_owned()
        } else {
            format!("{name}.{zone}")
        };
        self.0
            .state
            .records
            .lock()
            .unwrap()
            .get_mut(&fqdn)
            .unwrap()
            .retain(|item| item != value);
        self.0.deletes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn configured(server: &Server) -> (Dns01Solver, Arc<Provider>) {
    let provider = Arc::new(Provider {
        state: server.state.clone(),
        writes: AtomicUsize::new(0),
        deletes: AtomicUsize::new(0),
    });
    let mut solver = Dns01Solver::with_timeouts(
        Box::new(Handle(provider.clone())),
        Duration::from_secs(2),
        Duration::from_millis(5),
    );
    solver.resolvers = Some(vec![server.address.clone()]);
    (solver, provider)
}

async fn lifecycle(domain: &str, zone: &str, relative: &str, override_name: Option<&str>) {
    let server = Server::new(zone).await;
    let (mut solver, provider) = configured(&server);
    solver.override_domain = override_name.map(str::to_owned);
    let name = override_name
        .map(str::to_owned)
        .unwrap_or_else(|| certon::dns_util::challenge_record_name(domain));
    // A synchronous best-effort call must not substitute its guess for SOA.
    let _guess = certon::dns_util::find_zone_by_fqdn(&name);
    solver
        .present(domain, "token", "token.thumbprint")
        .await
        .unwrap();
    let expected = format!("{relative}{zone}");
    assert!(server.state.records.lock().unwrap().contains_key(&expected));
    assert_eq!(provider.writes.load(Ordering::SeqCst), 1);
    solver
        .wait(domain, "token", "token.thumbprint")
        .await
        .unwrap();
    assert!(
        server
            .state
            .queries
            .lock()
            .unwrap()
            .iter()
            .any(|(name, kind)| *kind == RecordType::SOA && name == zone)
    );
    let before = server.state.queries.lock().unwrap().len();
    // Cleanup uses the remembered discovery result even if DNS goes away.
    server.state.mode.store(3, Ordering::SeqCst);
    solver
        .cleanup(domain, "token", "token.thumbprint")
        .await
        .unwrap();
    assert_eq!(provider.deletes.load(Ordering::SeqCst), 1);
    assert!(
        server
            .state
            .records
            .lock()
            .unwrap()
            .values()
            .all(Vec::is_empty)
    );
    assert_eq!(before, server.state.queries.lock().unwrap().len());
}

#[tokio::test]
async fn co_uk_and_delegated_subzones_use_soa_after_a_heuristic_guess() {
    lifecycle("example.co.uk", "example.co.uk.", "_acme-challenge.", None).await;
    lifecycle(
        "app.delegated.example.com",
        "delegated.example.com.",
        "_acme-challenge.app.",
        None,
    )
    .await;
}

#[tokio::test]
async fn override_and_case_normalization_use_the_target_zone() {
    lifecycle(
        "CUSTOMER.example.net",
        "auth.example.org.",
        "_acme-challenge.acme.",
        Some("_Acme-Challenge.Acme.Auth.Example.Org"),
    )
    .await;
}

#[tokio::test]
async fn ordinary_two_label_zone_remains_a_positive_control() {
    let server = Server::new("example.com.").await;
    let (solver, provider) = configured(&server);
    solver
        .present("example.com", "token", "token.auth")
        .await
        .unwrap();
    solver
        .wait("example.com", "token", "token.auth")
        .await
        .unwrap();
    solver
        .cleanup("example.com", "token", "token.auth")
        .await
        .unwrap();
    assert_eq!(provider.writes.load(Ordering::SeqCst), 1);
    assert_eq!(provider.deletes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn distinct_custom_resolvers_cannot_reuse_each_others_zone() {
    let first = Server::new("example.test.").await;
    let second = Server::new("delegated.example.test.").await;
    let domain = "app.delegated.example.test";
    for server in [&first, &second, &first] {
        let (solver, provider) = configured(server);
        solver.present(domain, "token", "auth").await.unwrap();
        assert_eq!(provider.writes.load(Ordering::SeqCst), 1);
        assert!(!server.state.queries.lock().unwrap().is_empty());
        solver.cleanup(domain, "token", "auth").await.unwrap();
    }
}

#[tokio::test]
async fn no_soa_or_an_unrelated_alias_must_not_write_a_guessed_zone() {
    for mode in [1, 2] {
        let server = Server::new("example.test.").await;
        server.state.mode.store(mode, Ordering::SeqCst);
        let (solver, provider) = configured(&server);
        assert!(
            solver
                .present("app.example.test", "token", "auth")
                .await
                .is_err()
        );
        assert_eq!(provider.writes.load(Ordering::SeqCst), 0);
        assert!(server.state.records.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn cancelling_discovery_cannot_create_provider_state() {
    let server = Server::new("example.test.").await;
    server.state.mode.store(3, Ordering::SeqCst);
    let (solver, provider) = configured(&server);
    let operation =
        tokio::spawn(async move { solver.present("app.example.test", "token", "auth").await });
    tokio::time::timeout(Duration::from_secs(2), server.state.received.notified())
        .await
        .unwrap();
    operation.abort();
    assert!(operation.await.unwrap_err().is_cancelled());
    assert_eq!(provider.writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn invalid_resolver_configuration_never_calls_the_provider() {
    let server = Server::new("example.test.").await;
    for resolvers in [Vec::new(), vec!["not-an-address".into()]] {
        let (mut solver, provider) = configured(&server);
        solver.resolvers = Some(resolvers);
        assert!(matches!(
            solver.present("app.example.test", "token", "auth").await,
            Err(certon::Error::Config(_))
        ));
        assert_eq!(provider.writes.load(Ordering::SeqCst), 0);
    }
    assert!(server.state.queries.lock().unwrap().is_empty());
}

#[tokio::test]
async fn the_whole_zone_walk_has_a_ten_second_deadline() {
    let server = Server::new("example.test.").await;
    server.state.mode.store(3, Ordering::SeqCst);
    let (solver, provider) = configured(&server);
    let operation =
        tokio::spawn(async move { solver.present("a.b.c.example.test", "token", "auth").await });
    tokio::time::timeout(Duration::from_secs(2), server.state.received.notified())
        .await
        .unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    let result = operation.await.unwrap();
    tokio::time::resume();
    assert!(matches!(result, Err(certon::Error::Timeout(_))));
    assert_eq!(provider.writes.load(Ordering::SeqCst), 0);
}
