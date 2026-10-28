use std::collections::HashMap;
use std::sync::Arc;

use certon::http_handler::HttpChallengeHandler;
use certon::{DistributedSolver, FileStorage, Http01Solver, Solver, Storage};
use tokio::sync::RwLock;

struct Noop;
#[async_trait::async_trait]
impl Solver for Noop {
    async fn present(&self, _: &str, _: &str, _: &str) -> certon::Result<()> {
        Ok(())
    }
    async fn cleanup(&self, _: &str, _: &str, _: &str) -> certon::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn another_node_serves_the_presented_domain_and_token() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let solver = DistributedSolver::with_prefix(Box::new(Noop), storage.clone(), "ca".into());
    let handler = HttpChallengeHandler::with_prefix(
        Arc::new(RwLock::new(HashMap::new())),
        Some(Arc::new(FileStorage::new(directory.path()))),
        "ca".into(),
    );
    solver
        .present("example.com", "TokenA", "TokenA.thumbprint")
        .await
        .unwrap();
    let path = "/.well-known/acme-challenge/TokenA";
    assert_eq!(
        handler
            .handle_http_request("GET", "example.com:80", path)
            .await,
        Some((200, "TokenA.thumbprint".into()))
    );
    assert_eq!(
        handler
            .handle_http_request("GET", "other.example.com", path)
            .await,
        Some((404, String::new()))
    );
    solver
        .cleanup("example.com", "TokenA", "TokenA.thumbprint")
        .await
        .unwrap();
    assert_eq!(
        handler
            .handle_http_request("GET", "example.com", path)
            .await,
        Some((404, String::new()))
    );
}

#[tokio::test]
async fn concurrent_tokens_and_cleanup_preserve_siblings_and_case() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let solver = Arc::new(DistributedSolver::new(Box::new(Noop), storage.clone()));
    let handler = HttpChallengeHandler::new(Arc::default(), Some(storage));
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..32 {
        let solver = solver.clone();
        tasks.spawn(async move {
            let token = format!("Token{i}");
            solver
                .present("EXAMPLE.com", &token, &format!("{token}.thumbprint"))
                .await
                .unwrap();
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    solver
        .present("example.com", "token0", "token0.lower")
        .await
        .unwrap();
    for i in 0..32 {
        assert_eq!(
            handler
                .handle_http_request(
                    "GET",
                    "example.com",
                    &format!("/.well-known/acme-challenge/Token{i}")
                )
                .await,
            Some((200, format!("Token{i}.thumbprint")))
        );
        if i % 2 == 0 {
            let solver = solver.clone();
            tasks.spawn(async move {
                solver
                    .cleanup(
                        "example.com",
                        &format!("Token{i}"),
                        &format!("Token{i}.thumbprint"),
                    )
                    .await
                    .unwrap();
            });
        }
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    for i in 0..32 {
        let response = handler
            .handle_http_request(
                "GET",
                "example.com",
                &format!("/.well-known/acme-challenge/Token{i}"),
            )
            .await
            .unwrap();
        assert_eq!(response.0, if i % 2 == 0 { 404 } else { 200 });
    }
    assert_eq!(
        handler
            .handle_http_request("GET", "example.com", "/.well-known/acme-challenge/token0")
            .await,
        Some((200, "token0.lower".into()))
    );
}

struct FaultStorage {
    inner: FileStorage,
    fail: std::sync::atomic::AtomicBool,
    fail_delete: std::sync::atomic::AtomicBool,
    calls: std::sync::atomic::AtomicUsize,
}
impl FaultStorage {
    fn check(&self) -> certon::Result<()> {
        use std::sync::atomic::Ordering::SeqCst;
        self.calls.fetch_add(1, SeqCst);
        if self.fail.load(SeqCst) {
            Err(certon::Error::Storage(certon::error::StorageError::Io(
                std::io::Error::other("injected backend failure"),
            )))
        } else {
            Ok(())
        }
    }
}
#[async_trait::async_trait]
impl Storage for FaultStorage {
    async fn store(&self, k: &str, v: &[u8]) -> certon::Result<()> {
        self.check()?;
        self.inner.store(k, v).await
    }
    async fn load(&self, k: &str) -> certon::Result<Vec<u8>> {
        self.check()?;
        self.inner.load(k).await
    }
    async fn delete(&self, k: &str) -> certon::Result<()> {
        if self.fail_delete.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(certon::Error::Other("injected delete failure".into()));
        }
        self.check()?;
        self.inner.delete(k).await
    }
    async fn exists(&self, k: &str) -> certon::Result<bool> {
        self.inner.exists(k).await
    }
    async fn list(&self, k: &str, r: bool) -> certon::Result<Vec<String>> {
        self.inner.list(k, r).await
    }
    async fn stat(&self, k: &str) -> certon::Result<certon::storage::KeyInfo> {
        self.inner.stat(k).await
    }
    async fn lock(&self, k: &str) -> certon::Result<()> {
        self.inner.lock(k).await
    }
    async fn unlock(&self, k: &str) -> certon::Result<()> {
        self.inner.unlock(k).await
    }
}

#[tokio::test]
async fn backend_errors_are_visible_and_invalid_requests_never_access_storage() {
    use std::sync::atomic::Ordering::SeqCst;
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(FaultStorage {
        inner: FileStorage::new(directory.path()),
        fail: false.into(),
        fail_delete: false.into(),
        calls: 0.into(),
    });
    let solver = DistributedSolver::new(Box::new(Noop), storage.clone());
    let handler = HttpChallengeHandler::new(Arc::default(), Some(storage.clone()));
    solver
        .present("example.com", "Token", "Token.auth")
        .await
        .unwrap();
    let before = storage.calls.load(SeqCst);
    for host in [
        "",
        "evil.com@EXAMPLE.com",
        "example.com:bad",
        "[::1]evil",
        "a..com",
        "*.example.com",
        "example.com\r\n",
    ] {
        assert_eq!(
            handler
                .handle_http_request("GET", host, "/.well-known/acme-challenge/Token")
                .await,
            None,
            "{host:?}"
        );
    }
    for token in ["../Token", "Token%2f", "Token/extra", ""] {
        assert_eq!(
            handler
                .handle_http_request(
                    "GET",
                    "example.com",
                    &format!("/.well-known/acme-challenge/{token}")
                )
                .await,
            None
        );
    }
    assert!(
        solver
            .present("example.com", "bad/token", "bad/token.auth")
            .await
            .is_err()
    );
    assert_eq!(before, storage.calls.load(SeqCst));
    storage.fail.store(true, SeqCst);
    assert!(
        handler
            .try_handle_http_request("GET", "example.com", "/.well-known/acme-challenge/Token")
            .await
            .is_err()
    );
    assert_eq!(
        handler
            .handle_http_request("GET", "example.com", "/.well-known/acme-challenge/Token")
            .await,
        Some((503, String::new()))
    );
    assert!(
        solver
            .present("example.com", "Token", "Token.replacement")
            .await
            .is_err()
    );
    assert!(
        solver
            .cleanup("example.com", "Token", "Token.auth")
            .await
            .is_err()
    );
    storage.fail.store(false, SeqCst);
    assert_eq!(
        handler
            .handle_http_request("GET", "example.com", "/.well-known/acme-challenge/Token")
            .await,
        Some((200, "Token.auth".into()))
    );
}

#[tokio::test]
async fn legacy_read_cleanup_and_canonical_v2_priority() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let legacy = "challenge_tokens/example.com.json";
    storage
        .store(
            legacy,
            br#"{"Token":"Token.legacy","Sibling":"Sibling.auth"}"#,
        )
        .await
        .unwrap();
    let solver = DistributedSolver::new(Box::new(Http01Solver::new(0)), storage.clone());
    let handler = HttpChallengeHandler::new(Arc::default(), Some(storage.clone()));
    let path = "/.well-known/acme-challenge/Token";
    assert_eq!(
        handler
            .handle_http_request("GET", "example.com", path)
            .await,
        Some((200, "Token.legacy".into()))
    );
    solver
        .present("example.com", "Token", "Token.legacy")
        .await
        .unwrap();
    solver
        .present("example.com", "Token", "Token.new")
        .await
        .unwrap();
    assert_eq!(
        handler
            .handle_http_request("GET", "example.com", path)
            .await,
        Some((200, "Token.new".into()))
    );
    solver
        .cleanup("example.com", "Token", "Token.legacy")
        .await
        .unwrap();
    assert_eq!(
        handler
            .handle_http_request("GET", "example.com", path)
            .await,
        Some((200, "Token.new".into()))
    );
    assert_eq!(
        certon::solvers::get_active_challenge("Token").as_deref(),
        Some("Token.new")
    );
    let old: HashMap<String, String> =
        serde_json::from_slice(&storage.load(legacy).await.unwrap()).unwrap();
    assert_eq!(old.len(), 1);
    assert!(old.contains_key("Sibling"));
    // Corrupt v2 must not fall back to a valid old authorization.
    storage
        .store(legacy, br#"{"Token":"Token.legacy"}"#)
        .await
        .unwrap();
    let entry = storage
        .list("challenge_tokens/v2", true)
        .await
        .unwrap()
        .into_iter()
        .find(|k| k.ends_with(".json"))
        .unwrap();
    storage.store(&entry, b"broken").await.unwrap();
    assert!(
        handler
            .try_handle_http_request("GET", "example.com", path)
            .await
            .is_err()
    );
    assert!(
        solver
            .cleanup("example.com", "Token", "Token.new")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn host_aware_local_map_requires_explicit_domain_binding() {
    let map = Arc::new(RwLock::new(HashMap::from([(
        "Token".into(),
        "Token.auth".into(),
    )])));
    let handler = HttpChallengeHandler::new(map, None);
    let path = "/.well-known/acme-challenge/Token";
    assert_eq!(
        handler.handle_request(path).await,
        Some("Token.auth".into())
    );
    assert_eq!(
        handler
            .handle_http_request("GET", "example.com", path)
            .await,
        Some((404, String::new()))
    );
    let handler = handler.with_domain("example.com").unwrap();
    assert_eq!(
        handler
            .handle_http_request("GET", "EXAMPLE.com.:80", path)
            .await,
        Some((200, "Token.auth".into()))
    );
    assert_eq!(
        handler.handle_http_request("GET", "other.com", path).await,
        Some((404, String::new()))
    );
}

#[tokio::test]
async fn cleaning_current_v2_cannot_resurrect_stale_legacy_value() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    storage
        .store(
            "challenge_tokens/example.com.json",
            br#"{"Token":"Token.old","Sibling":"Sibling.auth"}"#,
        )
        .await
        .unwrap();
    let solver = DistributedSolver::new(Box::new(Noop), storage.clone());
    let handler = HttpChallengeHandler::new(Arc::default(), Some(storage));
    solver
        .present("example.com", "Token", "Token.new")
        .await
        .unwrap();
    solver
        .cleanup("example.com", "Token", "Token.new")
        .await
        .unwrap();
    assert_eq!(
        handler
            .handle_http_request("GET", "example.com", "/.well-known/acme-challenge/Token")
            .await,
        Some((404, String::new()))
    );
    assert_eq!(
        handler
            .handle_http_request("GET", "example.com", "/.well-known/acme-challenge/Sibling")
            .await,
        Some((200, "Sibling.auth".into()))
    );
}

#[tokio::test]
async fn corrupt_legacy_is_not_overwritten_and_cleanup_reports_failure() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let key = "challenge_tokens/example.com.json";
    storage.store(key, b"corrupt map").await.unwrap();
    let solver = DistributedSolver::new(Box::new(Noop), storage.clone());
    solver
        .present("example.com", "Token", "Token.auth")
        .await
        .unwrap();
    assert!(
        solver
            .cleanup("example.com", "Token", "Token.auth")
            .await
            .is_err()
    );
    assert_eq!(storage.load(key).await.unwrap(), b"corrupt map");
}

#[tokio::test]
async fn delete_failure_is_retryable_and_still_cleans_the_inner_solver() {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering::SeqCst;
    struct Cleanup(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl Solver for Cleanup {
        async fn present(&self, _: &str, _: &str, _: &str) -> certon::Result<()> {
            Ok(())
        }
        async fn cleanup(&self, _: &str, _: &str, _: &str) -> certon::Result<()> {
            self.0.fetch_add(1, SeqCst);
            Ok(())
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(FaultStorage {
        inner: FileStorage::new(directory.path()),
        fail: false.into(),
        fail_delete: true.into(),
        calls: 0.into(),
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let solver = DistributedSolver::new(Box::new(Cleanup(calls.clone())), storage.clone());
    let handler = HttpChallengeHandler::new(Arc::default(), Some(storage.clone()));
    solver
        .present("example.com", "Token", "Token.auth")
        .await
        .unwrap();
    assert!(
        solver
            .cleanup("example.com", "Token", "Token.auth")
            .await
            .is_err()
    );
    assert_eq!(calls.load(SeqCst), 1);
    assert_eq!(
        handler
            .handle_http_request("GET", "example.com", "/.well-known/acme-challenge/Token")
            .await,
        Some((200, "Token.auth".into()))
    );
    storage.fail_delete.store(false, SeqCst);
    solver
        .cleanup("example.com", "Token", "Token.auth")
        .await
        .unwrap();
    assert_eq!(calls.load(SeqCst), 2);
    assert_eq!(
        handler
            .handle_http_request("GET", "example.com", "/.well-known/acme-challenge/Token")
            .await,
        Some((404, String::new()))
    );
}

#[tokio::test]
async fn ambiguous_legacy_alias_is_neither_read_nor_removed() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let solver = DistributedSolver::new(Box::new(Noop), storage.clone());
    let handler = HttpChallengeHandler::new(Arc::default(), Some(storage.clone()));
    let old = br#"{"Token":"Token.other"}"#;
    for (domain, alias) in [
        ("2001:db8::1", "2001-db8--1"),
        ("*.example.com", "wildcard_.example.com"),
    ] {
        let legacy = format!("challenge_tokens/{alias}.json");
        storage.store(&legacy, old).await.unwrap();
        if domain == "2001:db8::1" {
            assert_eq!(
                handler
                    .handle_http_request(
                        "GET",
                        "[2001:db8::1]",
                        "/.well-known/acme-challenge/Token"
                    )
                    .await,
                Some((404, String::new()))
            );
        }
        solver.present(domain, "Token", "Token.new").await.unwrap();
        solver.cleanup(domain, "Token", "Token.new").await.unwrap();
        assert_eq!(
            storage.load(&legacy).await.unwrap(),
            old,
            "legacy alias for {domain} must survive"
        );
    }
}

#[tokio::test]
async fn long_domain_and_issuer_prefix_can_present_and_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let domain = format!(
        "{}.{}.{}.co.uk",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63)
    );
    assert_eq!(domain.len(), 197);
    let maximum_domain = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(maximum_domain.len(), 253);
    for domain in [domain, maximum_domain] {
        for prefix in [
            "acme/acme-v02.api.letsencrypt.org-directory".to_string(),
            format!("issuer-{}", "p".repeat(220)),
        ] {
            let solver =
                DistributedSolver::with_prefix(Box::new(Noop), storage.clone(), prefix.clone());
            let handler =
                HttpChallengeHandler::with_prefix(Arc::default(), Some(storage.clone()), prefix);
            solver
                .present(&domain, "Token", "Token.auth")
                .await
                .unwrap();
            assert_eq!(
                handler
                    .handle_http_request("GET", &domain, "/.well-known/acme-challenge/Token")
                    .await,
                Some((200, "Token.auth".into()))
            );
            solver
                .cleanup(&domain, "Token", "Token.auth")
                .await
                .unwrap();
            assert_eq!(
                handler
                    .handle_http_request("GET", &domain, "/.well-known/acme-challenge/Token")
                    .await,
                Some((404, String::new()))
            );
        }
    }
}

#[tokio::test]
async fn maximum_domain_without_v2_is_not_an_invalid_legacy_filename_error() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let domain = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(domain.len(), 253);
    DistributedSolver::new(Box::new(Noop), storage.clone())
        .present("other.example.com", "Other", "Other.auth")
        .await
        .unwrap();
    let handler = HttpChallengeHandler::new(Arc::default(), Some(storage));
    assert_eq!(
        handler
            .try_handle_http_request("GET", &domain, "/.well-known/acme-challenge/Token")
            .await
            .unwrap(),
        Some((404, String::new()))
    );
}

#[tokio::test]
async fn legacy_domain_at_portable_filename_boundary_remains_supported() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let domain = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(58)
    );
    assert_eq!(domain.len(), 250);
    // Seed an existing legacy file directly so the regression exercises the
    // cleanup rewrite with siblings, independently of how the old file arose.
    tokio::fs::create_dir(directory.path().join("challenge_tokens"))
        .await
        .unwrap();
    tokio::fs::write(
        directory
            .path()
            .join(format!("challenge_tokens/{domain}.json")),
        br#"{"Token":"Token.legacy","Sibling":"Sibling.auth"}"#,
    )
    .await
    .unwrap();
    let solver = DistributedSolver::new(Box::new(Noop), storage.clone());
    solver.present(&domain, "Token", "Token.new").await.unwrap();
    let handler = HttpChallengeHandler::new(Arc::default(), Some(storage.clone()));
    assert_eq!(
        handler
            .try_handle_http_request("GET", &domain, "/.well-known/acme-challenge/Token")
            .await
            .unwrap(),
        Some((200, "Token.new".into()))
    );
    solver.cleanup(&domain, "Token", "Token.new").await.unwrap();
    assert_eq!(
        handler
            .try_handle_http_request("GET", &domain, "/.well-known/acme-challenge/Token")
            .await
            .unwrap(),
        Some((404, String::new()))
    );
    assert_eq!(
        handler
            .try_handle_http_request("GET", &domain, "/.well-known/acme-challenge/Sibling")
            .await
            .unwrap(),
        Some((200, "Sibling.auth".into()))
    );
    let map: HashMap<String, String> = serde_json::from_slice(
        &storage
            .load(&format!("challenge_tokens/{domain}.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        map,
        HashMap::from([("Sibling".into(), "Sibling.auth".into())])
    );
}
