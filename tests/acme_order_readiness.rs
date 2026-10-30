use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use certon::acme_client::AcmeClient;
use certon::{AcmeIssuer, FileStorage, Solver};
use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x509_parser::prelude::FromDer;

const NOT_READY: &str = "urn:ietf:params:acme:error:orderNotReady";
#[derive(Clone)]
struct Plan {
    rejection: Option<(u16, Value)>,
    statuses: VecDeque<&'static str>,
    always_reject: bool,
    bad_nonce: bool,
    stalled: bool,
    stalled_order: bool,
    finalized_status: &'static str,
}
impl Plan {
    fn ready() -> Self {
        Self {
            rejection: None,
            statuses: VecDeque::new(),
            always_reject: false,
            bad_nonce: false,
            stalled: false,
            stalled_order: false,
            finalized_status: "valid",
        }
    }
    fn recovery(statuses: &[&'static str]) -> Self {
        Self {
            rejection: Some((403, json!({"type":NOT_READY,"detail":"order not ready"}))),
            statuses: statuses.iter().copied().collect(),
            ..Self::ready()
        }
    }
}
#[derive(Default)]
struct State {
    paths: Vec<String>,
    csrs: Vec<Vec<u8>>,
    protected: Vec<Value>,
}
struct Server {
    url: String,
    state: Arc<Mutex<State>>,
    entered: Arc<tokio::sync::Notify>,
    closed: Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct Public(Vec<u8>);
impl PublicKeyData for Public {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}
impl Server {
    async fn new(mut plan: Plan) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let base = url.clone();
        let state = Arc::new(Mutex::new(State::default()));
        let record = state.clone();
        let entered = Arc::new(tokio::sync::Notify::new());
        let notify_entered = entered.clone();
        let closed = Arc::new(tokio::sync::Notify::new());
        let notify_closed = closed.clone();
        let key = KeyPair::generate().unwrap();
        let ca = rcgen::Issuer::new(
            CertificateParams::new(vec!["local-ca".into()]).unwrap(),
            key,
        );
        let task = tokio::spawn(async move {
            let mut challenged = false;
            let mut certificate = String::new();
            let mut rejected = false;
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut input = Vec::new();
                let end = loop {
                    let mut buffer = [0; 4096];
                    let n = socket.read(&mut buffer).await.unwrap();
                    if n == 0 {
                        break 0;
                    }
                    input.extend_from_slice(&buffer[..n]);
                    if let Some(end) = input.windows(4).position(|part| part == b"\r\n\r\n") {
                        break end + 4;
                    }
                };
                if end == 0 {
                    continue;
                }
                let head = String::from_utf8_lossy(&input[..end]).into_owned();
                let len = head
                    .lines()
                    .find_map(|line| {
                        let (k, v) = line.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                while input.len() < end + len {
                    let mut buffer = [0; 4096];
                    let n = socket.read(&mut buffer).await.unwrap();
                    assert!(n > 0);
                    input.extend_from_slice(&buffer[..n]);
                }
                let path = head.split_whitespace().nth(1).unwrap().to_owned();
                let jws: Value = serde_json::from_slice(&input[end..]).unwrap_or(Value::Null);
                let decode = |field: &str| {
                    URL_SAFE_NO_PAD
                        .decode(jws[field].as_str().unwrap_or(""))
                        .unwrap()
                };
                let payload: Value =
                    serde_json::from_slice(&decode("payload")).unwrap_or(Value::Null);
                let protected: Value =
                    serde_json::from_slice(&decode("protected")).unwrap_or(Value::Null);
                {
                    let mut state = record.lock().unwrap();
                    state.paths.push(path.clone());
                    if path != "/directory" && path != "/nonce" {
                        state.protected.push(protected);
                    }
                }
                let mut status = 200;
                let mut extra = String::new();
                let body = match path.as_str() {
                    "/directory" => json!({
                        "newNonce": format!("{base}/nonce"),
                        "newAccount": format!("{base}/account"),
                        "newOrder": format!("{base}/new-order"),
                        "revokeCert": format!("{base}/revoke"),
                        "keyChange": format!("{base}/key-change")
                    }).to_string(),
                    "/nonce" => String::new(),
                    "/account" => {
                        extra = format!("Location: {base}/registered\r\n");
                        json!({"status": "valid", "contact": ["mailto:order@example.com"]}).to_string()
                    }
                    "/new-order" => {
                        extra = format!("Location: {base}/order\r\n");
                        json!({"status": "pending", "authorizations": [format!("{base}/authz")], "finalize": format!("{base}/finalize")}).to_string()
                    }
                    "/authz" => {
                        if challenged {
                            json!({"status": "valid", "identifier": {"type": "dns", "value": "order.example.com"}})
                        } else {
                            json!({"status": "pending", "identifier": {"type": "dns", "value": "order.example.com"}, "challenges": [{"type": "http-01", "url": format!("{base}/challenge"), "token": "validtoken"}]})
                        }.to_string()
                    }
                    "/challenge" => {
                        challenged = true;
                        json!({"type": "http-01", "url": format!("{base}/challenge"), "token": "validtoken", "status": "processing"}).to_string()
                    }
                    "/order" => {
                        if plan.stalled_order {
                            notify_entered.notify_one();
                            let mut byte = [0; 1];
                            while socket.read(&mut byte).await.unwrap_or(0) != 0 {}
                            notify_closed.notify_one();
                            continue;
                        }
                        let next = plan.statuses.pop_front().unwrap_or("ready");
                        let cert_url = (next == "valid").then(|| format!("{base}/certificate"));
                        let error = matches!(next, "invalid" | "unexpected").then(|| json!({"type": "urn:ietf:params:acme:error:badCSR", "detail": "terminal rejection"}));
                        json!({"status": next, "finalize": format!("{base}/finalize"), "certificate": cert_url, "error": error}).to_string()
                    }
                    "/finalize" => {
                        let csr = URL_SAFE_NO_PAD.decode(payload["csr"].as_str().unwrap()).unwrap();
                        record.lock().unwrap().csrs.push(csr.clone());
                        if plan.stalled {
                            notify_entered.notify_one();
                            let mut byte = [0; 1];
                            while socket.read(&mut byte).await.unwrap_or(0) != 0 {}
                            notify_closed.notify_one();
                            continue;
                        }
                        let (_, parsed) = x509_parser::certification_request::X509CertificationRequest::from_der(&csr).unwrap();
                        parsed.verify_signature().unwrap();
                        let public = Public(parsed.certification_request_info.subject_pki.subject_public_key.data.to_vec());
                        let cert = CertificateParams::new(vec!["order.example.com".into()]).unwrap().signed_by(&public, &ca).unwrap();
                        certificate = cert.pem();
                        if plan.bad_nonce {
                            plan.bad_nonce = false;
                            status = 400;
                            json!({"type": "urn:ietf:params:acme:error:badNonce"}).to_string()
                        } else if let Some((code, problem)) = plan.rejection.as_ref().filter(|_| !rejected || plan.always_reject) {
                            rejected = true;
                            status = *code;
                            problem.to_string()
                        } else {
                            let error = (plan.finalized_status == "invalid").then(|| json!({"type": "urn:ietf:params:acme:error:badCSR", "detail": "terminal rejection"}));
                            json!({"status": plan.finalized_status, "certificate": format!("{base}/certificate"), "error": error}).to_string()
                        }
                    }
                    "/certificate" => certificate.clone(),
                    _ => { status = 404; String::new() }
                };
                let reply = format!(
                    "HTTP/1.1 {status} Test\r\nReplay-Nonce: bm9uY2U\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(reply.as_bytes()).await;
            }
        });
        Self {
            url,
            state,
            entered,
            closed,
            task,
        }
    }
    fn count(&self, path: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .paths
            .iter()
            .filter(|p| *p == path)
            .count()
    }
}
#[derive(Default)]
struct Probe {
    present: AtomicUsize,
    cleanup: AtomicUsize,
}
#[async_trait::async_trait]
impl Solver for Probe {
    async fn present(&self, _: &str, _: &str, _: &str) -> certon::Result<()> {
        self.present.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn cleanup(&self, _: &str, _: &str, _: &str) -> certon::Result<()> {
        self.cleanup.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
fn issuer(
    server: &Server,
    storage: Arc<FileStorage>,
    probe: Arc<Probe>,
    timeout: Duration,
) -> AcmeIssuer {
    let ca = format!("{}/directory", server.url);
    AcmeIssuer::builder()
        .ca(&ca)
        .test_ca(&ca)
        .email("order@example.com")
        .agreed(true)
        .storage(storage)
        .http01_solver(probe)
        .disable_distributed_solvers(true)
        .cert_obtain_timeout(timeout)
        .build()
}
fn successful(issued: certon::IssuedCertificate) {
    let parsed =
        certon::Certificate::from_pem(&issued.certificate_pem, &issued.private_key_pem).unwrap();
    let (_, leaf) =
        x509_parser::certificate::X509Certificate::from_der(parsed.cert_chain[0].as_ref()).unwrap();
    let decoded = certon::crypto::decode_private_key_pem(
        std::str::from_utf8(&issued.private_key_pem).unwrap(),
    )
    .unwrap();
    let private = KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls::pki_types::PrivatePkcs8KeyDer::from(decoded.pkcs8_der()),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .unwrap();
    assert_eq!(
        leaf.public_key().subject_public_key.data.as_ref(),
        private.der_bytes()
    );
}
fn once(server: &Server, probe: &Probe) {
    assert_eq!(server.count("/new-order"), 1);
    assert_eq!(server.count("/account"), 1);
    assert_eq!(probe.present.load(Ordering::SeqCst), 1);
    assert_eq!(probe.cleanup.load(Ordering::SeqCst), 1);
    let state = server.state.lock().unwrap();
    assert!(state.csrs.windows(2).all(|csrs| csrs[0] == csrs[1]));
    let account = format!("{}/registered", server.url);
    assert!(
        state
            .protected
            .iter()
            .skip(1)
            .all(|header| header["kid"] == account)
    );
}

#[tokio::test]
async fn normal_finalization_keeps_its_single_request_fast_path() {
    let server = Server::new(Plan::ready()).await;
    let directory = tempfile::tempdir().unwrap();
    let probe = Arc::new(Probe::default());
    let issuer = issuer(
        &server,
        Arc::new(FileStorage::new(directory.path())),
        probe.clone(),
        Duration::from_secs(10),
    );
    successful(
        issuer
            .issue_for_domains(&["order.example.com".into()])
            .await
            .unwrap(),
    );
    assert_eq!(server.count("/finalize"), 1);
    assert_eq!(server.count("/order"), 0);
    once(&server, &probe);
}

#[tokio::test]
async fn not_ready_continues_the_same_order_until_pending_ready_processing_or_terminal() {
    for statuses in [
        &["pending", "ready"][..],
        &["processing", "valid"],
        &["valid"],
        &["invalid"],
        &["unexpected"],
    ] {
        let server = Server::new(Plan::recovery(statuses)).await;
        let directory = tempfile::tempdir().unwrap();
        let probe = Arc::new(Probe::default());
        let issuer = issuer(
            &server,
            Arc::new(FileStorage::new(directory.path())),
            probe.clone(),
            Duration::from_secs(12),
        );
        let result = issuer
            .issue_for_domains(&["order.example.com".into()])
            .await;
        if statuses.last() == Some(&"invalid") || statuses.last() == Some(&"unexpected") {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("terminal rejection")
            );
            assert_eq!(server.count("/finalize"), 1);
        } else {
            successful(result.unwrap());
        }
        assert_eq!(server.count("/order"), statuses.len());
        assert_eq!(
            server.count("/finalize"),
            if statuses.last() == Some(&"ready") {
                2
            } else {
                1
            }
        );
        once(&server, &probe);
    }
}

#[tokio::test]
async fn not_ready_requires_actual_403_and_exact_problem_type() {
    for (code, problem) in [
        (
            403,
            json!({"type":"urn:ietf:params:acme:error:unauthorized","detail":"orderNotReady"}),
        ),
        (403, json!({"type":"urn:vendor:orderNotReady"})),
        (400, json!({"type":NOT_READY,"status":403})),
        (500, json!({"type":NOT_READY})),
        (403, json!({"not-a-problem":"orderNotReady"})),
    ] {
        let mut plan = Plan::ready();
        plan.rejection = Some((code, problem));
        let server = Server::new(plan).await;
        let directory = tempfile::tempdir().unwrap();
        let probe = Arc::new(Probe::default());
        let issuer = issuer(
            &server,
            Arc::new(FileStorage::new(directory.path())),
            probe.clone(),
            Duration::from_secs(5),
        );
        assert!(
            issuer
                .issue_for_domains(&["order.example.com".into()])
                .await
                .is_err()
        );
        assert_eq!(server.count("/order"), 0);
        assert_eq!(server.count("/finalize"), 1);
        once(&server, &probe);
    }
}

#[tokio::test]
async fn bad_nonce_then_not_ready_uses_http_status_and_preserves_public_finalize_errors() {
    let mut plan = Plan::recovery(&["ready"]);
    plan.bad_nonce = true;
    plan.rejection = Some((403, json!({"type":NOT_READY,"status":400})));
    let server = Server::new(plan).await;
    let directory = tempfile::tempdir().unwrap();
    let probe = Arc::new(Probe::default());
    let storage = Arc::new(FileStorage::new(directory.path()));
    let issuer = issuer(&server, storage, probe.clone(), Duration::from_secs(8));
    successful(
        issuer
            .issue_for_domains(&["order.example.com".into()])
            .await
            .unwrap(),
    );
    assert_eq!(server.count("/finalize"), 3);
    assert_eq!(server.count("/order"), 1);
    once(&server, &probe);
    let server = Server::new(Plan::recovery(&["ready"])).await;
    let ca = format!("{}/directory", server.url);
    let client = AcmeClient::new(&ca).await.unwrap();
    let key = certon::crypto::generate_private_key(certon::KeyType::EcdsaP256).unwrap();
    let csr = certon::crypto::generate_csr(&key, &["order.example.com".into()], false).unwrap();
    let error = client
        .finalize_order(
            &key,
            &format!("{}/registered", server.url),
            &format!("{}/finalize", server.url),
            &csr,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("orderNotReady"));
    assert_eq!(server.count("/order"), 0);
}

#[tokio::test]
async fn repeated_ready_rejections_are_bounded_by_one_issuance_deadline() {
    let mut plan = Plan::recovery(&["ready"]);
    plan.always_reject = true;
    let server = Server::new(plan).await;
    let directory = tempfile::tempdir().unwrap();
    let probe = Arc::new(Probe::default());
    let issuer = issuer(
        &server,
        Arc::new(FileStorage::new(directory.path())),
        probe.clone(),
        Duration::from_millis(1600),
    );
    let start = tokio::time::Instant::now();
    assert!(matches!(
        issuer
            .issue_for_domains(&["order.example.com".into()])
            .await,
        Err(certon::Error::Timeout(_))
    ));
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!((1..=2).contains(&server.count("/finalize")));
    assert_eq!(server.count("/order"), server.count("/finalize"));
    once(&server, &probe);
}

#[tokio::test]
async fn cancellation_drops_the_inflight_finalization_and_stops_order_requests() {
    let mut plan = Plan::ready();
    plan.stalled = true;
    let server = Server::new(plan).await;
    let directory = tempfile::tempdir().unwrap();
    let probe = Arc::new(Probe::default());
    let issuer = Arc::new(issuer(
        &server,
        Arc::new(FileStorage::new(directory.path())),
        probe.clone(),
        Duration::from_secs(10),
    ));
    let request = issuer.clone();
    let task = tokio::spawn(async move {
        request
            .issue_for_domains(&["order.example.com".into()])
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), server.entered.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(3), server.closed.notified())
        .await
        .unwrap();
    assert_eq!(server.count("/finalize"), 1);
    assert_eq!(server.count("/order"), 0);
    once(&server, &probe);
}

#[tokio::test]
async fn ordinary_processing_finalization_keeps_its_immediate_first_order_poll() {
    let mut plan = Plan::ready();
    plan.finalized_status = "processing";
    plan.statuses.push_back("valid");
    let server = Server::new(plan).await;
    let directory = tempfile::tempdir().unwrap();
    let probe = Arc::new(Probe::default());
    let issuer = issuer(
        &server,
        Arc::new(FileStorage::new(directory.path())),
        probe.clone(),
        Duration::from_secs(3),
    );
    successful(
        issuer
            .issue_for_domains(&["order.example.com".into()])
            .await
            .unwrap(),
    );
    assert_eq!(server.count("/finalize"), 1);
    assert_eq!(server.count("/order"), 1);
    once(&server, &probe);
}

#[tokio::test]
async fn recovery_request_cancellation_and_timeout_close_the_same_order_socket() {
    for cancel in [false, true] {
        let mut plan = Plan::recovery(&[]);
        plan.stalled_order = true;
        let server = Server::new(plan).await;
        let directory = tempfile::tempdir().unwrap();
        let probe = Arc::new(Probe::default());
        let issuer = Arc::new(issuer(
            &server,
            Arc::new(FileStorage::new(directory.path())),
            probe.clone(),
            if cancel {
                Duration::from_secs(10)
            } else {
                Duration::from_millis(1500)
            },
        ));
        let request = issuer.clone();
        let task = tokio::spawn(async move {
            request
                .issue_for_domains(&["order.example.com".into()])
                .await
        });
        tokio::time::timeout(Duration::from_secs(3), server.entered.notified())
            .await
            .unwrap();
        if cancel {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            assert!(matches!(
                task.await.unwrap(),
                Err(certon::Error::Timeout(_))
            ));
        }
        tokio::time::timeout(Duration::from_secs(3), server.closed.notified())
            .await
            .unwrap();
        assert_eq!(server.count("/finalize"), 1);
        assert_eq!(server.count("/order"), 1);
        once(&server, &probe);
    }
}

#[tokio::test]
async fn initial_invalid_finalization_keeps_its_error_and_public_poll_still_waits_for_valid() {
    let mut plan = Plan::ready();
    plan.finalized_status = "invalid";
    let server = Server::new(plan).await;
    let directory = tempfile::tempdir().unwrap();
    let probe = Arc::new(Probe::default());
    let issuer = issuer(
        &server,
        Arc::new(FileStorage::new(directory.path())),
        probe.clone(),
        Duration::from_secs(5),
    );
    let error = issuer
        .issue_for_domains(&["order.example.com".into()])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("terminal rejection"));
    assert_eq!(server.count("/order"), 0);
    assert_eq!(server.count("/finalize"), 1);
    once(&server, &probe);
    let client = AcmeClient::new(&format!("{}/directory", server.url))
        .await
        .unwrap();
    let key = certon::crypto::generate_private_key(certon::KeyType::EcdsaP256).unwrap();
    let result = client
        .poll_order(
            &key,
            &format!("{}/registered", server.url),
            &format!("{}/order", server.url),
            Duration::from_millis(500),
        )
        .await;
    assert!(matches!(result, Err(certon::Error::Timeout(_))));
    assert_eq!(server.count("/order"), 1);
}

#[tokio::test]
async fn oversized_not_ready_problem_remains_an_order_error_without_recovery() {
    let mut plan = Plan::ready();
    plan.rejection = Some((403, json!({"type":NOT_READY,"detail":"x".repeat(128*1024)})));
    let server = Server::new(plan).await;
    let directory = tempfile::tempdir().unwrap();
    let probe = Arc::new(Probe::default());
    let issuer = issuer(
        &server,
        Arc::new(FileStorage::new(directory.path())),
        probe.clone(),
        Duration::from_secs(5),
    );
    let error = issuer
        .issue_for_domains(&["order.example.com".into()])
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        certon::Error::Acme(certon::error::AcmeError::Order(_))
    ));
    assert!(error.to_string().contains("exceeds"));
    assert_eq!(server.count("/order"), 0);
    assert_eq!(server.count("/finalize"), 1);
    once(&server, &probe);
}
