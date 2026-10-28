use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use certon::acme_client::AcmeClient;
use certon::{AcmeIssuer, CertIssuer, FileStorage, KeyType};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Debug)]
struct Request {
    method: String,
    path: String,
    protected: Value,
    payload: Value,
    signing_input: Vec<u8>,
    signature: Vec<u8>,
}

struct Server {
    url: String,
    requests: Arc<Mutex<Vec<Request>>>,
    task: tokio::task::JoinHandle<()>,
    revoke_responses: Arc<Mutex<std::collections::VecDeque<(u16, Value)>>>,
}

trait Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Stream for T {}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn start(recover: bool) -> Self {
        Self::start_transport(recover, None, false).await
    }

    async fn start_transport(
        recover: bool,
        tls: Option<rustls::ServerConfig>,
        pending: bool,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "{}://{}",
            if tls.is_some() { "https" } else { "http" },
            listener.local_addr().unwrap()
        );
        let acceptor = tls.map(|config| tokio_rustls::TlsAcceptor::from(Arc::new(config)));
        let requests = Arc::new(Mutex::new(Vec::<Request>::new()));
        let recorded = Arc::clone(&requests);
        let base = url.clone();
        let revoke_responses =
            Arc::new(Mutex::new(std::collections::VecDeque::<(u16, Value)>::new()));
        let responses = revoke_responses.clone();
        let task = tokio::spawn(async move {
            let mut orders = 0;
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let mut stream: Box<dyn Stream> = if let Some(acceptor) = &acceptor {
                    match acceptor.accept(socket).await {
                        Ok(stream) => Box::new(stream),
                        Err(_) => continue,
                    }
                } else {
                    Box::new(socket)
                };
                let mut input = Vec::new();
                let mut buffer = [0; 4096];
                let (head_len, body_len) = loop {
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert_ne!(count, 0);
                    input.extend_from_slice(&buffer[..count]);
                    if let Some(end) = input.windows(4).position(|part| part == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&input[..end]);
                        let len = header
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        break (end + 4, len);
                    }
                };
                while input.len() < head_len + body_len {
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert_ne!(count, 0);
                    input.extend_from_slice(&buffer[..count]);
                }
                let line = String::from_utf8_lossy(&input[..head_len]);
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap().to_string();
                let path = parts.next().unwrap().to_string();
                let jws: Value = serde_json::from_slice(&input[head_len..]).unwrap_or(Value::Null);
                let decode = |field: &str| -> Vec<u8> {
                    URL_SAFE_NO_PAD
                        .decode(jws[field].as_str().unwrap_or(""))
                        .unwrap()
                };
                let request = Request {
                    method,
                    path: path.clone(),
                    protected: serde_json::from_slice(&decode("protected")).unwrap_or(Value::Null),
                    payload: serde_json::from_slice(&decode("payload")).unwrap_or(Value::Null),
                    signing_input: format!(
                        "{}.{}",
                        jws["protected"].as_str().unwrap_or(""),
                        jws["payload"].as_str().unwrap_or("")
                    )
                    .into_bytes(),
                    signature: decode("signature"),
                };
                recorded.lock().unwrap().push(request);
                let mut status = 200;
                let mut extra = String::new();
                let body = match path.as_str() {
                    "/directory" => json!({
                        "newNonce": format!("{base}/nonce"), "newAccount": format!("{base}/new-account"),
                        "newOrder": format!("{base}/new-order"), "revokeCert": format!("{base}/revoke"),
                        "keyChange": format!("{base}/key-change"), "renewalInfo": format!("{base}/ari")
                    }).to_string(),
                    "/nonce" => String::new(),
                    "/new-account" => {
                        extra = format!("Location: {base}/account/new\r\n");
                        json!({"status":"valid", "contact":["mailto:review@example.com"]}).to_string()
                    }
                    "/new-order" => {
                        orders += 1;
                        if recover && orders == 1 {
                            status = 400;
                            json!({"type":"urn:ietf:params:acme:error:accountDoesNotExist", "detail":"account removed"}).to_string()
                        } else {
                            extra = format!("Location: {base}/order\r\n");
                            json!({"status":"ready", "authorizations":[format!("{base}/authz")], "finalize":format!("{base}/finalize")}).to_string()
                        }
                    }
                    "/authz" => if pending {
                        json!({"status":"pending", "identifier":{"type":"dns", "value":"review.example.com"}, "challenges":[{"type":"http-01", "url":format!("{base}/challenge"), "token":"token"}]}).to_string()
                    } else { json!({"status":"valid", "identifier":{"type":"dns", "value":"review.example.com"}}).to_string() },
                    "/finalize" => json!({"status":"valid", "certificate":format!("{base}/cert")}).to_string(),
                    "/cert" => "test certificate chain".into(),
                    "/revoke" => {
                        let response = responses.lock().unwrap().pop_front().unwrap_or((200, Value::Null));
                        status = response.0;
                        if response.1.is_null() { String::new() } else { response.1.to_string() }
                    }
                    "/ari/id" => {
                        extra = "Retry-After: 120\r\n".into();
                        json!({"suggestedWindow":{"start":"2026-01-01T00:00:00Z", "end":"2026-01-02T00:00:00Z"}, "retryAfter":999}).to_string()
                    }
                    _ => { status = 404; String::new() }
                };
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nReplay-Nonce: test-nonce-{orders}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        Self {
            url,
            requests,
            task,
            revoke_responses,
        }
    }
}

#[tokio::test]
async fn recovered_account_signs_all_following_requests_and_client_is_reused() {
    let server = Server::start(true).await;
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(FileStorage::new(directory.path()));
    let ca = format!("{}/directory", server.url);
    let mut old = certon::account::new_account("review@example.com", KeyType::EcdsaP256).unwrap();
    old.location = format!("{}/account/old", server.url);
    old.status = "valid".into();
    certon::account::save_account(storage.as_ref(), &ca, &old)
        .await
        .unwrap();
    let supplied = rcgen::KeyPair::generate().unwrap();
    let issuer = AcmeIssuer::builder()
        .ca(&ca)
        .test_ca(&ca)
        .storage(storage.clone())
        .email("review@example.com")
        .agreed(true)
        .account_key_pem(supplied.serialize_pem())
        .profile("shortlived")
        .not_before(Duration::from_secs(10))
        .not_after(Duration::from_secs(3600))
        .build();
    for _ in 0..2 {
        issuer
            .issue(b"csr", &["review.example.com".into()])
            .await
            .unwrap();
    }
    let account = certon::account::get_account(storage.as_ref(), &ca, "review@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(account.private_key_pem, supplied.serialize_pem());
    let requests = server.requests.lock().unwrap();
    assert_eq!(
        requests.iter().filter(|r| r.path == "/directory").count(),
        1
    );
    assert_eq!(requests.iter().filter(|r| r.path == "/nonce").count(), 1);
    assert_eq!(
        requests.iter().filter(|r| r.path == "/new-account").count(),
        1
    );
    let mut past_old_order = false;
    for request in requests.iter().filter(|r| r.method == "POST") {
        if request.path == "/new-order" && !past_old_order {
            past_old_order = true;
            continue;
        }
        if request.path != "/new-account" {
            assert_eq!(
                request.protected["kid"],
                format!("{}/account/new", server.url)
            );
        }
        #[cfg(feature = "aws-lc-rs")]
        use aws_lc_rs as provider;
        #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
        use ring as provider;
        provider::signature::UnparsedPublicKey::new(
            &provider::signature::ECDSA_P256_SHA256_FIXED,
            supplied.public_key_raw(),
        )
        .verify(&request.signing_input, &request.signature)
        .unwrap();
        if request.path == "/new-order" {
            assert_eq!(request.payload["profile"], "shortlived");
            let before = chrono::DateTime::parse_from_rfc3339(
                request.payload["notBefore"].as_str().unwrap(),
            )
            .unwrap();
            let after =
                chrono::DateTime::parse_from_rfc3339(request.payload["notAfter"].as_str().unwrap())
                    .unwrap();
            assert_eq!((after - before).num_seconds(), 3590);
        }
    }
}

#[tokio::test]
async fn ari_uses_unsigned_get_and_retry_after_header() {
    let server = Server::start(false).await;
    let client = AcmeClient::new(&format!("{}/directory", server.url))
        .await
        .unwrap();
    let key = certon::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
    let info = client.get_renewal_info(&key, "unused", "id").await.unwrap();
    assert_eq!(info.retry_after, Some(120));
    let requests = server.requests.lock().unwrap();
    let request = requests.iter().find(|r| r.path == "/ari/id").unwrap();
    assert_eq!(request.method, "GET");
    assert!(request.protected.is_null());
}

#[tokio::test]
async fn configured_total_timeout_bounds_a_stalled_directory_request() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ca = format!("http://{}/directory", listener.local_addr().unwrap());
    let directory = tempfile::tempdir().unwrap();
    let issuer = AcmeIssuer::builder()
        .storage(Arc::new(FileStorage::new(directory.path())))
        .ca(&ca)
        .test_ca(&ca)
        .cert_obtain_timeout(Duration::from_millis(50))
        .build();
    let error = tokio::time::timeout(
        Duration::from_secs(2),
        issuer.issue(b"csr", &["review.example.com".into()]),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(matches!(error, certon::Error::Timeout(_)));
}

#[test]
fn eab_debug_redacts_hmac_key() {
    let eab = certon::acme_client::ExternalAccountBinding {
        kid: "public-id".into(),
        hmac_key: b"secret-hmac-value".to_vec(),
    };
    let output = format!("{eab:?}");
    assert!(!output.contains(&format!("{:?}", eab.hmac_key)));
    assert!(output.contains("REDACTED"));
}

#[tokio::test]
async fn custom_ca_root_changes_real_https_trust() {
    certon::install_default_crypto_provider();
    let generated = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let root = generated.cert.der().clone();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![root.clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
    let server = Server::start_transport(false, Some(config), false).await;
    let directory = tempfile::tempdir().unwrap();
    let ca = format!("{}/directory", server.url);
    let build = || {
        AcmeIssuer::builder()
            .ca(&ca)
            .test_ca(&ca)
            .agreed(true)
            .email("review@example.com")
            .storage(Arc::new(FileStorage::new(directory.path())))
    };
    assert!(
        build()
            .build()
            .issue(b"csr", &["review.example.com".into()])
            .await
            .is_err()
    );
    let result = build()
        .trusted_roots(root.as_ref().to_vec())
        .build()
        .issue(b"csr", &["review.example.com".into()])
        .await
        .unwrap();
    assert_eq!(result.certificate_pem, b"test certificate chain");
}

struct HangingSolver {
    waiting: Arc<tokio::sync::Notify>,
    cleaned: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl certon::Solver for HangingSolver {
    async fn present(&self, _: &str, _: &str, _: &str) -> certon::Result<()> {
        Ok(())
    }
    async fn wait(&self, _: &str, _: &str, _: &str) -> certon::Result<()> {
        self.waiting.notify_one();
        std::future::pending().await
    }
    async fn cleanup(&self, _: &str, _: &str, _: &str) -> certon::Result<()> {
        self.cleaned.notify_one();
        Ok(())
    }
}

#[tokio::test]
async fn total_timeout_cleans_presented_challenge() {
    let server = Server::start_transport(false, None, true).await;
    let directory = tempfile::tempdir().unwrap();
    let ca = format!("{}/directory", server.url);
    let waiting = Arc::new(tokio::sync::Notify::new());
    let cleaned = Arc::new(tokio::sync::Notify::new());
    let issuer = AcmeIssuer::builder()
        .ca(&ca)
        .test_ca(&ca)
        .agreed(true)
        .storage(Arc::new(FileStorage::new(directory.path())))
        .http01_solver(Arc::new(HangingSolver {
            waiting: Arc::clone(&waiting),
            cleaned: Arc::clone(&cleaned),
        }))
        .cert_obtain_timeout(Duration::from_secs(30))
        .build();
    let mut issuance =
        tokio::spawn(async move { issuer.issue(b"csr", &["review.example.com".into()]).await });
    // Let real HTTP/account preparation finish before freezing the clock.
    // Otherwise a slow runner can expire the issuance budget before any
    // challenge exists and this test incorrectly demands its cleanup.
    tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(10), waiting.notified()) => {
            result.expect("issuance did not reach the presented challenge");
        }
        result = &mut issuance => panic!("issuance ended before challenge wait: {result:?}"),
    }
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    let result = issuance.await.unwrap();
    // Cleanup also performs real shared-storage I/O. Do not let automatic
    // virtual-time advancement outrun that I/O while waiting for its result.
    tokio::time::resume();
    assert!(matches!(result, Err(certon::Error::Timeout(_))));
    tokio::time::timeout(Duration::from_secs(5), cleaned.notified())
        .await
        .expect("the presented challenge was not cleaned after issuance timed out");
}

#[tokio::test]
async fn acme_revocation_accepts_only_the_exact_already_revoked_problem() {
    let server = Server::start(false).await;
    let client = AcmeClient::new(&format!("{}/directory", server.url))
        .await
        .unwrap();
    let supplied = rcgen::KeyPair::generate().unwrap();
    let key = certon::crypto::decode_private_key_pem(&supplied.serialize_pem()).unwrap();
    for (status, problem_type, succeeds) in [
        (400, "urn:ietf:params:acme:error:alreadyRevoked", true),
        (400, "urn:ietf:params:acme:error:unauthorized", false),
        (400, "urn:example:alreadyRevoked", false),
        (
            400,
            "urn:ietf:params:acme:error:alreadyRevokedSuffix",
            false,
        ),
        (500, "urn:ietf:params:acme:error:alreadyRevoked", false),
    ] {
        server.revoke_responses.lock().unwrap().push_back((
            status,
            json!({"type":problem_type,"detail":"alreadyRevoked text is not authoritative"}),
        ));
        assert_eq!(
            client
                .revoke_certificate(
                    &key,
                    &format!("{}/account", server.url),
                    b"certificate-der",
                    Some(1)
                )
                .await
                .is_ok(),
            succeeds,
            "status={status}, type={problem_type}"
        );
    }
    // A nonce retry must preserve the same narrowly accepted outcome.
    server.revoke_responses.lock().unwrap().extend([
        (400, json!({"type":"urn:ietf:params:acme:error:badNonce"})),
        (
            400,
            json!({"type":"urn:ietf:params:acme:error:alreadyRevoked"}),
        ),
    ]);
    client
        .revoke_certificate(
            &key,
            &format!("{}/account", server.url),
            b"certificate-der",
            Some(1),
        )
        .await
        .unwrap();
    let requests = server.requests.lock().unwrap();
    let revocations: Vec<_> = requests
        .iter()
        .filter(|request| request.path == "/revoke")
        .collect();
    assert_eq!(revocations.len(), 7);
    for request in revocations {
        assert_eq!(request.method, "POST");
        assert_eq!(request.protected["url"], format!("{}/revoke", server.url));
        assert_eq!(request.protected["kid"], format!("{}/account", server.url));
        assert_eq!(
            request.payload,
            json!({"certificate":URL_SAFE_NO_PAD.encode(b"certificate-der"),"reason":1})
        );
        #[cfg(feature = "aws-lc-rs")]
        use aws_lc_rs as provider;
        #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
        use ring as provider;
        provider::signature::UnparsedPublicKey::new(
            &provider::signature::ECDSA_P256_SHA256_FIXED,
            supplied.public_key_raw(),
        )
        .verify(&request.signing_input, &request.signature)
        .unwrap();
    }
}

struct ConfirmationFaultStorage {
    inner: Arc<dyn certon::Storage>,
    fail_confirmation: std::sync::atomic::AtomicBool,
}
#[async_trait::async_trait]
impl certon::Storage for ConfirmationFaultStorage {
    async fn store(&self, key: &str, value: &[u8]) -> certon::Result<()> {
        if key.starts_with("revocations/")
            && serde_json::from_slice::<Value>(value).unwrap()["confirmed"] == true
            && self
                .fail_confirmation
                .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(certon::Error::Other(
                "injected confirmation write failure".into(),
            ));
        }
        self.inner.store(key, value).await
    }
    async fn load(&self, key: &str) -> certon::Result<Vec<u8>> {
        self.inner.load(key).await
    }
    async fn delete(&self, key: &str) -> certon::Result<()> {
        self.inner.delete(key).await
    }
    async fn exists(&self, key: &str) -> certon::Result<bool> {
        self.inner.exists(key).await
    }
    async fn list(&self, path: &str, recursive: bool) -> certon::Result<Vec<String>> {
        self.inner.list(path, recursive).await
    }
    async fn stat(&self, key: &str) -> certon::Result<certon::storage::KeyInfo> {
        self.inner.stat(key).await
    }
    async fn lock(&self, name: &str) -> certon::Result<()> {
        self.inner.lock(name).await
    }
    async fn unlock(&self, name: &str) -> certon::Result<()> {
        self.inner.unlock(name).await
    }
}

#[tokio::test]
async fn acme_revocation_retries_confirmation_failure_and_cleans_up_already_revoked_leaf() {
    use certon::Storage;
    let server = Server::start(false).await;
    server.revoke_responses.lock().unwrap().extend([
        (200, Value::Null),
        (
            400,
            json!({"type":"urn:ietf:params:acme:error:alreadyRevoked"}),
        ),
    ]);
    let directory = tempfile::tempdir().unwrap();
    let inner = Arc::new(FileStorage::new(directory.path()));
    let storage = Arc::new(ConfirmationFaultStorage {
        inner: inner.clone(),
        fail_confirmation: true.into(),
    });
    let ca = format!("{}/directory", server.url);
    let issuer = Arc::new(
        AcmeIssuer::builder()
            .ca(&ca)
            .test_ca(&ca)
            .storage(storage.clone())
            .email("review@example.com")
            .agreed(true)
            .build(),
    );
    let manager = certon::CertManager::builder()
        .storage(storage)
        .issuers(vec![issuer.clone()])
        .ocsp(certon::OcspConfig {
            disable_stapling: true,
            ..Default::default()
        })
        .build();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["review.example.com".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let resource = certon::CertificateResource {
        sans: vec!["review.example.com".into()],
        certificate_pem: cert.pem().into_bytes(),
        private_key_pem: key.serialize_pem().into_bytes(),
        issuer_key: issuer.issuer_key(),
        issuer_data: None,
    };
    manager
        .certificates
        .save(&issuer.issuer_key(), &resource)
        .await
        .unwrap();
    manager
        .manage(&["review.example.com".into()])
        .await
        .unwrap();
    let first_error = manager
        .revoke("review.example.com", Some(1))
        .await
        .unwrap_err()
        .to_string();
    assert!(first_error.contains("confirmation write failure"));
    let marker_keys = inner.list("revocations", true).await.unwrap();
    assert_eq!(marker_keys.len(), 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&inner.load(&marker_keys[0]).await.unwrap()).unwrap()["confirmed"],
        false
    );
    assert!(manager.cache.get_all().await.is_empty());
    assert!(
        manager
            .load_certificate("review.example.com")
            .await
            .is_err()
    );
    manager.revoke("review.example.com", Some(1)).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&inner.load(&marker_keys[0]).await.unwrap()).unwrap()["confirmed"],
        true
    );
    assert!(
        manager
            .certificates
            .load(&issuer.issuer_key(), "review.example.com")
            .await
            .unwrap()
            .is_none()
    );
    let requests = server.requests.lock().unwrap();
    let revocations: Vec<_> = requests
        .iter()
        .filter(|request| request.path == "/revoke")
        .collect();
    assert_eq!(revocations.len(), 2);
    for request in revocations {
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(request.payload["certificate"].as_str().unwrap())
                .unwrap(),
            cert.der().as_ref()
        );
    }
}
