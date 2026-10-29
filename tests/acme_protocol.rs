use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use certon::acme_client::AcmeClient;
use certon::{AcmeIssuer, CertIssuer, FileStorage, KeyType};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn round9_account_thumbprint(account: &certon::account::AcmeAccount) -> String {
    let key = certon::crypto::decode_private_key_pem(&account.private_key_pem).unwrap();
    certon::acme_client::key_authorization("identity", &key).unwrap()
}

#[tokio::test]
async fn explicitly_migrated_ca_account_recovers_without_resurrecting_legacy_identity() {
    use certon::Storage;
    let server = Server::start(false).await;
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(FileStorage::new(directory.path()));
    let ca = format!("{}/directory", server.url);
    let mut original =
        certon::account::new_account("review@example.com", KeyType::EcdsaP256).unwrap();
    original.location = format!("{}/account/old", server.url);
    original.status = "valid".into();
    let old_key = format!(
        "acme/{}/users/review@example.com/_certon/account.v1.key",
        certon::storage::safe_key(&certon::storage::legacy_issuer_key(&ca))
    );
    let old_bytes = serde_json::to_vec(
        &json!({"version":1,"registration":original,"private_key_pem":original.private_key_pem}),
    )
    .unwrap();
    storage.store(&old_key, &old_bytes).await.unwrap();
    certon::account::migrate_account_ca_identity(
        storage.clone(),
        &ca,
        "review@example.com",
        &original,
    )
    .await
    .unwrap();
    server.order_problem_responses.lock().unwrap().push_back((
        400,
        json!({"type":"urn:ietf:params:acme:error:accountDoesNotExist"}).to_string(),
    ));
    let supplied = rcgen::KeyPair::generate().unwrap().serialize_pem();
    let build = || {
        AcmeIssuer::builder()
            .ca(&ca)
            .test_ca(&ca)
            .storage(storage.clone())
            .email("review@example.com")
            .agreed(true)
            .account_key_pem(supplied.clone())
            .build()
    };
    let issuer = build();
    issuer
        .issue(b"csr", &["review.example.com".into()])
        .await
        .unwrap();
    let recovered = certon::account::get_account(storage.as_ref(), &ca, "review@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        round9_account_thumbprint(&recovered),
        round9_account_thumbprint(&original)
    );
    assert_ne!(recovered.location, original.location);
    assert_eq!(storage.load(&old_key).await.unwrap(), old_bytes);
    drop(issuer);
    build()
        .issue(b"csr", &["review.example.com".into()])
        .await
        .unwrap();
    let reloaded = certon::account::get_account(storage.as_ref(), &ca, "review@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        round9_account_thumbprint(&reloaded),
        round9_account_thumbprint(&recovered)
    );
    assert_eq!(reloaded.location, recovered.location);
    let requests = server.requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.path == "/new-account")
            .count(),
        1
    );
    let orders: Vec<_> = requests
        .iter()
        .filter(|request| request.path == "/new-order")
        .collect();
    assert_eq!(orders.len(), 3);
    assert_eq!(orders[0].protected["kid"], original.location);
    assert!(
        orders[1..]
            .iter()
            .all(|request| request.protected["kid"] == recovered.location)
    );
}

#[tokio::test]
async fn round9_only_the_exact_account_missing_problem_may_replace_a_persisted_account() {
    let missing = "urn:ietf:params:acme:error:accountDoesNotExist";
    let unauthorized = "urn:ietf:params:acme:error:unauthorized";
    let cases = [
        (
            "unauthorized-control",
            403,
            unauthorized,
            "policy rejected",
            false,
        ),
        (
            "unauthorized-detail",
            403,
            unauthorized,
            "the prior accountDoesNotExist incident is unrelated to this policy rejection",
            false,
        ),
        (
            "server-error-detail",
            500,
            "urn:ietf:params:acme:error:serverInternal",
            "accountDoesNotExist metrics unavailable; account remains valid",
            false,
        ),
        (
            "nonstandard-type",
            400,
            "urn:vendor:accountDoesNotExist",
            "this is not the standard account missing error",
            false,
        ),
        ("exact-type-on-403", 403, missing, "account removed", false),
        ("exact-type-on-500", 500, missing, "account removed", false),
        (
            "exact-missing-control",
            400,
            missing,
            "account removed",
            true,
        ),
    ];
    let mut violations = Vec::new();
    let mut scenarios: Vec<_> = cases
        .into_iter()
        .map(|(label, status, problem_type, detail, may_replace)| {
            (
                label,
                status,
                json!({"type":problem_type,"detail":detail}).to_string(),
                may_replace,
                false,
            )
        })
        .collect();
    scenarios.extend([
        (
            "malformed-json-400",
            400,
            "not JSON: accountDoesNotExist".into(),
            false,
            false,
        ),
        (
            "malformed-json-500",
            500,
            "not JSON: accountDoesNotExist".into(),
            false,
            false,
        ),
        (
            "request-url-token",
            403,
            json!({"type":unauthorized,"detail":"policy rejected"}).to_string(),
            false,
            true,
        ),
    ]);
    for (label, status, body, may_replace, token_in_url) in scenarios {
        for bad_nonce_first in [false, true] {
            let server = Server::start(false).await;
            if token_in_url {
                *server.order_path.lock().unwrap() = "/new-order/accountDoesNotExist".into();
            }
            {
                let mut responses = server.order_problem_responses.lock().unwrap();
                if bad_nonce_first {
                    responses.push_back((400,json!({"type":"urn:ietf:params:acme:error:badNonce","detail":"retry nonce"}).to_string()));
                }
                responses.push_back((status, body.clone()));
            }
            let directory = tempfile::tempdir().unwrap();
            let storage = Arc::new(FileStorage::new(directory.path()));
            let ca = format!("{}/directory", server.url);
            let mut original =
                certon::account::new_account("review@example.com", KeyType::EcdsaP256).unwrap();
            original.location = format!("{}/account/old", server.url);
            original.status = "valid".into();
            certon::account::save_account(storage.as_ref(), &ca, &original)
                .await
                .unwrap();
            let old_thumbprint = round9_account_thumbprint(&original);
            let supplied = rcgen::KeyPair::generate().unwrap().serialize_pem();
            let issuer = AcmeIssuer::builder()
                .ca(&ca)
                .test_ca(&ca)
                .storage(storage.clone())
                .email("review@example.com")
                .agreed(true)
                .account_key_pem(supplied.clone())
                .build();
            let outcome = issuer.issue(b"csr", &["review.example.com".into()]).await;
            let current = certon::account::get_account(storage.as_ref(), &ca, "review@example.com")
                .await
                .unwrap()
                .unwrap();
            let current_thumbprint = round9_account_thumbprint(&current);
            let key_changed = current_thumbprint != old_thumbprint;
            let location_changed = current.location != original.location;
            let registrations_before_restart = server
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|request| request.path == "/new-account")
                .count();
            // Recreating the issuer proves this is persistent account replacement,
            // rather than an in-memory account-cache observation.
            drop(issuer);
            let recreated = AcmeIssuer::builder()
                .ca(&ca)
                .test_ca(&ca)
                .storage(storage.clone())
                .email("review@example.com")
                .agreed(true)
                .account_key_pem(supplied)
                .build();
            recreated
                .issue(b"csr", &["review.example.com".into()])
                .await
                .unwrap();
            let reloaded =
                certon::account::get_account(storage.as_ref(), &ca, "review@example.com")
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(round9_account_thumbprint(&reloaded), current_thumbprint);
            assert_eq!(reloaded.location, current.location);
            let requests = server.requests.lock().unwrap();
            let registrations = requests
                .iter()
                .filter(|request| request.path == "/new-account")
                .count();
            assert_eq!(registrations, registrations_before_restart);
            let orders = requests
                .iter()
                .filter(|request| request.path.starts_with("/new-order"))
                .count();
            assert_eq!(
                orders,
                2 + usize::from(bad_nonce_first) + usize::from(may_replace),
                "{label}, bad_nonce_first={bad_nonce_first}: only one nonce retry and one exact missing-account recovery are allowed"
            );
            assert_eq!(
                outcome.is_ok(),
                may_replace,
                "{label}, bad_nonce_first={bad_nonce_first}: non-target errors must propagate"
            );
            eprintln!(
                "case={label} status={status} bad_nonce_first={bad_nonce_first} initial_issue_ok={} persisted_key_changed={key_changed} persisted_location_changed={location_changed} registrations={registrations} new_orders_including_restart={orders} restart_preserved_current_identity=true",
                outcome.is_ok()
            );
            if key_changed != may_replace
                || location_changed != may_replace
                || registrations != usize::from(may_replace)
            {
                violations.push(label);
            }
        }
    }
    assert!(
        violations.is_empty(),
        "non-authoritative error text replaced valid persisted accounts: {violations:?}"
    );
}

#[tokio::test]
async fn public_new_order_still_reports_account_missing_as_an_order_error() {
    for bad_nonce_first in [false, true] {
        let server = Server::start(false).await;
        {
            let mut responses = server.order_problem_responses.lock().unwrap();
            if bad_nonce_first {
                responses.push_back((400,json!({"type":"urn:ietf:params:acme:error:badNonce","detail":"fresh nonce required"}).to_string()));
            }
            responses.push_back((400,json!({"type":"urn:ietf:params:acme:error:accountDoesNotExist","detail":"public-error-detail"}).to_string()));
        }
        let client = AcmeClient::new(&format!("{}/directory", server.url))
            .await
            .unwrap();
        let key = certon::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
        let error = client
            .new_order(
                &key,
                &format!("{}/account/existing", server.url),
                &["review.example.com".into()],
            )
            .await
            .unwrap_err();
        assert!(matches!(
            &error,
            certon::Error::Acme(certon::error::AcmeError::Order(_))
        ));
        assert!(
            error.to_string().contains("accountDoesNotExist")
                && error.to_string().contains("public-error-detail")
        );
        let requests = server.requests.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.path == "/new-order")
                .count(),
            1 + usize::from(bad_nonce_first)
        );
        assert!(
            !requests
                .iter()
                .any(|request| request.path == "/new-account")
        );
    }
}

#[tokio::test]
async fn account_recovery_retries_order_creation_only_once() {
    let server = Server::start(false).await;
    for _ in 0..2 {
        server.order_problem_responses.lock().unwrap().push_back((400,json!({"type":"urn:ietf:params:acme:error:accountDoesNotExist","detail":"account removed"}).to_string()));
    }
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(FileStorage::new(directory.path()));
    let ca = format!("{}/directory", server.url);
    let mut original =
        certon::account::new_account("review@example.com", KeyType::EcdsaP256).unwrap();
    original.location = format!("{}/account/old", server.url);
    original.status = "valid".into();
    certon::account::save_account(storage.as_ref(), &ca, &original)
        .await
        .unwrap();
    let issuer = AcmeIssuer::builder()
        .ca(&ca)
        .test_ca(&ca)
        .email("review@example.com")
        .agreed(true)
        .storage(storage.clone())
        .build();
    let error = issuer
        .issue(b"csr", &["review.example.com".into()])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("accountDoesNotExist"));
    let current = certon::account::get_account(storage.as_ref(), &ca, "review@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        round9_account_thumbprint(&current),
        round9_account_thumbprint(&original)
    );
    let requests = server.requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.path == "/new-order")
            .count(),
        2
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.path == "/new-account")
            .count(),
        1
    );
}

#[tokio::test]
async fn account_lookup_accepts_only_the_exact_missing_account_problem() {
    for (status,body,missing) in [
        (400,json!({"type":"urn:ietf:params:acme:error:accountDoesNotExist","detail":"missing"}).to_string(),true),
        (400,json!({"type":"urn:vendor:accountDoesNotExist","detail":"foreign problem"}).to_string(),false),
        (400,json!({"type":"urn:ietf:params:acme:error:unauthorized","detail":"accountDoesNotExist text is unrelated"}).to_string(),false),
        (400,"accountDoesNotExist is not JSON".into(),false),
        (403,json!({"type":"urn:ietf:params:acme:error:accountDoesNotExist","detail":"wrong status"}).to_string(),false),
    ] {
        let server=Server::start(false).await;
        server.lookup_responses.lock().unwrap().push_back((status,body));
        let client=AcmeClient::new(&format!("{}/directory",server.url)).await.unwrap();
        let key=certon::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
        let result=client.find_account(&key).await;
        if missing { assert!(matches!(result,Ok(None))); }
        else { assert!(matches!(result,Err(certon::Error::Acme(certon::error::AcmeError::Account(_))))); }
        // Ordinary account lookup remains a public successful Option result.
        assert!(client.find_account(&key).await.unwrap().is_some());
    }
}

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
    order_problem_responses: Arc<Mutex<std::collections::VecDeque<(u16, String)>>>,
    lookup_responses: Arc<Mutex<std::collections::VecDeque<(u16, String)>>>,
    order_path: Arc<Mutex<String>>,
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
        let order_problem_responses = Arc::new(Mutex::new(std::collections::VecDeque::<(
            u16,
            String,
        )>::new()));
        let order_problems = order_problem_responses.clone();
        let lookup_responses = Arc::new(Mutex::new(
            std::collections::VecDeque::<(u16, String)>::new(),
        ));
        let account_lookups = lookup_responses.clone();
        let order_path = Arc::new(Mutex::new("/new-order".to_string()));
        let response_order_path = order_path.clone();
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
                        "newOrder": format!("{base}{}",response_order_path.lock().unwrap()), "revokeCert": format!("{base}/revoke"),
                        "keyChange": format!("{base}/key-change"), "renewalInfo": format!("{base}/ari")
                    }).to_string(),
                    "/nonce" => String::new(),
                    "/new-account" => {
                        let response=account_lookups.lock().unwrap().pop_front();
                        if let Some((code,body))=response { status=code;body } else {
                            extra = format!("Location: {base}/account/new\r\n");
                            json!({"status":"valid", "contact":["mailto:review@example.com"]}).to_string()
                        }
                    }
                    path if path.starts_with("/new-order") => {
                        orders += 1;
                        let problem = order_problems.lock().unwrap().pop_front();
                        if let Some((code, body)) = problem {
                            status = code;
                            body
                        } else if recover && orders == 1 {
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
                    "/poll-stalled-authz" | "/poll-stalled-order" | "/poll-body-authz" | "/poll-body-order" => {
                        if path.contains("body") {
                            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nReplay-Nonce: poll-body\r\nContent-Length: 8192\r\nConnection: close\r\n\r\n{").await.unwrap();
                        }
                        let mut eof = [0; 1];
                        while stream.read(&mut eof).await.unwrap_or(0) != 0 {}
                        continue;
                    }
                    "/poll-retry-authz" | "/poll-retry-order" | "/poll-progress-authz" | "/poll-progress-order" => {
                        let count = recorded.lock().unwrap().iter().filter(|request| request.path == path).count();
                        if count == 1 && path.contains("retry") {
                            status = 400;
                            json!({"type":"urn:ietf:params:acme:error:badNonce", "detail":"try a new nonce"}).to_string()
                        } else if count == 1 {
                            if path.ends_with("authz") {
                                json!({"status":"pending", "identifier":{"type":"dns","value":"review.example.com"}}).to_string()
                            } else { json!({"status":"pending"}).to_string() }
                        } else {
                            let mut eof = [0; 1];
                            while stream.read(&mut eof).await.unwrap_or(0) != 0 {}
                            continue;
                        }
                    }
                    "/poll-valid-order" => json!({"status":"valid", "certificate":format!("{base}/cert")}).to_string(),
                    "/poll-invalid-authz" => json!({"status":"invalid", "identifier":{"type":"dns","value":"review.example.com"}, "challenges":[{"type":"http-01", "url":format!("{base}/challenge"), "token":"token", "error":{"type":"urn:ietf:params:acme:error:unauthorized", "detail":"proof rejected"}}]}).to_string(),
                    "/poll-invalid-order" => json!({"status":"invalid", "error":{"type":"urn:ietf:params:acme:error:rejectedIdentifier", "detail":"order rejected"}}).to_string(),
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
            order_problem_responses,
            lookup_responses,
            order_path,
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

#[tokio::test]
async fn identity_contacts_can_change_or_clear_without_registering_again() {
    for contact_mode in [0, 1, 2] {
        let server = Server::start(false).await;
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(FileStorage::new(directory.path()));
        let ca = format!("{}/directory", server.url);
        for _ in 0..2 {
            let issuer = AcmeIssuer::builder()
                .ca(&ca)
                .test_ca(&ca)
                .storage(storage.clone())
                .email("original@example.com")
                .agreed(true)
                .new_account_func(Arc::new(move |account| {
                    if contact_mode == 1 {
                        account.contact = vec!["mailto:replacement@example.com".into()];
                    }
                    if contact_mode == 2 {
                        account.contact.clear();
                    }
                }))
                .build();
            issuer
                .issue(b"csr", &["review.example.com".into()])
                .await
                .unwrap();
        }
        let requests = server.requests.lock().unwrap();
        let registrations = requests
            .iter()
            .filter(|request| request.path == "/new-account")
            .count();
        let keys: std::collections::HashSet<_> = requests
            .iter()
            .filter(|request| request.path == "/new-account")
            .map(|request| request.protected["jwk"].to_string())
            .collect();
        eprintln!(
            "contact_mode={contact_mode} registrations={registrations} keys={}",
            keys.len()
        );
        assert_eq!(
            registrations, 1,
            "recreating an issuer must preserve its account identity"
        );
        assert_eq!(keys.len(), 1);
    }
}

fn contact_issuer(
    server: &Server,
    storage: Arc<dyn certon::Storage>,
    key: Option<String>,
    clear: bool,
) -> AcmeIssuer {
    let ca = format!("{}/directory", server.url);
    let mut builder = AcmeIssuer::builder()
        .ca(&ca)
        .test_ca(&ca)
        .storage(storage)
        .email("original@example.com")
        .agreed(true)
        .new_account_func(Arc::new(move |account| {
            account.contact = if clear {
                Vec::new()
            } else {
                vec!["mailto:replacement@example.com".into()]
            };
        }));
    if let Some(key) = key {
        builder = builder.account_key_pem(key);
    }
    builder.build()
}

#[tokio::test]
async fn identity_matching_legacy_contact_and_key_migrate_without_registration() {
    for clear in [false, true] {
        let server = Server::start(false).await;
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(FileStorage::new(directory.path()));
        let ca = format!("{}/directory", server.url);
        let email = if clear { "" } else { "replacement@example.com" };
        let mut legacy = certon::account::new_account(email, KeyType::EcdsaP256).unwrap();
        legacy.status = "valid".into();
        legacy.location = format!("{}/account/legacy", server.url);
        certon::account::save_account(storage.as_ref(), &ca, &legacy)
            .await
            .unwrap();
        let decoded = certon::crypto::decode_private_key_pem(&legacy.private_key_pem).unwrap();
        let pkcs8 = pem::encode(&pem::Pem::new("PRIVATE KEY", decoded.pkcs8_der().to_vec()));
        assert_ne!(
            pkcs8, legacy.private_key_pem,
            "fixture must compare equivalent PEM encodings"
        );
        for _ in 0..2 {
            let issuer = contact_issuer(&server, storage.clone(), Some(pkcs8.clone()), clear);
            issuer
                .issue(b"csr", &["review.example.com".into()])
                .await
                .unwrap();
        }
        let canonical = certon::account::get_account(storage.as_ref(), &ca, "original@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(canonical.location, legacy.location);
        assert_eq!(canonical.private_key_pem, legacy.private_key_pem);
        assert!(
            certon::account::get_account(storage.as_ref(), &ca, email)
                .await
                .unwrap()
                .is_some(),
            "legacy alias remains readable"
        );
        let requests = server.requests.lock().unwrap();
        assert!(!requests.iter().any(|r| r.path == "/new-account"));
        assert!(
            requests
                .iter()
                .filter(|r| r.path == "/new-order")
                .all(|r| r.protected["kid"] == legacy.location)
        );
    }
}

#[tokio::test]
async fn identity_mismatched_supplied_or_callback_keys_do_not_adopt_legacy_accounts() {
    for mode in [0, 1, 2] {
        let server = Server::start(false).await;
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(FileStorage::new(directory.path()));
        let ca = format!("{}/directory", server.url);
        let mut legacy =
            certon::account::new_account("replacement@example.com", KeyType::EcdsaP256).unwrap();
        legacy.status = "valid".into();
        legacy.location = format!("{}/account/legacy", server.url);
        certon::account::save_account(storage.as_ref(), &ca, &legacy)
            .await
            .unwrap();
        let other = certon::account::new_account("other@example.com", KeyType::EcdsaP256)
            .unwrap()
            .private_key_pem;
        let mut issuer = contact_issuer(
            &server,
            storage.clone(),
            if mode == 0 {
                None
            } else if mode == 1 {
                Some(other.clone())
            } else {
                Some(legacy.private_key_pem.clone())
            },
            false,
        );
        if mode == 2 {
            issuer.new_account_func = Some(Arc::new(move |account| {
                account.contact = vec!["mailto:replacement@example.com".into()];
                account.private_key_pem = other.clone();
            }));
        }
        let error = issuer
            .issue(b"csr", &["review.example.com".into()])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("different key"), "{error}");
        assert!(
            certon::account::get_account(storage.as_ref(), &ca, "original@example.com")
                .await
                .unwrap()
                .is_none()
        );
        let after = certon::account::get_account(storage.as_ref(), &ca, "replacement@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.private_key_pem, legacy.private_key_pem);
        assert!(
            !server
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|r| r.path == "/new-account" || r.path == "/new-order")
        );
    }
}

#[tokio::test]
async fn identity_migrated_account_recovery_removes_invalid_alias_and_survives_restart() {
    let server = Server::start(true).await;
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(FileStorage::new(directory.path()));
    let ca = format!("{}/directory", server.url);
    let mut legacy =
        certon::account::new_account("replacement@example.com", KeyType::EcdsaP256).unwrap();
    legacy.status = "valid".into();
    legacy.location = format!("{}/account/old", server.url);
    certon::account::save_account(storage.as_ref(), &ca, &legacy)
        .await
        .unwrap();
    for _ in 0..2 {
        let issuer = contact_issuer(
            &server,
            storage.clone(),
            Some(legacy.private_key_pem.clone()),
            false,
        );
        issuer
            .issue(b"csr", &["review.example.com".into()])
            .await
            .unwrap();
    }
    let canonical = certon::account::get_account(storage.as_ref(), &ca, "original@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(canonical.location, format!("{}/account/new", server.url));
    assert_eq!(canonical.contact, legacy.contact);
    assert!(
        certon::account::get_account(storage.as_ref(), &ca, "replacement@example.com")
            .await
            .unwrap()
            .is_none()
    );
    let requests = server.requests.lock().unwrap();
    assert_eq!(
        requests.iter().filter(|r| r.path == "/new-account").count(),
        1
    );
    let orders: Vec<_> = requests.iter().filter(|r| r.path == "/new-order").collect();
    assert_eq!(orders.len(), 3);
    assert_eq!(orders[0].protected["kid"], legacy.location);
    assert!(
        orders[1..]
            .iter()
            .all(|r| r.protected["kid"] == canonical.location)
    );
}

#[tokio::test]
async fn identity_concurrent_issuers_with_changed_contacts_share_one_registration() {
    let server = Server::start(false).await;
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(FileStorage::new(directory.path()));
    let first = contact_issuer(&server, storage.clone(), None, false);
    let second = contact_issuer(&server, storage, None, false);
    let domains = vec!["review.example.com".into()];
    let (a, b) = tokio::join!(
        first.issue(b"csr", &domains),
        second.issue(b"csr", &domains)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(
        server
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path == "/new-account")
            .count(),
        1
    );
}

async fn assert_poll_timeout(authorization: bool, mode: &str) {
    let server = Server::start(false).await;
    let client = AcmeClient::new(&format!("{}/directory", server.url))
        .await
        .unwrap();
    let key = certon::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
    let account = format!("{}/account/1", server.url);
    let valid = if authorization {
        "/authz"
    } else {
        "/poll-valid-order"
    };
    let poll = |url: String, budget| {
        let client = &client;
        let key = &key;
        let account = &account;
        async move {
            if authorization {
                client
                    .poll_authorization(key, account, &url, budget)
                    .await
                    .map(|_| ())
            } else {
                client
                    .poll_order(key, account, &url, budget)
                    .await
                    .map(|_| ())
            }
        }
    };
    poll(format!("{}{valid}", server.url), Duration::from_secs(2))
        .await
        .unwrap();
    let path = format!(
        "/poll-{mode}-{}",
        if authorization { "authz" } else { "order" }
    );
    let (budget, outer) = if mode == "progress" {
        (Duration::from_millis(2500), Duration::from_millis(3500))
    } else {
        (Duration::from_millis(500), Duration::from_secs(3))
    };
    let result = tokio::time::timeout(outer, poll(format!("{}{path}", server.url), budget))
        .await
        .expect("polling missed its total deadline");
    assert!(
        matches!(result, Err(certon::Error::Timeout(_))),
        "{result:?}"
    );
    let count = server
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|request| request.path == path)
        .count();
    assert_eq!(
        count,
        if matches!(mode, "retry" | "progress") {
            2
        } else {
            1
        },
        "test must reach the stalled POST"
    );
    // Cancellation must release the stalled connection so the same serial
    // mock and client can complete another request, including nonce recovery.
    poll(format!("{}{valid}", server.url), Duration::from_secs(2))
        .await
        .unwrap();
}

#[tokio::test]
async fn polling_deadlines_include_stalled_http_requests() {
    for authorization in [true, false] {
        assert_poll_timeout(authorization, "stalled").await;
    }
}
#[tokio::test]
async fn polling_deadlines_include_stalled_response_bodies() {
    for authorization in [true, false] {
        assert_poll_timeout(authorization, "body").await;
    }
}
#[tokio::test]
async fn polling_deadlines_cover_bad_nonce_retries() {
    for authorization in [true, false] {
        assert_poll_timeout(authorization, "retry").await;
    }
}
#[tokio::test]
async fn polling_deadlines_are_not_reset_after_pending_status() {
    for authorization in [true, false] {
        assert_poll_timeout(authorization, "progress").await;
    }
}
#[tokio::test]
async fn polling_preserves_terminal_errors_and_accepts_a_large_ready_budget() {
    use certon::error::{AcmeError, Error};
    for authorization in [true, false] {
        let server = Server::start(false).await;
        let client = AcmeClient::new(&format!("{}/directory", server.url))
            .await
            .unwrap();
        let key = certon::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
        let account = format!("{}/account/1", server.url);
        if authorization {
            assert_eq!(
                client
                    .poll_authorization(
                        &key,
                        &account,
                        &format!("{}/authz", server.url),
                        Duration::MAX
                    )
                    .await
                    .unwrap()
                    .status,
                "valid"
            );
            let error = client
                .poll_authorization(
                    &key,
                    &account,
                    &format!("{}/poll-invalid-authz", server.url),
                    Duration::from_secs(2),
                )
                .await
                .unwrap_err();
            assert!(matches!(&error, Error::Acme(AcmeError::Authorization(_))));
            assert!(error.to_string().contains("proof rejected"));
        } else {
            assert_eq!(
                client
                    .poll_order(
                        &key,
                        &account,
                        &format!("{}/poll-valid-order", server.url),
                        Duration::MAX
                    )
                    .await
                    .unwrap()
                    .status,
                "valid"
            );
            let error = client
                .poll_order(
                    &key,
                    &account,
                    &format!("{}/poll-invalid-order", server.url),
                    Duration::from_secs(2),
                )
                .await
                .unwrap_err();
            assert!(matches!(&error, Error::Acme(AcmeError::Order(_))));
            assert!(error.to_string().contains("order rejected"));
        }
    }
}

#[tokio::test]
async fn distinct_configured_email_issuers_keep_signers_separate_through_recovery_and_restart() {
    let server = Server::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(FileStorage::new(dir.path()));
    let ca = format!("{}/directory", server.url);
    let plus = "operator+prod@example.com";
    let literal = "operator_plus_prod@example.com";
    let plus_key = rcgen::KeyPair::generate().unwrap();
    let literal_key = rcgen::KeyPair::generate().unwrap();
    let replacement_key = rcgen::KeyPair::generate().unwrap();
    let mut first = certon::account::new_account(plus, KeyType::EcdsaP256).unwrap();
    first.status = "valid".into();
    first.location = format!("{}/account/plus", server.url);
    first.private_key_pem = plus_key.serialize_pem();
    let mut second = certon::account::new_account(literal, KeyType::EcdsaP256).unwrap();
    second.status = "valid".into();
    second.location = format!("{}/account/literal", server.url);
    second.private_key_pem = literal_key.serialize_pem();
    certon::account::save_account(storage.as_ref(), &ca, &first)
        .await
        .unwrap();
    certon::account::save_account(storage.as_ref(), &ca, &second)
        .await
        .unwrap();
    let build = |email: &str| {
        AcmeIssuer::builder()
            .ca(&ca)
            .test_ca(&ca)
            .storage(Arc::new(FileStorage::new(dir.path())))
            .email(email)
            .agreed(true)
            .account_key_pem(replacement_key.serialize_pem())
            .build()
    };
    for email in [plus, literal] {
        build(email)
            .issue(b"csr", &["review.example.com".into()])
            .await
            .unwrap();
    }
    server.order_problem_responses.lock().unwrap().push_back((
        400,
        json!({"type":"urn:ietf:params:acme:error:accountDoesNotExist"}).to_string(),
    ));
    build(plus)
        .issue(b"csr", &["review.example.com".into()])
        .await
        .unwrap();
    for email in [plus, literal] {
        build(email)
            .issue(b"csr", &["review.example.com".into()])
            .await
            .unwrap();
    }
    let kept = certon::account::get_account(storage.as_ref(), &ca, literal)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kept.location, second.location);
    assert_eq!(
        round9_account_thumbprint(&kept),
        round9_account_thumbprint(&second)
    );
    let recovered = certon::account::get_account(storage.as_ref(), &ca, plus)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.location, format!("{}/account/new", server.url));
    let mut expected = first.clone();
    expected.private_key_pem = replacement_key.serialize_pem();
    assert_eq!(
        round9_account_thumbprint(&recovered),
        round9_account_thumbprint(&expected)
    );
    assert_ne!(
        round9_account_thumbprint(&recovered),
        round9_account_thumbprint(&first)
    );
    let requests = server.requests.lock().unwrap();
    assert_eq!(
        requests.iter().filter(|r| r.path == "/new-account").count(),
        1
    );
    let orders: Vec<_> = requests.iter().filter(|r| r.path == "/new-order").collect();
    assert_eq!(orders.len(), 6);
    for (request, wanted) in orders.iter().zip([
        &first.location,
        &second.location,
        &first.location,
        &recovered.location,
        &recovered.location,
        &second.location,
    ]) {
        assert_eq!(&request.protected["kid"], wanted);
    }
    #[cfg(feature = "aws-lc-rs")]
    use aws_lc_rs as provider;
    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    use ring as provider;
    for request in requests.iter().filter(|r| r.method == "POST") {
        let public = if request.path == "/new-account" {
            replacement_key.public_key_raw()
        } else if request.protected["kid"] == first.location {
            plus_key.public_key_raw()
        } else if request.protected["kid"] == second.location {
            literal_key.public_key_raw()
        } else {
            assert_eq!(request.protected["kid"], recovered.location);
            replacement_key.public_key_raw()
        };
        provider::signature::UnparsedPublicKey::new(
            &provider::signature::ECDSA_P256_SHA256_FIXED,
            public,
        )
        .verify(&request.signing_input, &request.signature)
        .unwrap();
    }
}
