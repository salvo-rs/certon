use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use certon::acme_client::AcmeClient;
use certon::async_jobs::{RetryConfig, do_with_retry, should_retry};
use certon::error::AcmeError;
use certon::{Error, KeyType, Result};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PREFIX: &str = "urn:ietf:params:acme:error:";

#[derive(Clone)]
struct Reply(u16, String);

struct Server {
    base: String,
    posts: Arc<Mutex<Vec<(String, Value, Value)>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn start(replies: Vec<Reply>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let posts = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn({
            let base = base.clone();
            let posts = posts.clone();
            async move {
                let mut replies: VecDeque<_> = replies.into();
                let last = replies.back().unwrap().clone();
                let mut nonce = 0u64;
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut bytes = Vec::new();
                    let end = loop {
                        let mut part = [0; 4096];
                        let count = stream.read(&mut part).await.unwrap();
                        assert!(count > 0);
                        bytes.extend_from_slice(&part[..count]);
                        if let Some(position) = bytes.windows(4).position(|p| p == b"\r\n\r\n") {
                            break position + 4;
                        }
                    };
                    let header = String::from_utf8_lossy(&bytes[..end]);
                    let path = header.split_whitespace().nth(1).unwrap().to_owned();
                    let length: usize = header
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().unwrap())
                        })
                        .unwrap_or(0);
                    while bytes.len() < end + length {
                        let mut part = [0; 4096];
                        let count = stream.read(&mut part).await.unwrap();
                        assert!(count > 0);
                        bytes.extend_from_slice(&part[..count]);
                    }
                    let mut location = String::new();
                    let (status, body) = if path == "/directory" {
                        (200, json!({"newNonce":format!("{base}/nonce"),"newAccount":format!("{base}/account"),"newOrder":format!("{base}/order"),"revokeCert":format!("{base}/revoke"),"keyChange":format!("{base}/key-change")}).to_string())
                    } else if path == "/nonce" {
                        (200, String::new())
                    } else {
                        let jws: Value = serde_json::from_slice(&bytes[end..end + length]).unwrap();
                        let decode = |name: &str| {
                            let raw = URL_SAFE_NO_PAD.decode(jws[name].as_str().unwrap()).unwrap();
                            serde_json::from_slice::<Value>(&raw).unwrap_or(Value::Null)
                        };
                        posts.lock().unwrap().push((
                            path.clone(),
                            decode("protected"),
                            decode("payload"),
                        ));
                        let Reply(status, body) =
                            replies.pop_front().unwrap_or_else(|| last.clone());
                        if status == 0 {
                            continue;
                        } // A dropped transport, no HTTP status.
                        if status == 200 {
                            location = format!("Location: {base}/resource\r\n");
                            let body = if path == "/account" {
                                json!({"status":"valid"})
                            } else {
                                json!({"status":"valid","finalize":format!("{base}/finalize"),"certificate":format!("{base}/certificate")})
                            };
                            (status, body.to_string())
                        } else {
                            (status, body)
                        }
                    };
                    nonce += 1;
                    let token = URL_SAFE_NO_PAD.encode(nonce.to_be_bytes());
                    stream.write_all(format!("HTTP/1.1 {status} Fixture\r\nReplay-Nonce: {token}\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
                }
            }
        });
        Self { base, posts, task }
    }

    async fn client(&self) -> AcmeClient {
        AcmeClient::new(&format!("{}/directory", self.base))
            .await
            .unwrap()
    }
}

#[derive(Clone, Copy, Debug)]
enum Operation {
    Order,
    Find,
    Finalize,
    Download,
    Revoke,
}

async fn call(
    client: &AcmeClient,
    key: &certon::crypto::PrivateKey,
    base: &str,
    operation: Operation,
) -> Result<()> {
    let account = format!("{base}/account/1");
    match operation {
        Operation::Order => client
            .new_order(key, &account, &["example.com".into()])
            .await
            .map(|_| ()),
        Operation::Find => client.find_account(key).await.map(|_| ()),
        Operation::Finalize => client
            .finalize_order(
                key,
                &account,
                &format!("{base}/finalize"),
                b"controlled-csr",
            )
            .await
            .map(|_| ()),
        Operation::Download => client
            .download_certificate(key, &account, &format!("{base}/certificate"))
            .await
            .map(|_| ()),
        Operation::Revoke => {
            client
                .revoke_certificate(key, &account, b"certificate", None)
                .await
        }
    }
}

fn problem(kind: &str, document_status: u16) -> String {
    json!({"type":kind,"status":document_status,"detail":"controlled rejection"}).to_string()
}

#[tokio::test]
async fn actual_http_status_controls_public_retry_counts_for_problem_and_nonproblem_bodies() {
    let key = certon::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
    let config = RetryConfig {
        intervals: vec![Duration::from_millis(1)],
        max_duration: Duration::from_secs(5),
        max_retries: 3,
    };
    for (status, body, kind, retry) in [
        (
            400,
            problem(&format!("{PREFIX}rejectedIdentifier"), 503),
            Some(format!("{PREFIX}rejectedIdentifier")),
            false,
        ),
        (
            403,
            problem(&format!("{PREFIX}unauthorized"), 429),
            Some(format!("{PREFIX}unauthorized")),
            false,
        ),
        (
            400,
            problem("urn:vendor:badNonce", 400),
            Some("urn:vendor:badNonce".into()),
            false,
        ),
        (
            403,
            problem(&format!("{PREFIX}badNonce"), 400),
            Some(format!("{PREFIX}badNonce")),
            false,
        ),
        (
            404,
            problem(&format!("{PREFIX}badNonce"), 400),
            Some(format!("{PREFIX}badNonce")),
            false,
        ),
        (400, "broken JSON".into(), None, false),
        (403, "<html>denied</html>".into(), None, false),
        (400, "{\"success\":false}".into(), None, false),
        (
            429,
            problem(&format!("{PREFIX}unauthorized"), 403),
            Some(format!("{PREFIX}unauthorized")),
            true,
        ),
        (
            503,
            problem(&format!("{PREFIX}rejectedIdentifier"), 400),
            Some(format!("{PREFIX}rejectedIdentifier")),
            true,
        ),
        (429, "not JSON".into(), None, true),
        (503, "not JSON".into(), None, true),
    ] {
        for operation in [Operation::Order, Operation::Find] {
            let server = Server::start(vec![Reply(status, body.clone())]).await;
            let client = server.client().await;
            let error = do_with_retry(&config, |_| call(&client, &key, &server.base, operation))
                .await
                .unwrap_err();
            assert_eq!(should_retry(&error), retry);
            match error {
                Error::Acme(AcmeError::HttpResponse {
                    status: actual,
                    problem_type,
                    ..
                }) => {
                    assert_eq!(actual, status);
                    assert_eq!(problem_type, kind);
                }
                other => panic!("lost HTTP metadata: {other:?}"),
            }
            let count = server.posts.lock().unwrap().len();
            println!("{operation:?} HTTP{status} retry={retry}: {count} POSTs");
            assert_eq!(count, if retry { 3 } else { 1 });
        }
    }
}

#[tokio::test]
async fn finalize_bad_csr_and_certificate_or_revocation_rejection_stop_after_one_post() {
    let key = certon::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
    let config = RetryConfig {
        intervals: vec![Duration::ZERO],
        max_duration: Duration::from_secs(5),
        max_retries: 3,
    };
    for (operation, status, kind) in [
        (Operation::Finalize, 400, "badCSR"),
        (Operation::Download, 403, "unauthorized"),
        (Operation::Revoke, 403, "unauthorized"),
    ] {
        let server = Server::start(vec![Reply(
            status,
            problem(&format!("{PREFIX}{kind}"), 503),
        )])
        .await;
        let client = server.client().await;
        let error = do_with_retry(&config, |_| call(&client, &key, &server.base, operation))
            .await
            .unwrap_err();
        assert!(!should_retry(&error));
        assert!(
            matches!(error, Error::Acme(AcmeError::HttpResponse { status: actual, .. }) if actual == status)
        );
        let posts = server.posts.lock().unwrap();
        assert_eq!(posts.len(), 1);
        if matches!(operation, Operation::Finalize) {
            assert_eq!(posts[0].0, "/finalize");
            assert_eq!(posts[0].2["csr"], URL_SAFE_NO_PAD.encode(b"controlled-csr"));
        }
    }
}

#[tokio::test]
async fn nonce_recovery_and_outer_retry_limits_keep_their_distinct_budgets() {
    let key = certon::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
    let config = RetryConfig {
        intervals: vec![Duration::ZERO],
        max_duration: Duration::from_secs(5),
        max_retries: 3,
    };
    let nonce = Reply(400, problem(&format!("{PREFIX}badNonce"), 503));
    for operation in [Operation::Order, Operation::Find] {
        let server = Server::start(vec![nonce.clone(), Reply(200, String::new())]).await;
        let client = server.client().await;
        do_with_retry(&config, |_| call(&client, &key, &server.base, operation))
            .await
            .unwrap();
        assert_eq!(server.posts.lock().unwrap().len(), 2);
        let server = Server::start(vec![nonce.clone()]).await;
        let client = server.client().await;
        let error = do_with_retry(&config, |_| call(&client, &key, &server.base, operation))
            .await
            .unwrap_err();
        assert!(should_retry(&error));
        assert_eq!(
            server.posts.lock().unwrap().len(),
            6,
            "three outer attempts, each with only one nonce replay"
        );
    }
}

#[tokio::test]
async fn lookup_missing_and_revocation_confirmation_still_accept_only_exact_problems() {
    let key = certon::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
    for (operation, kind) in [
        (Operation::Find, "accountDoesNotExist"),
        (Operation::Revoke, "alreadyRevoked"),
    ] {
        let server = Server::start(vec![
            Reply(400, problem(&format!("{PREFIX}badNonce"), 400)),
            Reply(400, problem(&format!("{PREFIX}{kind}"), 503)),
        ])
        .await;
        let client = server.client().await;
        call(&client, &key, &server.base, operation).await.unwrap();
        assert_eq!(server.posts.lock().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn transport_failures_and_explicit_rate_limits_remain_transient() {
    let server = Server::start(vec![Reply(0, String::new())]).await;
    let client = server.client().await;
    let key = certon::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
    let config = RetryConfig {
        intervals: vec![Duration::ZERO],
        max_duration: Duration::from_secs(5),
        max_retries: 3,
    };
    let error = do_with_retry(&config, |_| {
        call(&client, &key, &server.base, Operation::Order)
    })
    .await
    .unwrap_err();
    assert!(should_retry(&error));
    assert_eq!(server.posts.lock().unwrap().len(), 3);
    let retry_after = Some(Duration::from_secs(123));
    let explicit = Error::Acme(AcmeError::RateLimited {
        retry_after,
        message: "controlled rate limit".into(),
    });
    assert!(should_retry(&explicit));
    assert!(
        matches!(explicit, Error::Acme(AcmeError::RateLimited { retry_after: Some(wait), .. }) if wait == Duration::from_secs(123))
    );
}
