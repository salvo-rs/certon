use std::sync::Mutex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

#[derive(Clone, Copy)]
enum Mode {
    Supported,
    Unsupported,
    TemporaryFailure,
}

struct Server {
    directory: String,
    requests: Arc<Mutex<Vec<(String, String)>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn new(mode: Mode) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let directory = format!("{origin}/directory");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut input = Vec::new();
                while !input.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let mut buffer = [0; 4096];
                    let size = socket.read(&mut buffer).await.unwrap();
                    assert_ne!(size, 0);
                    input.extend_from_slice(&buffer[..size]);
                }
                let input = String::from_utf8_lossy(&input);
                let mut line = input.split_whitespace();
                let method = line.next().unwrap();
                let path = line.next().unwrap();
                seen.lock()
                    .unwrap()
                    .push((method.to_owned(), path.to_owned()));
                if method == "HEAD" && path == "/nonce" {
                    socket.write_all(b"HTTP/1.1 200 OK\r\nReplay-Nonce: local-ari-nonce\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                    continue;
                }
                let (status, body) = if method == "GET" && path == "/directory" {
                    let mut body = serde_json::json!({
                        "newNonce": format!("{origin}/nonce"),
                        "newAccount": format!("{origin}/account"),
                        "newOrder": format!("{origin}/order"),
                        "revokeCert": format!("{origin}/revoke"),
                        "keyChange": format!("{origin}/key-change"),
                        "renewalInfo": format!("{origin}/ari"),
                    });
                    if matches!(mode, Mode::Unsupported) {
                        body.as_object_mut().unwrap().remove("renewalInfo");
                    }
                    ("200 OK", body)
                } else if method == "GET" && path.starts_with("/ari/") {
                    if matches!(mode, Mode::TemporaryFailure) {
                        (
                            "503 Service Unavailable",
                            serde_json::json!({"detail": "local ARI outage"}),
                        )
                    } else {
                        (
                            "200 OK",
                            serde_json::json!({"suggestedWindow": {
                                "start": (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339(),
                                "end": (chrono::Utc::now() + chrono::Duration::days(2)).to_rfc3339(),
                            }}),
                        )
                    }
                } else {
                    (
                        "400 Bad Request",
                        serde_json::json!({"detail": "account/EAB operations are not supported by this test"}),
                    )
                };
                let body = body.to_string();
                socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nRetry-After: 120\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            }
        });
        Self {
            directory,
            requests,
            task,
        }
    }

    fn assert_no_account_operations(&self) {
        assert!(self.requests.lock().unwrap().iter().all(|(method, path)| {
            (method == "GET" && (path == "/directory" || path.starts_with("/ari/")))
                || (method == "HEAD" && path == "/nonce")
        }));
    }

    fn count(&self, prefix: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, path)| path.starts_with(prefix))
            .count()
    }
}

fn configured(server: &Server) -> (tempfile::TempDir, ZeroSslIssuer, Vec<u8>) {
    let storage = tempfile::tempdir().unwrap();
    let issuer = ZeroSslIssuer {
        api_key: "unused-local-test-value".into(),
        inner: AcmeIssuer::builder()
            .ca(&server.directory)
            .storage(Arc::new(crate::FileStorage::new(storage.path())))
            .build(),
    };
    let mut ca = rcgen::CertificateParams::new(vec!["ari-test-ca".into()]).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = rcgen::Issuer::new(ca, rcgen::KeyPair::generate().unwrap());
    let mut leaf = rcgen::CertificateParams::new(vec!["ari.example".into()]).unwrap();
    leaf.use_authority_key_identifier_extension = true;
    let leaf = leaf
        .signed_by(&rcgen::KeyPair::generate().unwrap(), &ca)
        .unwrap();
    (storage, issuer, leaf.der().to_vec())
}

#[tokio::test]
async fn ari_is_delegated_without_registration_and_reuses_the_inner_client() {
    let server = Server::new(Mode::Supported).await;
    let (_storage, issuer, leaf) = configured(&server);
    for _ in 0..2 {
        let info = CertIssuer::renewal_info(&issuer, &leaf)
            .await
            .unwrap()
            .expect("advertised ARI must not be discarded");
        assert!(info.suggested_window.is_some());
        assert_eq!(info.retry_after, Some(120));
    }
    assert_eq!(server.count("/directory"), 1);
    assert_eq!(server.count("/ari/"), 2);
    server.assert_no_account_operations();
}

#[tokio::test]
async fn unsupported_ari_keeps_the_inner_none_result() {
    let server = Server::new(Mode::Unsupported).await;
    let (_storage, issuer, leaf) = configured(&server);
    assert!(
        CertIssuer::renewal_info(&issuer, &leaf)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(server.count("/ari/"), 0);
    server.assert_no_account_operations();
}

#[tokio::test]
async fn temporary_ari_errors_remain_visible_to_the_retry_policy() {
    let server = Server::new(Mode::TemporaryFailure).await;
    let (_storage, issuer, leaf) = configured(&server);
    let result = CertIssuer::renewal_info(&issuer, &leaf).await;
    assert!(matches!(
        result,
        Err(Error::Acme(crate::error::AcmeError::RenewalInfoTemporary(
            _
        )))
    ));
    assert_eq!(server.count("/ari/"), 1);
    server.assert_no_account_operations();
}

#[tokio::test]
async fn invalid_leaf_is_rejected_before_any_network_or_account_work() {
    let server = Server::new(Mode::Supported).await;
    let (_storage, issuer, _leaf) = configured(&server);
    assert!(
        CertIssuer::renewal_info(&issuer, b"invalid-leaf-der")
            .await
            .is_err()
    );
    assert!(server.requests.lock().unwrap().is_empty());
}
