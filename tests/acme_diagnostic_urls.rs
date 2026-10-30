use std::io::Write;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use certon::KeyType;
use certon::acme_client::AcmeClient;
use certon::crypto::generate_private_key;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);
impl Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Use a current-thread runtime so the scoped subscriber also observes the
// async protocol calls after each await. The server records actual wire URLs
// and JWS protected URLs independently of diagnostic output.
#[tokio::test(flavor = "current_thread")]
async fn private_acme_urls_are_redacted_without_changing_requests() {
    let logs = Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let key = generate_private_key(KeyType::EcdsaP256).unwrap();

    for status in [200, 400, 403, 503] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let private = "private-tenant";
        let suffix = "?access_key=diagnostic-query-secret#diagnostic-fragment-secret";
        let order_url = format!("{base}/{private}/order{suffix}");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let server = tokio::spawn({
            let (base, order_url, seen) = (base.clone(), order_url.clone(), seen.clone());
            async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let (base, order_url, seen) = (base.clone(), order_url.clone(), seen.clone());
                    tokio::spawn(async move {
                        let mut bytes = Vec::new();
                        let end = loop {
                            let mut buffer = [0; 4096];
                            let n = stream.read(&mut buffer).await.unwrap();
                            if n == 0 {
                                return;
                            }
                            bytes.extend_from_slice(&buffer[..n]);
                            if let Some(end) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
                                break end + 4;
                            }
                        };
                        let head = String::from_utf8_lossy(&bytes[..end]);
                        let path = head.split_whitespace().nth(1).unwrap().to_string();
                        let len: usize = head
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse().unwrap())
                            })
                            .unwrap_or(0);
                        while bytes.len() < end + len {
                            let mut buffer = [0; 4096];
                            let n = stream.read(&mut buffer).await.unwrap();
                            assert!(n > 0);
                            bytes.extend_from_slice(&buffer[..n]);
                        }
                        let (code, body, location) = if path.starts_with("/private-directory") {
                            (200, json!({
                                "newNonce":format!("{base}/private-tenant/nonce?access_key=diagnostic-query-secret"),
                                "newAccount":format!("{base}/private-tenant/account?access_key=diagnostic-query-secret"),
                                "newOrder":order_url,
                                "revokeCert":format!("{base}/private-tenant/revoke"),
                                "keyChange":format!("{base}/private-tenant/key-change"),
                                "renewalInfo":format!("{base}/private-tenant/ari")
                            }).to_string(), String::new())
                        } else if path.starts_with("/private-tenant/nonce") {
                            (200, String::new(), String::new())
                        } else if path.starts_with("/private-tenant/ari/") {
                            // The server's error body may itself echo a secret;
                            // optional ARI diagnostics must not log the body.
                            (
                                403,
                                "diagnostic-query-secret private-tenant".into(),
                                String::new(),
                            )
                        } else {
                            let jws: Value =
                                serde_json::from_slice(&bytes[end..end + len]).unwrap();
                            let protected: Value = serde_json::from_slice(
                                &URL_SAFE_NO_PAD
                                    .decode(jws["protected"].as_str().unwrap())
                                    .unwrap(),
                            )
                            .unwrap();
                            seen.lock()
                                .unwrap()
                                .push((path, protected["url"].as_str().unwrap().to_string()));
                            if status == 200 {
                                (201, json!({"status":"pending","identifiers":[],"authorizations":[],"finalize":format!("{base}/private-tenant/finalize")}).to_string(), format!("Location: {base}/private-tenant/order/1?access_key=diagnostic-query-secret\r\n"))
                            } else {
                                (status, json!({"type":"urn:ietf:params:acme:error:unauthorized","detail":"fixture rejected request"}).to_string(), String::new())
                            }
                        };
                        let wire = format!(
                            "HTTP/1.1 {code} Fixture\r\n{location}Content-Length: {}\r\nReplay-Nonce: aW5pdGlhbA\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        stream.write_all(wire.as_bytes()).await.unwrap();
                    });
                }
            }
        });
        let directory = format!(
            "{base}/private-directory?access_key=diagnostic-bootstrap-secret#diagnostic-directory-fragment"
        );
        let client = AcmeClient::new(&directory).await.unwrap();
        let debug = format!("{client:?}");
        assert!(!debug.contains(private));
        assert!(!debug.contains("diagnostic-query-secret"));
        let result = client
            .new_order(&key, &format!("{base}/account/1"), &["example.com".into()])
            .await;
        if status == 200 {
            assert!(result.is_ok());
        } else {
            let error = result.unwrap_err().to_string();
            assert!(error.contains(&status.to_string()), "{error}");
            assert!(error.contains("unauthorized"));
            assert!(error.contains("fixture rejected request"));
            assert!(error.contains(&base));
            for secret in [
                private,
                "diagnostic-query-secret",
                "diagnostic-fragment-secret",
            ] {
                assert!(!error.contains(secret), "{error}");
            }
        }
        client
            .get_renewal_info(&key, &format!("{base}/account/1"), "private-cert-id")
            .await
            .unwrap();
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert_eq!(
                seen[0].0,
                "/private-tenant/order?access_key=diagnostic-query-secret"
            );
            assert_eq!(seen[0].1, order_url);
        }
        if status == 403 {
            let account_url = format!("{base}/private-tenant/account/1{suffix}");
            let authz = format!("{base}/private-tenant/authz{suffix}");
            let challenge = format!("{base}/private-tenant/challenge{suffix}");
            let finalize = format!("{base}/private-tenant/finalize{suffix}");
            let cert = format!("{base}/private-tenant/cert{suffix}");
            let errors = [
                client
                    .get_authorization(&key, &account_url, &authz)
                    .await
                    .unwrap_err()
                    .to_string(),
                client
                    .accept_challenge(&key, &account_url, &challenge)
                    .await
                    .unwrap_err()
                    .to_string(),
                client
                    .finalize_order(&key, &account_url, &finalize, &[1, 2, 3])
                    .await
                    .unwrap_err()
                    .to_string(),
                client
                    .download_certificate(&key, &account_url, &cert)
                    .await
                    .unwrap_err()
                    .to_string(),
            ];
            for error in errors {
                assert!(error.contains("403"), "{error}");
                for secret in [
                    private,
                    "diagnostic-query-secret",
                    "diagnostic-fragment-secret",
                ] {
                    assert!(!error.contains(secret), "{error}");
                }
            }
            let temp = tempfile::tempdir().unwrap();
            let storage = Arc::new(certon::file_storage::FileStorage::new(temp.path()));
            let email = "diagnostic@example.com";
            let mut account = certon::account::new_account(email, KeyType::EcdsaP256).unwrap();
            account.location =
                format!("{base}/private-tenant/account/1?access_key=diagnostic-query-secret");
            certon::account::save_account(storage.as_ref(), &directory, &account)
                .await
                .unwrap();
            let (loaded, is_new) = certon::account::get_or_create_account(
                storage.as_ref(),
                &directory,
                email,
                KeyType::EcdsaP256,
            )
            .await
            .unwrap();
            assert!(!is_new);
            assert_eq!(loaded.location, account.location);
            assert!(!format!("{loaded:?}").contains("diagnostic-query-secret"));
            let issuer = certon::acme_issuer::AcmeIssuer::builder()
                .ca(&directory)
                .test_ca(&directory)
                .email(email)
                .storage(storage.clone())
                .build();
            let debug = format!("{issuer:?}");
            assert!(!debug.contains("diagnostic-bootstrap-secret"));
            assert!(!debug.contains("private-directory"));
            let error = issuer
                .issue_for_domains(&["example.com".into()])
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("403"), "{error}");
            assert!(!error.contains("diagnostic-query-secret"), "{error}");
            certon::account::delete_account_locally(storage.as_ref(), &directory, &account)
                .await
                .unwrap();
            let issued = certon::acme_issuer::IssuedCertificate {
                certificate_pem: vec![],
                private_key_pem: vec![],
                metadata: json!({"ca":directory,"order_url":order_url}),
            };
            assert!(!format!("{issued:?}").contains("diagnostic-query-secret"));
            assert_eq!(issued.metadata["order_url"], order_url);
            let resource = certon::storage::CertificateResource {
                sans: vec!["example.com".into()],
                certificate_pem: vec![],
                private_key_pem: vec![],
                issuer_data: Some(issued.metadata.clone()),
                issuer_key: certon::storage::issuer_key(&directory),
            };
            assert!(!format!("{resource:?}").contains("diagnostic-query-secret"));
            assert_eq!(
                serde_json::to_value(&resource).unwrap()["issuer_data"]["order_url"],
                order_url
            );
        }
        server.abort();
        let _ = server.await;
    }
    let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(output.contains("ACME directory loaded"));
    assert!(output.contains("ACME order created"));
    assert!(output.contains("ARI request returned non-success status"));
    assert!(output.contains("saved ACME account to storage"));
    assert!(output.contains("using existing ACME account from storage"));
    assert!(output.contains("starting ACME certificate issuance"));
    assert!(output.contains("deleted local ACME account data"));
    for secret in [
        "private-tenant",
        "private-directory",
        "private-cert-id",
        "diagnostic-query-secret",
        "diagnostic-bootstrap-secret",
        "diagnostic-fragment-secret",
        "diagnostic-directory-fragment",
    ] {
        // reqwest/hyper may have their own logs: only Certon's fields are in
        // scope, so the subscriber below filters dependency diagnostics.
        assert!(
            !output
                .lines()
                .filter(|line| line.contains("certon::"))
                .any(|line| line.contains(secret)),
            "{output}"
        );
    }
}

#[tokio::test]
async fn directory_transport_error_omits_credentials_and_url() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let endpoint = format!(
        "http://diagnostic-user:diagnostic-password@{address}/private-directory?key=diagnostic-query-secret#diagnostic-fragment-secret"
    );
    let error = AcmeClient::new(&endpoint).await.unwrap_err().to_string();
    assert!(error.contains("failed to fetch directory"));
    for secret in [
        "diagnostic-user",
        "diagnostic-password",
        "private-directory",
        "diagnostic-query-secret",
        "diagnostic-fragment-secret",
    ] {
        assert!(!error.contains(secret), "{error}");
    }
}

#[tokio::test]
async fn nonce_and_signed_post_transport_errors_omit_private_urls() {
    let key = generate_private_key(KeyType::EcdsaP256).unwrap();
    for fail_nonce in [true, false] {
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = closed.local_addr().unwrap();
        drop(closed);
        let private_url = format!(
            "http://diagnostic-user:diagnostic-password@{address}/private-tenant?key=diagnostic-query-secret#diagnostic-fragment-secret"
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn({
            let base = base.clone();
            async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut bytes = Vec::new();
                    loop {
                        let mut buffer = [0; 4096];
                        let n = stream.read(&mut buffer).await.unwrap();
                        assert!(n > 0);
                        bytes.extend_from_slice(&buffer[..n]);
                        if bytes.windows(4).any(|s| s == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let body = if bytes.starts_with(b"GET ") {
                        json!({"newNonce":if fail_nonce {private_url.clone()} else {format!("{base}/nonce")},"newAccount":format!("{base}/account"),"newOrder":private_url,"revokeCert":format!("{base}/revoke"),"keyChange":format!("{base}/key-change")}).to_string()
                    } else {
                        String::new()
                    };
                    let wire = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nReplay-Nonce: aW5pdGlhbA\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(wire.as_bytes()).await.unwrap();
                }
            }
        });
        let result = AcmeClient::new(&format!("{base}/directory")).await;
        let error = if fail_nonce {
            result.unwrap_err().to_string()
        } else {
            result
                .unwrap()
                .new_order(&key, &format!("{base}/account/1"), &["example.com".into()])
                .await
                .unwrap_err()
                .to_string()
        };
        assert!(
            error.contains(if fail_nonce {
                "HEAD newNonce failed"
            } else {
                "ACME POST"
            }),
            "{error}"
        );
        for secret in [
            "diagnostic-user",
            "diagnostic-password",
            "private-tenant",
            "diagnostic-query-secret",
            "diagnostic-fragment-secret",
        ] {
            assert!(!error.contains(secret), "{error}");
        }
        server.abort();
        let _ = server.await;
    }
}
