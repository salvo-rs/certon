use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use certon::{AcmeIssuer, FileStorage, Solver};
use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x509_parser::prelude::FromDer;

struct Public(Vec<u8>);
impl PublicKeyData for Public {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}
#[derive(Clone, Copy)]
enum Mode {
    Prevalidated,
    TlsOnly,
    Both,
    HttpOnly,
    All,
}
struct Server {
    url: String,
    paths: Arc<Mutex<Vec<String>>>,
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
        let url = format!("http://{}", listener.local_addr().unwrap());
        let base = url.clone();
        let paths = Arc::new(Mutex::new(Vec::new()));
        let requests = paths.clone();
        let key = KeyPair::generate().unwrap();
        let ca = rcgen::Issuer::new(
            CertificateParams::new(vec!["local-ca".into()]).unwrap(),
            key,
        );
        let task = tokio::spawn(async move {
            let mut challenged = false;
            let mut certificate = String::new();
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let end = loop {
                    let mut buf = [0; 4096];
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break 0;
                    }
                    bytes.extend_from_slice(&buf[..n]);
                    if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                        break end + 4;
                    }
                };
                if end == 0 {
                    continue;
                }
                let head = String::from_utf8_lossy(&bytes[..end]).into_owned();
                let len = head
                    .lines()
                    .find_map(|line| {
                        let (k, v) = line.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                while bytes.len() < end + len {
                    let mut buf = [0; 4096];
                    let n = stream.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buf[..n]);
                }
                let path = head.split_whitespace().nth(1).unwrap().to_owned();
                requests.lock().unwrap().push(path.clone());
                let jws: Value = serde_json::from_slice(&bytes[end..]).unwrap_or(Value::Null);
                let payload: Value = serde_json::from_slice(
                    &URL_SAFE_NO_PAD
                        .decode(jws["payload"].as_str().unwrap_or(""))
                        .unwrap(),
                )
                .unwrap_or(Value::Null);
                let mut status = 200;
                let mut extra = String::new();
                let body = match path.as_str() {
                    "/directory" => json!({
                        "newNonce": format!("{base}/nonce"),
                        "newAccount": format!("{base}/account"),
                        "newOrder": format!("{base}/new-order"),
                        "revokeCert": format!("{base}/revoke"),
                        "keyChange": format!("{base}/key-change"),
                    })
                    .to_string(),
                    "/nonce" => String::new(),
                    "/account" => {
                        extra = format!("Location: {base}/registered\r\n");
                        json!({"status": "valid", "contact": ["mailto:round9@example.com"]})
                            .to_string()
                    }
                    "/new-order" => {
                        extra = format!("Location: {base}/order\r\n");
                        let state = if matches!(mode, Mode::Prevalidated) {
                            "ready"
                        } else {
                            "pending"
                        };
                        json!({
                            "status": state,
                            "authorizations": [format!("{base}/authz")],
                            "finalize": format!("{base}/finalize"),
                        })
                        .to_string()
                    }
                    "/authz" => {
                        let identifier = json!({"type": "dns", "value": "round9.example.com"});
                        if matches!(mode, Mode::Prevalidated) || challenged {
                            json!({"status": "valid", "identifier": identifier}).to_string()
                        } else {
                            let mut challenges = Vec::new();
                            for (offered, kind, route) in [
                                (!matches!(mode, Mode::HttpOnly), "tls-alpn-01", "tls"),
                                (
                                    matches!(mode, Mode::Both | Mode::HttpOnly | Mode::All),
                                    "http-01",
                                    "http",
                                ),
                                (matches!(mode, Mode::All), "dns-01", "dns"),
                            ] {
                                if offered {
                                    challenges.push(json!({
                                        "type": kind,
                                        "url": format!("{base}/{route}-challenge"),
                                        "token": "validtoken",
                                    }));
                                }
                            }
                            json!({"status": "pending", "identifier": identifier, "challenges": challenges}).to_string()
                        }
                    }
                    "/tls-challenge" | "/http-challenge" | "/dns-challenge" => {
                        challenged = true;
                        let kind = match path.as_str() {
                            "/tls-challenge" => "tls-alpn-01",
                            "/dns-challenge" => "dns-01",
                            _ => "http-01",
                        };
                        json!({"type": kind, "url": format!("{base}{path}"), "token": "validtoken", "status": "processing"}).to_string()
                    }
                    "/order" => json!({"status": "ready", "finalize": format!("{base}/finalize")})
                        .to_string(),
                    "/finalize" => {
                        let csr = URL_SAFE_NO_PAD
                            .decode(payload["csr"].as_str().unwrap())
                            .unwrap();
                        let (_, parsed) =
                            x509_parser::certification_request::X509CertificationRequest::from_der(
                                &csr,
                            )
                            .unwrap();
                        let public = Public(
                            parsed
                                .certification_request_info
                                .subject_pki
                                .subject_public_key
                                .data
                                .to_vec(),
                        );
                        let cert = CertificateParams::new(vec!["round9.example.com".into()])
                            .unwrap()
                            .signed_by(&public, &ca)
                            .unwrap();
                        certificate = cert.pem();
                        json!({"status": "valid", "certificate": format!("{base}/certificate")})
                            .to_string()
                    }
                    "/certificate" => certificate.clone(),
                    _ => {
                        status = 404;
                        String::new()
                    }
                };
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nReplay-Nonce: fresh-nonce\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        Self { url, paths, task }
    }
    fn path_count(&self, path: &str) -> usize {
        self.paths
            .lock()
            .unwrap()
            .iter()
            .filter(|p| *p == path)
            .count()
    }
}
#[derive(Default)]
struct ProbeSolver {
    present: AtomicUsize,
    clean: AtomicUsize,
}
#[async_trait::async_trait]
impl Solver for ProbeSolver {
    async fn present(&self, _: &str, _: &str, _: &str) -> certon::Result<()> {
        self.present.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn cleanup(&self, _: &str, _: &str, _: &str) -> certon::Result<()> {
        self.clean.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn assert_certificate_key_match(pem: &[u8], key: &[u8]) {
    let certificate = certon::Certificate::from_pem(pem, key).unwrap();
    assert!(
        certificate
            .names
            .iter()
            .any(|name| name == "round9.example.com")
    );
    let (_, leaf) =
        x509_parser::certificate::X509Certificate::from_der(certificate.cert_chain[0].as_ref())
            .unwrap();
    let private = KeyPair::from_pem(std::str::from_utf8(key).unwrap()).unwrap();
    assert_eq!(
        leaf.public_key().subject_public_key.data.as_ref(),
        private.der_bytes()
    );
}

#[derive(Clone, Copy, Default)]
struct Capabilities {
    http: bool,
    tls: bool,
    dns: bool,
    disable_http: bool,
    disable_tls: bool,
}

async fn check_selection(mode: Mode, capabilities: Capabilities, expected: Option<&str>) {
    let server = Server::new(mode).await;
    let directory = tempfile::tempdir().unwrap();
    let ca = format!("{}/directory", server.url);
    let http = Arc::new(ProbeSolver::default());
    let tls = Arc::new(ProbeSolver::default());
    let dns = Arc::new(ProbeSolver::default());
    let mut builder = AcmeIssuer::builder()
        .ca(&ca)
        .test_ca(&ca)
        .email("solver-capabilities@example.com")
        .agreed(true)
        .storage(Arc::new(FileStorage::new(directory.path())))
        .disable_http_challenge(capabilities.disable_http)
        .disable_tlsalpn_challenge(capabilities.disable_tls)
        .disable_distributed_solvers(true)
        .cert_obtain_timeout(Duration::from_secs(3));
    if capabilities.http {
        builder = builder.http01_solver(http.clone());
    }
    if capabilities.tls {
        builder = builder.tlsalpn01_solver(tls.clone());
    }
    if capabilities.dns {
        builder = builder.dns01_solver(dns.clone());
    }
    let issuer = builder.build();
    let result = issuer
        .issue_for_domains(&["round9.example.com".into()])
        .await;
    if expected.is_some() {
        let issued = result.unwrap();
        assert_certificate_key_match(&issued.certificate_pem, &issued.private_key_pem);
        assert_eq!(server.path_count("/finalize"), 1);
        assert_eq!(server.path_count("/certificate"), 1);
    } else {
        let error = result.unwrap_err();
        assert!(
            matches!(error, certon::Error::Acme(certon::error::AcmeError::Challenge { ref challenge_type, .. }) if challenge_type == "none"),
            "{error}"
        );
        assert_eq!(server.path_count("/finalize"), 0);
    }
    for (name, solver) in [("http", http), ("tls", tls), ("dns", dns)] {
        let count = usize::from(expected == Some(name));
        assert_eq!(
            solver.present.load(Ordering::SeqCst),
            count,
            "{name} present"
        );
        assert_eq!(solver.clean.load(Ordering::SeqCst), count, "{name} cleanup");
        assert_eq!(server.path_count(&format!("/{name}-challenge")), count);
    }
    assert_eq!(server.path_count("/account"), 1);
    assert_eq!(server.path_count("/new-order"), 1);
}

#[tokio::test]
async fn tls_only_configuration_ignores_an_unconfigured_http_offer() {
    for mode in [Mode::TlsOnly, Mode::Both, Mode::All] {
        check_selection(
            mode,
            Capabilities {
                tls: true,
                ..Default::default()
            },
            Some("tls"),
        )
        .await;
    }
    check_selection(
        Mode::Both,
        Capabilities {
            tls: true,
            disable_http: true,
            ..Default::default()
        },
        Some("tls"),
    )
    .await;
}

#[tokio::test]
async fn capable_solvers_keep_dns_http_tls_preferences_and_disable_flags() {
    check_selection(
        Mode::Both,
        Capabilities {
            http: true,
            tls: true,
            ..Default::default()
        },
        Some("http"),
    )
    .await;
    check_selection(
        Mode::Both,
        Capabilities {
            http: true,
            tls: true,
            disable_http: true,
            ..Default::default()
        },
        Some("tls"),
    )
    .await;
    check_selection(
        Mode::Both,
        Capabilities {
            http: true,
            tls: true,
            disable_tls: true,
            ..Default::default()
        },
        Some("http"),
    )
    .await;
    check_selection(
        Mode::All,
        Capabilities {
            http: true,
            tls: true,
            dns: true,
            ..Default::default()
        },
        Some("dns"),
    )
    .await;
    check_selection(
        Mode::All,
        Capabilities {
            dns: true,
            disable_http: true,
            disable_tls: true,
            ..Default::default()
        },
        Some("dns"),
    )
    .await;
}

#[tokio::test]
async fn empty_capability_intersections_do_not_present_a_challenge() {
    for (mode, capabilities) in [
        (Mode::Both, Capabilities::default()),
        (
            Mode::TlsOnly,
            Capabilities {
                http: true,
                ..Default::default()
            },
        ),
        (
            Mode::HttpOnly,
            Capabilities {
                tls: true,
                ..Default::default()
            },
        ),
        (
            Mode::Both,
            Capabilities {
                tls: true,
                disable_tls: true,
                ..Default::default()
            },
        ),
    ] {
        check_selection(mode, capabilities, None).await;
    }
}

#[tokio::test]
async fn already_valid_authorizations_need_no_configured_solver() {
    check_selection(
        Mode::Prevalidated,
        Capabilities::default(),
        Some("prevalidated"),
    )
    .await;
}
