use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use chrono::{DateTime, Utc};
use rcgen::{CertificateParams, KeyPair, SigningKey};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x509_parser::prelude::{FromDer, X509Certificate};

const USER: &str = "TEST_ONLY_OCSP_USER";
const PASSWORD: &str = "TEST_ONLY_OCSP_PASSWORD";
const QUERY: &str = "TEST_ONLY_OCSP_QUERY";
const FRAGMENT: &str = "TEST_ONLY_OCSP_FRAGMENT";
const PATH: &str = "TEST_ONLY_OCSP_PATH";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Capture {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}
fn capture() -> (Capture, tracing::subscriber::DefaultGuard) {
    let logs = Capture::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    (logs, tracing::subscriber::set_default(subscriber))
}
fn assert_redacted(text: &str) {
    for secret in [USER, PASSWORD, QUERY, FRAGMENT, PATH] {
        assert!(
            !text.contains(secret),
            "private endpoint data leaked ({secret}): {text}"
        );
    }
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{USER}:{PASSWORD}"));
    assert!(
        !text.contains(&auth),
        "HTTP credentials leaked through diagnostics: {text}"
    );
}
fn private_url(origin: &str, route: &str) -> String {
    format!(
        "{}://{USER}:{PASSWORD}@{}/{PATH}/{route}?access_key={QUERY}#{FRAGMENT}",
        origin.split_once("://").unwrap().0,
        origin.split_once("://").unwrap().1
    )
}
fn der(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    if bytes.len() < 128 {
        output.push(bytes.len() as u8);
    } else {
        let size = bytes.len().to_be_bytes();
        let start = size.iter().position(|v| *v != 0).unwrap();
        output.push(0x80 | (size.len() - start) as u8);
        output.extend_from_slice(&size[start..]);
    }
    output.extend_from_slice(bytes);
    output
}
fn time(value: DateTime<Utc>) -> Vec<u8> {
    der(0x18, value.format("%Y%m%d%H%M%SZ").to_string().as_bytes())
}

struct Fixture {
    pem: Vec<u8>,
    leaf_pem: Vec<u8>,
    key_pem: String,
    ca_der: Vec<u8>,
    response: Vec<u8>,
}
impl Fixture {
    fn new(ocsp_url: &str, issuer_url: Option<&str>) -> Self {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        ca.distinguished_name
            .push(rcgen::DnType::CommonName, "OCSP redaction CA");
        let root = ca.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca, &ca_key);
        let key = KeyPair::generate().unwrap();
        let mut leaf = CertificateParams::new(vec!["ocsp-secret.example".into()]).unwrap();
        leaf.serial_number = Some(123u64.into());
        let mut access = vec![der(
            0x30,
            &[
                der(0x06, &[0x2b, 6, 1, 5, 5, 7, 0x30, 1]),
                der(0x86, ocsp_url.as_bytes()),
            ]
            .concat(),
        )];
        if let Some(url) = issuer_url {
            access.push(der(
                0x30,
                &[
                    der(0x06, &[0x2b, 6, 1, 5, 5, 7, 0x30, 2]),
                    der(0x86, url.as_bytes()),
                ]
                .concat(),
            ));
        }
        leaf.custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 1, 1],
                der(0x30, &access.concat()),
            ));
        let leaf = leaf.signed_by(&key, &issuer).unwrap();
        let (_, parsed) = X509Certificate::from_der(leaf.der()).unwrap();
        let (_, root_parsed) = X509Certificate::from_der(root.der()).unwrap();
        let id = der(
            0x30,
            &[
                der(
                    0x30,
                    &[der(0x06, &[0x2b, 0x0e, 3, 2, 0x1a]), der(0x05, &[])].concat(),
                ),
                der(0x04, &Sha1::digest(root_parsed.subject().as_raw())),
                der(
                    0x04,
                    &Sha1::digest(&root_parsed.public_key().subject_public_key.data),
                ),
                der(0x02, parsed.raw_serial()),
            ]
            .concat(),
        );
        let now = Utc::now();
        let single = der(
            0x30,
            &[
                id,
                der(0x80, &[]),
                time(now - chrono::Duration::minutes(1)),
                der(0xa0, &time(now + chrono::Duration::hours(4))),
            ]
            .concat(),
        );
        let tbs = der(
            0x30,
            &[
                der(0xa1, root_parsed.subject().as_raw()),
                time(now),
                der(0x30, &single),
            ]
            .concat(),
        );
        let signature = ca_key.sign(&tbs).unwrap();
        let basic = der(
            0x30,
            &[
                tbs,
                der(0x30, &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2]),
                der(0x03, &[vec![0], signature].concat()),
            ]
            .concat(),
        );
        let response_bytes = der(
            0x30,
            &[
                der(0x06, &[0x2b, 6, 1, 5, 5, 7, 0x30, 1, 1]),
                der(0x04, &basic),
            ]
            .concat(),
        );
        let response = der(
            0x30,
            &[vec![0x0a, 1, 0], der(0xa0, &response_bytes)].concat(),
        );
        Self {
            pem: format!("{}{}", leaf.pem(), root.pem()).into_bytes(),
            leaf_pem: leaf.pem().into_bytes(),
            key_pem: key.serialize_pem(),
            ca_der: root.der().to_vec(),
            response,
        }
    }
    fn cert(&self, full_chain: bool) -> certon::Certificate {
        certon::Certificate::from_pem(
            if full_chain {
                &self.pem
            } else {
                &self.leaf_pem
            },
            self.key_pem.as_bytes(),
        )
        .unwrap()
    }
}

#[derive(Clone, Copy, Debug)]
enum Failure {
    Transport,
    Status,
    Truncated,
    Chunked,
    Oversized,
}
fn failed_wire(failure: Failure) -> Vec<u8> {
    match failure {
        Failure::Transport=>Vec::new(),
        Failure::Status=>b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        Failure::Truncated=>b"HTTP/1.1 200 OK\r\nContent-Length: 8192\r\nConnection: close\r\n\r\nx".to_vec(),
        Failure::Chunked=>b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nnot-a-size\r\n".to_vec(),
        Failure::Oversized=>b"HTTP/1.1 200 OK\r\nContent-Length: 67108864\r\nConnection: close\r\n\r\n".to_vec(),
    }
}
fn ok_wire(body: &[u8]) -> Vec<u8> {
    [
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes(),
        body.to_vec(),
    ]
    .concat()
}
struct Server {
    origin: String,
    responses: Arc<Mutex<VecDeque<Vec<u8>>>>,
    task: tokio::task::JoinHandle<Vec<String>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn new() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let responses = Arc::new(Mutex::new(VecDeque::<Vec<u8>>::new()));
        let pending = responses.clone();
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let end = loop {
                    let mut buf = [0; 4096];
                    let n = socket.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&buf[..n]);
                    if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                        break end + 4;
                    }
                };
                let length = String::from_utf8_lossy(&request[..end])
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                while request.len() < end + length {
                    let mut buf = [0; 4096];
                    let n = socket.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&buf[..n]);
                }
                requests.push(String::from_utf8_lossy(&request).into_owned());
                let wire = pending
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected network request");
                if !wire.is_empty() {
                    let _ = socket.write_all(&wire).await;
                }
                if pending.lock().unwrap().is_empty() {
                    return requests;
                }
            }
        });
        Self {
            origin,
            responses,
            task,
        }
    }
    async fn requests(&mut self) -> Vec<String> {
        tokio::time::timeout(Duration::from_secs(3), &mut self.task)
            .await
            .unwrap()
            .as_ref()
            .unwrap()
            .clone()
    }
}
fn assert_private_request(request: &str, method: &str, route: &str) {
    assert!(
        request.starts_with(&format!(
            "{method} /{PATH}/{route}?access_key={QUERY} HTTP/1.1"
        )),
        "request target was modified: {request}"
    );
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{USER}:{PASSWORD}"));
    let authorization = request.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case("authorization")
            .then(|| value.trim())
    });
    assert_eq!(authorization, Some(format!("Basic {auth}").as_str()));
    assert!(!request.contains(FRAGMENT));
}

#[tokio::test(flavor = "current_thread")]
async fn private_override_errors_redact_logs_without_changing_requests() {
    for failure in [
        Failure::Transport,
        Failure::Status,
        Failure::Truncated,
        Failure::Chunked,
        Failure::Oversized,
    ] {
        let mut server = Server::new().await;
        server
            .responses
            .lock()
            .unwrap()
            .push_back(failed_wire(failure));
        // The certificate does not contain any override secret.
        let fixture = Fixture::new(&format!("{}/ocsp", server.origin), None);
        let mut cert = fixture.cert(true);
        let directory = tempfile::tempdir().unwrap();
        let storage = certon::FileStorage::new(directory.path());
        let mut config = certon::OcspConfig::default();
        config.responder_overrides.insert(
            "ocsp-secret.example".into(),
            private_url(&server.origin, "ocsp"),
        );
        let (logs, _guard) = capture();
        assert!(
            !certon::ocsp::staple_ocsp(&storage, &mut cert, &config)
                .await
                .unwrap()
        );
        let requests = server.requests().await;
        assert_private_request(&requests[0], "POST", "ocsp");
        let text = logs.text();
        assert!(
            text.contains("using responder override URL")
                && text.contains("failed to get OCSP response")
        );
        assert!(text.contains(&server.origin));
        assert_redacted(&text);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn public_fetch_errors_redact_url_but_preserve_error_categories() {
    for failure in [
        Failure::Transport,
        Failure::Status,
        Failure::Truncated,
        Failure::Chunked,
        Failure::Oversized,
    ] {
        let mut server = Server::new().await;
        server
            .responses
            .lock()
            .unwrap()
            .push_back(failed_wire(failure));
        let fixture = Fixture::new(&private_url(&server.origin, "ocsp"), None);
        let (logs, _guard) = capture();
        let error = certon::ocsp::get_ocsp_for_cert(&fixture.pem)
            .await
            .unwrap_err()
            .to_string();
        let requests = server.requests().await;
        assert_private_request(&requests[0], "POST", "ocsp");
        let category = match failure {
            Failure::Transport => "OCSP HTTP request",
            Failure::Status => "HTTP 503",
            Failure::Truncated | Failure::Chunked => "read response body",
            Failure::Oversized => "byte limit",
        };
        assert!(error.contains(category), "{failure:?}: {error}");
        assert_redacted(&error);
        assert_redacted(&logs.text());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn issuer_aia_failure_diagnostics_are_also_redacted() {
    for failure in [
        Failure::Transport,
        Failure::Status,
        Failure::Truncated,
        Failure::Oversized,
    ] {
        let mut server = Server::new().await;
        server
            .responses
            .lock()
            .unwrap()
            .push_back(failed_wire(failure));
        let fixture = Fixture::new(
            &format!("{}/ocsp", server.origin),
            Some(&private_url(&server.origin, "issuer")),
        );
        let directory = tempfile::tempdir().unwrap();
        let storage = certon::FileStorage::new(directory.path());
        let mut cert = fixture.cert(false);
        let (logs, _guard) = capture();
        assert!(
            !certon::ocsp::staple_ocsp(&storage, &mut cert, &certon::OcspConfig::default())
                .await
                .unwrap()
        );
        let requests = server.requests().await;
        assert_private_request(&requests[0], "GET", "issuer");
        let text = logs.text();
        assert!(
            text.contains("failed to fetch issuer from AIA URL") && text.contains(&server.origin)
        );
        assert_redacted(&text);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn signed_good_private_endpoints_and_plain_errors_remain_usable() {
    for issuer_fetch in [false, true] {
        let mut server = Server::new().await;
        let fixture = Fixture::new(
            &format!("{}/ocsp", server.origin),
            issuer_fetch
                .then(|| private_url(&server.origin, "issuer"))
                .as_deref(),
        );
        {
            let mut responses = server.responses.lock().unwrap();
            if issuer_fetch {
                responses.push_back(ok_wire(&fixture.ca_der));
            }
            responses.push_back(ok_wire(&fixture.response));
        }
        let directory = tempfile::tempdir().unwrap();
        let storage = certon::FileStorage::new(directory.path());
        let mut cert = fixture.cert(!issuer_fetch);
        let mut config = certon::OcspConfig::default();
        config.responder_overrides.insert(
            "ocsp-secret.example".into(),
            private_url(&server.origin, "ocsp"),
        );
        let (logs, _guard) = capture();
        assert!(
            certon::ocsp::staple_ocsp(&storage, &mut cert, &config)
                .await
                .unwrap()
        );
        assert_eq!(cert.ocsp_status, Some(certon::ocsp::OcspStatus::Good));
        assert_eq!(cert.ocsp_response, Some(fixture.response));
        let requests = server.requests().await;
        if issuer_fetch {
            assert_private_request(&requests[0], "GET", "issuer");
        }
        assert_private_request(requests.last().unwrap(), "POST", "ocsp");
        assert_redacted(&logs.text());
    }
    // A cached response takes a different AIA verification path from a new
    // responder request. It needs only the issuer GET, not an OCSP POST.
    {
        use certon::Storage;
        let mut server = Server::new().await;
        let fixture = Fixture::new(
            &format!("{}/ocsp", server.origin),
            Some(&private_url(&server.origin, "issuer")),
        );
        server
            .responses
            .lock()
            .unwrap()
            .push_back(ok_wire(&fixture.ca_der));
        let directory = tempfile::tempdir().unwrap();
        let storage = certon::FileStorage::new(directory.path());
        let mut cert = fixture.cert(false);
        storage
            .store(
                &certon::storage::ocsp_key(&cert.names[0], &cert.hash),
                &fixture.response,
            )
            .await
            .unwrap();
        let (logs, _guard) = capture();
        assert!(
            certon::ocsp::staple_ocsp(&storage, &mut cert, &certon::OcspConfig::default())
                .await
                .unwrap()
        );
        assert_eq!(cert.ocsp_status, Some(certon::ocsp::OcspStatus::Good));
        assert_eq!(cert.ocsp_response, Some(fixture.response));
        let requests = server.requests().await;
        assert_eq!(requests.len(), 1);
        assert_private_request(&requests[0], "GET", "issuer");
        assert!(
            logs.text()
                .contains("fetched issuer certificate from AIA extension")
        );
        assert_redacted(&logs.text());
    }
    let mut server = Server::new().await;
    server
        .responses
        .lock()
        .unwrap()
        .push_back(failed_wire(Failure::Status));
    let fixture = Fixture::new(&format!("{}/ocsp", server.origin), None);
    let error = certon::ocsp::get_ocsp_for_cert(&fixture.pem)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("HTTP 503"));
    server.requests().await;
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_override_url_never_reappears_in_diagnostics() {
    let fixture = Fixture::new("http://127.0.0.1/unused", None);
    let mut cert = fixture.cert(true);
    let directory = tempfile::tempdir().unwrap();
    let storage = certon::FileStorage::new(directory.path());
    let mut config = certon::OcspConfig::default();
    config.responder_overrides.insert(
        "ocsp-secret.example".into(),
        format!("http://{USER}:{PASSWORD}@invalid:not-a-port/{PATH}?access_key={QUERY}#{FRAGMENT}"),
    );
    let (logs, _guard) = capture();
    assert!(
        !certon::ocsp::staple_ocsp(&storage, &mut cert, &config)
            .await
            .unwrap()
    );
    assert!(logs.text().contains("failed to get OCSP response"));
    assert_redacted(&logs.text());
    let invalid = config.responder_overrides["ocsp-secret.example"].clone();
    let fixture = Fixture::new(&invalid, None);
    let error = certon::ocsp::get_ocsp_for_cert(&fixture.pem)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("OCSP HTTP request") && error.contains("invalid or non-HTTP endpoint"));
    assert_redacted(&error);
    assert_redacted(&logs.text());
}
