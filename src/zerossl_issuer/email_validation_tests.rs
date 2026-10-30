use std::sync::Mutex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x509_parser::prelude::FromDer;

use super::*;

const API_KEY: &str = "SYNTHETIC+key/secret?";
const ID: &str = "certificate-id";
const DOMAINS: [&str; 2] = ["one.example.com", "*.two.example.com"];
const EMAILS: [&str; 2] = ["admin@one.example.com", "hostmaster@two.example.com"];

#[derive(Clone, Debug)]
struct Request {
    method: String,
    path: String,
    form: BTreeMap<String, String>,
}

struct PublicKey(Vec<u8>);
impl rcgen::PublicKeyData for PublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

struct Api {
    origin: Url,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

fn create_response() -> serde_json::Value {
    serde_json::json!({"id": ID, "status": "draft", "validation": {"email_validation": {
        "ONE.EXAMPLE.COM": [EMAILS[0], "webmaster@one.example.com"],
        "*.two.example.com": [EMAILS[1], "admin@two.example.com"]
    }}})
}

impl Api {
    async fn start(create: String, status: u16, challenge: String, chunked: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let records = requests.clone();
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let root = params.self_signed(&key).unwrap().pem();
            let ca = rcgen::Issuer::new(params, key);
            let mut certificate = String::new();
            loop {
                let mut socket = tokio::select! {
                    result = listener.accept() => result.unwrap().0,
                    _ = &mut stopped => break,
                };
                let mut bytes = Vec::new();
                let end = loop {
                    let mut buffer = [0; 2048];
                    let count = socket.read(&mut buffer).await.unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&buffer[..count]);
                    if let Some(position) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                        break position + 4;
                    }
                };
                let header = String::from_utf8_lossy(&bytes[..end]);
                let mut first = header.lines().next().unwrap().split_whitespace();
                let method = first.next().unwrap().to_owned();
                let target = Url::parse(&format!("http://local{}", first.next().unwrap())).unwrap();
                assert_eq!(
                    target
                        .query_pairs()
                        .find(|(name, _)| name == "access_key")
                        .unwrap()
                        .1,
                    API_KEY
                );
                let size: usize = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                while bytes.len() < end + size {
                    let mut buffer = [0; 2048];
                    let count = socket.read(&mut buffer).await.unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&buffer[..count]);
                }
                let form: BTreeMap<String, String> =
                    url::form_urlencoded::parse(&bytes[end..end + size])
                        .into_owned()
                        .collect();
                let path = target.path().to_owned();
                records.lock().unwrap().push(Request {
                    method,
                    path: path.clone(),
                    form: form.clone(),
                });
                let (status, body) = match path.as_str() {
                    "/certificates" => {
                        let csr = pem::parse(&form["certificate_csr"]).unwrap();
                        let (_, parsed) =
                            x509_parser::certification_request::X509CertificationRequest::from_der(
                                csr.contents(),
                            )
                            .unwrap();
                        parsed.verify_signature().unwrap();
                        let public = PublicKey(
                            parsed
                                .certification_request_info
                                .subject_pki
                                .subject_public_key
                                .data
                                .to_vec(),
                        );
                        let names = form["certificate_domains"]
                            .split(',')
                            .map(String::from)
                            .collect::<Vec<_>>();
                        let mut params = rcgen::CertificateParams::new(names).unwrap();
                        params.distinguished_name = rcgen::DistinguishedName::new();
                        certificate = params.signed_by(&public, &ca).unwrap().pem();
                        (200, create.clone())
                    }
                    "/certificates/certificate-id/challenges" => (status, challenge.clone()),
                    "/certificates/certificate-id" => (
                        200,
                        serde_json::json!({"id": ID, "status":"issued"}).to_string(),
                    ),
                    "/certificates/certificate-id/download/return" => (
                        200,
                        serde_json::json!({"certificate.crt": certificate, "ca_bundle.crt": root})
                            .to_string(),
                    ),
                    _ => panic!("unexpected ZeroSSL path {path}"),
                };
                let is_chunked = chunked && path.ends_with("/challenges");
                let header = if is_chunked {
                    format!(
                        "HTTP/1.1 {status} Fixture\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                    )
                } else {
                    format!(
                        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                };
                if socket.write_all(header.as_bytes()).await.is_ok() {
                    if is_chunked {
                        for bytes in body.as_bytes().chunks(4096) {
                            if socket
                                .write_all(format!("{:x}\r\n", bytes.len()).as_bytes())
                                .await
                                .is_err()
                                || socket.write_all(bytes).await.is_err()
                                || socket.write_all(b"\r\n").await.is_err()
                            {
                                break;
                            }
                        }
                        let _ = socket.write_all(b"0\r\n\r\n").await;
                    } else {
                        let _ = socket.write_all(body.as_bytes()).await;
                    }
                }
            }
        });
        Self {
            origin,
            requests,
            stop,
            task,
        }
    }

    fn issuer(&self, path: &std::path::Path) -> ZeroSslApiIssuer {
        let mut issuer = ZeroSslApiIssuer::new(API_KEY, Arc::new(crate::FileStorage::new(path)))
            .with_validation_email(DOMAINS[1], EMAILS[1])
            .unwrap()
            .with_validation_email("One.Example.COM.", EMAILS[0])
            .unwrap()
            .with_validation_email("unused.example.com", "admin@unused.example.com")
            .unwrap()
            .with_poll_interval(Duration::ZERO);
        issuer.revocation_origin = Some(self.origin.clone());
        issuer
    }

    async fn finish(self) -> Vec<Request> {
        let _ = self.stop.send(());
        self.task.await.unwrap();
        Arc::try_unwrap(self.requests)
            .unwrap()
            .into_inner()
            .unwrap()
    }
}

fn domains() -> Vec<String> {
    DOMAINS.iter().map(|name| (*name).to_owned()).collect()
}

fn assert_email_form(requests: &[Request]) {
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].form["certificate_domains"], DOMAINS.join(","));
    assert_eq!(requests[1].method, "POST");
    assert_eq!(requests[1].form.len(), 2);
    assert_eq!(requests[1].form["validation_method"], "EMAIL");
    assert_eq!(requests[1].form["validation_email"], EMAILS.join(","));
}

#[tokio::test]
async fn issue_email_accepts_certificate_objects_and_explicit_confirmations() {
    for confirmation in [
        serde_json::json!({"id":ID,"status":"pending_validation"}),
        serde_json::json!({"id":ID,"status":"issued","validation_type":"EMAIL","validation_emails":EMAILS.join(",")}),
        serde_json::json!({"success":true}),
        serde_json::json!({"success":1}),
        serde_json::json!({"id":ID,"status":"pending_validation","validation_type":"email","validation_emails":format!("{}, {}", EMAILS[1], EMAILS[0])}),
    ] {
        let api = Api::start(
            create_response().to_string(),
            200,
            confirmation.to_string(),
            false,
        )
        .await;
        let directory = tempfile::tempdir().unwrap();
        let issued = tokio::time::timeout(
            Duration::from_secs(5),
            api.issuer(directory.path()).issue(&[], &domains()),
        )
        .await
        .unwrap()
        .unwrap();
        let parsed =
            crate::Certificate::from_pem(&issued.certificate_pem, &issued.private_key_pem).unwrap();
        assert_eq!(parsed.names.len(), 2);
        assert_eq!(parsed.names, domains());
        let key = crate::crypto::decode_private_key_pem(
            std::str::from_utf8(&issued.private_key_pem).unwrap(),
        )
        .unwrap();
        let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &rustls::pki_types::PrivatePkcs8KeyDer::from(key.pkcs8_der()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        )
        .unwrap();
        let (_, leaf) =
            x509_parser::prelude::X509Certificate::from_der(parsed.cert_chain[0].as_ref()).unwrap();
        assert_eq!(
            pem::parse(key.public_key_pem()).unwrap().contents(),
            leaf.tbs_certificate.subject_pki.raw
        );
        assert_eq!(issued.metadata["certificate_id"], ID);
        let requests = api.finish().await;
        assert_eq!(
            requests.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
            [
                "/certificates",
                "/certificates/certificate-id/challenges",
                "/certificates/certificate-id",
                "/certificates/certificate-id/download/return"
            ]
        );
        assert_email_form(&requests);
    }
}

#[tokio::test]
async fn issue_email_preserves_caller_csr_and_external_private_key_ownership() {
    let api = Api::start(
        create_response().to_string(),
        200,
        serde_json::json!({"id":ID,"status":"pending_validation"}).to_string(),
        false,
    )
    .await;
    let directory = tempfile::tempdir().unwrap();
    let key = crate::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
    let csr = generate_csr(&key, &domains(), false).unwrap();
    let issued = api
        .issuer(directory.path())
        .issue(&csr, &domains())
        .await
        .unwrap();
    assert!(
        issued.private_key_pem.is_empty(),
        "caller retains external key ownership"
    );
    let leaf = pem::parse_many(&issued.certificate_pem).unwrap().remove(0);
    let (_, leaf) = x509_parser::prelude::X509Certificate::from_der(leaf.contents()).unwrap();
    let (_, csr_parsed) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&csr).unwrap();
    assert_eq!(
        leaf.tbs_certificate.subject_pki.raw,
        csr_parsed.certification_request_info.subject_pki.raw
    );
    let requests = api.finish().await;
    assert_eq!(
        pem::parse(&requests[0].form["certificate_csr"])
            .unwrap()
            .contents(),
        csr
    );
    assert_eq!(requests.len(), 4);
    assert_email_form(&requests);
}

#[tokio::test]
async fn issue_email_rejection_never_polls_or_downloads() {
    let failures = [
        r#"{"success":false,"error":{"code":2824,"type":"missing_validation_emails"}}"#,
        "not JSON",
        "{}",
        "null",
        r#"{"success":0}"#,
        r#"{"success":"true"}"#,
        r#"{"success":true,"error":{"code":2825,"type":"missing_validation_email"}}"#,
        r#"{"id":"wrong-id","status":"pending_validation"}"#,
        r#"{"id":"certificate-id","status":"draft"}"#,
        r#"{"id":"certificate-id","status":"unknown"}"#,
        r#"{"success":true,"id":"certificate-id"}"#,
        r#"{"id":"certificate-id","status":"pending_validation","validation_type":"CNAME_CSR_HASH"}"#,
        r#"{"id":"certificate-id","status":"pending_validation","validation_emails":"other@example.com"}"#,
        r#"{"success":null,"success":true}"#,
        r#"{"success":true,"success":false}"#,
        r#"{"id":"certificate-id","id":"other","status":"pending_validation"}"#,
    ];
    for (status, body) in failures
        .into_iter()
        .map(|body| (200, body))
        .chain([(403, r#"{"success":true}"#)])
    {
        let api = Api::start(create_response().to_string(), status, body.into(), false).await;
        let directory = tempfile::tempdir().unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            api.issuer(directory.path()).issue(&[], &domains()),
        )
        .await
        .unwrap();
        assert!(
            result.is_err(),
            "unexpected confirmation for fixture {body}"
        );
        let requests = api.finish().await;
        assert_eq!(requests.len(), 2, "failed initiation must stop issuance");
        assert_email_form(&requests);
    }
}

#[tokio::test]
async fn issue_email_checks_all_configuration_before_creating_an_order() {
    let api = Api::start(
        create_response().to_string(),
        200,
        r#"{"success":true}"#.into(),
        false,
    )
    .await;
    let directory = tempfile::tempdir().unwrap();
    let mut issuer =
        ZeroSslApiIssuer::new(API_KEY, Arc::new(crate::FileStorage::new(directory.path())))
            .with_validation_email(DOMAINS[0], EMAILS[0])
            .unwrap();
    issuer.revocation_origin = Some(api.origin.clone());
    assert!(matches!(
        issuer.issue(&[], &domains()).await,
        Err(Error::Config(_))
    ));
    assert!(
        issuer
            .issue(&[], &[DOMAINS[0].into(), "ONE.EXAMPLE.COM.".into()])
            .await
            .is_err()
    );
    assert!(api.finish().await.is_empty());
}

#[tokio::test]
async fn issue_email_requires_per_domain_ca_candidates_before_initiating() {
    let mut wrong_recipient = create_response();
    wrong_recipient["validation"]["email_validation"][DOMAINS[1]] =
        serde_json::json!(["other@two.example.com"]);
    let mut duplicate_domain = create_response();
    duplicate_domain["validation"]["email_validation"][DOMAINS[0]] = serde_json::json!([EMAILS[0]]);
    for create in [
        serde_json::json!({"id":ID,"status":"draft"}),
        serde_json::json!({"id":ID,"status":"draft","validation":{"email_validation":{DOMAINS[0]:[EMAILS[0]]}}}),
        wrong_recipient,
        duplicate_domain,
        serde_json::json!({"success":false,"id":ID,"validation":{"email_validation":{DOMAINS[0]:[EMAILS[0]],DOMAINS[1]:[EMAILS[1]]}}}),
    ] {
        let api = Api::start(create.to_string(), 200, r#"{"success":true}"#.into(), false).await;
        let directory = tempfile::tempdir().unwrap();
        assert!(
            api.issuer(directory.path())
                .issue(&[], &domains())
                .await
                .is_err()
        );
        assert_eq!(
            api.finish().await.len(),
            1,
            "invalid selection must not initiate validation"
        );
    }
}

#[tokio::test]
async fn email_response_errors_preserve_identifiers_without_echoing_credentials() {
    for kind in [
        "missing_validation_emails",
        API_KEY,
        "SYNTHETIC%2Bkey%2Fsecret%3F",
        "https://example.com/?access_key=SYNTHETIC%2Bkey%2Fsecret%3F",
    ] {
        let body =
            serde_json::json!({"success":false,"error":{"code":2824,"type":kind,"detail":API_KEY}})
                .to_string();
        let api = Api::start(create_response().to_string(), 200, body, false).await;
        let directory = tempfile::tempdir().unwrap();
        let error = api
            .issuer(directory.path())
            .issue(&[], &domains())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("2824"));
        assert!(!error.contains(API_KEY));
        assert!(!error.contains("SYNTHETIC%2B"));
        if kind == "missing_validation_emails" {
            assert!(error.contains(kind));
        }
        assert_eq!(api.finish().await.len(), 2);
    }
    for body in [
        format!("malformed {API_KEY}"),
        serde_json::json!({"success":true,"id":API_KEY}).to_string(),
    ] {
        let api = Api::start(create_response().to_string(), 200, body, false).await;
        let directory = tempfile::tempdir().unwrap();
        let error = api
            .issuer(directory.path())
            .issue(&[], &domains())
            .await
            .unwrap_err()
            .to_string();
        assert!(!error.contains(API_KEY));
        assert_eq!(api.finish().await.len(), 2);
    }
}

#[tokio::test]
async fn email_response_reads_are_bounded_for_known_and_streamed_bodies() {
    for chunked in [false, true] {
        for (status, limit) in [
            (200, crate::http::MAX_JSON_BODY_BYTES),
            (403, crate::http::MAX_ERROR_BODY_BYTES),
        ] {
            let body = format!(r#"{{"success":true,"padding":"{}"}}"#, "x".repeat(limit));
            let api = Api::start(create_response().to_string(), status, body, chunked).await;
            let directory = tempfile::tempdir().unwrap();
            let error = api
                .issuer(directory.path())
                .issue(&[], &domains())
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("exceeds"), "{error}");
            assert_eq!(api.finish().await.len(), 2);
        }
    }
}

#[test]
fn email_configuration_rejects_duplicate_domains_and_list_injection() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(crate::FileStorage::new(directory.path()));
    for email in [
        "",
        "admin",
        "@example.com",
        "admin@",
        "a@example.com,b@example.com",
        "a@example.com\r\nX: y",
        "\r\nadmin@example.com",
        "admin@example.com\n",
        "a @example.com",
        "a@@example.com",
    ] {
        assert!(
            ZeroSslApiIssuer::new(API_KEY, storage.clone())
                .with_validation_email(DOMAINS[0], email)
                .is_err()
        );
    }
    let issuer = ZeroSslApiIssuer::new(API_KEY, storage.clone())
        .with_validation_email("ONE.example.com.", EMAILS[0])
        .unwrap();
    assert!(issuer.with_validation_email(DOMAINS[0], EMAILS[0]).is_err());
    assert!(
        ZeroSslApiIssuer::new(API_KEY, storage)
            .with_validation_email("bad/domain", EMAILS[0])
            .is_err()
    );
}

#[test]
fn email_domains_keep_dns_syntax_and_wildcard_identity_without_dns_solver() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(crate::FileStorage::new(directory.path()));
    let issuer = ZeroSslApiIssuer::new(API_KEY, storage.clone())
        .with_validation_email("Example.COM.", "admin@example.com")
        .unwrap()
        .with_validation_email("*.Example.COM.", "hostmaster@example.com")
        .unwrap();
    assert_eq!(
        issuer
            .selected_validation_emails(&["*.EXAMPLE.com".into(), "example.com".into()])
            .unwrap(),
        ["hostmaster@example.com", "admin@example.com"]
    );
    let longest = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    assert_eq!(longest.len(), 253);
    assert!(
        ZeroSslApiIssuer::new(API_KEY, storage.clone())
            .with_validation_email(&longest, EMAILS[0])
            .is_ok()
    );
    for domain in [
        "".to_owned(),
        "localhost".into(),
        "bad/domain.com".into(),
        "bad..example.com".into(),
        "example.com..".into(),
        "-bad.example.com".into(),
        "bad-.example.com".into(),
        "_bad.example.com".into(),
        "*.*.example.com".into(),
        "例子.example.com".into(),
        format!("{}.example.com", "a".repeat(64)),
        format!("{longest}d"),
    ] {
        assert!(
            ZeroSslApiIssuer::new(API_KEY, storage.clone())
                .with_validation_email(&domain, EMAILS[0])
                .is_err(),
            "invalid configured domain: {domain}"
        );
    }
}
