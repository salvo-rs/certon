use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use certon::acme_client::{AcmeClient, OrderOptions};
use certon::{AcmeIssuer, CertManager, FileStorage, Http01Solver, KeyType, Solver};
use rcgen::PublicKeyData;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x509_parser::prelude::FromDer;

struct CsrPublicKey(Vec<u8>);
impl PublicKeyData for CsrPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

struct Ca {
    url: String,
    requests: Arc<Mutex<Vec<(String, Value)>>>,
    validated: Arc<Mutex<Vec<(String, String)>>>,
    root: rustls::pki_types::CertificateDer<'static>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Ca {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_request(socket: &mut tokio::net::TcpStream) -> (String, Value, Value) {
    let mut input = Vec::new();
    let mut buffer = [0u8; 4096];
    let (header_len, body_len) = loop {
        let count = socket.read(&mut buffer).await.unwrap();
        assert!(count > 0);
        input.extend_from_slice(&buffer[..count]);
        if let Some(end) = input.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
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
    while input.len() < header_len + body_len {
        let count = socket.read(&mut buffer).await.unwrap();
        assert!(count > 0);
        input.extend_from_slice(&buffer[..count]);
    }
    let path = String::from_utf8_lossy(&input[..header_len])
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned();
    let jws: Value = serde_json::from_slice(&input[header_len..]).unwrap_or(Value::Null);
    let decode = |field: &str| {
        serde_json::from_slice::<Value>(
            &URL_SAFE_NO_PAD
                .decode(jws[field].as_str().unwrap_or(""))
                .unwrap(),
        )
        .unwrap_or(Value::Null)
    };
    (path, decode("payload"), decode("protected"))
}

impl Ca {
    async fn start(http_port: Option<u16>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let root_key = rcgen::KeyPair::generate().unwrap();
        let mut root_params = rcgen::CertificateParams::new(vec!["ip-test-ca".into()]).unwrap();
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root = root_cert.der().clone();
        let root_pem = root_cert.pem();
        let issuer = rcgen::Issuer::new(root_params, root_key);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let validated = Arc::new(Mutex::new(Vec::new()));
        let proofs = validated.clone();
        let base = url.clone();
        let task = tokio::spawn(async move {
            let mut identifiers = json!([]);
            let mut thumbprint = String::new();
            let mut complete = false;
            let mut certificate = String::new();
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (path, payload, protected) = read_request(&mut socket).await;
                recorded
                    .lock()
                    .unwrap()
                    .push((path.clone(), payload.clone()));
                let mut location = String::new();
                let body = match path.as_str() {
                    "/directory" => json!({ "newNonce":format!("{base}/nonce"), "newAccount":format!("{base}/account"), "newOrder":format!("{base}/order"), "revokeCert":format!("{base}/revoke"), "keyChange":format!("{base}/key-change") }).to_string(),
                    "/nonce" => String::new(),
                    "/account" => {
                        let jwk = &protected["jwk"];
                        let canonical = json!({ "crv":jwk["crv"], "kty":jwk["kty"], "x":jwk["x"], "y":jwk["y"] });
                        thumbprint = URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&canonical).unwrap()));
                        location = format!("Location: {base}/account/1\r\n");
                        json!({"status":"valid"}).to_string()
                    }
                    "/order" => {
                        identifiers = payload["identifiers"].clone();
                        complete = http_port.is_none();
                        location = format!("Location: {base}/order/1\r\n");
                        json!({"status":"pending","authorizations":[format!("{base}/authz")],"finalize":format!("{base}/finalize")}).to_string()
                    }
                    "/authz" => if complete {
                        json!({"status":"valid","identifier":identifiers[0]}).to_string()
                    } else {
                        // Include an unusable DNS offer to prove that an IP
                        // authorization never gets sent to a configured DNS solver.
                        json!({"status":"pending","identifier":identifiers[0],"challenges":[
                            {"type":"dns-01","token":"ip-token","url":format!("{base}/dns-challenge")},
                            {"type":"http-01","token":"ip-token","url":format!("{base}/challenge")},
                            {"type":"tls-alpn-01","token":"ip-token","url":format!("{base}/tls-challenge")}
                        ]}).to_string()
                    },
                    "/challenge" => {
                        let address = identifiers[0]["value"].as_str().unwrap().to_owned();
                        let host = if address.contains(':') { format!("[{address}]") } else { address.clone() };
                        // The mock CA forwards its IP validation transport to
                        // the local listener, preserving the RFC HTTP Host.
                        let mut proof = tokio::net::TcpStream::connect(("127.0.0.1",http_port.unwrap())).await.unwrap();
                        proof.write_all(format!("GET /.well-known/acme-challenge/ip-token HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                        let mut response = Vec::new();
                        proof.read_to_end(&mut response).await.unwrap();
                        let response = String::from_utf8(response).unwrap();
                        assert!(response.starts_with("HTTP/1.1 200"));
                        assert_eq!(response.split_once("\r\n\r\n").unwrap().1, format!("ip-token.{thumbprint}"));
                        proofs.lock().unwrap().push((address, host));
                        complete = true;
                        json!({"type":"http-01","url":format!("{base}/challenge"),"token":"ip-token","status":"valid"}).to_string()
                    }
                    "/finalize" => {
                        let csr = URL_SAFE_NO_PAD.decode(payload["csr"].as_str().unwrap()).unwrap();
                        let (_, parsed) = x509_parser::certification_request::X509CertificationRequest::from_der(&csr).unwrap();
                        parsed.verify_signature().unwrap();
                        let public = CsrPublicKey(parsed.certification_request_info.subject_pki.subject_public_key.data.to_vec());
                        let names: Vec<String> = identifiers.as_array().unwrap().iter().map(|id| id["value"].as_str().unwrap().to_owned()).collect();
                        let params = rcgen::CertificateParams::new(names).unwrap();
                        certificate = format!("{}{}",params.signed_by(&public,&issuer).unwrap().pem(),root_pem);
                        json!({"status":"valid","certificate":format!("{base}/certificate")}).to_string()
                    }
                    "/certificate" => certificate.clone(),
                    _ => panic!("unexpected ACME endpoint {path}"),
                };
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nReplay-Nonce: ip-test-nonce\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            }
        });
        Self {
            url,
            requests,
            validated,
            root,
            task,
        }
    }
}

#[tokio::test]
async fn ipv4_and_ipv6_orders_use_ip_identifiers() {
    for (input, expected) in [
        ("192.0.2.1", "192.0.2.1"),
        ("2001:0DB8:0:0:0:0:0:1", "2001:db8::1"),
    ] {
        let ca = Ca::start(None).await;
        let client = AcmeClient::new(&format!("{}/directory", ca.url))
            .await
            .unwrap();
        let key = certon::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
        client
            .new_order(&key, &format!("{}/account/1", ca.url), &[input.into()])
            .await
            .unwrap();
        let requests = ca.requests.lock().unwrap();
        let order = requests.iter().find(|(path, _)| path == "/order").unwrap();
        assert_eq!(
            order.1["identifiers"],
            json!([{"type":"ip","value":expected}])
        );
    }
}

#[tokio::test]
async fn mixed_identifiers_preserve_dns_values_and_order_options() {
    let ca = Ca::start(None).await;
    let client = AcmeClient::new(&format!("{}/directory", ca.url))
        .await
        .unwrap();
    let key = certon::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
    let options = OrderOptions {
        profile: Some("shortlived".into()),
        ..Default::default()
    };
    client
        .new_order_with_options(
            &key,
            &format!("{}/account/1", ca.url),
            &[
                "EXAMPLE.com".into(),
                "192.0.2.1".into(),
                "2001:0DB8::1".into(),
            ],
            &options,
        )
        .await
        .unwrap();
    let requests = ca.requests.lock().unwrap();
    let order = requests.iter().find(|(path, _)| path == "/order").unwrap();
    assert_eq!(
        order.1["identifiers"],
        json!([{"type":"dns","value":"EXAMPLE.com"},{"type":"ip","value":"192.0.2.1"},{"type":"ip","value":"2001:db8::1"}])
    );
    assert_eq!(order.1["profile"], "shortlived");
}

#[tokio::test]
async fn dns_only_orders_keep_the_existing_dns_encoding() {
    let ca = Ca::start(None).await;
    let client = AcmeClient::new(&format!("{}/directory", ca.url))
        .await
        .unwrap();
    let key = certon::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
    client
        .new_order(
            &key,
            &format!("{}/account/1", ca.url),
            &["EXAMPLE.com".into(), "*.example.com".into()],
        )
        .await
        .unwrap();
    let requests = ca.requests.lock().unwrap();
    let order = requests.iter().find(|(path, _)| path == "/order").unwrap();
    assert_eq!(
        order.1["identifiers"],
        json!([{"type":"dns","value":"EXAMPLE.com"},{"type":"dns","value":"*.example.com"}])
    );
}

struct RejectDns;
#[async_trait::async_trait]
impl Solver for RejectDns {
    async fn present(&self, _: &str, _: &str, _: &str) -> certon::Result<()> {
        panic!("IP authorization must not select DNS-01")
    }
    async fn cleanup(&self, _: &str, _: &str, _: &str) -> certon::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn manager_obtain_ip_completes_real_http_validation_and_serves_the_signed_csr_key() {
    certon::install_default_crypto_provider();
    for input in ["192.0.2.1", "2001:0DB8:0:0:0:0:0:1"] {
        let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let ca = Ca::start(Some(port)).await;
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(FileStorage::new(directory.path()));
        let endpoint = format!("{}/directory", ca.url);
        let issuer = AcmeIssuer::builder()
            .storage(storage.clone())
            .ca(&endpoint)
            .test_ca(&endpoint)
            .agreed(true)
            .http01_solver(Arc::new(Http01Solver::new(port)))
            .dns01_solver(Arc::new(RejectDns))
            .cert_obtain_timeout(Duration::from_secs(10))
            .build();
        let manager = CertManager::builder()
            .storage(storage)
            .issuers(vec![Arc::new(issuer)])
            .disable_ari(true)
            .ocsp(certon::OcspConfig {
                disable_stapling: true,
                ..Default::default()
            })
            .default_server_name(input.parse::<std::net::IpAddr>().unwrap().to_string())
            .build();
        manager.obtain(input).await.unwrap();
        let expected = input.parse::<std::net::IpAddr>().unwrap().to_string();
        assert_eq!(ca.validated.lock().unwrap().len(), 1);
        {
            let requests = ca.requests.lock().unwrap();
            let order = requests.iter().find(|(path, _)| path == "/order").unwrap();
            assert_eq!(
                order.1["identifiers"],
                json!([{"type":"ip","value":expected}])
            );
        }
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.root.clone()).unwrap();
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server = manager.server_config();
        let (client_io, server_io) = tokio::io::duplex(65536);
        let (client, server) = tokio::join!(
            tokio_rustls::TlsConnector::from(Arc::new(client))
                .connect(expected.try_into().unwrap(), client_io),
            tokio_rustls::TlsAcceptor::from(Arc::new(server)).accept(server_io)
        );
        assert!(client.is_ok(), "IP client handshake failed: {client:?}");
        assert!(server.is_ok(), "IP server handshake failed: {server:?}");
    }
}
