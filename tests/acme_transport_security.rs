use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use certon::acme_client::AcmeClient;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

#[derive(Clone)]
enum Behavior {
    Normal,
    RedirectDirectory(String),
    HttpEndpoint(&'static str, String),
    RedirectEndpoint(&'static str, String),
    DelayDirectory(Duration),
}

struct Server {
    url: String,
    root: Option<reqwest::Certificate>,
    requests: Arc<Mutex<Vec<String>>>,
    contacts: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_request(stream: &mut dyn Io) -> Option<String> {
    let mut data = Vec::new();
    let mut buffer = [0; 2048];
    loop {
        let count = stream.read(&mut buffer).await.ok()?;
        if count == 0 {
            return None;
        }
        data.extend_from_slice(&buffer[..count]);
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let header = std::str::from_utf8(&data[..end]).ok()?;
            let len = header
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if data.len() >= end + 4 + len {
                return String::from_utf8(data).ok();
            }
        }
    }
}

impl Server {
    async fn start(tls: bool, behavior: Behavior) -> Self {
        certon::install_default_crypto_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "{}://{}",
            if tls { "https" } else { "http" },
            listener.local_addr().unwrap()
        );
        let (root, acceptor) = if tls {
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            let root = reqwest::Certificate::from_der(cert.der()).unwrap();
            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
                )
                .unwrap();
            (
                Some(root),
                Some(tokio_rustls::TlsAcceptor::from(Arc::new(config))),
            )
        } else {
            (None, None)
        };
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let contacts = Arc::new(AtomicUsize::new(0));
        let accepted = contacts.clone();
        let base = url.clone();
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    _ = children.join_next(), if !children.is_empty() => {},
                    connection = listener.accept() => {
                        let Ok((socket, _)) = connection else { return; };
                        accepted.fetch_add(1,Ordering::SeqCst);
                        let acceptor = acceptor.clone();
                        let recorded = recorded.clone();
                        let base = base.clone();
                        let behavior = behavior.clone();
                        children.spawn(async move {
                            let stream: Box<dyn Io> = if let Some(acceptor) = acceptor {
                                match acceptor.accept(socket).await {
                                    Ok(stream) => Box::new(stream),
                                    Err(_) => return,
                                }
                            } else { Box::new(socket) };
                            serve_request(stream, &base, &behavior, recorded).await;
                        });
                    }
                }
            }
        });
        Self {
            url,
            root,
            requests,
            contacts,
            task,
        }
    }
    fn builder(&self) -> reqwest::ClientBuilder {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3));
        if let Some(root) = &self.root {
            builder = builder.add_root_certificate(root.clone());
        }
        builder
    }
    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

async fn serve_request(
    mut stream: Box<dyn Io>,
    base: &str,
    behavior: &Behavior,
    recorded: Arc<Mutex<Vec<String>>>,
) {
    let Some(request) = read_request(stream.as_mut()).await else {
        return;
    };
    let path = request.split_whitespace().nth(1).unwrap().to_owned();
    recorded.lock().unwrap().push(request);
    let mut directory = json!({
        "newNonce": format!("{base}/nonce"), "newAccount": format!("{base}/account"),
        "newOrder": format!("{base}/order"), "newAuthz": format!("{base}/new-authz"),
        "revokeCert": format!("{base}/revoke"), "keyChange": format!("{base}/key-change"),
        "renewalInfo": format!("{base}/ari")
    });
    if let Behavior::HttpEndpoint(field, target) = behavior {
        directory[*field] = json!(target);
    }
    if let Behavior::DelayDirectory(delay) = behavior
        && path == "/directory"
    {
        tokio::time::sleep(*delay).await;
    }
    let redirect = match behavior {
        Behavior::RedirectDirectory(target) if path == "/directory" => Some(target.as_str()),
        Behavior::RedirectEndpoint(endpoint, target) if path == *endpoint => Some(target.as_str()),
        _ => None,
    };
    let (status, extra, body) = if let Some(target) = redirect {
        (307, format!("Location: {target}\r\n"), String::new())
    } else if path == "/directory" {
        (200, String::new(), directory.to_string())
    } else if path == "/nonce" {
        (200, String::new(), String::new())
    } else if path == "/account" {
        (
            200,
            format!("Location: {base}/account/id\r\n"),
            json!({"status":"valid","contact":[]}).to_string(),
        )
    } else {
        (200, String::new(), Value::Null.to_string())
    };
    let response = format!(
        "HTTP/1.1 {status} Test\r\nReplay-Nonce: test-nonce\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

#[tokio::test]
async fn https_directory_redirect_is_blocked_before_sending_cleartext() {
    let plain = Server::start(false, Behavior::Normal).await;
    let tls = Server::start(
        true,
        Behavior::RedirectDirectory(format!("{}/directory", plain.url)),
    )
    .await;
    let builder = tls
        .builder()
        .redirect(reqwest::redirect::Policy::limited(50));
    let result =
        AcmeClient::with_http_client_builder(&format!("{}/directory", tls.url), builder).await;
    assert!(
        result.is_err(),
        "TLS to HTTP redirect succeeded; cleartext requests={}",
        plain.count()
    );
    assert_eq!(
        plain.contacts.load(Ordering::SeqCst),
        0,
        "no connection may reach the HTTP listener"
    );
}

#[tokio::test]
async fn https_directory_http_endpoint_is_rejected_before_sending_cleartext() {
    let plain = Server::start(false, Behavior::Normal).await;
    let tls = Server::start(
        true,
        Behavior::HttpEndpoint("newNonce", format!("{}/nonce", plain.url)),
    )
    .await;
    let result =
        AcmeClient::with_http_client_builder(&format!("{}/directory", tls.url), tls.builder())
            .await;
    assert!(
        result.is_err(),
        "HTTP endpoint was accepted; cleartext requests={}",
        plain.count()
    );
    assert_eq!(
        plain.contacts.load(Ordering::SeqCst),
        0,
        "no connection may reach the HTTP endpoint"
    );
}

#[tokio::test]
async fn every_directory_endpoint_obeys_the_https_source_policy() {
    let plain = Server::start(false, Behavior::Normal).await;
    for field in [
        "newNonce",
        "newAccount",
        "newOrder",
        "newAuthz",
        "revokeCert",
        "keyChange",
        "renewalInfo",
    ] {
        let tls = Server::start(
            true,
            Behavior::HttpEndpoint(field, format!("{}/unused", plain.url)),
        )
        .await;
        assert!(
            AcmeClient::with_http_client_builder(&format!("{}/directory", tls.url), tls.builder())
                .await
                .is_err(),
            "field={field}"
        );
    }
    assert_eq!(plain.contacts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn nonce_post_and_ari_redirects_cannot_send_cleartext() {
    let plain = Server::start(false, Behavior::Normal).await;
    let key = certon::crypto::generate_private_key(certon::KeyType::EcdsaP256).unwrap();
    for endpoint in ["/nonce", "/account", "/ari/id"] {
        let tls = Server::start(
            true,
            Behavior::RedirectEndpoint(endpoint, format!("{}/forbidden", plain.url)),
        )
        .await;
        let client =
            AcmeClient::with_http_client_builder(&format!("{}/directory", tls.url), tls.builder())
                .await;
        if endpoint == "/nonce" {
            assert!(client.is_err());
        } else {
            let client = client.unwrap();
            if endpoint == "/account" {
                assert!(client.new_account(&key, &[], true, None).await.is_err());
                assert!(client.find_account(&key).await.is_err());
            } else {
                assert!(client.get_renewal_info(&key, "unused", "id").await.is_err());
            }
        }
    }
    assert_eq!(plain.contacts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn derived_post_urls_are_validated_before_any_request_is_sent() {
    let plain = Server::start(false, Behavior::Normal).await;
    let tls = Server::start(true, Behavior::Normal).await;
    let client =
        AcmeClient::with_http_client_builder(&format!("{}/directory", tls.url), tls.builder())
            .await
            .unwrap();
    let key = certon::crypto::generate_private_key(certon::KeyType::EcdsaP256).unwrap();
    let endpoint = format!("{}/forbidden", plain.url);
    assert!(
        client
            .get_authorization(&key, "account", &endpoint)
            .await
            .is_err()
    );
    assert!(
        client
            .accept_challenge(&key, "account", &endpoint)
            .await
            .is_err()
    );
    assert!(
        client
            .finalize_order(&key, "account", &endpoint, b"csr")
            .await
            .is_err()
    );
    assert!(
        client
            .download_certificate(&key, "account", &endpoint)
            .await
            .is_err()
    );
    assert_eq!(plain.contacts.load(Ordering::SeqCst), 0);
    // Invalid derived endpoints must not consume the cached nonce either.
    assert_eq!(tls.count(), 2);
}

#[tokio::test]
async fn secure_redirects_preserve_custom_roots_and_builder_headers() {
    let destination = Server::start(true, Behavior::Normal).await;
    let source = Server::start(
        true,
        Behavior::RedirectDirectory(format!("{}/directory", destination.url)),
    )
    .await;
    let builder = source
        .builder()
        .add_root_certificate(destination.root.clone().unwrap())
        .user_agent("custom-acme-agent");
    AcmeClient::with_http_client_builder(&format!("{}/directory", source.url), builder)
        .await
        .unwrap();
    assert_eq!(destination.count(), 2);
    for request in destination.requests.lock().unwrap().iter() {
        assert!(
            request
                .to_ascii_lowercase()
                .contains("user-agent: custom-acme-agent\r\n")
        );
    }
}

#[tokio::test]
async fn redirect_policy_checks_every_hop_and_retains_a_loop_budget() {
    let plain = Server::start(false, Behavior::Normal).await;
    let middle = Server::start(
        true,
        Behavior::RedirectDirectory(format!("{}/directory", plain.url)),
    )
    .await;
    let first = Server::start(
        true,
        Behavior::RedirectDirectory(format!("{}/directory", middle.url)),
    )
    .await;
    let builder = first
        .builder()
        .add_root_certificate(middle.root.clone().unwrap());
    assert!(
        AcmeClient::with_http_client_builder(&format!("{}/directory", first.url), builder)
            .await
            .is_err()
    );
    assert_eq!(middle.count(), 1);
    assert_eq!(plain.contacts.load(Ordering::SeqCst), 0);
    // A self-redirecting endpoint must not defeat the caller's timeout.
    let loop_server = Server::start(true, Behavior::RedirectDirectory("/directory".into())).await;
    let error = AcmeClient::with_http_client_builder(
        &format!("{}/directory", loop_server.url),
        loop_server.builder(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("redirect"));
    assert!(loop_server.count() <= 11);
}

#[tokio::test]
async fn local_http_exceptions_and_custom_resolution_are_retained() {
    let plain = Server::start(false, Behavior::Normal).await;
    let address: std::net::SocketAddr = plain.url.strip_prefix("http://").unwrap().parse().unwrap();
    for host in ["localhost", "ca.internal", "ca.localhost", "127.0.0.1"] {
        let builder = plain.builder().resolve(host, address);
        AcmeClient::with_http_client_builder(
            &format!("http://{host}:{}/directory", address.port()),
            builder,
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn custom_builder_timeout_is_not_replaced_by_redirect_security() {
    let tls = Server::start(true, Behavior::DelayDirectory(Duration::from_secs(2))).await;
    let builder = tls.builder().timeout(Duration::from_millis(150));
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        AcmeClient::with_http_client_builder(&format!("{}/directory", tls.url), builder),
    )
    .await
    .expect("custom request timeout must remain active");
    assert!(result.is_err());
    assert_eq!(
        tls.count(),
        1,
        "the TLS request was received but its delayed response exceeded the builder timeout"
    );
}

#[tokio::test]
async fn http_directory_upgrade_cannot_reintroduce_http_endpoints() {
    let trap = Server::start(false, Behavior::Normal).await;
    let tls = Server::start(
        true,
        Behavior::HttpEndpoint("newNonce", format!("{}/nonce", trap.url)),
    )
    .await;
    let source = Server::start(
        false,
        Behavior::RedirectDirectory(format!("{}/directory", tls.url)),
    )
    .await;
    let builder = source
        .builder()
        .add_root_certificate(tls.root.clone().unwrap());
    assert!(
        AcmeClient::with_http_client_builder(&format!("{}/directory", source.url), builder)
            .await
            .is_err()
    );
    assert_eq!(trap.contacts.load(Ordering::SeqCst), 0);
}
