use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use certon::acme_client::{AcmeClient, MAX_ALTERNATE_CHAINS};
use certon::acme_issuer::ChainPreference;
use certon::{AcmeIssuer, CertIssuer, FileStorage, KeyType};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone)]
struct Response {
    body: Vec<u8>,
    links: Vec<String>,
    status: u16,
    chunked: bool,
    stall: bool,
}

impl Response {
    fn pem(pem: &str, links: Vec<String>) -> Self {
        Self {
            body: pem.as_bytes().to_vec(),
            links,
            status: 200,
            chunked: false,
            stall: false,
        }
    }
}

struct Server {
    url: String,
    requests: Arc<Mutex<Vec<(String, String)>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn start(routes: HashMap<String, Response>) -> Self {
        Self::start_with_finalize_delay(routes, Duration::ZERO).await
    }

    async fn start_with_finalize_delay(
        routes: HashMap<String, Response>,
        finalize_delay: Duration,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let base = url.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 4096];
                let (header_end, content_length) = loop {
                    let size = stream.read(&mut buffer).await.unwrap();
                    assert_ne!(size, 0);
                    request.extend_from_slice(&buffer[..size]);
                    if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..end]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        break (end + 4, length);
                    }
                };
                while request.len() < header_end + content_length {
                    let size = stream.read(&mut buffer).await.unwrap();
                    assert_ne!(size, 0);
                    request.extend_from_slice(&buffer[..size]);
                }
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let mut line = headers.split_whitespace();
                let method = line.next().unwrap().to_owned();
                let path = line.next().unwrap().to_owned();
                recorded
                    .lock()
                    .unwrap()
                    .push((method.clone(), path.clone()));
                if path.starts_with("/cert/") {
                    assert_eq!(
                        method, "POST",
                        "certificate resources use signed POST-as-GET"
                    );
                    let jws: serde_json::Value =
                        serde_json::from_slice(&request[header_end..]).unwrap();
                    assert_eq!(jws["payload"], "");
                }
                if path == "/finalize" {
                    tokio::time::sleep(finalize_delay).await;
                }
                let mut extra = String::new();
                let generated = match path.as_str() {
                    "/directory" => Some(json!({
                        "newNonce":format!("{base}/nonce"), "newAccount":format!("{base}/new-account"),
                        "newOrder":format!("{base}/new-order"), "revokeCert":format!("{base}/revoke"),
                        "keyChange":format!("{base}/key-change")
                    }).to_string()),
                    "/nonce" => Some(String::new()),
                    "/new-account" => {
                        extra = format!("Location: {base}/account\r\n");
                        Some(json!({"status":"valid"}).to_string())
                    }
                    "/new-order" => {
                        extra = format!("Location: {base}/order\r\n");
                        Some(json!({"status":"ready", "authorizations":[], "finalize":format!("{base}/finalize")}).to_string())
                    }
                    "/finalize" => Some(json!({"status":"valid", "certificate":format!("{base}/cert/default")}).to_string()),
                    _ => None,
                };
                let response = generated
                    .map(|body| Response::pem(&body, Vec::new()))
                    .or_else(|| routes.get(&path).cloned())
                    .unwrap_or(Response {
                        body: Vec::new(),
                        links: Vec::new(),
                        status: 404,
                        chunked: false,
                        stall: false,
                    });
                if response.stall {
                    std::future::pending::<()>().await;
                }
                for link in &response.links {
                    extra.push_str(&format!("Link: {link}\r\n"));
                }
                let framing = if response.chunked {
                    "Transfer-Encoding: chunked\r\n".to_owned()
                } else {
                    format!("Content-Length: {}\r\n", response.body.len())
                };
                let headers = format!(
                    "HTTP/1.1 {} Test\r\nReplay-Nonce: chain-nonce\r\n{extra}{framing}Connection: close\r\n\r\n",
                    response.status
                );
                if stream.write_all(headers.as_bytes()).await.is_err() {
                    continue;
                }
                if response.chunked {
                    for chunk in response.body.chunks(16384) {
                        if stream
                            .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                            .await
                            .is_err()
                            || stream.write_all(chunk).await.is_err()
                            || stream.write_all(b"\r\n").await.is_err()
                        {
                            break;
                        }
                    }
                    let _ = stream.write_all(b"0\r\n\r\n").await;
                } else {
                    let _ = stream.write_all(&response.body).await;
                }
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }

    fn certificate_requests(&self) -> Vec<(String, String)> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, path)| path.starts_with("/cert/"))
            .cloned()
            .collect()
    }

    async fn wait_for_request(&self, path: &str) {
        let wall_deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            if self
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|(_, requested)| requested == path)
            {
                return;
            }
            assert!(!self.task.is_finished(), "test server exited before {path}");
            assert!(
                std::time::Instant::now() < wall_deadline,
                "test server never received {path}"
            );
            // Keep the paused runtime runnable while real socket/filesystem
            // setup progresses; its automatic clock must not consume the
            // issuance budget before the controlled protocol phase starts.
            tokio::task::yield_now().await;
        }
    }
}

fn chains() -> (String, String) {
    let root = |common_name: &str, padding: Option<String>| {
        let mut parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters.distinguished_name = DistinguishedName::new();
        parameters
            .distinguished_name
            .push(DnType::CommonName, common_name);
        if let Some(padding) = padding {
            parameters
                .distinguished_name
                .push(DnType::OrganizationName, padding);
        }
        parameters
    };
    let large_parameters = root("Large Root", Some("Larger default root policy ".repeat(10)));
    let compact_parameters = root("Compact Root", None);
    let large_key = KeyPair::generate().unwrap();
    let compact_key = KeyPair::generate().unwrap();
    let large = large_parameters.self_signed(&large_key).unwrap();
    let compact = compact_parameters.self_signed(&compact_key).unwrap();
    let intermediate_parameters = root("Shared Intermediate", None);
    let intermediate_key = KeyPair::generate().unwrap();
    let intermediate_large = intermediate_parameters
        .signed_by(
            &intermediate_key,
            &Issuer::from_params(&large_parameters, &large_key),
        )
        .unwrap();
    let intermediate_compact = intermediate_parameters
        .signed_by(
            &intermediate_key,
            &Issuer::from_params(&compact_parameters, &compact_key),
        )
        .unwrap();
    let leaf_parameters = CertificateParams::new(vec!["review.example.com".into()]).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = leaf_parameters
        .signed_by(
            &leaf_key,
            &Issuer::from_params(&intermediate_parameters, &intermediate_key),
        )
        .unwrap();
    let default = format!("{}{}{}", leaf.pem(), intermediate_large.pem(), large.pem());
    let alternate = format!(
        "{}{}{}",
        leaf.pem(),
        intermediate_compact.pem(),
        compact.pem()
    );
    assert!(default.len() > alternate.len());
    (default, alternate)
}

async fn issue(server: &Server, preference: Option<ChainPreference>) -> String {
    issue_with_timeout(server, preference, None).await
}

async fn issue_with_timeout(
    server: &Server,
    preference: Option<ChainPreference>,
    timeout: Option<Duration>,
) -> String {
    let directory = tempfile::tempdir().unwrap();
    let ca = format!("{}/directory", server.url);
    let builder = AcmeIssuer::builder()
        .ca(&ca)
        .test_ca(&ca)
        .storage(Arc::new(FileStorage::new(directory.path())))
        .email("chains@example.com")
        .agreed(true);
    let builder = match timeout {
        Some(timeout) => builder.cert_obtain_timeout(timeout),
        None => builder,
    };
    let issuer = match preference {
        Some(preference) => builder.preferred_chains(preference).build(),
        None => builder.build(),
    };
    String::from_utf8(
        issuer
            .issue(b"csr", &["review.example.com".into()])
            .await
            .unwrap()
            .certificate_pem,
    )
    .unwrap()
}

#[tokio::test]
async fn advertised_alternate_changes_issued_chain_for_root_any_and_size_preferences() {
    let (default, alternate) = chains();
    let server = Server::start(HashMap::from([
        ("/cert/default".into(), Response::pem(&default, vec![
            r#"<../cert/alternate?pair=a,b>; rel="up alternate"; title="a,b; escaped \"quote\"", </ignored>; rel="up""#.into(),
            r#"</cert/alternate?pair=a,b#duplicate>; rel=alternate, </cert/default>; rel="alternate""#.into(),
        ])),
        ("/cert/alternate?pair=a,b".into(), Response::pem(&alternate, vec![r#"</cert/default>; rel=alternate"#.into()])),
    ])).await;
    assert_eq!(issue(&server, None).await, default);
    assert_eq!(
        server.certificate_requests().len(),
        1,
        "unconfigured preferences do not fetch alternatives"
    );
    let preferences = [
        (ChainPreference::default(), &default),
        (
            ChainPreference {
                root_common_name: vec!["Compact Root".into()],
                ..Default::default()
            },
            &alternate,
        ),
        (
            ChainPreference {
                any_common_name: vec!["Compact Root".into()],
                ..Default::default()
            },
            &alternate,
        ),
        (
            ChainPreference {
                smallest: Some(true),
                ..Default::default()
            },
            &alternate,
        ),
        (
            ChainPreference {
                smallest: Some(false),
                ..Default::default()
            },
            &default,
        ),
        (
            ChainPreference {
                root_common_name: vec!["Missing".into()],
                any_common_name: vec!["Compact Root".into()],
                ..Default::default()
            },
            &alternate,
        ),
        (
            ChainPreference {
                root_common_name: vec!["Large Root".into()],
                any_common_name: vec!["Compact Root".into()],
                smallest: Some(true),
            },
            &default,
        ),
    ];
    for (preference, expected) in preferences {
        assert_eq!(issue(&server, Some(preference)).await, *expected);
    }
    let requests = server.certificate_requests();
    assert_eq!(
        requests
            .iter()
            .filter(|(_, path)| path == "/cert/default")
            .count(),
        8
    );
    assert_eq!(
        requests
            .iter()
            .filter(|(_, path)| path == "/cert/alternate?pair=a,b")
            .count(),
        7
    );
}

#[tokio::test]
async fn alternate_downloads_bound_requests_and_stop_cycles() {
    let (default, alternate) = chains();
    let mut routes = HashMap::from([(
        "/cert/default".into(),
        Response::pem(&default, vec![r#"</cert/1>; rel=alternate"#.into()]),
    )]);
    for number in 1..20 {
        routes.insert(format!("/cert/{number}"), Response::pem(&alternate, vec![format!(r#"</cert/{}>; rel=alternate, </cert/default>; rel=alternate, </cert/{number}>; rel=alternate"#, number + 1)]));
    }
    let server = Server::start(routes).await;
    let client = AcmeClient::new(&format!("{}/directory", server.url))
        .await
        .unwrap();
    let key = certon::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
    let result = client
        .download_certificate_chains(
            &key,
            &format!("{}/account", server.url),
            &format!("{}/cert/default", server.url),
            usize::MAX,
        )
        .await
        .unwrap();
    assert_eq!(result, vec![default, alternate]);
    let requests = server.certificate_requests();
    assert_eq!(requests.len(), 1 + MAX_ALTERNATE_CHAINS);
    for (_, path) in &requests {
        assert_eq!(
            requests.iter().filter(|(_, other)| other == path).count(),
            1
        );
    }
}

#[tokio::test]
async fn invalid_different_leaf_and_unavailable_alternatives_preserve_default() {
    let (default, alternate) = chains();
    let unrelated = rcgen::generate_simple_self_signed(vec!["other.example.com".into()]).unwrap();
    let server = Server::start(HashMap::from([
        ("/cert/default".into(), Response::pem(&default, vec![r#"</cert/unrelated>; rel=alternate, </cert/invalid>; rel=alternate, </cert/missing>; rel=alternate, </cert/valid>; rel=alternate"#.into()])),
        ("/cert/unrelated".into(), Response::pem(&unrelated.cert.pem(), Vec::new())),
        ("/cert/invalid".into(), Response::pem("not PEM", Vec::new())),
        ("/cert/valid".into(), Response::pem(&alternate, Vec::new())),
    ])).await;
    let client = AcmeClient::new(&format!("{}/directory", server.url))
        .await
        .unwrap();
    let key = certon::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
    let result = client
        .download_certificate_chains(
            &key,
            &format!("{}/account", server.url),
            &format!("{}/cert/default", server.url),
            MAX_ALTERNATE_CHAINS,
        )
        .await
        .unwrap();
    assert_eq!(result, vec![default, alternate]);
    assert_eq!(server.certificate_requests().len(), 5);
}

#[tokio::test]
async fn certificate_response_limit_covers_content_length_and_chunked_bodies() {
    for chunked in [false, true] {
        let server = Server::start(HashMap::from([(
            "/cert/default".into(),
            Response {
                body: vec![b'x'; 1024 * 1024 + 1],
                links: Vec::new(),
                status: 200,
                chunked,
                stall: false,
            },
        )]))
        .await;
        let client = AcmeClient::new(&format!("{}/directory", server.url))
            .await
            .unwrap();
        let key = certon::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
        let error = client
            .download_certificate(
                &key,
                &format!("{}/account", server.url),
                &format!("{}/cert/default", server.url),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("1 MiB"), "{error}");
    }
}

fn stalled_response() -> Response {
    Response {
        stall: true,
        ..Response::pem("", Vec::new())
    }
}

#[tokio::test(start_paused = true)]
async fn short_issuance_timeout_keeps_default_despite_stalled_alternates() {
    let (default, _) = chains();
    let server = Server::start_with_finalize_delay(
        HashMap::from([
            (
                "/cert/default".into(),
                Response::pem(
                    &default,
                    vec![
                        r#"</cert/stall-1>; rel=alternate, </cert/stall-2>; rel=alternate"#.into(),
                    ],
                ),
            ),
            ("/cert/stall-1".into(), stalled_response()),
            ("/cert/stall-2".into(), stalled_response()),
        ]),
        Duration::from_millis(500),
    )
    .await;
    // Consume 500 ms only after the real server reaches finalization. Crypto,
    // filesystem and HTTP setup must not depend on a runner's wall-clock speed.
    let issued = issue_with_timeout(
        &server,
        Some(ChainPreference::default()),
        Some(Duration::from_millis(800)),
    );
    tokio::pin!(issued);
    tokio::select! {
        _ = &mut issued => panic!("issuance finished before finalization"),
        _ = server.wait_for_request("/finalize") => {},
    }
    tokio::time::advance(Duration::from_millis(500)).await;
    tokio::select! {
        _ = &mut issued => panic!("issuance did not attempt the stalled alternate"),
        _ = server.wait_for_request("/cert/stall-1") => {},
    }
    // With the response genuinely stalled, automatic time advance exercises
    // discovery's remaining-time budget. A fresh relative timeout would instead
    // hit the outer 800 ms issuance timeout and fail this test.
    let issued = issued.await;
    assert_eq!(issued, default);
    assert_eq!(server.certificate_requests().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn short_issuance_timeout_keeps_a_collected_chain_despite_stalled_alternates() {
    let (default, alternate) = chains();
    let server = Server::start_with_finalize_delay(HashMap::from([
        ("/cert/default".into(), Response::pem(&default, vec![r#"</cert/valid>; rel=alternate, </cert/stall-1>; rel=alternate, </cert/stall-2>; rel=alternate"#.into()])),
        ("/cert/valid".into(), Response::pem(&alternate, Vec::new())),
        ("/cert/stall-1".into(), stalled_response()),
        ("/cert/stall-2".into(), stalled_response()),
    ]), Duration::from_millis(500)).await;
    let preference = ChainPreference {
        root_common_name: vec!["Compact Root".into()],
        ..Default::default()
    };
    let issued = issue_with_timeout(&server, Some(preference), Some(Duration::from_millis(800)));
    tokio::pin!(issued);
    tokio::select! {
        _ = &mut issued => panic!("issuance finished before finalization"),
        _ = server.wait_for_request("/finalize") => {},
    }
    tokio::time::advance(Duration::from_millis(500)).await;
    tokio::select! {
        _ = &mut issued => panic!("issuance did not attempt the stalled alternate"),
        _ = server.wait_for_request("/cert/stall-1") => {},
    }
    let issued = issued.await;
    assert_eq!(issued, alternate);
    assert_eq!(server.certificate_requests().len(), 3);
}

#[tokio::test]
async fn public_chain_discovery_uses_one_aggregate_budget() {
    let (default, _) = chains();
    let server = Server::start(HashMap::from([
        (
            "/cert/default".into(),
            Response::pem(
                &default,
                vec![r#"</cert/stall-1>; rel=alternate, </cert/stall-2>; rel=alternate"#.into()],
            ),
        ),
        ("/cert/stall-1".into(), stalled_response()),
        ("/cert/stall-2".into(), stalled_response()),
    ]))
    .await;
    let client = AcmeClient::new(&format!("{}/directory", server.url))
        .await
        .unwrap();
    let key = certon::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(7),
        client.download_certificate_chains(
            &key,
            &format!("{}/account", server.url),
            &format!("{}/cert/default", server.url),
            MAX_ALTERNATE_CHAINS,
        ),
    )
    .await
    .expect("alternate discovery must have a total budget shorter than HTTP timeouts")
    .unwrap();
    assert_eq!(result, vec![default]);
    assert_eq!(server.certificate_requests().len(), 2);
}
