use certon::KeyType;
use certon::acme_client::AcmeClient;
use certon::crypto::generate_private_key;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Server {
    url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn start(oversized_path: &'static str, status: u16, chunked: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let base = url.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 4096];
                let (header_end, body_length) = loop {
                    let count = stream.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        return;
                    }
                    request.extend_from_slice(&buffer[..count]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&request[..end]);
                        let length = header
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
                while request.len() < header_end + body_length {
                    let count = stream.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        return;
                    }
                    request.extend_from_slice(&buffer[..count]);
                }
                let header = String::from_utf8_lossy(&request[..header_end]);
                let path = header.split_whitespace().nth(1).unwrap();
                let head = header.starts_with("HEAD ");
                let mut body = match path {
                    "/directory" => json!({
                        "newNonce": format!("{base}/nonce"),
                        "newAccount": format!("{base}/account"),
                        "newOrder": format!("{base}/order"),
                        "revokeCert": format!("{base}/revoke"),
                        "keyChange": format!("{base}/key-change"),
                        "renewalInfo": format!("{base}/ari")
                    }),
                    "/account" => json!({"status": "valid", "contact": []}),
                    _ => json!({}),
                };
                let oversized = path == oversized_path;
                if oversized {
                    body["padding"] = json!("x".repeat(1024 * 1024 + 1));
                }
                let bytes = if head {
                    Vec::new()
                } else {
                    body.to_string().into_bytes()
                };
                let code = if oversized { status } else { 200 };
                let encoding = if chunked && !head {
                    "Transfer-Encoding: chunked\r\n".to_string()
                } else {
                    format!("Content-Length: {}\r\n", bytes.len())
                };
                let response = format!(
                    "HTTP/1.1 {code} Test\r\n{encoding}Replay-Nonce: limits-nonce\r\nLocation: {base}/account/id\r\nConnection: close\r\n\r\n"
                );
                if stream.write_all(response.as_bytes()).await.is_err() {
                    continue;
                }
                if chunked && !head {
                    for part in bytes.chunks(4096) {
                        let length = format!("{:x}\r\n", part.len());
                        if stream.write_all(length.as_bytes()).await.is_err()
                            || stream.write_all(part).await.is_err()
                            || stream.write_all(b"\r\n").await.is_err()
                        {
                            break;
                        }
                    }
                    let _ = stream.write_all(b"0\r\n\r\n").await;
                } else {
                    let _ = stream.write_all(&bytes).await;
                }
            }
        });
        Self { url, task }
    }
}

#[tokio::test]
async fn oversized_directory_is_rejected() {
    for chunked in [false, true] {
        let server = Server::start("/directory", 200, chunked).await;
        let error = AcmeClient::new(&format!("{}/directory", server.url))
            .await
            .expect_err("oversized directory was accepted");
        assert!(error.to_string().contains("exceeds"), "{error}");
    }
}

#[tokio::test]
async fn oversized_account_json_and_errors_are_bounded() {
    let key = generate_private_key(KeyType::EcdsaP256).unwrap();
    for status in [200, 400, 503] {
        let server = Server::start("/account", status, true).await;
        let client = AcmeClient::new(&format!("{}/directory", server.url))
            .await
            .unwrap();
        let error = client
            .new_account(&key, &[], true, None)
            .await
            .expect_err("oversized account response was accepted");
        assert!(error.to_string().contains("exceeds"), "{error}");
        assert!(
            error.to_string().len() < 1024,
            "error body escaped the log budget"
        );
    }
}

#[tokio::test]
async fn oversized_ari_response_is_bounded() {
    let server = Server::start("/ari/id", 200, true).await;
    let client = AcmeClient::new(&format!("{}/directory", server.url))
        .await
        .unwrap();
    let key = generate_private_key(KeyType::EcdsaP256).unwrap();
    let error = client
        .get_renewal_info(&key, "unused", "id")
        .await
        .expect_err("oversized ARI response was accepted");
    assert!(error.to_string().contains("exceeds"), "{error}");
}
