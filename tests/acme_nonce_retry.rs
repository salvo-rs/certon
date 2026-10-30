use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use certon::KeyType;
use certon::acme_client::AcmeClient;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn scenario(
    concurrent: bool,
    lookup: bool,
    fault: Option<(u16, &'static str, Option<&'static str>)>,
    repeat: bool,
) -> (bool, Vec<(String, String)>) {
    for token in ["aW5pdGlhbA", "cmVzZXJ2ZWQ", "dW5yZWxhdGVk"] {
        assert_eq!(
            URL_SAFE_NO_PAD.encode(URL_SAFE_NO_PAD.decode(token).unwrap()),
            token
        );
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let records = Arc::new(Mutex::new(Vec::new()));
    let headers = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let server = tokio::spawn({
        let (base, records, headers, release, attempts) = (
            base.clone(),
            records.clone(),
            headers.clone(),
            release.clone(),
            attempts.clone(),
        );
        async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (base, records, headers, release, attempts) = (
                    base.clone(),
                    records.clone(),
                    headers.clone(),
                    release.clone(),
                    attempts.clone(),
                );
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let end = loop {
                        let mut buffer = [0; 4096];
                        let n = socket.read(&mut buffer).await.unwrap();
                        assert!(n > 0);
                        request.extend_from_slice(&buffer[..n]);
                        if let Some(end) = request.windows(4).position(|s| s == b"\r\n\r\n") {
                            break end + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&request[..end]);
                    let path = head.split_whitespace().nth(1).unwrap().to_string();
                    let len: usize = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().unwrap())
                        })
                        .unwrap_or(0);
                    while request.len() < end + len {
                        let mut buffer = [0; 4096];
                        let n = socket.read(&mut buffer).await.unwrap();
                        assert!(n > 0);
                        request.extend_from_slice(&buffer[..n]);
                    }
                    let mut status = 200;
                    let mut nonce = "aW5pdGlhbA";
                    let mut extra = String::new();
                    let body = if path == "/directory" {
                        json!({"newNonce":format!("{base}/nonce"),"newAccount":format!("{base}/account"),"newOrder":format!("{base}/order"),"revokeCert":format!("{base}/revoke"),"keyChange":format!("{base}/key-change")}).to_string()
                    } else if path == "/nonce" {
                        if attempts.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                            nonce = "bmV3LW5vbmNl";
                        }
                        String::new()
                    } else {
                        let jws: Value = serde_json::from_slice(&request[end..end + len]).unwrap();
                        let protected: Value = serde_json::from_slice(
                            &URL_SAFE_NO_PAD
                                .decode(jws["protected"].as_str().unwrap())
                                .unwrap(),
                        )
                        .unwrap();
                        let payload: Value = serde_json::from_slice(
                            &URL_SAFE_NO_PAD
                                .decode(jws["payload"].as_str().unwrap())
                                .unwrap(),
                        )
                        .unwrap();
                        if lookup {
                            assert!(protected.get("jwk").is_some());
                            assert!(protected.get("kid").is_none());
                            assert_eq!(payload, json!({"onlyReturnExisting":true}));
                        }
                        let label = if lookup {
                            "lookup"
                        } else {
                            payload["identifiers"][0]["value"].as_str().unwrap()
                        };
                        let received = protected["nonce"].as_str().unwrap().to_string();
                        records
                            .lock()
                            .unwrap()
                            .push((label.into(), received.clone()));
                        let first = label != "second.example";
                        let attempt = if first {
                            attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                        } else {
                            0
                        };
                        if first && (attempt == 0 || repeat) {
                            let (status, kind, nonce) = fault.unwrap_or((
                                400,
                                "urn:ietf:params:acme:error:badNonce",
                                Some("cmVzZXJ2ZWQ"),
                            ));
                            let body = json!({"type":kind,"status":400}).to_string();
                            let header = nonce
                                .map(|value| format!("Replay-Nonce: {value}\r\n"))
                                .unwrap_or_default();
                            socket.write_all(format!("HTTP/1.1 {status} Fixture\r\n{header}Content-Length: {}\r\nConnection: close\r\n\r\n{{", body.len()).as_bytes()).await.unwrap();
                            headers.notify_one();
                            if concurrent {
                                release.notified().await;
                            }
                            socket.write_all(&body.as_bytes()[1..]).await.unwrap();
                            return;
                        }
                        nonce = "dW5yZWxhdGVk";
                        if first && received != "cmVzZXJ2ZWQ" {
                            status = 400;
                            json!({"type":"urn:ietf:params:acme:error:badNonce","detail":"retry must use reserved nonce"}).to_string()
                        } else {
                            if !first {
                                nonce = "c2Vjb25kLXJlc3BvbnNl";
                            }
                            extra = format!("Location: {base}/resource\r\n");
                            if lookup {
                                json!({"status":"valid"}).to_string()
                            } else {
                                json!({"status":"ready","finalize":format!("{base}/finalize")})
                                    .to_string()
                            }
                        }
                    };
                    socket.write_all(format!("HTTP/1.1 {status} Fixture\r\nReplay-Nonce: {nonce}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
                });
            }
        }
    });
    let client = Arc::new(AcmeClient::new(&format!("{base}/directory")).await.unwrap());
    let key = Arc::new(certon::crypto::generate_private_key(KeyType::EcdsaP256).unwrap());
    let first = tokio::spawn({
        let (client, key, base) = (client.clone(), key.clone(), base.clone());
        async move {
            if lookup {
                client
                    .find_account(&key)
                    .await
                    .map(|value| {
                        let (account, location) = value.expect("existing account");
                        assert_eq!(account.status, "valid");
                        assert_eq!(location, format!("{base}/resource"));
                    })
                    .is_ok()
            } else {
                client
                    .new_order(
                        &key,
                        &format!("{base}/account/1"),
                        &["first.example".into()],
                    )
                    .await
                    .is_ok()
            }
        }
    });
    if concurrent {
        headers.notified().await;
        // Header processing caches the nonce before awaiting the held body.
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            client
                .new_order(
                    &key,
                    &format!("{base}/account/1"),
                    &["second.example".into()]
                )
                .await
                .is_ok()
        );
        release.notify_one();
    }
    let ok = tokio::time::timeout(Duration::from_secs(5), first)
        .await
        .unwrap()
        .unwrap();
    if ok && !lookup && !concurrent {
        client
            .new_order(
                &key,
                &format!("{base}/account/1"),
                &["second.example".into()],
            )
            .await
            .unwrap();
    }
    let records = records.lock().unwrap().clone();
    server.abort();
    (ok, records)
}

#[tokio::test]
async fn round11_bad_nonce_serial_control() {
    let (ok, records) = scenario(false, false, None, false).await;
    println!("serial: ok={ok}, trace={records:?}");
    assert!(ok);
    assert_eq!(records[1].1, "cmVzZXJ2ZWQ");
    assert_eq!(
        records[2].1, "dW5yZWxhdGVk",
        "normal response nonce must remain reusable"
    );
}

#[tokio::test]
async fn round11_bad_nonce_concurrent_retry_keeps_its_nonce() {
    let (ok, records) = scenario(true, false, None, false).await;
    println!("concurrent: ok={ok}, trace={records:?}");
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].0, "first.example");
    assert_eq!(records[1].0, "second.example");
    assert_eq!(records[2].0, "first.example");
    assert_ne!(
        records[1].1, "cmVzZXJ2ZWQ",
        "the error nonce must never enter the pool shared with another request"
    );
    assert_eq!(
        records[2].1, "cmVzZXJ2ZWQ",
        "the original request must retry with its own error response nonce"
    );
    assert!(
        ok,
        "a concurrent request consumed the badNonce-specific nonce: {records:?}"
    );
}

#[tokio::test]
async fn round11_find_account_retries_bad_nonce() {
    let (ok, records) = scenario(false, true, None, false).await;
    println!("lookup: ok={ok}, trace={records:?}");
    assert!(ok, "lookup must recover a fresh nonce: {records:?}");
}

#[tokio::test]
async fn nonce_retry_requires_exact_type_status_and_valid_nonce() {
    for lookup in [false, true] {
        for fault in [
            (400, "urn:ietf:params:acme:error:badNonce", None),
            (400, "urn:ietf:params:acme:error:badNonce", Some("+invalid")),
            (400, "urn:ietf:params:acme:error:badNonce", Some("a")),
            (400, "urn:vendor:badNonce", Some("cmVzZXJ2ZWQ")),
            (
                403,
                "urn:ietf:params:acme:error:badNonce",
                Some("cmVzZXJ2ZWQ"),
            ),
            (
                400,
                "urn:ietf:params:acme:error:unauthorized",
                Some("cmVzZXJ2ZWQ"),
            ),
        ] {
            let (ok, records) = scenario(false, lookup, Some(fault), false).await;
            assert!(!ok, "lookup={lookup}, fault={fault:?}");
            assert_eq!(
                records.len(),
                1,
                "must not replay lookup={lookup}, fault={fault:?}"
            );
        }
    }
}

#[tokio::test]
async fn nonce_retry_is_bounded_to_one_replay() {
    for lookup in [false, true] {
        let (ok, records) = scenario(false, lookup, None, true).await;
        assert!(!ok);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].1, "cmVzZXJ2ZWQ");
    }
}
