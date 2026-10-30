use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

const API_KEY: &str = "synthetic-api-key&private=value";
const KID: &str = "synthetic-eab-kid";
const HMAC: &str = "c3ludGhldGljLWVhYi1obWFj";

async fn build_response(body: &str, chunked: bool, status: u16) -> Result<ZeroSslIssuer> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let body = body.to_owned();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut part = [0; 1024];
            let count = stream.read(&mut part).await.unwrap();
            assert!(count > 0);
            request.extend_from_slice(&part[..count]);
        }
        let encoding = if chunked {
            "Transfer-Encoding: chunked\r\n".to_owned()
        } else {
            format!("Content-Length: {}\r\n", body.len())
        };
        let header = format!("HTTP/1.1 {status} Fixture\r\n{encoding}Connection: close\r\n\r\n");
        if stream.write_all(header.as_bytes()).await.is_ok() {
            if chunked {
                for part in body.as_bytes().chunks(4096) {
                    if stream
                        .write_all(format!("{:x}\r\n", part.len()).as_bytes())
                        .await
                        .is_err()
                        || stream.write_all(part).await.is_err()
                        || stream.write_all(b"\r\n").await.is_err()
                    {
                        break;
                    }
                }
                let _ = stream.write_all(b"0\r\n\r\n").await;
            } else {
                let _ = stream.write_all(body.as_bytes()).await;
            }
        }
        String::from_utf8(request).unwrap()
    });
    let directory = tempfile::tempdir().unwrap();
    let mut builder = ZeroSslIssuer::builder()
        .api_key(API_KEY)
        .storage(Arc::new(crate::FileStorage::new(directory.path())));
    builder.eab_origin = Some(origin);
    let result = builder.build().await;
    let request = server.await.unwrap();
    assert!(request.starts_with("POST /acme/eab-credentials?"));
    let target = request
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();
    let target = Url::parse(&format!("http://localhost{target}")).unwrap();
    let query: Vec<_> = target.query_pairs().collect();
    assert_eq!(query.len(), 1);
    assert_eq!(query[0].0, "access_key");
    assert_eq!(query[0].1, API_KEY);
    result
}

#[tokio::test]
async fn builder_accepts_documented_integer_and_boolean_eab_success() {
    for chunked in [false, true] {
        for success in [serde_json::json!(1), serde_json::json!(true)] {
            let body = serde_json::json!({"success":success,"eab_kid":KID,"eab_hmac_key":HMAC})
                .to_string();
            let issuer = build_response(&body, chunked, 200).await.unwrap();
            let eab = issuer.inner.external_account.as_ref().unwrap();
            assert_eq!(eab.kid, KID);
            assert_eq!(eab.hmac_key, b"synthetic-eab-hmac");
            let debug = format!("{issuer:?}");
            assert!(!debug.contains(API_KEY));
            assert!(!debug.contains(KID));
            assert!(!debug.contains(HMAC));
            assert!(!debug.contains("synthetic-eab-hmac"));
        }
    }
}

#[tokio::test]
async fn builder_rejects_unsuccessful_or_invalid_eab_success_flags() {
    for chunked in [false, true] {
        for success in [
            "false", "0", "2", "-1", "1.0", "null", "\"1\"", "\"true\"", "[]", "{}",
        ] {
            let body =
                format!(r#"{{"success":{success},"eab_kid":"{KID}","eab_hmac_key":"{HMAC}"}}"#);
            assert!(
                build_response(&body, chunked, 200).await.is_err(),
                "accepted {success}"
            );
        }
        let missing = format!(r#"{{"eab_kid":"{KID}","eab_hmac_key":"{HMAC}"}}"#);
        assert!(build_response(&missing, chunked, 200).await.is_err());
        let duplicate =
            format!(r#"{{"success":true,"success":1,"eab_kid":"{KID}","eab_hmac_key":"{HMAC}"}}"#);
        assert!(build_response(&duplicate, chunked, 200).await.is_err());
    }
}

#[tokio::test]
async fn builder_requires_eab_credentials_and_decodes_hmac_after_success() {
    for chunked in [false, true] {
        for body in [
            serde_json::json!({"success":1,"eab_hmac_key":HMAC}),
            serde_json::json!({"success":1,"eab_kid":KID}),
            serde_json::json!({"success":1,"eab_kid":KID,"eab_hmac_key":"not+base64url!"}),
            serde_json::json!({"success":1,"eab_kid":"","eab_hmac_key":HMAC}),
            serde_json::json!({"success":1,"eab_kid":KID,"eab_hmac_key":""}),
        ] {
            let error = build_response(&body.to_string(), chunked, 200)
                .await
                .unwrap_err()
                .to_string();
            assert!(!error.contains(API_KEY));
            assert!(!error.contains(HMAC));
        }
    }
}

#[tokio::test]
async fn builder_keeps_eab_success_and_error_response_read_limits() {
    for chunked in [false, true] {
        for (status, limit) in [
            (200, crate::http::MAX_JSON_BODY_BYTES),
            (400, crate::http::MAX_ERROR_BODY_BYTES),
        ] {
            let body = serde_json::json!({"success":1,"padding":"x".repeat(limit),"eab_kid":KID,"eab_hmac_key":HMAC}).to_string();
            let error = build_response(&body, chunked, status)
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("exceeds"));
            assert!(error.len() < 1024);
            assert!(!error.contains(API_KEY));
            assert!(!error.contains(HMAC));
        }
    }
}

#[tokio::test]
async fn builder_eab_failures_never_echo_api_keys_or_binding_credentials() {
    let reflected = format!("{API_KEY} {KID} {HMAC}");
    let invalid = serde_json::json!({
        "success": reflected,
        "eab_kid": KID,
        "eab_hmac_key": HMAC,
    })
    .to_string();
    let denied = serde_json::json!({
        "success": false,
        "error": {"code": 123, "type": reflected},
        "eab_kid": KID,
        "eab_hmac_key": HMAC,
    })
    .to_string();
    let http_error = serde_json::json!({
        "error": {"code": 123, "type": reflected},
        "eab_kid": KID,
        "eab_hmac_key": HMAC,
    })
    .to_string();
    for chunked in [false, true] {
        for (status, body, code) in [
            (200, invalid.as_str(), false),
            (200, denied.as_str(), true),
            (400, http_error.as_str(), true),
            (400, reflected.as_str(), false),
        ] {
            let error = build_response(body, chunked, status)
                .await
                .unwrap_err()
                .to_string();
            for credential in [API_KEY, KID, HMAC] {
                assert!(!error.contains(credential), "{error}");
            }
            if code {
                assert!(error.contains("error code 123"));
            }
            if status == 400 {
                assert!(error.contains("400"));
            }
        }
    }
}

#[tokio::test]
async fn builder_rejects_eab_error_envelopes_even_with_explicit_success() {
    for chunked in [false, true] {
        for success in [serde_json::json!(1), serde_json::json!(true)] {
            for error in [
                serde_json::json!({"code": 123}),
                serde_json::json!({}),
                serde_json::json!([]),
                serde_json::json!(false),
                serde_json::json!(0),
                serde_json::json!(""),
            ] {
                let body = serde_json::json!({
                    "success": success, "error": error,
                    "eab_kid": KID, "eab_hmac_key": HMAC,
                });
                assert!(
                    build_response(&body.to_string(), chunked, 200)
                        .await
                        .is_err()
                );
            }
            let body = serde_json::json!({
                "success": success, "error": null,
                "eab_kid": KID, "eab_hmac_key": HMAC,
            });
            let issuer = build_response(&body.to_string(), chunked, 200)
                .await
                .unwrap();
            assert_eq!(issuer.inner.external_account.as_ref().unwrap().kid, KID);
        }
    }
}
