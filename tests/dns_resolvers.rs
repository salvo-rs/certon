#![cfg(feature = "dns-01")]

use std::time::Duration;

#[tokio::test]
async fn propagation_uses_custom_resolver_and_combines_txt_fragments() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let mut query = [0; 2048];
        let (length, peer) = server.recv_from(&mut query).await.unwrap();
        assert!(length > 16);
        let mut end = 12;
        while query[end] != 0 {
            end += query[end] as usize + 1;
        }
        end += 5;
        let mut response = query[..2].to_vec();
        response.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        response.extend_from_slice(&query[12..end]);
        response.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 0, 0, 13]);
        response.extend_from_slice(b"\x05hello\x06-world");
        server.send_to(&response, peer).await.unwrap();
    });
    let result = certon::dns_util::check_dns_propagation_with_resolvers(
        "_acme-challenge.review.example.com",
        "hello-world",
        Duration::from_secs(2),
        Duration::from_millis(10),
        Some(&[address]),
    )
    .await
    .unwrap();
    assert!(result);
    task.await.unwrap();
}

#[tokio::test]
async fn empty_or_invalid_custom_resolver_configuration_is_rejected() {
    for resolvers in [vec![], vec!["not-an-ip-and-port".into()]] {
        let result = certon::dns_util::check_dns_propagation_with_resolvers(
            "_acme-challenge.example.com",
            "value",
            Duration::from_millis(10),
            Duration::from_millis(1),
            Some(&resolvers),
        )
        .await;
        assert!(matches!(result, Err(certon::Error::Config(_))));
    }
}
