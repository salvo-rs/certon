// No other test may initialize the process-wide provider before this entry point.
#[tokio::test]
async fn manage_without_http_initializes_tls() {
    certon::manage(&[]).await.unwrap();
}
