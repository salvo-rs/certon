// Keep this in a separate process: no HTTP client may install the provider first.
#[test]
fn tls_configuration_before_http_is_supported() {
    let directory = tempfile::tempdir().unwrap();
    let config = certon::Config::builder()
        .storage(std::sync::Arc::new(certon::FileStorage::new(
            directory.path(),
        )))
        .build();
    let _ = config.tls_config();
}
