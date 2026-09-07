//! The HTTP client must work as the very first thing a program does.
//!
//! This is an integration test, and therefore its own binary and its own
//! process, because that is the only way to assert it. Inside the unit tests
//! something else has always constructed a `Config` or an `AcmeClient` first,
//! and those used to be what installed the rustls provider that `reqwest`
//! requires — so the OCSP and ZeroSSL paths appeared to work there while
//! aborting the process in a program that reached them first.
//!
//! Nothing else may go in this file. A second test would run in the same
//! process and this one would stop proving anything.

#[test]
fn building_the_client_needs_nothing_to_have_run_before_it() {
    // Before the single client existed, the equivalent of this line inside
    // `ocsp` or `zerossl_issuer` panicked with "No rustls crypto provider is
    // configured", killing the process rather than returning an error.
    let client = certon::http::client().expect("the client builds on its own");

    // And it is genuinely usable: a request that cannot connect has to come
    // back as an error, not as an abort.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let outcome = runtime.block_on(async {
        client
            .get("https://127.0.0.1:1/nothing-is-listening-here")
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
    });
    assert!(outcome.is_err(), "nothing is listening on port 1");
}
