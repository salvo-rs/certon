use super::*;

fn status(payload: &[u8]) -> (OcspStatus, Option<DateTime<Utc>>) {
    let encoded = der_wrap(0xa1, payload);
    let (rest, object) = x509_parser::der_parser::parse_der(&encoded).unwrap();
    assert!(rest.is_empty());
    parse_cert_status(&object).unwrap()
}

#[test]
fn implicit_revocation_time_is_preserved_with_or_without_a_reason() {
    let timestamp = der_wrap(0x18, b"20240102030405Z");
    let expected = DateTime::parse_from_rfc3339("2024-01-02T03:04:05Z")
        .unwrap()
        .with_timezone(&Utc);
    for reason in [None, Some(0), Some(1), Some(6), Some(10)] {
        let mut payload = timestamp.clone();
        if let Some(reason) = reason {
            payload.extend(der_wrap(0xa0, &der_wrap(0x0a, &[reason])));
        }
        assert_eq!(status(&payload), (OcspStatus::Revoked, Some(expected)));
    }
}

#[test]
fn malformed_time_remains_revoked_without_inventing_a_timestamp() {
    let timestamp = der_wrap(0x18, b"20240102030405Z");
    for payload in [
        Vec::new(),
        der_wrap(0x05, &[]),
        der_wrap(0x18, b"invalid-time"),
        der_wrap(0x18, b"20241332030405Z"),
        der_wrap(0x17, b"240102030405Z"),
        der_wrap(0x30, &timestamp),
        vec![0x18, 0x0f, b'2'],
    ] {
        assert_eq!(status(&payload), (OcspStatus::Revoked, None));
    }
}

#[test]
fn good_and_unknown_do_not_gain_revocation_metadata() {
    for (tag, expected) in [(0x80, OcspStatus::Good), (0x82, OcspStatus::Unknown)] {
        let encoded = der_wrap(tag, &[]);
        let (_, object) = x509_parser::der_parser::parse_der(&encoded).unwrap();
        assert_eq!(parse_cert_status(&object).unwrap(), (expected, None));
    }
}

#[tokio::test]
async fn verified_cache_parser_keeps_the_signed_revocation_time() {
    let (chain, key, _) = super::tests::signed_chain();
    let start = Utc::now() - chrono::Duration::minutes(1);
    let raw = super::tests::signed_response(
        &chain,
        &key,
        1,
        start,
        Utc::now() + chrono::Duration::hours(1),
    );
    let verified = parse_ocsp_response_for_cert_chain(&raw, &chain)
        .await
        .unwrap();
    assert_eq!(verified.status, OcspStatus::Revoked);
    assert_eq!(verified.raw, raw);
    assert_eq!(
        verified.revoked_at.map(|time| time.timestamp()),
        Some(start.timestamp())
    );
}
