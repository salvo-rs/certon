use std::sync::Arc;

use certon::{CertManager, Certificate, Error, FileStorage, Policy};
use chrono::Datelike;

fn certificate(due: bool) -> Certificate {
    certon::install_default_crypto_provider();
    let year = chrono::Utc::now().year();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["example.com".into()]).unwrap();
    params.not_before = rcgen::date_time_ymd(year - if due { 4 } else { 1 }, 1, 1);
    params.not_after = rcgen::date_time_ymd(year + if due { 1 } else { 10 }, 1, 1);
    let cert = params.self_signed(&key).unwrap();
    Certificate::from_pem(cert.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap()
}

#[test]
fn malformed_low_level_ratios_never_panic_or_silently_disable_the_renewal_window() {
    for due in [false, true] {
        let cert = certificate(due);
        let default = cert.needs_renewal(0.0);
        assert_eq!(default, due);
        for ratio in [f64::INFINITY, f64::NEG_INFINITY, f64::NAN, f64::MAX, 2.0] {
            assert_eq!(
                cert.needs_renewal(ratio),
                default,
                "ratio {ratio} changed default behavior"
            );
        }
        assert_eq!(cert.needs_renewal(-1.0), default);
    }
}

#[test]
fn fallible_builder_rejects_invalid_ratios_from_setters_and_whole_policies() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(FileStorage::new(directory.path()));
    for ratio in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, f64::MAX, 1.01] {
        let error = CertManager::builder()
            .storage(storage.clone())
            .renewal_window_ratio(ratio)
            .try_build()
            .unwrap_err();
        assert!(
            matches!(error, Error::Config(ref detail) if detail.contains("renewal_window_ratio"))
        );
        let error = CertManager::builder()
            .storage(storage.clone())
            .policy(Policy {
                renewal_window_ratio: ratio,
                ..Default::default()
            })
            .try_build()
            .unwrap_err();
        assert!(
            matches!(error, Error::Config(ref detail) if detail.contains("renewal_window_ratio"))
        );
    }
    // Configuration validation must not probe or write the storage backend.
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn fallible_builder_preserves_supported_ratios_and_reports_missing_storage() {
    let directory = tempfile::tempdir().unwrap();
    for ratio in [-1.0, 0.0, 1.0 / 3.0, 0.95, 1.0] {
        CertManager::builder()
            .storage(Arc::new(FileStorage::new(directory.path())))
            .renewal_window_ratio(ratio)
            .try_build()
            .unwrap();
    }
    assert!(
        matches!(CertManager::builder().try_build(), Err(Error::Config(detail)) if detail.contains("Storage"))
    );
}
