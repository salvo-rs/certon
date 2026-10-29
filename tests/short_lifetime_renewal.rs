use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use certon::{
    CertIssuer, CertManager, CertificateResource, FileStorage, IssuedCertificate, OcspConfig,
    RenewalInfo, RenewalWindow, Result,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PublicKeyData};
use x509_parser::prelude::FromDer;

const DOMAIN: &str = "short.example";
const HOUR: u64 = 3600;

struct Public(Vec<u8>);
impl PublicKeyData for Public {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

struct Issuer {
    ca: rcgen::Issuer<'static, KeyPair>,
    lifetime: Duration,
    calls: AtomicUsize,
    // 0: no ARI, 1: future window, 2: already selected/due window.
    ari: AtomicU8,
}

impl Issuer {
    fn new(hours: u64, ari: u8) -> Self {
        let mut ca = CertificateParams::new(vec!["short-lived-root".into()]).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        Self {
            ca: rcgen::Issuer::new(ca, KeyPair::generate().unwrap()),
            lifetime: Duration::from_secs(hours * HOUR),
            calls: AtomicUsize::new(0),
            ari: AtomicU8::new(ari),
        }
    }

    fn seed(&self, before: SystemTime, after: SystemTime) -> CertificateResource {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![DOMAIN.into()]).unwrap();
        params.not_before = before.into();
        params.not_after = after.into();
        params.serial_number = Some(100u64.into());
        params.use_authority_key_identifier_extension = true;
        CertificateResource {
            certificate_pem: params.signed_by(&key, &self.ca).unwrap().pem().into_bytes(),
            private_key_pem: key.serialize_pem().into_bytes(),
            sans: vec![DOMAIN.into()],
            issuer_key: self.issuer_key(),
            issuer_data: None,
        }
    }
}

#[async_trait::async_trait]
impl CertIssuer for Issuer {
    fn issuer_key(&self) -> String {
        "short-lived-ca".into()
    }

    async fn issue(&self, csr: &[u8], domains: &[String]) -> Result<IssuedCertificate> {
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(csr).unwrap();
        csr.verify_signature().unwrap();
        let serial = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let public = Public(
            csr.certification_request_info
                .subject_pki
                .subject_public_key
                .data
                .to_vec(),
        );
        let mut params = CertificateParams::new(domains.to_vec()).unwrap();
        params.not_before = (SystemTime::now() - Duration::from_secs(60)).into();
        params.not_after = (SystemTime::now() + self.lifetime).into();
        params.serial_number = Some((serial as u64).into());
        params.use_authority_key_identifier_extension = true;
        Ok(IssuedCertificate {
            certificate_pem: params
                .signed_by(&public, &self.ca)
                .unwrap()
                .pem()
                .into_bytes(),
            private_key_pem: Vec::new(),
            metadata: serde_json::Value::Null,
        })
    }

    async fn renewal_info(&self, _: &[u8]) -> Result<Option<RenewalInfo>> {
        let (start, end) = match self.ari.load(Ordering::SeqCst) {
            0 => return Ok(None),
            1 => (chrono::Duration::hours(3), chrono::Duration::hours(4)),
            2 => (chrono::Duration::minutes(-2), chrono::Duration::minutes(-1)),
            _ => unreachable!(),
        };
        let now = chrono::Utc::now();
        Ok(Some(RenewalInfo {
            suggested_window: Some(RenewalWindow {
                start: (now + start).to_rfc3339(),
                end: (now + end).to_rfc3339(),
            }),
            retry_after: Some(3600),
            ..Default::default()
        }))
    }
}

fn manager(storage: Arc<FileStorage>, issuer: Arc<Issuer>) -> CertManager {
    CertManager::builder()
        .storage(storage)
        .issuers(vec![issuer])
        .interactive(true)
        .reuse_private_keys(true)
        .ocsp(OcspConfig {
            disable_stapling: true,
            ..Default::default()
        })
        .build()
}

async fn fresh_without_reissuance(hours: u64, ari: u8) {
    let directory = tempfile::tempdir().unwrap();
    let issuer = Arc::new(Issuer::new(hours, ari));
    let manager = manager(Arc::new(FileStorage::new(directory.path())), issuer.clone());
    manager.manage(&[DOMAIN.into()]).await.unwrap();
    let initial = manager.cache.get_by_name(DOMAIN).await.unwrap();
    if ari == 1 {
        assert!(initial.ari.as_ref().unwrap().selected_time.unwrap() > chrono::Utc::now());
    }
    for _ in 0..3 {
        manager.renew(DOMAIN, false).await.unwrap();
    }
    eprintln!(
        "validity_hours={hours} ari={ari} actual_ca_calls={}",
        issuer.calls.load(Ordering::SeqCst)
    );
    assert_eq!(
        issuer.calls.load(Ordering::SeqCst),
        1,
        "{hours}-hour certificate was reissued without time advancing"
    );
    assert!(!initial.needs_renewal(1.0 / 3.0));
    assert_eq!(
        manager.cache.get_by_name(DOMAIN).await.unwrap().hash,
        initial.hash
    );
}

#[tokio::test]
async fn fresh_short_certificates_do_not_reissue_on_nonforced_renewal() {
    for hours in [1, 6, 24, 48, 72] {
        fresh_without_reissuance(hours, 0).await;
    }
}

#[tokio::test]
async fn fresh_ninety_day_control_keeps_its_original_renewal_behaviour() {
    fresh_without_reissuance(90 * 24, 0).await;
}

#[tokio::test]
async fn a_future_ari_window_keeps_a_fresh_six_hour_leaf_without_reissuance() {
    fresh_without_reissuance(6, 1).await;
}

#[tokio::test]
async fn due_ari_still_renews_a_six_hour_leaf_once_and_keeps_its_fresh_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let issuer = Arc::new(Issuer::new(6, 2));
    let manager = manager(Arc::new(FileStorage::new(directory.path())), issuer.clone());
    manager.manage(&[DOMAIN.into()]).await.unwrap();
    let initial = manager.cache.get_by_name(DOMAIN).await.unwrap();
    assert!(initial.ari.as_ref().unwrap().selected_time.unwrap() < chrono::Utc::now());
    assert!(initial.needs_renewal(1.0 / 3.0));
    issuer.ari.store(1, Ordering::SeqCst);
    manager.renew(DOMAIN, false).await.unwrap();
    let replacement = manager.cache.get_by_name(DOMAIN).await.unwrap();
    assert_ne!(replacement.hash, initial.hash);
    for _ in 0..3 {
        manager.renew(DOMAIN, false).await.unwrap();
    }
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 2);
    assert!(!replacement.needs_renewal(1.0 / 3.0));
}

#[tokio::test]
async fn due_expired_and_future_short_resources_are_replaced_by_normal_renewal() {
    for (before_hours, after_hours) in [(-5, 1), (-7, -1), (1, 7)] {
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(FileStorage::new(directory.path()));
        let issuer = Arc::new(Issuer::new(6, 0));
        let now = SystemTime::now();
        let at = |hours: i64| {
            if hours < 0 {
                now - Duration::from_secs(hours.unsigned_abs() * HOUR)
            } else {
                now + Duration::from_secs(hours as u64 * HOUR)
            }
        };
        let old = issuer.seed(at(before_hours), at(after_hours));
        let old_leaf = certon::Certificate::from_pem(&old.certificate_pem, &old.private_key_pem)
            .unwrap()
            .cert_chain[0]
            .clone();
        certon::storage::store_certificate(storage.as_ref(), &issuer.issuer_key(), &old)
            .await
            .unwrap();
        let manager = manager(storage, issuer.clone());
        manager.renew(DOMAIN, false).await.unwrap();
        let replacement = manager.cache.get_by_name(DOMAIN).await.unwrap();
        assert_ne!(replacement.cert_chain[0], old_leaf);
        manager.renew(DOMAIN, false).await.unwrap();
        assert_eq!(
            issuer.calls.load(Ordering::SeqCst),
            1,
            "{before_hours}/{after_hours} hour validity"
        );
        assert!(!replacement.needs_renewal(1.0 / 3.0));
    }
}
