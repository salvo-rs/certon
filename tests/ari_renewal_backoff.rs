//! Real credentials and persisted ARI exercise the public manager path against
//! a local failing issuer. Counts are method calls, not real CA HTTP requests.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use certon::{
    CacheOptions, CertCache, CertManager, Certificate, KeyInfo, OcspConfig, Result, Storage,
};
use chrono::Utc;
#[derive(Default)]
struct Memory {
    marker_reads: Mutex<HashMap<String, usize>>,
    certificate_loads: Mutex<HashMap<String, usize>>,
    values: Mutex<HashMap<String, Vec<u8>>>,
    marker_errors: Mutex<HashSet<String>>,
    read_finished: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl Storage for Memory {
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        if key.starts_with("revocations/") {
            *self
                .marker_reads
                .lock()
                .unwrap()
                .entry(key.into())
                .or_default() += 1;
            self.read_finished.notify_one();
            if self.marker_errors.lock().unwrap().contains(key) {
                return Err(certon::Error::Other("marker backend unavailable".into()));
            }
        }
        if key.starts_with("certificates/") && key.ends_with("resource.v1.key") {
            *self
                .certificate_loads
                .lock()
                .unwrap()
                .entry(key.into())
                .or_default() += 1;
        }
        self.values
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| certon::error::StorageError::NotFound(key.into()).into())
    }
    async fn store(&self, _: &str, _: &[u8]) -> Result<()> {
        Ok(())
    }
    async fn delete(&self, _: &str) -> Result<()> {
        Ok(())
    }
    async fn exists(&self, _: &str) -> Result<bool> {
        Ok(false)
    }
    async fn list(&self, _: &str, _: bool) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
    async fn stat(&self, key: &str) -> Result<KeyInfo> {
        Err(certon::error::StorageError::NotFound(key.into()).into())
    }
    async fn lock(&self, _: &str) -> Result<()> {
        Ok(())
    }
    async fn unlock(&self, _: &str) -> Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct FailingIssuer {
    calls: Mutex<HashMap<String, usize>>,
    changed: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl certon::CertIssuer for FailingIssuer {
    fn issuer_key(&self) -> String {
        "diagnostic-ca".into()
    }
    async fn issue(&self, _: &[u8], domains: &[String]) -> Result<certon::IssuedCertificate> {
        *self
            .calls
            .lock()
            .unwrap()
            .entry(domains[0].clone())
            .or_default() += 1;
        self.changed.notify_one();
        Err(certon::Error::Other(
            "controlled temporary issuer failure".into(),
        ))
    }
}

async fn real_failure_scenario(k: usize, staggered: bool, disabled: bool) {
    use sha2::{Digest, Sha256};
    let storage = Arc::new(Memory::default());
    let cache = CertCache::new(CacheOptions::default());
    let issuer = Arc::new(FailingIssuer::default());
    let first_due = Utc::now() + chrono::Duration::seconds(2);
    for index in 0..k {
        let name = format!("real-{index}.example");
        let mut params = rcgen::CertificateParams::new(vec![name.clone()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        let epoch = rcgen::date_time_ymd(1970, 1, 1);
        params.not_before = epoch + Duration::from_secs((Utc::now().timestamp() - 86400) as u64);
        params.not_after =
            epoch + Duration::from_secs((Utc::now().timestamp() + 90 * 86400) as u64);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert_pem = params.self_signed(&key).unwrap().pem().into_bytes();
        let key_pem = key.serialize_pem().into_bytes();
        let mut cert = Certificate::from_pem(&cert_pem, &key_pem).unwrap();
        cert.managed = true;
        cert.issuer_key = "diagnostic-ca".into();
        let selected = first_due
            + chrono::Duration::milliseconds(if staggered { index as i64 * 200 } else { 0 });
        cert.ari = Some(certon::RenewalInfo {
            suggested_window: Some(certon::RenewalWindow {
                start: (selected - chrono::Duration::seconds(1)).to_rfc3339(),
                end: (selected + chrono::Duration::seconds(1)).to_rfc3339(),
            }),
            selected_time: Some(selected),
            retry_after: Some(3600),
            ..Default::default()
        });
        let resource = certon::CertificateResource {
            sans: vec![name.clone()],
            certificate_pem: cert_pem,
            private_key_pem: key_pem,
            issuer_key: cert.issuer_key.clone(),
            issuer_data: None,
        };
        let resource_key = format!(
            "{}/_certon/resource.v1.key",
            certon::storage::certs_site_prefix(&cert.issuer_key, &name)
        );
        storage.values.lock().unwrap().insert(
            resource_key,
            serde_json::to_vec(&serde_json::json!({
                "version": 1, "certificate_pem": resource.certificate_pem,
                "private_key_pem": resource.private_key_pem, "metadata": resource,
            }))
            .unwrap(),
        );
        let leaf = certon::certificates::hash_certificate_chain(&cert.cert_chain[..1]);
        let issuer_digest: String = Sha256::digest(cert.issuer_key.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        storage.values.lock().unwrap().insert(
            format!("ari/{issuer_digest}/{leaf}/state.json"),
            serde_json::to_vec(&serde_json::json!({
                "version": 1, "issuer": cert.issuer_key, "leaf": leaf, "info": cert.ari,
                "selected_time": selected, "next_check": Utc::now()+chrono::Duration::hours(1),
                "failures": 0, "leaf_not_after": cert.not_after,
            }))
            .unwrap(),
        );
        cache.add(cert).await;
    }
    let manager = CertManager::builder()
        .storage(storage.clone())
        .cache(cache.clone())
        .issuers(vec![issuer.clone()])
        .disable_ari(disabled)
        .ocsp(OcspConfig {
            disable_stapling: true,
            ..Default::default()
        })
        .build();
    let handle = certon::start_maintenance(&manager);
    if disabled {
        tokio::time::sleep(
            (first_due + chrono::Duration::milliseconds((k - 1) as i64 * 200) - Utc::now())
                .to_std()
                .unwrap_or_default()
                + Duration::from_millis(100),
        )
        .await;
    } else {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let changed = issuer.changed.notified();
                if issuer.calls.lock().unwrap().len() == k {
                    break;
                }
                changed.await;
            }
        })
        .await
        .expect("every real certificate must reach the failing issuer");
    }
    cache.stop_and_wait().await;
    handle.await.unwrap();
    let calls = issuer.calls.lock().unwrap();
    let total = calls.values().sum::<usize>();
    let earliest = calls.get("real-0.example").copied().unwrap_or_default();
    eprintln!(
        "REAL k={k} staggered={staggered} disabled={disabled} issuer_calls={total} earliest_leaf={earliest} unique={}",
        calls.len()
    );
    if disabled {
        assert_eq!(total, 0);
    } else {
        assert_eq!(total, k);
        assert_eq!(earliest, 1);
    }
}

#[tokio::test]
async fn staggered_ari_deadlines_do_not_retry_failed_real_issuance_before_backoff() {
    real_failure_scenario(8, true, false).await;
    real_failure_scenario(16, true, false).await;
    real_failure_scenario(16, false, false).await;
    real_failure_scenario(8, true, true).await;
}
