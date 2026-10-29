use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use rcgen::{CertificateParams, KeyPair, SigningKey};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x509_parser::prelude::{FromDer, X509Certificate};

fn der(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        let size = value.len().to_be_bytes();
        let first = size.iter().position(|byte| *byte != 0).unwrap();
        out.push(0x80 | (size.len() - first) as u8);
        out.extend_from_slice(&size[first..]);
    }
    out.extend_from_slice(value);
    out
}
fn time(value: DateTime<Utc>) -> Vec<u8> {
    der(0x18, value.format("%Y%m%d%H%M%SZ").to_string().as_bytes())
}

struct Fixture {
    ca_der: Vec<u8>,
    key: KeyPair,
    target_der: Vec<u8>,
    other_der: Vec<u8>,
    pem: Vec<u8>,
    target_key_pem: String,
    produced_at: DateTime<Utc>,
}
impl Fixture {
    fn new(url: &str) -> Self {
        let key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::new(vec!["probe-ca".into()]).unwrap();
        ca.distinguished_name
            .push(rcgen::DnType::CommonName, "Batch OCSP CA");
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let root = ca.self_signed(&key).unwrap();
        let issuer = rcgen::Issuer::new(ca, &key);
        let mut leaf = CertificateParams::new(vec!["target.example".into()]).unwrap();
        leaf.serial_number = Some(123u64.into());
        // AIA = SEQUENCE { AccessDescription { id-ad-ocsp, URI } }.
        let aia = der(
            0x30,
            &der(
                0x30,
                &[
                    der(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]),
                    der(0x86, url.as_bytes()),
                ]
                .concat(),
            ),
        );
        leaf.custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 1, 1],
                aia,
            ));
        // Actual status_request Must-Staple certificate, though the low-level
        // public OCSP fetch does not enforce serving admission itself.
        leaf.custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 1, 24],
                vec![0x30, 3, 2, 1, 5],
            ));
        let target_key = KeyPair::generate().unwrap();
        let target = leaf.signed_by(&target_key, &issuer).unwrap();
        let mut other = CertificateParams::new(vec!["other.example".into()]).unwrap();
        other.serial_number = Some(124u64.into());
        let other = other
            .signed_by(&KeyPair::generate().unwrap(), &issuer)
            .unwrap();
        let pem = format!("{}{}", target.pem(), root.pem()).into_bytes();
        Self {
            ca_der: root.der().to_vec(),
            key,
            target_der: target.der().to_vec(),
            other_der: other.der().to_vec(),
            pem,
            target_key_pem: target_key.serialize_pem(),
            produced_at: Utc::now(),
        }
    }
    fn single(&self, spec: &Single) -> Vec<u8> {
        let leaf_der = if spec.id == Identity::Other {
            &self.other_der
        } else {
            &self.target_der
        };
        let (_, leaf) = X509Certificate::from_der(leaf_der).unwrap();
        let (_, issuer) = X509Certificate::from_der(&self.ca_der).unwrap();
        let mut name_hash = Sha1::digest(issuer.subject().as_raw()).to_vec();
        let mut key_hash = Sha1::digest(&issuer.public_key().subject_public_key.data).to_vec();
        let mut hash_oid = vec![0x2b, 0x0e, 0x03, 0x02, 0x1a];
        match spec.id {
            Identity::WrongName => name_hash[0] ^= 0x80,
            Identity::WrongKey => key_hash[0] ^= 0x80,
            Identity::Sha256 => {
                hash_oid = vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
                name_hash = sha2::Sha256::digest(issuer.subject().as_raw()).to_vec();
                key_hash =
                    sha2::Sha256::digest(&issuer.public_key().subject_public_key.data).to_vec();
            }
            _ => {}
        }
        let id = der(
            0x30,
            &[
                der(0x30, &[der(0x06, &hash_oid), der(0x05, &[])].concat()),
                der(0x04, &name_hash),
                der(0x04, &key_hash),
                der(0x02, leaf.raw_serial()),
            ]
            .concat(),
        );
        let status = spec
            .status_der
            .clone()
            .unwrap_or_else(|| match spec.status {
                0 => der(0x80, &[]),
                1 => der(0xa1, &time(spec.start)),
                _ => der(0x82, &[]),
            });
        let this_update = if spec.invalid_time {
            der(0x18, b"invalid-time")
        } else {
            time(spec.start)
        };
        der(
            0x30,
            &[id, status, this_update, der(0xa0, &time(spec.end))].concat(),
        )
    }
    fn tbs(&self, entries: &[Single], wrong_responder: bool) -> Vec<u8> {
        let (_, issuer) = X509Certificate::from_der(&self.ca_der).unwrap();
        let (_, leaf) = X509Certificate::from_der(&self.target_der).unwrap();
        let responder = if wrong_responder {
            leaf.subject().as_raw()
        } else {
            issuer.subject().as_raw()
        };
        der(
            0x30,
            &[
                der(0xa1, responder),
                time(self.produced_at),
                der(
                    0x30,
                    &entries
                        .iter()
                        .map(|entry| self.single(entry))
                        .collect::<Vec<_>>()
                        .concat(),
                ),
            ]
            .concat(),
        )
    }
    fn envelope(&self, tbs: Vec<u8>, signature: Vec<u8>) -> Vec<u8> {
        let algorithm = der(
            0x30,
            &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
        );
        let basic = der(
            0x30,
            &[tbs, algorithm, der(0x03, &[vec![0], signature].concat())].concat(),
        );
        let bytes = der(
            0x30,
            &[
                der(0x06, &[0x2b, 6, 1, 5, 5, 7, 0x30, 1, 1]),
                der(0x04, &basic),
            ]
            .concat(),
        );
        der(0x30, &[vec![0x0a, 1, 0], der(0xa0, &bytes)].concat())
    }
    fn response(&self, entries: &[Single]) -> Vec<u8> {
        let tbs = self.tbs(entries, false);
        let signature = self.key.sign(&tbs).unwrap();
        self.envelope(tbs, signature)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Identity {
    Target,
    Other,
    WrongName,
    WrongKey,
    Sha256,
}

#[derive(Clone)]
struct Single {
    id: Identity,
    status: u8,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    invalid_time: bool,
    status_der: Option<Vec<u8>>,
}
impl Single {
    fn new(id: Identity) -> Self {
        Self {
            id,
            status: 0,
            start: Utc::now() - Duration::minutes(1),
            end: Utc::now() + Duration::hours(4),
            invalid_time: false,
            status_der: None,
        }
    }
}

struct Server {
    url: String,
    responses: Arc<Mutex<VecDeque<Vec<u8>>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn new() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/ocsp", listener.local_addr().unwrap());
        let responses = Arc::new(Mutex::new(VecDeque::<Vec<u8>>::new()));
        let pending = responses.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut buffer = [0; 4096];
                    let size = socket.read(&mut buffer).await.unwrap();
                    assert_ne!(size, 0);
                    request.extend_from_slice(&buffer[..size]);
                    if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&request[..end]);
                        let length: usize = head
                            .lines()
                            .find_map(|line| {
                                let (key, value) = line.split_once(':')?;
                                key.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse().unwrap())
                            })
                            .unwrap_or(0);
                        assert!(head.starts_with("POST /ocsp "));
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let body = pending
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected request");
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                socket.write_all(header.as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            }
        });
        Self {
            url,
            responses,
            task,
        }
    }
}

#[tokio::test]
async fn signed_target_is_found_in_a_single_or_arbitrarily_ordered_batch() {
    let server = Server::new().await;
    let fixture = Fixture::new(&server.url);
    let target = Single::new(Identity::Target);
    let other = Single::new(Identity::Other);
    for entries in [
        vec![target.clone()],
        vec![target.clone(), other.clone()],
        vec![other, target],
    ] {
        let raw = fixture.response(&entries);
        server.responses.lock().unwrap().push_back(raw.clone());
        let (accepted, status) = certon::ocsp::get_ocsp_for_cert(&fixture.pem)
            .await
            .expect("a legal signed batch must select its target");
        assert_eq!(
            accepted, raw,
            "stapling must preserve the entire signed envelope"
        );
        assert_eq!(status.status, certon::ocsp::OcspStatus::Good);
    }
}

#[tokio::test]
async fn stale_unrelated_status_does_not_expire_the_fresh_target() {
    let server = Server::new().await;
    let fixture = Fixture::new(&server.url);
    let mut other = Single::new(Identity::Other);
    other.start = Utc::now() - Duration::days(2);
    other.end = Utc::now() - Duration::days(1);
    other.status = 1;
    server
        .responses
        .lock()
        .unwrap()
        .push_back(fixture.response(&[other, Single::new(Identity::Target)]));
    let (_, response) = certon::ocsp::get_ocsp_for_cert(&fixture.pem).await.unwrap();
    assert_eq!(response.status, certon::ocsp::OcspStatus::Good);
    assert!(certon::ocsp::is_ocsp_fresh(&response));
}

#[tokio::test]
async fn same_serial_requires_the_matching_algorithm_and_both_issuer_hashes() {
    for wrong in [Identity::WrongName, Identity::WrongKey, Identity::Sha256] {
        let server = Server::new().await;
        let fixture = Fixture::new(&server.url);
        let mut unrelated = Single::new(wrong);
        unrelated.status = 1;
        for include_target in [false, true] {
            let mut entries = vec![unrelated.clone()];
            if include_target {
                entries.push(Single::new(Identity::Target));
            }
            server
                .responses
                .lock()
                .unwrap()
                .push_back(fixture.response(&entries));
            let response = certon::ocsp::get_ocsp_for_cert(&fixture.pem).await;
            if include_target {
                assert_eq!(response.unwrap().1.status, certon::ocsp::OcspStatus::Good);
            } else {
                assert!(
                    response.is_err(),
                    "an unrelated issuer/algorithm must never authorize the target"
                );
            }
        }
    }
}

#[tokio::test]
async fn absent_or_duplicate_target_is_rejected_including_conflicting_statuses() {
    let server = Server::new().await;
    let fixture = Fixture::new(&server.url);
    let target = Single::new(Identity::Target);
    let mut revoked = target.clone();
    revoked.status = 1;
    for entries in [
        vec![Single::new(Identity::Other)],
        vec![target.clone(), target.clone()],
        vec![target, revoked],
    ] {
        server
            .responses
            .lock()
            .unwrap()
            .push_back(fixture.response(&entries));
        assert!(
            certon::ocsp::get_ocsp_for_cert(&fixture.pem).await.is_err(),
            "target selection must be unique and fail closed"
        );
    }
}

#[tokio::test]
async fn target_freshness_status_and_complete_envelope_signature_are_still_enforced() {
    let server = Server::new().await;
    let fixture = Fixture::new(&server.url);
    let target = Single::new(Identity::Target);
    for mode in [
        "expired",
        "future",
        "backwards",
        "bad-time",
        "tamper-other",
        "wrong-responder",
        "malformed-der",
    ] {
        let other = Single::new(Identity::Other);
        let mut changed = target.clone();
        match mode {
            "expired" => {
                changed.start = Utc::now() - Duration::days(2);
                changed.end = Utc::now() - Duration::days(1);
            }
            "future" => {
                changed.start = Utc::now() + Duration::hours(1);
            }
            "backwards" => {
                changed.end = changed.start - Duration::hours(1);
            }
            "bad-time" => changed.invalid_time = true,
            _ => {}
        }
        let mut tbs = fixture.tbs(&[other.clone(), changed], mode == "wrong-responder");
        let signature = fixture.key.sign(&tbs).unwrap();
        if mode == "tamper-other" {
            let mut tampered = other;
            tampered.status = 2;
            tbs = fixture.tbs(&[tampered, target.clone()], false);
        }
        let mut raw = fixture.envelope(tbs, signature);
        if mode == "malformed-der" {
            raw.pop();
        }
        server.responses.lock().unwrap().push_back(raw);
        assert!(
            certon::ocsp::get_ocsp_for_cert(&fixture.pem).await.is_err(),
            "invalid {mode} was accepted"
        );
    }
    let mut revoked = target;
    revoked.status = 1;
    server
        .responses
        .lock()
        .unwrap()
        .push_back(fixture.response(&[Single::new(Identity::Other), revoked]));
    let response = certon::ocsp::get_ocsp_for_cert(&fixture.pem)
        .await
        .unwrap()
        .1;
    assert_eq!(response.status, certon::ocsp::OcspStatus::Revoked);
}

#[tokio::test]
async fn moderate_batch_preserves_one_original_raw_envelope() {
    let server = Server::new().await;
    let fixture = Fixture::new(&server.url);
    let mut entries = vec![Single::new(Identity::Other); 256];
    entries.push(Single::new(Identity::Target));
    let raw = fixture.response(&entries);
    server.responses.lock().unwrap().push_back(raw.clone());
    let (_, response) = certon::ocsp::get_ocsp_for_cert(&fixture.pem).await.unwrap();
    assert_eq!(response.raw, raw);
    assert_eq!(response.status, certon::ocsp::OcspStatus::Good);
}

#[tokio::test]
async fn signed_implicit_revoked_info_keeps_its_time_and_optional_reason() {
    let server = Server::new().await;
    let fixture = Fixture::new(&server.url);
    let revoked_at = Utc::now() - Duration::days(1);
    for reason in [None, Some(1), Some(6), Some(10)] {
        let mut payload = time(revoked_at);
        if let Some(reason) = reason {
            payload.extend(der(0xa0, &der(0x0a, &[reason])));
        }
        let mut revoked = Single::new(Identity::Target);
        revoked.status = 1;
        revoked.status_der = Some(der(0xa1, &payload));
        let raw = fixture.response(&[Single::new(Identity::Other), revoked]);
        server.responses.lock().unwrap().push_back(raw.clone());
        let (accepted, parsed) = certon::ocsp::get_ocsp_for_cert(&fixture.pem).await.unwrap();
        assert_eq!(accepted, raw);
        assert_eq!(parsed.raw, raw);
        assert_eq!(parsed.status, certon::ocsp::OcspStatus::Revoked);
        assert_eq!(
            parsed.revoked_at.map(|time| time.timestamp()),
            Some(revoked_at.timestamp())
        );
        assert_ne!(parsed.this_update.timestamp(), revoked_at.timestamp());
    }
}

#[tokio::test]
async fn signed_bad_revocation_time_still_retains_the_revoked_status() {
    let server = Server::new().await;
    let fixture = Fixture::new(&server.url);
    for payload in [
        Vec::new(),
        der(0x05, &[]),
        der(0x18, b"invalid-time"),
        der(0x30, &time(Utc::now())),
        vec![0x18, 0x0f, b'2'],
    ] {
        let mut revoked = Single::new(Identity::Target);
        revoked.status = 1;
        revoked.status_der = Some(der(0xa1, &payload));
        server
            .responses
            .lock()
            .unwrap()
            .push_back(fixture.response(&[revoked]));
        let (_, parsed) = certon::ocsp::get_ocsp_for_cert(&fixture.pem).await.unwrap();
        assert_eq!(parsed.status, certon::ocsp::OcspStatus::Revoked);
        assert_eq!(parsed.revoked_at, None);
    }
}

#[tokio::test]
async fn changing_the_revocation_time_without_resigning_is_rejected() {
    let server = Server::new().await;
    let fixture = Fixture::new(&server.url);
    let revoked_at = Utc::now() - Duration::days(1);
    let mut revoked = Single::new(Identity::Target);
    revoked.status = 1;
    revoked.status_der = Some(der(0xa1, &time(revoked_at)));
    let original = fixture.tbs(&[revoked.clone()], false);
    let signature = fixture.key.sign(&original).unwrap();
    revoked.status_der = Some(der(0xa1, &time(revoked_at + Duration::seconds(1))));
    let changed = fixture.tbs(&[revoked], false);
    assert_ne!(changed, original);
    server
        .responses
        .lock()
        .unwrap()
        .push_back(fixture.envelope(changed, signature));
    assert!(certon::ocsp::get_ocsp_for_cert(&fixture.pem).await.is_err());
}

async fn tls_works(cache: Arc<certon::CertCache>, fixture: &Fixture) -> bool {
    certon::install_default_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            fixture.ca_der.clone(),
        ))
        .unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(certon::CertResolver::new(cache)));
    let (client_io, server_io) = tokio::io::duplex(65536);
    let result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        tokio::join!(
            tokio_rustls::TlsConnector::from(Arc::new(client))
                .connect("target.example".try_into().unwrap(), client_io),
            tokio_rustls::TlsAcceptor::from(Arc::new(server)).accept(server_io)
        )
    })
    .await;
    matches!(result, Ok((Ok(_), Ok(_))))
}

#[tokio::test]
async fn must_staple_reload_accepts_the_target_from_a_cached_batch() {
    use certon::Storage;
    let server = Server::new().await;
    let fixture = Fixture::new(&server.url);
    let cert =
        certon::Certificate::from_pem(&fixture.pem, fixture.target_key_pem.as_bytes()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let storage = certon::FileStorage::new(directory.path());
    let resource = certon::CertificateResource {
        sans: vec!["target.example".into()],
        certificate_pem: fixture.pem.clone(),
        private_key_pem: fixture.target_key_pem.as_bytes().to_vec(),
        issuer_key: "batch-ca".into(),
        issuer_data: None,
    };
    certon::storage::store_certificate(&storage, "batch-ca", &resource)
        .await
        .unwrap();
    let raw = fixture.response(&[Single::new(Identity::Other), Single::new(Identity::Target)]);
    storage
        .store(&certon::storage::ocsp_key(&cert.names[0], &cert.hash), &raw)
        .await
        .unwrap();
    server.responses.lock().unwrap().push_back(raw.clone());
    let cache = certon::CertCache::new(certon::CacheOptions::default());
    certon::certificates::reload_managed_certificate(
        &cache,
        &storage,
        "target.example",
        "batch-ca",
    )
    .await
    .unwrap();
    let published = cache.get_by_hash(&cert.hash).await.unwrap();
    assert_eq!(published.ocsp_status, Some(certon::ocsp::OcspStatus::Good));
    assert_eq!(published.ocsp_response, Some(raw));
    assert_eq!(
        server.responses.lock().unwrap().len(),
        1,
        "fresh cached batch should not require an HTTP fallback"
    );
    assert!(tls_works(cache.clone(), &fixture).await);
    let mut revoked = Single::new(Identity::Target);
    revoked.status = 1;
    let raw = fixture.response(&[Single::new(Identity::Other), revoked]);
    storage
        .store(&certon::storage::ocsp_key(&cert.names[0], &cert.hash), &raw)
        .await
        .unwrap();
    let result = certon::certificates::reload_managed_certificate(
        &cache,
        &storage,
        "target.example",
        "batch-ca",
    )
    .await;
    assert!(matches!(
        result,
        Err(certon::Error::Cert(certon::error::CertError::OcspFailed(_)))
    ));
    let quarantined = cache.get_by_hash(&cert.hash).await.unwrap();
    assert_eq!(
        quarantined.ocsp_status,
        Some(certon::ocsp::OcspStatus::Revoked)
    );
    assert!(quarantined.ocsp_response.is_none());
    assert!(
        !tls_works(cache, &fixture).await,
        "the target's verified revocation must stop TLS serving"
    );
}
#[tokio::test]
async fn verified_leaf_revocation_quarantines_all_cached_chain_encodings() {
    use certon::Storage;
    let server = Server::new().await;
    let fixture = Fixture::new(&server.url);
    let good = fixture.response(&[Single::new(Identity::Target)]);
    let mut alternate_ca = CertificateParams::new(vec!["probe-ca".into()]).unwrap();
    alternate_ca
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Batch OCSP CA");
    alternate_ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    alternate_ca.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    alternate_ca.serial_number = Some(999u64.into());
    let alternate = alternate_ca.self_signed(&fixture.key).unwrap();
    let alternate_pem = format!(
        "{}{}",
        pem::encode(&pem::Pem::new("CERTIFICATE", fixture.target_der.clone())),
        alternate.pem()
    );
    let mut a =
        certon::Certificate::from_pem(&fixture.pem, fixture.target_key_pem.as_bytes()).unwrap();
    let mut b =
        certon::Certificate::from_pem(alternate_pem.as_bytes(), fixture.target_key_pem.as_bytes())
            .unwrap();
    assert_eq!(a.cert_chain[0], b.cert_chain[0]);
    assert_ne!(a.hash, b.hash);
    for certificate in [&mut a, &mut b] {
        certificate.managed = true;
        certificate.issuer_key = "batch-ca".into();
        certificate.ocsp_response = Some(good.clone());
    }
    let cache = certon::CertCache::new(certon::CacheOptions::default());
    cache.add(a.clone()).await;
    assert!(
        tls_works(cache.clone(), &fixture).await,
        "chain A positive TLS control"
    );
    cache.remove(&a.hash).await;
    cache.add(b.clone()).await;
    assert!(
        tls_works(cache.clone(), &fixture).await,
        "chain B positive TLS control"
    );
    cache.add(a.clone()).await;
    assert_eq!(cache.get_all().await.len(), 2);
    let directory = tempfile::tempdir().unwrap();
    let storage = certon::FileStorage::new(directory.path());
    certon::storage::store_certificate(
        &storage,
        "batch-ca",
        &certon::CertificateResource {
            sans: vec!["target.example".into()],
            certificate_pem: fixture.pem.clone(),
            private_key_pem: fixture.target_key_pem.as_bytes().to_vec(),
            issuer_key: "batch-ca".into(),
            issuer_data: None,
        },
    )
    .await
    .unwrap();
    let mut revoked = Single::new(Identity::Target);
    revoked.status = 1;
    storage
        .store(
            &certon::storage::ocsp_key(&a.names[0], &a.hash),
            &fixture.response(&[revoked]),
        )
        .await
        .unwrap();
    let result = certon::certificates::reload_managed_certificate(
        &cache,
        &storage,
        "target.example",
        "batch-ca",
    )
    .await;
    assert!(matches!(
        result,
        Err(certon::Error::Cert(certon::error::CertError::OcspFailed(_)))
    ));
    assert_eq!(
        cache.get_by_hash(&a.hash).await.unwrap().ocsp_status,
        Some(certon::ocsp::OcspStatus::Revoked)
    );
    let sibling_status = cache.get_by_hash(&b.hash).await.unwrap().ocsp_status;
    assert_eq!(sibling_status, Some(certon::ocsp::OcspStatus::Revoked));
    assert!(
        cache
            .get_by_hash(&b.hash)
            .await
            .unwrap()
            .ocsp_response
            .is_none()
    );
    let still_serves = tls_works(cache.clone(), &fixture).await;
    cache.remove(&b.hash).await;
    assert!(
        !tls_works(cache, &fixture).await,
        "the updated A chain itself must be rejected"
    );
    eprintln!(
        "same_leaf=true different_legal_chains=true a_revoked=true b_status={sibling_status:?} real_tls_after_verified_status={still_serves}"
    );
    assert!(
        !still_serves,
        "verified status for a leaf must apply to all cached chains of that same leaf"
    );
}
