//! Certificate wrapping, renewal logic, and subject validation.
//!
//! This module provides the [`Certificate`] type that wraps a TLS certificate
//! chain (as DER-encoded bytes) together with its private key and metadata
//! extracted from the leaf certificate (SANs, validity period, hash).
//!
//!
//! # Key concepts
//!
//! - **Renewal window**: a certificate is considered due for renewal when the
//!   remaining fraction of its total lifetime drops below a configurable ratio
//!   (default [`DEFAULT_RENEWAL_WINDOW_RATIO`] = 1/3). An emergency renewal is
//!   also triggered when fewer than 24 hours remain.
//! - **Subject qualification**: helper functions such as
//!   [`subject_qualifies_for_cert`] and [`subject_qualifies_for_public_cert`]
//!   validate domain names before attempting certificate issuance, catching
//!   common typos and misconfigurations early.
//! - **Wildcard matching**: [`match_wildcard`] implements RFC 6125 / RFC 2818
//!   wildcard rules for certificate lookups.

use std::net::IpAddr;
use std::path::Path;

use chrono::{DateTime, Duration as ChronoDuration, Timelike, Utc};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::acme_client::RenewalInfo;
use crate::error::{CertError, CryptoError, Result};
use crate::ocsp::OcspStatus;

// ---------------------------------------------------------------------------
// PrivateKeyKind
// ---------------------------------------------------------------------------

/// Indicates which variant of [`PrivateKeyDer`] the stored raw bytes represent.
///
/// Because [`PrivateKeyDer`] does not implement `Clone`, `Certificate` stores
/// the private key as plain `Vec<u8>` bytes and uses this enum to record which
/// PEM/DER format the bytes correspond to, so the correct [`PrivateKeyDer`]
/// variant can be reconstructed when needed (e.g. for TLS configuration).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateKeyKind {
    /// PKCS#8 format (PEM tag `PRIVATE KEY`).
    Pkcs8,
    /// PKCS#1 RSA format (PEM tag `RSA PRIVATE KEY`).
    Pkcs1,
    /// SEC 1 EC format (PEM tag `EC PRIVATE KEY`).
    Sec1,
    /// No private key is present (the certificate was loaded without one).
    None,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The default ratio of remaining lifetime to total lifetime at which a
/// certificate is considered due for renewal.
///
/// A value of `1.0 / 3.0` means "renew when only 1/3 of the lifetime
/// remains". For a typical 90-day certificate this triggers renewal at
/// day 60 (30 days before expiration).
pub const DEFAULT_RENEWAL_WINDOW_RATIO: f64 = 1.0 / 3.0;

/// Certificates expiring in fewer than this many hours trigger an emergency
/// renewal regardless of the configured renewal window ratio. This safety
/// net ensures that even certificates with very long lifetimes are renewed
/// before expiration.
const EMERGENCY_RENEWAL_HOURS: i64 = 24;

// ---------------------------------------------------------------------------
// Certificate
// ---------------------------------------------------------------------------

/// A TLS certificate chain together with its private key and parsed metadata.
///
/// This struct stores
/// everything needed to serve the certificate over TLS and to decide when it
/// should be renewed.
///
/// Even though much of this information could be re-derived by parsing the
/// certificate, pre-extracting it onto the struct avoids repeated parsing and
/// makes lookups more efficient -- at the cost of slightly higher memory use.
///
/// Construct via [`Certificate::from_pem`] (for PEM-encoded data) or
/// [`Certificate::from_der`] (for pre-parsed DER chains).
#[derive(Debug, Clone)]
pub struct Certificate {
    /// The certificate chain as DER-encoded certificates.
    /// The first entry is the leaf certificate.
    pub cert_chain: Vec<CertificateDer<'static>>,

    /// The raw DER bytes of the private key, together with a tag indicating
    /// its format (`Pkcs1`, `Pkcs8`, or `Sec1`). Stored as raw bytes so that
    /// `Certificate` does not require `PrivateKeyDer: Clone`.
    pub private_key_der: Option<Vec<u8>>,

    /// Which variant of [`PrivateKeyDer`] the stored bytes represent.
    pub private_key_kind: PrivateKeyKind,

    /// Subject names extracted from the leaf certificate (CN + SANs),
    /// lower-cased.
    pub names: Vec<String>,

    /// User-provided tags for grouping or filtering certificates.
    pub tags: Vec<String>,

    /// Whether this certificate is managed (automatically renewed) by
    /// certon.
    pub managed: bool,

    /// The unique string identifying the issuer that issued this certificate.
    pub issuer_key: String,

    /// SHA-256 hash of the full certificate chain (all DER bytes),
    /// hex-encoded.
    pub hash: String,

    /// Raw OCSP response bytes that may be stapled during the TLS handshake.
    pub ocsp_response: Option<Vec<u8>>,

    /// Parsed OCSP certificate status, set when an OCSP response is stapled.
    ///
    /// This allows the maintenance loop to inspect the revocation status
    /// without re-parsing the raw OCSP response bytes.
    pub ocsp_status: Option<OcspStatus>,

    /// The `notAfter` timestamp of the leaf certificate.
    pub not_after: DateTime<Utc>,

    /// The `notBefore` timestamp of the leaf certificate.
    pub not_before: DateTime<Utc>,

    /// ACME Renewal Information (ARI), if available from the issuer.
    ///
    /// When set, the suggested renewal window and selected renewal time
    /// from ARI take precedence over the standard time-based renewal
    /// check.
    pub ari: Option<RenewalInfo>,
}

impl Certificate {
    /// Returns `true` if the certificate struct has no certificate data.
    pub fn is_empty(&self) -> bool {
        self.cert_chain.is_empty()
    }

    /// Returns the hex-encoded SHA-256 hash of the certificate chain.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// Returns `true` if the certificate has expired (its `notAfter` time,
    /// adjusted for ASN.1 second-resolution, is in the past).
    pub fn expired(&self) -> bool {
        Utc::now() > expires_at(self.not_after)
    }

    /// Returns the total lifetime of the certificate (from `notBefore` to
    /// `notAfter`).
    pub fn lifetime(&self) -> ChronoDuration {
        self.not_after - self.not_before
    }

    /// Returns `true` if the certificate needs to be renewed.
    ///
    /// The decision is based on:
    /// 1. Whether the current time falls within the renewal window determined
    ///    by `renewal_window_ratio` (fraction of lifetime that should remain
    ///    when renewal starts). Pass `0.0` to use
    ///    [`DEFAULT_RENEWAL_WINDOW_RATIO`].
    /// 2. Whether fewer than 24 hours remain before expiration (emergency
    ///    renewal).
    /// 3. Whether the certificate is already expired.
    pub fn needs_renewal(&self, renewal_window_ratio: f64) -> bool {
        // If already expired, definitely needs renewal.
        if self.expired() {
            return true;
        }

        // Check ARI (ACME Renewal Information) if available.
        if let Some(ref ari) = self.ari {
            if let Some(selected_time) = ari.selected_time {
                // If a specific renewal time was selected, check against it.
                if Utc::now() >= selected_time {
                    return true;
                }
            } else if let Some(ref window) = ari.suggested_window {
                // If we have a window but no selected time, pick a random
                // time within the window and check if we are past it.
                if let (Ok(start), Ok(end)) = (
                    DateTime::parse_from_rfc3339(&window.start),
                    DateTime::parse_from_rfc3339(&window.end),
                ) {
                    let start_utc = start.with_timezone(&Utc);
                    let end_utc = end.with_timezone(&Utc);
                    if start_utc < end_utc {
                        use rand::RngExt;
                        let range_secs = (end_utc - start_utc).num_seconds().max(1);
                        let offset = rand::rng().random_range(0..range_secs);
                        let random_time = start_utc + ChronoDuration::seconds(offset);
                        if Utc::now() >= random_time {
                            return true;
                        }
                    }
                }
            }
        }

        // Check the configured renewal window.
        if currently_in_renewal_window(self.not_before, self.not_after, renewal_window_ratio) {
            return true;
        }

        // Emergency: fewer than 24 hours remaining.
        let remaining = expires_at(self.not_after) - Utc::now();
        if remaining < ChronoDuration::hours(EMERGENCY_RENEWAL_HOURS) {
            return true;
        }

        // Also check an extremely tight ratio (1/50 of lifetime) as an
        // additional safety net for emergency renewal.
        if currently_in_renewal_window(self.not_before, self.not_after, 1.0 / 50.0) {
            return true;
        }

        false
    }

    /// Returns `true` if `tag` is present in [`Certificate::tags`].
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }

    /// Construct a [`Certificate`] from PEM-encoded certificate and key data.
    ///
    /// The certificate PEM may contain multiple `CERTIFICATE` blocks (a
    /// chain). The key PEM must contain exactly one private key block.
    ///
    /// The leaf (first) certificate is parsed with `x509-parser` to extract
    /// subject names, validity period, and to compute the chain hash.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM data is malformed, contains no
    /// certificates, or the leaf certificate cannot be parsed.
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self> {
        let cert_pem_str = std::str::from_utf8(cert_pem)
            .map_err(|e| CryptoError::InvalidCertificate(format!("cert PEM is not valid UTF-8: {e}")))?;
        let key_pem_str = std::str::from_utf8(key_pem)
            .map_err(|e| CryptoError::InvalidKey(format!("key PEM is not valid UTF-8: {e}")))?;

        // Parse certificate chain from PEM.
        let cert_ders = parse_cert_chain_from_pem(cert_pem_str)?;
        if cert_ders.is_empty() {
            return Err(CryptoError::InvalidCertificate("no certificates found in PEM data".into()).into());
        }

        // Parse the private key from PEM.
        let private_key = parse_private_key_from_pem(key_pem_str)?;

        // Parse the leaf certificate to extract metadata.
        let leaf_der = cert_ders[0].as_ref();
        let (_, leaf) = X509Certificate::from_der(leaf_der)
            .map_err(|e| CryptoError::InvalidCertificate(format!("failed to parse leaf certificate: {e}")))?;

        // Extract subject names (CN + SANs).
        let names = extract_names(&leaf)?;

        // Extract validity period.
        let not_before = asn1_time_to_chrono(leaf.validity().not_before)?;
        let not_after = asn1_time_to_chrono(leaf.validity().not_after)?;

        // Compute hash of the entire chain.
        let hash = hash_certificate_chain(&cert_ders);

        let (pk_der, pk_kind) = private_key_to_raw(private_key);

        Ok(Certificate {
            cert_chain: cert_ders,
            private_key_der: Some(pk_der),
            private_key_kind: pk_kind,
            names,
            tags: Vec::new(),
            managed: false,
            issuer_key: String::new(),
            hash,
            ocsp_response: None,
            ocsp_status: None,
            not_after,
            not_before,
            ari: None,
        })
    }

    /// Create a [`Certificate`] from PEM file paths (cert file + key file).
    ///
    /// Reads both files from disk and parses them as PEM. This is a
    /// convenience wrapper around [`Certificate::from_pem`] for loading
    /// unmanaged (user-provided) certificates.
    ///
    /// # Errors
    ///
    /// Returns an error if either file cannot be read or contains invalid
    /// PEM data.
    pub fn from_pem_files(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_pem = std::fs::read(cert_path).map_err(|e| {
            CryptoError::InvalidCertificate(format!(
                "failed to read certificate file {}: {e}",
                cert_path.display()
            ))
        })?;
        let key_pem = std::fs::read(key_path).map_err(|e| {
            CryptoError::InvalidKey(format!(
                "failed to read key file {}: {e}",
                key_path.display()
            ))
        })?;
        Self::from_pem(&cert_pem, &key_pem)
    }

    /// Attach an OCSP response to this certificate, returning the modified
    /// certificate.
    ///
    /// This is useful for attaching a pre-fetched OCSP staple to an
    /// unmanaged certificate before caching it.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let cert = Certificate::from_pem(cert_pem, key_pem)?
    ///     .with_ocsp(ocsp_response_bytes);
    /// ```
    pub fn with_ocsp(mut self, ocsp_response: Vec<u8>) -> Self {
        self.ocsp_response = Some(ocsp_response);
        self
    }

    /// Construct a [`Certificate`] from DER-encoded certificate chain bytes
    /// and an optional private key, without parsing PEM.
    ///
    /// This is useful when certificates are loaded from storage where the DER
    /// bytes and metadata are already available.
    pub fn from_der(
        cert_chain: Vec<CertificateDer<'static>>,
        private_key: Option<PrivateKeyDer<'static>>,
    ) -> Result<Self> {
        if cert_chain.is_empty() {
            return Err(CryptoError::InvalidCertificate("certificate chain is empty".into()).into());
        }

        let leaf_der = cert_chain[0].as_ref();
        let (_, leaf) = X509Certificate::from_der(leaf_der)
            .map_err(|e| CryptoError::InvalidCertificate(format!("failed to parse leaf certificate: {e}")))?;

        let names = extract_names(&leaf)?;
        let not_before = asn1_time_to_chrono(leaf.validity().not_before)?;
        let not_after = asn1_time_to_chrono(leaf.validity().not_after)?;
        let hash = hash_certificate_chain(&cert_chain);

        let (pk_der, pk_kind) = match private_key {
            Some(pk) => {
                let (der, kind) = private_key_to_raw(pk);
                (Some(der), kind)
            }
            None => (None, PrivateKeyKind::None),
        };

        Ok(Certificate {
            cert_chain,
            private_key_der: pk_der,
            private_key_kind: pk_kind,
            names,
            tags: Vec::new(),
            managed: false,
            issuer_key: String::new(),
            hash,
            ocsp_response: None,
            ocsp_status: None,
            not_after,
            not_before,
            ari: None,
        })
    }
}

// ---------------------------------------------------------------------------
// reload_managed_certificate
// ---------------------------------------------------------------------------

/// Reload a managed certificate from storage, replacing the old version in
/// cache.
///
/// This function loads the certificate PEM and private key PEM from storage
/// using the standard key paths for the given `issuer_key` and `domain`,
/// parses them into a [`Certificate`], marks it as managed, and replaces
/// any existing certificate for those SANs in the cache.
///
/// This is useful after an external renewal (e.g. by another cluster node)
/// has written a new certificate to shared storage.
///
/// # Errors
///
/// Returns an error if the certificate or key cannot be loaded from storage,
/// or if the PEM data is invalid.
pub async fn reload_managed_certificate(
    cache: &crate::cache::CertCache,
    storage: &dyn crate::storage::Storage,
    domain: &str,
    issuer_key: &str,
) -> Result<()> {
    use crate::storage::{site_cert_key, site_private_key};

    // Load certificate and key PEM from storage.
    let cert_key = site_cert_key(issuer_key, domain);
    let key_key = site_private_key(issuer_key, domain);

    let cert_pem = storage.load(&cert_key).await?;
    let key_pem = storage.load(&key_key).await?;

    // Parse into a Certificate.
    let mut cert = Certificate::from_pem(&cert_pem, &key_pem)?;
    cert.managed = true;
    cert.issuer_key = issuer_key.to_owned();

    // Find the existing certificate in the cache for replacement.
    let existing = cache.get_by_name(domain).await;
    match existing {
        Some(old_cert) => {
            cache.replace(&old_cert.hash, cert).await;
        }
        None => {
            // No existing cert to replace; just add it.
            cache.add(cert).await;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Storage-based renewal check
// ---------------------------------------------------------------------------

/// Check whether a managed certificate stored in `storage` needs renewal.
///
/// Loads the certificate PEM from storage using the standard key paths for
/// the given `issuer_key` and `domain`, parses the leaf, and delegates to
/// [`Certificate::needs_renewal`].
///
/// Returns `Ok(true)` if the certificate needs renewal (or if it cannot be
/// loaded / parsed, in which case obtaining a fresh one is the right thing
/// to do). Returns `Ok(false)` if the certificate is still valid and does
/// not yet require renewal.
pub async fn managed_cert_in_storage_needs_renewal(
    storage: &dyn crate::storage::Storage,
    domain: &str,
    issuer_key: &str,
    renewal_window_ratio: f64,
) -> Result<bool> {
    use crate::storage::{site_cert_key, site_private_key};

    let cert_key = site_cert_key(issuer_key, domain);
    let key_key = site_private_key(issuer_key, domain);

    let cert_pem = match storage.load(&cert_key).await {
        Ok(data) => data,
        Err(_) => return Ok(true), // cannot load -> needs issuance
    };

    let key_pem = match storage.load(&key_key).await {
        Ok(data) => data,
        Err(_) => return Ok(true),
    };

    let cert = match Certificate::from_pem(&cert_pem, &key_pem) {
        Ok(c) => c,
        Err(_) => return Ok(true), // cannot parse -> needs re-issuance
    };

    Ok(cert.needs_renewal(renewal_window_ratio))
}

// ---------------------------------------------------------------------------
// Renewal window logic
// ---------------------------------------------------------------------------

/// Returns `true` if the current time is within (or past) the renewal window.
///
/// The renewal window is computed as the last `renewal_window_ratio` fraction
/// of the certificate's total lifetime. For example, with a ratio of `1/3`,
/// a 90-day certificate would enter the renewal window at day 60.
///
/// If `renewal_window_ratio` is `0.0` (or negative), the
/// [`DEFAULT_RENEWAL_WINDOW_RATIO`] is used.
pub fn currently_in_renewal_window(
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    renewal_window_ratio: f64,
) -> bool {
    let lifetime = not_after - not_before;
    if lifetime.num_seconds() <= 0 {
        return false;
    }

    let ratio = if renewal_window_ratio <= 0.0 {
        DEFAULT_RENEWAL_WINDOW_RATIO
    } else {
        renewal_window_ratio
    };

    let renewal_window_secs = (lifetime.num_seconds() as f64 * ratio) as i64;
    let renewal_window = ChronoDuration::seconds(renewal_window_secs);
    let renewal_start = not_after - renewal_window;

    Utc::now() > renewal_start
}

// ---------------------------------------------------------------------------
// Expiration helper
// ---------------------------------------------------------------------------

/// Returns the effective expiration time for a certificate, accounting for
/// the 1-second resolution of ASN.1 UTCTime / GeneralizedTime.
///
/// The extra fraction of a second of validity beyond
/// `not_after` is included by truncating to the second and adding one
/// second.
fn expires_at(not_after: DateTime<Utc>) -> DateTime<Utc> {
    // Truncate sub-second precision, then add 1 second.
    let truncated = not_after
        .with_nanosecond(0)
        .unwrap_or(not_after);
    truncated + ChronoDuration::seconds(1)
}

// ---------------------------------------------------------------------------
// Subject qualification
// ---------------------------------------------------------------------------

/// Returns `true` if `subject` looks like it could be a valid certificate
/// subject name.
///
/// Requirements:
/// - Must not be empty.
/// - Must not start or end with a dot.
/// - If it contains a wildcard `*`, it must be a left-most label (`*.` prefix)
///   or exactly `"*"`.
/// - Must not contain common special characters that indicate a typo or
///   misconfiguration.
pub fn subject_qualifies_for_cert(subject: &str) -> bool {
    let trimmed = subject.trim();
    if trimmed.is_empty() {
        return false;
    }

    if subject.starts_with('.') || subject.ends_with('.') {
        return false;
    }

    // Wildcard must be left-most label or exactly "*".
    if subject.contains('*') && !subject.starts_with("*.") && subject != "*" {
        return false;
    }

    // Must not contain common accidental special characters.
    const BAD_CHARS: &str = "()[]{}<> \t\n\"\\!@#$%^&|;'+=";
    if subject.chars().any(|c| BAD_CHARS.contains(c)) {
        return false;
    }

    true
}

/// Returns `true` if the subject name appears eligible for a certificate
/// from a public CA such as Let's Encrypt.
///
/// This adds extra checks on top of [`subject_qualifies_for_cert`]:
/// - The subject must not be an internal/loopback address or name.
/// - Wildcard domains must have exactly one wildcard label on the left, with
///   at least 3 labels total (e.g. `*.example.com`).
pub fn subject_qualifies_for_public_cert(subject: &str) -> bool {
    if !subject_qualifies_for_cert(subject) {
        return false;
    }

    if subject_is_internal(subject) {
        return false;
    }

    // Wildcard rules for public CAs (CABF).
    if subject.contains('*') {
        let star_count = subject.matches('*').count();
        let dot_count = subject.matches('.').count();
        if star_count != 1 || dot_count <= 1 || subject.len() <= 2 || !subject.starts_with("*.") {
            return false;
        }
    }

    true
}

/// Returns `true` if `subject` is an IP address (either IPv4 or IPv6).
///
/// This is useful for determining whether a SAN should be added as an IP
/// address SAN rather than a DNS name SAN in a CSR.
pub fn subject_is_ip(subject: &str) -> bool {
    subject.parse::<IpAddr>().is_ok()
}

/// Returns `true` if `subject` is an internal-facing hostname or address
/// that cannot receive a certificate from a public CA.
///
/// Specifically, this returns `true` for:
/// - `"localhost"` and subdomains of `.localhost`
/// - Names ending in `.local`, `.internal`, or `.home.arpa`
/// - Loopback addresses (`127.0.0.0/8`, `::1`)
/// - Private/link-local IP addresses (`10/8`, `172.16/12`, `192.168/16`,
///   `169.254/16`, `fe80::/10`, `fc00::/7`)
pub fn subject_is_internal(subject: &str) -> bool {
    let subj = host_only(subject).to_lowercase();
    let subj = subj.trim_end_matches('.');

    subj == "localhost"
        || subj.ends_with(".localhost")
        || subj.ends_with(".local")
        || subj.ends_with(".internal")
        || subj.ends_with(".home.arpa")
        || is_internal_ip(subj)
}

/// Returns `true` if `addr` parses as an IP address that belongs to a
/// private or loopback network.
fn is_internal_ip(addr: &str) -> bool {
    let host = host_only(addr);
    let ip: IpAddr = match host.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()             // 127.0.0.0/8
                || v4.is_unspecified()    // 0.0.0.0
                || v4.is_private()        // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()     // 169.254/16
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()             // ::1
                || v6.is_unspecified()    // ::
                // Check for link-local (fe80::/10).
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // Check for unique local (fc00::/7).
                || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Extracts only the host part from a potential `host:port` string.
fn host_only(hostport: &str) -> &str {
    // Handle IPv6 bracket notation: [::1]:8080
    if hostport.starts_with('[') {
        if let Some(end) = hostport.find(']') {
            return &hostport[1..end];
        }
    }
    // If there are multiple colons, it is likely a bare IPv6 address (not
    // bracket-wrapped), so do not attempt host:port splitting.
    if hostport.matches(':').count() > 1 {
        return hostport;
    }
    // Handle host:port (exactly one colon).
    if let Some(colon_pos) = hostport.rfind(':') {
        let after = &hostport[colon_pos + 1..];
        if !after.is_empty() && after.chars().all(|c| c.is_ascii_digit()) {
            return &hostport[..colon_pos];
        }
    }
    hostport
}

// ---------------------------------------------------------------------------
// Wildcard matching
// ---------------------------------------------------------------------------

/// Returns `true` if `subject` (a candidate DNS name) matches `wildcard`
/// (a reference DNS name), using DNS wildcard matching logic.
///
/// Matching is case-insensitive and follows RFC 6125 / RFC 2818 rules:
/// a `*` in the wildcard replaces exactly one label in the subject.
pub fn match_wildcard(subject: &str, wildcard: &str) -> bool {
    let subject = subject.to_lowercase();
    let wildcard = wildcard.to_lowercase();

    if subject == wildcard {
        return true;
    }

    if !wildcard.contains('*') {
        return false;
    }

    let labels: Vec<&str> = subject.split('.').collect();
    for i in 0..labels.len() {
        if labels[i].is_empty() {
            continue;
        }
        let mut candidate: Vec<&str> = labels.clone();
        candidate[i] = "*";
        let joined = candidate.join(".");
        if joined == wildcard {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Convert a [`PrivateKeyDer`] into raw bytes and a [`PrivateKeyKind`] tag.
fn private_key_to_raw(pk: PrivateKeyDer<'static>) -> (Vec<u8>, PrivateKeyKind) {
    match pk {
        PrivateKeyDer::Pkcs8(der) => (der.secret_pkcs8_der().to_vec(), PrivateKeyKind::Pkcs8),
        PrivateKeyDer::Pkcs1(der) => (der.secret_pkcs1_der().to_vec(), PrivateKeyKind::Pkcs1),
        PrivateKeyDer::Sec1(der) => (der.secret_sec1_der().to_vec(), PrivateKeyKind::Sec1),
        _ => (Vec::new(), PrivateKeyKind::None),
    }
}

/// Parse all `CERTIFICATE` PEM blocks from a PEM bundle and return them as
/// owned `CertificateDer` values.
fn parse_cert_chain_from_pem(pem_str: &str) -> Result<Vec<CertificateDer<'static>>> {
    let pems: Vec<::pem::Pem> = ::pem::parse_many(pem_str)
        .map_err(|e| CryptoError::InvalidCertificate(format!("failed to parse PEM bundle: {e}")))?;

    let certs: Vec<CertificateDer<'static>> = pems
        .into_iter()
        .filter(|p: &::pem::Pem| p.tag() == "CERTIFICATE")
        .map(|p: ::pem::Pem| CertificateDer::from(p.into_contents()))
        .collect();

    if certs.is_empty() {
        return Err(CryptoError::InvalidCertificate("no certificates found in PEM data".into()).into());
    }

    Ok(certs)
}

/// Parse a private key from PEM data, returning a [`PrivateKeyDer`].
///
/// Recognises `PRIVATE KEY` (PKCS#8), `RSA PRIVATE KEY` (PKCS#1), and
/// `EC PRIVATE KEY` (SEC 1) tags.
fn parse_private_key_from_pem(pem_str: &str) -> Result<PrivateKeyDer<'static>> {
    let parsed = ::pem::parse(pem_str)
        .map_err(|e| CryptoError::InvalidKey(format!("failed to parse key PEM: {e}")))?;

    let tag = parsed.tag().to_owned();
    let der = parsed.into_contents();

    match tag.as_str() {
        "PRIVATE KEY" | "ED25519 PRIVATE KEY" => {
            Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)))
        }
        "RSA PRIVATE KEY" => {
            Ok(PrivateKeyDer::Pkcs1(rustls::pki_types::PrivatePkcs1KeyDer::from(der)))
        }
        "EC PRIVATE KEY" => {
            Ok(PrivateKeyDer::Sec1(rustls::pki_types::PrivateSec1KeyDer::from(der)))
        }
        other if other.ends_with("PRIVATE KEY") => {
            // Fallback: try PKCS#8.
            Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)))
        }
        _ => Err(CryptoError::InvalidKey(format!("unsupported PEM tag for private key: {tag}")).into()),
    }
}

/// Extract subject names from an X.509 certificate.
///
/// Names are collected from:
/// 1. The Subject CN (Common Name), if non-empty.
/// 2. The Subject Alternative Name (SAN) extension — DNS names, IP
///    addresses, email addresses, and URIs.
///
/// All names are lower-cased. Duplicates of the CN are skipped.
fn extract_names(cert: &X509Certificate<'_>) -> Result<Vec<String>> {
    let mut names = Vec::new();

    // Extract Common Name from the subject.
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(|s| s.to_lowercase());

    if let Some(ref cn) = cn {
        if !cn.is_empty() {
            names.push(cn.clone());
        }
    }

    // Extract SANs.
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            let san_str = match name {
                GeneralName::DNSName(dns) => Some(dns.to_lowercase()),
                GeneralName::IPAddress(ip_bytes) => {
                    // ip_bytes is a 4-byte (IPv4) or 16-byte (IPv6) slice.
                    parse_ip_from_bytes(ip_bytes).map(|ip| ip.to_string().to_lowercase())
                }
                GeneralName::RFC822Name(email) => Some(email.to_lowercase()),
                GeneralName::URI(uri) => Some(uri.to_string()),
                _ => None,
            };

            if let Some(san) = san_str {
                // Skip if it duplicates the CN.
                let dominated_by_cn = cn.as_ref().map_or(false, |c| c == &san);
                if !dominated_by_cn && !san.is_empty() {
                    names.push(san);
                }
            }
        }
    }

    if names.is_empty() {
        return Err(CertError::InvalidDomain("certificate has no names (no CN or SANs)".into()).into());
    }

    Ok(names)
}

/// Extract subject names from a DER-encoded certificate without requiring
/// the full [`Certificate`] struct.
///
/// This is a lightweight convenience for callers that only need the SANs
/// (e.g. OCSP responder override matching).
pub fn extract_names_from_der(cert_der: &[u8]) -> Result<Vec<String>> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| CryptoError::InvalidCertificate(format!("failed to parse certificate: {e}")))?;
    extract_names(&cert)
}

/// Parse an IP address from a SAN IP address byte slice.
fn parse_ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => {
            let octets: [u8; 4] = bytes.try_into().ok()?;
            Some(IpAddr::V4(std::net::Ipv4Addr::from(octets)))
        }
        16 => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// Convert an `x509_parser::time::ASN1Time` into a `chrono::DateTime<Utc>`.
fn asn1_time_to_chrono(t: x509_parser::time::ASN1Time) -> Result<DateTime<Utc>> {
    let epoch_secs = t.timestamp();
    DateTime::from_timestamp(epoch_secs, 0)
        .ok_or_else(|| {
            CryptoError::InvalidCertificate(format!(
                "failed to convert ASN.1 time (epoch {epoch_secs}) to DateTime"
            ))
            .into()
        })
}

/// Compute the SHA-256 hash of the entire certificate chain (all DER bytes
/// concatenated) and return it as a lowercase hex string.
///
/// This hash serves as a unique, stable identifier for the certificate chain
/// and is used as the primary key in the certificate cache.
pub fn hash_certificate_chain(chain: &[CertificateDer<'_>]) -> String {
    let mut hasher = Sha256::new();
    for cert_der in chain {
        hasher.update(cert_der.as_ref());
    }
    let digest = hasher.finalize();
    hex_encode(&digest)
}

/// Lowercase hex encoding of a byte slice.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- subject_qualifies_for_cert -----------------------------------------

    #[test]
    fn qualifies_normal_domain() {
        assert!(subject_qualifies_for_cert("example.com"));
    }

    #[test]
    fn qualifies_wildcard_domain() {
        assert!(subject_qualifies_for_cert("*.example.com"));
    }

    #[test]
    fn qualifies_bare_wildcard() {
        assert!(subject_qualifies_for_cert("*"));
    }

    #[test]
    fn does_not_qualify_empty() {
        assert!(!subject_qualifies_for_cert(""));
        assert!(!subject_qualifies_for_cert("   "));
    }

    #[test]
    fn does_not_qualify_leading_dot() {
        assert!(!subject_qualifies_for_cert(".example.com"));
    }

    #[test]
    fn does_not_qualify_trailing_dot() {
        assert!(!subject_qualifies_for_cert("example.com."));
    }

    #[test]
    fn does_not_qualify_middle_wildcard() {
        assert!(!subject_qualifies_for_cert("ex*ample.com"));
        assert!(!subject_qualifies_for_cert("example.*.com"));
    }

    #[test]
    fn does_not_qualify_special_chars() {
        assert!(!subject_qualifies_for_cert("exam ple.com"));
        assert!(!subject_qualifies_for_cert("exam[ple].com"));
    }

    // -- subject_qualifies_for_public_cert ----------------------------------

    #[test]
    fn public_cert_normal_domain() {
        assert!(subject_qualifies_for_public_cert("example.com"));
    }

    #[test]
    fn public_cert_wildcard_valid() {
        assert!(subject_qualifies_for_public_cert("*.example.com"));
    }

    #[test]
    fn public_cert_rejects_localhost() {
        assert!(!subject_qualifies_for_public_cert("localhost"));
    }

    #[test]
    fn public_cert_rejects_internal_domain() {
        assert!(!subject_qualifies_for_public_cert("myapp.local"));
    }

    #[test]
    fn public_cert_rejects_loopback() {
        assert!(!subject_qualifies_for_public_cert("127.0.0.1"));
    }

    #[test]
    fn public_cert_rejects_private_ip() {
        assert!(!subject_qualifies_for_public_cert("192.168.1.1"));
        assert!(!subject_qualifies_for_public_cert("10.0.0.1"));
    }

    #[test]
    fn public_cert_rejects_wildcard_too_few_labels() {
        // *.com has only 2 labels but dot_count == 1 which is <= 1
        assert!(!subject_qualifies_for_public_cert("*.com"));
    }

    // -- subject_is_ip ------------------------------------------------------

    #[test]
    fn is_ip_v4() {
        assert!(subject_is_ip("192.168.1.1"));
    }

    #[test]
    fn is_ip_v6() {
        assert!(subject_is_ip("::1"));
    }

    #[test]
    fn is_not_ip() {
        assert!(!subject_is_ip("example.com"));
    }

    // -- subject_is_internal ------------------------------------------------

    #[test]
    fn internal_localhost() {
        assert!(subject_is_internal("localhost"));
        assert!(subject_is_internal("LOCALHOST"));
    }

    #[test]
    fn internal_localhost_subdomain() {
        assert!(subject_is_internal("foo.localhost"));
    }

    #[test]
    fn internal_dot_local() {
        assert!(subject_is_internal("myhost.local"));
    }

    #[test]
    fn internal_dot_internal() {
        assert!(subject_is_internal("myhost.internal"));
    }

    #[test]
    fn internal_home_arpa() {
        assert!(subject_is_internal("myhost.home.arpa"));
    }

    #[test]
    fn internal_loopback_ip() {
        assert!(subject_is_internal("127.0.0.1"));
    }

    #[test]
    fn internal_private_ip() {
        assert!(subject_is_internal("10.0.0.1"));
        assert!(subject_is_internal("172.16.0.1"));
        assert!(subject_is_internal("192.168.0.1"));
    }

    #[test]
    fn not_internal_public_domain() {
        assert!(!subject_is_internal("example.com"));
    }

    #[test]
    fn not_internal_public_ip() {
        assert!(!subject_is_internal("8.8.8.8"));
    }

    // -- match_wildcard -----------------------------------------------------

    #[test]
    fn wildcard_match_basic() {
        assert!(match_wildcard("foo.example.com", "*.example.com"));
    }

    #[test]
    fn wildcard_exact_match() {
        assert!(match_wildcard("example.com", "example.com"));
    }

    #[test]
    fn wildcard_no_match_different_domain() {
        assert!(!match_wildcard("foo.other.com", "*.example.com"));
    }

    #[test]
    fn wildcard_no_match_sub_sub() {
        // *.example.com should not match sub.sub.example.com
        assert!(!match_wildcard("sub.sub.example.com", "*.example.com"));
    }

    #[test]
    fn wildcard_case_insensitive() {
        assert!(match_wildcard("FOO.Example.COM", "*.example.com"));
    }

    #[test]
    fn wildcard_no_star_no_match() {
        assert!(!match_wildcard("foo.example.com", "example.com"));
    }

    // -- currently_in_renewal_window ----------------------------------------

    #[test]
    fn renewal_window_expired_cert() {
        let not_before = Utc::now() - ChronoDuration::days(100);
        let not_after = Utc::now() - ChronoDuration::days(1);
        assert!(currently_in_renewal_window(not_before, not_after, DEFAULT_RENEWAL_WINDOW_RATIO));
    }

    #[test]
    fn renewal_window_fresh_cert() {
        let not_before = Utc::now() - ChronoDuration::days(1);
        let not_after = Utc::now() + ChronoDuration::days(89);
        assert!(!currently_in_renewal_window(not_before, not_after, DEFAULT_RENEWAL_WINDOW_RATIO));
    }

    #[test]
    fn renewal_window_due_cert() {
        // 90-day cert with 20 days remaining -> in the 1/3 window (30 days).
        let not_before = Utc::now() - ChronoDuration::days(70);
        let not_after = Utc::now() + ChronoDuration::days(20);
        assert!(currently_in_renewal_window(not_before, not_after, DEFAULT_RENEWAL_WINDOW_RATIO));
    }

    #[test]
    fn renewal_window_zero_ratio_uses_default() {
        let not_before = Utc::now() - ChronoDuration::days(70);
        let not_after = Utc::now() + ChronoDuration::days(20);
        assert!(currently_in_renewal_window(not_before, not_after, 0.0));
    }

    // -- hash_certificate_chain ---------------------------------------------

    #[test]
    fn hash_chain_deterministic() {
        let certs = vec![
            CertificateDer::from(vec![1u8, 2, 3]),
            CertificateDer::from(vec![4u8, 5, 6]),
        ];
        let h1 = hash_certificate_chain(&certs);
        let h2 = hash_certificate_chain(&certs);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn hash_chain_different_data() {
        let c1 = vec![CertificateDer::from(vec![1u8, 2, 3])];
        let c2 = vec![CertificateDer::from(vec![4u8, 5, 6])];
        assert_ne!(hash_certificate_chain(&c1), hash_certificate_chain(&c2));
    }

    // -- host_only ----------------------------------------------------------

    #[test]
    fn host_only_with_port() {
        assert_eq!(host_only("example.com:443"), "example.com");
    }

    #[test]
    fn host_only_without_port() {
        assert_eq!(host_only("example.com"), "example.com");
    }

    #[test]
    fn host_only_ipv6_bracket() {
        assert_eq!(host_only("[::1]:8080"), "::1");
    }

    #[test]
    fn host_only_bare_ipv6() {
        assert_eq!(host_only("::1"), "::1");
    }

    // -- expires_at ---------------------------------------------------------

    #[test]
    fn expires_at_adds_one_second() {
        let t = Utc::now().with_nanosecond(0).unwrap();
        let exp = expires_at(t);
        assert_eq!(exp - t, ChronoDuration::seconds(1));
    }
}
