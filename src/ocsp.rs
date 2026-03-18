//! OCSP (Online Certificate Status Protocol) stapling support.
//!
//! This module handles fetching, caching, and stapling OCSP responses for
//! TLS certificates.
//!
//! # Overview
//!
//! OCSP stapling allows a TLS server to include a signed assertion from
//! the CA about whether its certificate is still valid. This saves clients
//! from having to contact the CA's OCSP responder themselves.
//!
//! The workflow is:
//! 1. Extract the OCSP responder URL from the certificate's Authority Information Access (AIA)
//!    extension.
//! 2. Build an OCSP request containing the certificate's serial number and issuer information.
//! 3. Send the request to the OCSP responder via HTTP POST.
//! 4. Parse the response and cache it in storage.
//! 5. Attach the raw response bytes to the certificate for TLS stapling.

use std::collections::HashMap;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sha1::{Digest as Sha1Digest, Sha1};
use tracing::{debug, warn};
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::{
    OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS, OID_PKIX_ACCESS_DESCRIPTOR_OCSP,
};
use x509_parser::prelude::*;

use crate::certificates::Certificate;
use crate::error::{CertError, CryptoError, Error, Result, StorageError};
use crate::storage::{self, Storage};

// ---------------------------------------------------------------------------
// OCSPConfig
// ---------------------------------------------------------------------------

/// Configuration for OCSP stapling behavior.
///
/// By default, OCSP responses are fetched for every certificate that has
/// an OCSP responder URL, and cached on disk. Changing these defaults is
/// **strongly discouraged** unless you have a compelling reason to put
/// clients at greater risk and reduce their privacy.
#[derive(Debug, Clone)]
pub struct OcspConfig {
    /// Whether to disable OCSP stapling entirely.
    ///
    /// When `true`, no OCSP requests will be made and no staples will be
    /// attached to certificates.
    pub disable_stapling: bool,

    /// Whether to replace certificates that have been revoked according
    /// to their OCSP response.
    ///
    /// When `true`, a revoked certificate triggers an immediate re-issuance
    /// attempt.
    pub replace_revoked: bool,

    /// Per-domain OCSP responder URL overrides.
    ///
    /// Maps domain names (SANs) to custom OCSP responder URLs. When
    /// fetching an OCSP response, if any SAN on the certificate matches
    /// a key in this map, the corresponding URL is used instead of the
    /// one extracted from the certificate's AIA extension.
    pub responder_overrides: HashMap<String, String>,
}

impl Default for OcspConfig {
    fn default() -> Self {
        Self {
            disable_stapling: false,
            replace_revoked: true,
            responder_overrides: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// OCSPStatus
// ---------------------------------------------------------------------------

/// The certificate status reported by an OCSP response.
///
/// These values map to the `CertStatus` choices defined in RFC 6960
/// Section 4.2.1. Only certificates with [`OcspStatus::Good`] should
/// be stapled during TLS handshakes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspStatus {
    /// The certificate is valid (not revoked).
    Good,
    /// The certificate has been revoked by the CA.
    Revoked,
    /// The responder does not know about this certificate.
    Unknown,
    /// The OCSP responder returned an error (e.g. internal error,
    /// try later, unauthorized).
    ServerFailed,
}

impl std::fmt::Display for OcspStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Good => write!(f, "Good"),
            Self::Revoked => write!(f, "Revoked"),
            Self::Unknown => write!(f, "Unknown"),
            Self::ServerFailed => write!(f, "ServerFailed"),
        }
    }
}

// ---------------------------------------------------------------------------
// OCSPResponse
// ---------------------------------------------------------------------------

/// A parsed OCSP response with the information needed for stapling and
/// freshness checks.
///
/// The `raw` field contains the complete DER-encoded response suitable for
/// TLS stapling. The remaining fields are extracted for convenience during
/// freshness checks and status inspection.
#[derive(Debug, Clone)]
pub struct OcspResponse {
    /// The certificate status.
    pub status: OcspStatus,

    /// The raw DER-encoded OCSP response bytes (suitable for TLS stapling).
    pub raw: Vec<u8>,

    /// The `thisUpdate` field from the response -- the time at which the
    /// status was known to be correct.
    pub this_update: DateTime<Utc>,

    /// The `nextUpdate` field from the response -- the time after which
    /// the client should fetch a new response. `None` if the responder
    /// did not include this field.
    pub next_update: Option<DateTime<Utc>>,

    /// The `producedAt` field from the response envelope.
    pub produced_at: DateTime<Utc>,

    /// If the certificate is revoked, the time at which revocation occurred.
    pub revoked_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum OCSP response size we are willing to accept (10 MiB).
const MAX_OCSP_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

/// Content-Type header value for OCSP requests.
const OCSP_REQUEST_CONTENT_TYPE: &str = "application/ocsp-request";

/// Content-Type header value for OCSP responses.
const OCSP_RESPONSE_CONTENT_TYPE: &str = "application/ocsp-response";

/// When `nextUpdate` is absent, consider an OCSP response fresh for this
/// long after `thisUpdate`.
const DEFAULT_OCSP_LIFETIME_HOURS: i64 = 24;

/// SHA-1 algorithm OID for OCSP request hashing: 1.3.14.3.2.26
const OID_SHA1: &[u8] = &[0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A];

// ---------------------------------------------------------------------------
// OCSP response status codes (outer envelope)
// ---------------------------------------------------------------------------

/// OCSPResponseStatus ::= ENUMERATED (RFC 6960 Section 4.2.1)
const OCSP_RESPONSE_STATUS_SUCCESSFUL: u8 = 0;

// ---------------------------------------------------------------------------
// CertStatus tags in SingleResponse (context-specific)
// ---------------------------------------------------------------------------

/// CertStatus ::= CHOICE { good [0] IMPLICIT NULL, ... }
const CERT_STATUS_GOOD: u8 = 0;
/// CertStatus ::= CHOICE { ..., revoked [1] IMPLICIT RevokedInfo, ... }
const CERT_STATUS_REVOKED: u8 = 1;

// ---------------------------------------------------------------------------
// Public API: high-level OCSP stapling
// ---------------------------------------------------------------------------

/// Attempt to staple an OCSP response to `cert`.
///
/// This is the main entry point for OCSP stapling. The function:
///
/// 1. Checks for a cached OCSP staple in `storage`. If it exists and is still fresh (per
///    [`is_ocsp_fresh`]), it is used directly.
/// 2. Otherwise, fetches a fresh OCSP response from the CA's responder.
/// 3. Caches the response in `storage` for future use.
/// 4. Staples the response to `cert` (sets [`Certificate::ocsp_response`]).
///
/// Returns `Ok(true)` if a staple was successfully attached, `Ok(false)`
/// if OCSP stapling is not available for this certificate (e.g. no OCSP
/// responder URL in the certificate, or the leaf is self-signed with no
/// issuer).
/// Certificates with a total lifetime shorter than this are considered
/// short-lived and OCSP stapling is skipped for them.
const SHORT_LIVED_CERT_DAYS: i64 = 7;

pub async fn staple_ocsp(
    storage: &dyn Storage,
    cert: &mut Certificate,
    _config: &OcspConfig,
) -> Result<bool> {
    // Skip OCSP stapling for short-lived certificates (< 7 days total
    // lifetime). These certificates expire before OCSP responses would
    // typically need refreshing, so stapling adds overhead with little
    // benefit.
    let lifetime = cert.not_after - cert.not_before;
    if lifetime < ChronoDuration::days(SHORT_LIVED_CERT_DAYS) {
        debug!(
            lifetime_hours = lifetime.num_hours(),
            "certificate lifetime is shorter than {SHORT_LIVED_CERT_DAYS} days; skipping OCSP stapling"
        );
        return Ok(false);
    }

    if cert.cert_chain.is_empty() {
        debug!("certificate chain is empty; skipping OCSP stapling");
        return Ok(false);
    }

    // Parse the leaf to extract its first SAN for storage key generation.
    let first_name = cert.names.first().cloned().unwrap_or_default();
    let ocsp_storage_key = storage::ocsp_key(&first_name, &cert.hash);

    // Try loading a cached OCSP response from storage.
    match storage.load(&ocsp_storage_key).await {
        Ok(cached_bytes) => {
            match parse_ocsp_response_raw(&cached_bytes) {
                Ok(parsed) if is_ocsp_fresh(&parsed) => {
                    debug!(
                        name = %first_name,
                        status = %parsed.status,
                        "using cached OCSP staple"
                    );
                    cert.ocsp_status = Some(parsed.status);
                    cert.ocsp_response = Some(cached_bytes);
                    return Ok(parsed.status != OcspStatus::Revoked);
                }
                Ok(parsed) => {
                    debug!(
                        name = %first_name,
                        status = %parsed.status,
                        "cached OCSP staple is stale; fetching fresh one"
                    );
                }
                Err(e) => {
                    debug!(
                        name = %first_name,
                        error = %e,
                        "failed to parse cached OCSP response; deleting corrupt entry and fetching fresh one"
                    );
                    // Delete the corrupt cached staple from storage (best effort).
                    if let Err(del_err) = storage.delete(&ocsp_storage_key).await {
                        warn!(
                            name = %first_name,
                            error = %del_err,
                            "failed to delete corrupt cached OCSP response"
                        );
                    }
                }
            }
        }
        Err(Error::Storage(StorageError::NotFound(_))) => {
            debug!(name = %first_name, "no cached OCSP staple found");
        }
        Err(e) => {
            warn!(name = %first_name, error = %e, "error loading cached OCSP staple");
        }
    }

    // Fetch a fresh OCSP response.
    let (raw_response, parsed) =
        match get_ocsp_for_cert_chain(&cert.cert_chain, &_config.responder_overrides).await {
            Ok(result) => result,
            Err(e) => {
                debug!(
                    name = %first_name,
                    error = %e,
                    "failed to get OCSP response; stapling skipped"
                );
                return Ok(false);
            }
        };

    // Cache the response to storage (best effort).
    if let Err(e) = storage.store(&ocsp_storage_key, &raw_response).await {
        warn!(
            name = %first_name,
            error = %e,
            "failed to cache OCSP response"
        );
    }

    debug!(
        name = %first_name,
        status = %parsed.status,
        "stapled fresh OCSP response"
    );

    cert.ocsp_status = Some(parsed.status);
    cert.ocsp_response = Some(raw_response);
    Ok(parsed.status != OcspStatus::Revoked)
}

// ---------------------------------------------------------------------------
// Public API: freshness checks
// ---------------------------------------------------------------------------

/// Returns `true` if the OCSP response is still considered fresh (valid).
///
/// Freshness is determined by:
/// - If `next_update` is set: fresh while `now < next_update`.
/// - If `next_update` is absent: fresh for `DEFAULT_OCSP_LIFETIME_HOURS` (24) hours after
///   `this_update`.
pub fn is_ocsp_fresh(response: &OcspResponse) -> bool {
    let now = Utc::now();

    if let Some(next_update) = response.next_update {
        now < next_update
    } else {
        // No nextUpdate; consider fresh for DEFAULT_OCSP_LIFETIME_HOURS.
        let expires = response.this_update + ChronoDuration::hours(DEFAULT_OCSP_LIFETIME_HOURS);
        now < expires
    }
}

/// Returns `true` if the OCSP response should be refreshed proactively.
///
/// Refreshing is recommended when:
/// - The response is past the midpoint of its validity window, OR
/// - `next_update` is within 1 hour from now, OR
/// - The response is no longer fresh.
pub fn ocsp_needs_update(response: &OcspResponse) -> bool {
    if !is_ocsp_fresh(response) {
        return true;
    }

    let now = Utc::now();

    if let Some(next_update) = response.next_update {
        // Refresh when within 1 hour of expiration.
        if next_update - now < ChronoDuration::hours(1) {
            return true;
        }

        // Refresh when past the midpoint of the validity window.
        let total = next_update - response.this_update;
        let elapsed = now - response.this_update;
        if elapsed > total / 2 {
            return true;
        }
    } else {
        // No nextUpdate: refresh after half the default lifetime.
        let half_life =
            response.this_update + ChronoDuration::hours(DEFAULT_OCSP_LIFETIME_HOURS / 2);
        if now > half_life {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Public API: extract OCSP responder URLs
// ---------------------------------------------------------------------------

/// Extract OCSP responder URLs from a DER-encoded X.509 certificate.
///
/// Examines the Authority Information Access (AIA) extension and returns
/// all URLs whose access method is `id-ad-ocsp` (OID 1.3.6.1.5.5.7.48.1).
pub fn extract_ocsp_urls(cert_der: &[u8]) -> Result<Vec<String>> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
        CryptoError::InvalidCertificate(format!(
            "failed to parse certificate for OCSP URL extraction: {e}"
        ))
    })?;

    extract_ocsp_urls_from_parsed(&cert)
}

/// Extract OCSP responder URLs from an already-parsed X.509 certificate.
fn extract_ocsp_urls_from_parsed(cert: &X509Certificate<'_>) -> Result<Vec<String>> {
    let mut urls = Vec::new();

    // Walk all extensions looking for AuthorityInfoAccess.
    for ext in cert.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            for desc in aia.accessdescs.iter() {
                if desc.access_method == OID_PKIX_ACCESS_DESCRIPTOR_OCSP
                    && let GeneralName::URI(uri) = &desc.access_location
                {
                    urls.push(uri.to_string());
                }
            }
        }
    }

    Ok(urls)
}

/// Extract CA Issuer URLs from an already-parsed X.509 certificate's AIA
/// extension.
///
/// These URLs point to the issuer's certificate and can be used to
/// reconstruct the certificate chain when only the leaf is available.
fn extract_ca_issuer_urls_from_parsed(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut urls = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            for desc in aia.accessdescs.iter() {
                if desc.access_method == OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS
                    && let GeneralName::URI(uri) = &desc.access_location
                {
                    urls.push(uri.to_string());
                }
            }
        }
    }
    urls
}

/// Fetch an issuer certificate from a URL (typically from the AIA
/// extension's `id-ad-caIssuers` access method).
///
/// The URL may return the certificate in either DER or PEM format.
/// This function auto-detects the encoding and returns the DER bytes.
async fn fetch_issuer_cert(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| CertError::OcspFailed(format!("failed to build HTTP client: {e}")))?;

    let response = client.get(url).send().await.map_err(|e| {
        CertError::OcspFailed(format!(
            "failed to fetch issuer certificate from {url}: {e}"
        ))
    })?;

    if !response.status().is_success() {
        return Err(CertError::OcspFailed(format!(
            "issuer certificate fetch from {url} returned HTTP {}",
            response.status()
        ))
        .into());
    }

    let body = response.bytes().await.map_err(|e| {
        CertError::OcspFailed(format!(
            "failed to read issuer certificate response body: {e}"
        ))
    })?;

    if body.is_empty() {
        return Err(
            CertError::OcspFailed("issuer certificate response body is empty".into()).into(),
        );
    }

    // Auto-detect PEM vs DER. If the body starts with "-----BEGIN", treat
    // it as PEM; otherwise assume raw DER.
    if body.starts_with(b"-----BEGIN") {
        let pem_str = std::str::from_utf8(&body).map_err(|e| {
            CertError::OcspFailed(format!("issuer certificate PEM is not valid UTF-8: {e}"))
        })?;
        let parsed = ::pem::parse(pem_str).map_err(|e| {
            CertError::OcspFailed(format!("failed to parse issuer certificate PEM: {e}"))
        })?;
        Ok(parsed.into_contents())
    } else {
        // Assume DER. Validate by attempting to parse.
        X509Certificate::from_der(&body).map_err(|e| {
            CertError::OcspFailed(format!(
                "downloaded issuer certificate is not valid DER: {e}"
            ))
        })?;
        Ok(body.to_vec())
    }
}

// ---------------------------------------------------------------------------
// Fetch OCSP response for a certificate chain
// ---------------------------------------------------------------------------

/// Fetch an OCSP response for the leaf certificate in a DER chain.
///
/// If the chain has at least two entries, `chain[0]` is the leaf and
/// `chain[1]` is the issuer. If only the leaf is present, the function
/// attempts to discover the issuer certificate from the leaf's Authority
/// Information Access (AIA) extension (`id-ad-caIssuers` URL) and
/// downloads it via HTTP. This allows OCSP stapling even when the full
/// chain is not available.
///
/// When `responder_overrides` is non-empty, the leaf certificate's SANs
/// are checked against the map. If a match is found, the override URL
/// is used instead of the URL from the certificate's AIA extension.
///
/// Returns the raw response bytes and a parsed [`OcspResponse`].
async fn get_ocsp_for_cert_chain(
    chain: &[rustls::pki_types::CertificateDer<'static>],
    responder_overrides: &HashMap<String, String>,
) -> Result<(Vec<u8>, OcspResponse)> {
    if chain.is_empty() {
        return Err(CertError::OcspFailed("certificate chain is empty".into()).into());
    }

    let leaf_der = chain[0].as_ref();

    // Parse leaf.
    let (_, leaf) = X509Certificate::from_der(leaf_der).map_err(|e| {
        CryptoError::InvalidCertificate(format!("failed to parse leaf certificate: {e}"))
    })?;

    // If the chain has an issuer, use it directly. Otherwise, try to
    // fetch the issuer from the AIA extension's Issuing Certificate URL.
    let fetched_issuer_der: Option<Vec<u8>>;
    let issuer_der_ref: &[u8] = if chain.len() >= 2 {
        chain[1].as_ref()
    } else {
        // Attempt to discover the issuer from the AIA extension.
        let issuer_urls = extract_ca_issuer_urls_from_parsed(&leaf);
        let mut downloaded = None;
        for url in &issuer_urls {
            match fetch_issuer_cert(url).await {
                Ok(der_bytes) => {
                    debug!(url = %url, "fetched issuer certificate from AIA extension");
                    downloaded = Some(der_bytes);
                    break;
                }
                Err(e) => {
                    debug!(url = %url, error = %e, "failed to fetch issuer from AIA URL");
                }
            }
        }
        fetched_issuer_der = downloaded;
        match fetched_issuer_der.as_deref() {
            Some(d) => d,
            None => {
                return Err(CertError::OcspFailed(
                    "certificate chain has only 1 entry and issuer could not be fetched from AIA"
                        .into(),
                )
                .into());
            }
        }
    };

    let (_, issuer) = X509Certificate::from_der(issuer_der_ref).map_err(|e| {
        CryptoError::InvalidCertificate(format!("failed to parse issuer certificate: {e}"))
    })?;

    // Check for a responder override matching any SAN on the leaf.
    let override_url = if !responder_overrides.is_empty() {
        crate::certificates::extract_names_from_der(leaf_der)
            .ok()
            .and_then(|names| {
                names
                    .iter()
                    .find_map(|name| responder_overrides.get(name).cloned())
            })
    } else {
        None
    };

    // Extract OCSP responder URL from the leaf (used as fallback).
    let ocsp_url: String = if let Some(url) = override_url {
        debug!(url = %url, "using responder override URL");
        url
    } else {
        let ocsp_urls = extract_ocsp_urls_from_parsed(&leaf)?;
        ocsp_urls.into_iter().next().ok_or_else(|| {
            CertError::OcspFailed("no OCSP responder URL found in certificate AIA extension".into())
        })?
    };

    // Build the OCSP request.
    let ocsp_request_der = build_ocsp_request(&leaf, &issuer)?;

    // Send HTTP POST request.
    let raw_response = send_ocsp_request(&ocsp_url, &ocsp_request_der).await?;

    // Parse the response.
    let parsed = parse_ocsp_response_raw(&raw_response)?;

    Ok((raw_response, parsed))
}

/// Fetch an OCSP response for PEM-encoded certificate data.
///
/// This is a convenience wrapper that parses the PEM bundle, extracts
/// the leaf and issuer, and calls the internal `get_ocsp_for_cert_chain`.
///
/// The PEM data must contain at least two `CERTIFICATE` blocks.
pub async fn get_ocsp_for_cert(cert_pem: &[u8]) -> Result<(Vec<u8>, OcspResponse)> {
    let pem_str = std::str::from_utf8(cert_pem).map_err(|e| {
        CryptoError::InvalidCertificate(format!("certificate PEM is not valid UTF-8: {e}"))
    })?;

    let pems: Vec<::pem::Pem> = ::pem::parse_many(pem_str)
        .map_err(|e| CryptoError::InvalidCertificate(format!("failed to parse PEM bundle: {e}")))?;

    let cert_ders: Vec<rustls::pki_types::CertificateDer<'static>> = pems
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| rustls::pki_types::CertificateDer::from(p.into_contents()))
        .collect();

    if cert_ders.len() < 2 {
        return Err(CertError::OcspFailed(
            "PEM bundle must contain at least 2 certificates (leaf + issuer)".into(),
        )
        .into());
    }

    get_ocsp_for_cert_chain(&cert_ders, &HashMap::new()).await
}

// ---------------------------------------------------------------------------
// OCSP request building
// ---------------------------------------------------------------------------

/// Build a DER-encoded OCSP request for the given leaf and issuer
/// certificates.
///
/// The OCSP request is constructed per RFC 6960 Section 4.1:
///
/// ```text
/// OCSPRequest ::= SEQUENCE {
///   tbsRequest TBSRequest
/// }
///
/// TBSRequest ::= SEQUENCE {
///   requestList SEQUENCE OF Request
/// }
///
/// Request ::= SEQUENCE {
///   reqCert CertID
/// }
///
/// CertID ::= SEQUENCE {
///   hashAlgorithm AlgorithmIdentifier,
///   issuerNameHash OCTET STRING,
///   issuerKeyHash  OCTET STRING,
///   serialNumber   CertificateSerialNumber
/// }
/// ```
///
/// We always use SHA-1 for hashing (as required by RFC 5019 and most
/// OCSP responders).
fn build_ocsp_request(leaf: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> Result<Vec<u8>> {
    // Hash the issuer's distinguished name (DER-encoded).
    let issuer_name_der = issuer.subject().as_raw();
    let issuer_name_hash = sha1_hash(issuer_name_der);

    // Hash the issuer's public key (the BIT STRING value, without the tag
    // and length, and without the leading unused-bits octet).
    let issuer_key_hash = hash_issuer_public_key(issuer)?;

    // Serial number of the leaf certificate (as big-endian bytes).
    let serial = leaf.raw_serial();

    // Build CertID.
    let cert_id = build_cert_id(&issuer_name_hash, &issuer_key_hash, serial);

    // Build Request (just wraps CertID in a SEQUENCE).
    let request = der_wrap(0x30, &cert_id);

    // Build requestList (SEQUENCE OF Request).
    let request_list = der_wrap(0x30, &request);

    // Build TBSRequest (SEQUENCE containing requestList).
    let tbs_request = der_wrap(0x30, &request_list);

    // Build OCSPRequest (SEQUENCE containing TBSRequest).
    let ocsp_request = der_wrap(0x30, &tbs_request);

    Ok(ocsp_request)
}

/// Build a DER-encoded CertID structure.
fn build_cert_id(issuer_name_hash: &[u8], issuer_key_hash: &[u8], serial_number: &[u8]) -> Vec<u8> {
    // AlgorithmIdentifier for SHA-1:
    // SEQUENCE { OID sha1, NULL }
    let sha1_null = der_wrap(0x05, &[]); // NULL
    let mut algo_content = Vec::new();
    algo_content.extend_from_slice(OID_SHA1);
    algo_content.extend_from_slice(&sha1_null);
    let algo_id = der_wrap(0x30, &algo_content);

    // issuerNameHash: OCTET STRING
    let name_hash = der_wrap(0x04, issuer_name_hash);

    // issuerKeyHash: OCTET STRING
    let key_hash = der_wrap(0x04, issuer_key_hash);

    // serialNumber: INTEGER
    // Ensure the serial number is positive by checking the high bit.
    let serial_int = if !serial_number.is_empty() && (serial_number[0] & 0x80) != 0 {
        // Prepend a 0x00 byte to keep it positive.
        let mut padded = vec![0x00];
        padded.extend_from_slice(serial_number);
        der_wrap(0x02, &padded)
    } else {
        der_wrap(0x02, serial_number)
    };

    let mut cert_id_content = Vec::new();
    cert_id_content.extend_from_slice(&algo_id);
    cert_id_content.extend_from_slice(&name_hash);
    cert_id_content.extend_from_slice(&key_hash);
    cert_id_content.extend_from_slice(&serial_int);

    cert_id_content
}

/// Extract and hash the issuer's raw public key bytes (BIT STRING content
/// without the unused-bits octet).
fn hash_issuer_public_key(issuer: &X509Certificate<'_>) -> Result<Vec<u8>> {
    let spki = issuer.public_key();
    // spki.subject_public_key contains the BIT STRING data, which is the
    // raw SubjectPublicKey. The `subject_public_key.as_ref()` gives us
    // the BIT STRING content. We need to use the `data` field which
    // contains the actual key bytes (without the unused-bits octet).
    Ok(sha1_hash(&spki.subject_public_key.data))
}

// ---------------------------------------------------------------------------
// OCSP HTTP transport
// ---------------------------------------------------------------------------

/// Send an OCSP request to the given responder URL via HTTP POST.
async fn send_ocsp_request(url: &str, request_der: &[u8]) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| CertError::OcspFailed(format!("failed to build HTTP client: {e}")))?;

    let response = client
        .post(url)
        .header("Content-Type", OCSP_REQUEST_CONTENT_TYPE)
        .header("Accept", OCSP_RESPONSE_CONTENT_TYPE)
        .body(request_der.to_vec())
        .send()
        .await
        .map_err(|e| CertError::OcspFailed(format!("OCSP HTTP request to {url} failed: {e}")))?;

    if !response.status().is_success() {
        return Err(CertError::OcspFailed(format!(
            "OCSP responder returned HTTP {}",
            response.status()
        ))
        .into());
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| CertError::OcspFailed(format!("failed to read OCSP response body: {e}")))?;

    if body.len() > MAX_OCSP_RESPONSE_SIZE {
        return Err(CertError::OcspFailed(format!(
            "OCSP response too large: {} bytes (max {})",
            body.len(),
            MAX_OCSP_RESPONSE_SIZE
        ))
        .into());
    }

    Ok(body.to_vec())
}

// ---------------------------------------------------------------------------
// OCSP response parsing
// ---------------------------------------------------------------------------

/// Parse a raw DER-encoded OCSP response.
///
/// The OCSP response structure (RFC 6960 Section 4.2):
///
/// ```text
/// OCSPResponse ::= SEQUENCE {
///   responseStatus   OCSPResponseStatus,
///   responseBytes    [0] EXPLICIT ResponseBytes OPTIONAL
/// }
///
/// ResponseBytes ::= SEQUENCE {
///   responseType OID,
///   response     OCTET STRING (containing BasicOCSPResponse DER)
/// }
///
/// BasicOCSPResponse ::= SEQUENCE {
///   tbsResponseData  ResponseData,
///   signatureAlgorithm AlgorithmIdentifier,
///   signature         BIT STRING,
///   certs             [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
/// }
///
/// ResponseData ::= SEQUENCE {
///   version          [0] EXPLICIT INTEGER DEFAULT v1,
///   responderID      ResponderID,
///   producedAt       GeneralizedTime,
///   responses        SEQUENCE OF SingleResponse,
///   responseExtensions [1] EXPLICIT Extensions OPTIONAL
/// }
///
/// SingleResponse ::= SEQUENCE {
///   certID           CertID,
///   certStatus       CertStatus,
///   thisUpdate       GeneralizedTime,
///   nextUpdate       [0] EXPLICIT GeneralizedTime OPTIONAL,
///   singleExtensions [1] EXPLICIT Extensions OPTIONAL
/// }
/// ```
fn parse_ocsp_response_raw(data: &[u8]) -> Result<OcspResponse> {
    use x509_parser::der_parser::parse_der;

    let (_, outer) = parse_der(data)
        .map_err(|e| CertError::OcspFailed(format!("failed to parse OCSP response DER: {e}")))?;

    let outer_seq = outer
        .as_sequence()
        .map_err(|e| CertError::OcspFailed(format!("OCSP response is not a SEQUENCE: {e}")))?;

    if outer_seq.is_empty() {
        return Err(CertError::OcspFailed("OCSP response SEQUENCE is empty".into()).into());
    }

    // responseStatus: ENUMERATED
    let response_status = outer_seq[0]
        .as_u32()
        .map_err(|e| CertError::OcspFailed(format!("failed to parse responseStatus: {e}")))?;

    if response_status != OCSP_RESPONSE_STATUS_SUCCESSFUL as u32 {
        return Ok(OcspResponse {
            status: OcspStatus::ServerFailed,
            raw: data.to_vec(),
            this_update: Utc::now(),
            next_update: None,
            produced_at: Utc::now(),
            revoked_at: None,
        });
    }

    if outer_seq.len() < 2 {
        return Err(
            CertError::OcspFailed("successful OCSP response missing responseBytes".into()).into(),
        );
    }

    // responseBytes: [0] EXPLICIT ResponseBytes
    // The context-tagged [0] wraps a SEQUENCE { OID, OCTET STRING }.
    let response_bytes_wrapper = &outer_seq[1];
    let response_bytes_content = get_context_content(response_bytes_wrapper).ok_or_else(|| {
        CertError::OcspFailed("failed to unwrap responseBytes context tag".into())
    })?;

    let (_, resp_bytes_der) = parse_der(response_bytes_content)
        .map_err(|e| CertError::OcspFailed(format!("failed to parse ResponseBytes: {e}")))?;

    let resp_bytes_seq = resp_bytes_der
        .as_sequence()
        .map_err(|e| CertError::OcspFailed(format!("ResponseBytes is not a SEQUENCE: {e}")))?;

    if resp_bytes_seq.len() < 2 {
        return Err(CertError::OcspFailed("ResponseBytes SEQUENCE too short".into()).into());
    }

    // resp_bytes_seq[0] is the responseType OID (should be id-pkix-ocsp-basic).
    // resp_bytes_seq[1] is the OCTET STRING containing BasicOCSPResponse.
    let basic_resp_der = resp_bytes_seq[1].as_slice().map_err(|e| {
        CertError::OcspFailed(format!(
            "failed to extract BasicOCSPResponse OCTET STRING: {e}"
        ))
    })?;

    parse_basic_ocsp_response(basic_resp_der, data)
}

/// Parse a BasicOCSPResponse structure.
fn parse_basic_ocsp_response(data: &[u8], raw: &[u8]) -> Result<OcspResponse> {
    use x509_parser::der_parser::parse_der;

    let (_, basic) = parse_der(data)
        .map_err(|e| CertError::OcspFailed(format!("failed to parse BasicOCSPResponse: {e}")))?;

    let basic_seq = basic
        .as_sequence()
        .map_err(|e| CertError::OcspFailed(format!("BasicOCSPResponse is not a SEQUENCE: {e}")))?;

    if basic_seq.is_empty() {
        return Err(CertError::OcspFailed("BasicOCSPResponse SEQUENCE is empty".into()).into());
    }

    // tbsResponseData is the first element.
    let tbs = basic_seq[0]
        .as_sequence()
        .map_err(|e| CertError::OcspFailed(format!("tbsResponseData is not a SEQUENCE: {e}")))?;

    parse_tbs_response_data(tbs, raw)
}

/// Parse the ResponseData (tbsResponseData) structure.
///
/// ResponseData ::= SEQUENCE {
///   version          [0] EXPLICIT INTEGER DEFAULT v1,
///   responderID      ResponderID,
///   producedAt       GeneralizedTime,
///   responses        SEQUENCE OF SingleResponse,
///   ...
/// }
fn parse_tbs_response_data(
    tbs: &[x509_parser::der_parser::ber::BerObject<'_>],
    raw: &[u8],
) -> Result<OcspResponse> {
    // The version field is optional (context tag [0]). We need to handle
    // both cases: with and without version.
    let mut idx = 0;

    // Check if the first element is a context-tagged version.
    if !tbs.is_empty() && is_context_tagged(&tbs[0], 0) {
        idx += 1; // skip version
    }

    // responderID: can be byName [1] or byKey [2] -- skip it.
    if idx >= tbs.len() {
        return Err(CertError::OcspFailed("ResponseData too short".into()).into());
    }
    idx += 1; // skip responderID

    // producedAt: GeneralizedTime
    if idx >= tbs.len() {
        return Err(CertError::OcspFailed("ResponseData missing producedAt".into()).into());
    }
    let produced_at = parse_generalized_time_from_obj(&tbs[idx]).unwrap_or_else(Utc::now);
    idx += 1;

    // responses: SEQUENCE OF SingleResponse
    if idx >= tbs.len() {
        return Err(CertError::OcspFailed("ResponseData missing responses".into()).into());
    }

    let responses = tbs[idx]
        .as_sequence()
        .map_err(|e| CertError::OcspFailed(format!("responses is not a SEQUENCE: {e}")))?;

    if responses.is_empty() {
        return Err(CertError::OcspFailed(
            "OCSP response contains no SingleResponse entries".into(),
        )
        .into());
    }

    // Parse the first SingleResponse (we only need one).
    parse_single_response(&responses[0], raw, produced_at)
}

/// Parse a SingleResponse structure.
///
/// SingleResponse ::= SEQUENCE {
///   certID           CertID,
///   certStatus       CertStatus,
///   thisUpdate       GeneralizedTime,
///   nextUpdate       [0] EXPLICIT GeneralizedTime OPTIONAL,
///   singleExtensions [1] EXPLICIT Extensions OPTIONAL
/// }
fn parse_single_response(
    obj: &x509_parser::der_parser::ber::BerObject<'_>,
    raw: &[u8],
    produced_at: DateTime<Utc>,
) -> Result<OcspResponse> {
    let seq = obj
        .as_sequence()
        .map_err(|e| CertError::OcspFailed(format!("SingleResponse is not a SEQUENCE: {e}")))?;

    if seq.len() < 3 {
        return Err(CertError::OcspFailed(
            "SingleResponse SEQUENCE too short (need certID, certStatus, thisUpdate)".into(),
        )
        .into());
    }

    // seq[0] = certID (skip)
    // seq[1] = certStatus
    let (status, revoked_at) = parse_cert_status(&seq[1])?;

    // seq[2] = thisUpdate
    let this_update = parse_generalized_time_from_obj(&seq[2])
        .ok_or_else(|| CertError::OcspFailed("failed to parse thisUpdate".into()))?;

    // seq[3] = nextUpdate (optional, context-tagged [0])
    let next_update = if seq.len() > 3 && is_context_tagged(&seq[3], 0) {
        // Unwrap the context tag to get the GeneralizedTime inside.
        let content = get_context_content(&seq[3]);
        content.and_then(parse_generalized_time_from_bytes)
    } else {
        None
    };

    Ok(OcspResponse {
        status,
        raw: raw.to_vec(),
        this_update,
        next_update,
        produced_at,
        revoked_at,
    })
}

/// Parse the CertStatus field from a SingleResponse.
///
/// CertStatus ::= CHOICE {
///   good    [0] IMPLICIT NULL,
///   revoked [1] IMPLICIT RevokedInfo,
///   unknown [2] IMPLICIT NULL
/// }
///
/// RevokedInfo ::= SEQUENCE {
///   revocationTime    GeneralizedTime,
///   revocationReason  [0] EXPLICIT CRLReason OPTIONAL
/// }
fn parse_cert_status(
    obj: &x509_parser::der_parser::ber::BerObject<'_>,
) -> Result<(OcspStatus, Option<DateTime<Utc>>)> {
    // The CertStatus is context-tagged (IMPLICIT).
    let tag = obj.header.tag();

    if tag.0 == CERT_STATUS_GOOD as u32 {
        return Ok((OcspStatus::Good, None));
    }

    if tag.0 == CERT_STATUS_REVOKED as u32 {
        // Try to extract revocation time from the content.
        let revoked_at = get_context_content(obj).and_then(|bytes| {
            // The content is a RevokedInfo SEQUENCE.
            // First field is GeneralizedTime.
            x509_parser::der_parser::parse_der(bytes)
                .ok()
                .and_then(|(_, inner)| {
                    inner.as_sequence().ok().and_then(|seq| {
                        if seq.is_empty() {
                            None
                        } else {
                            parse_generalized_time_from_obj(&seq[0])
                        }
                    })
                })
        });
        return Ok((OcspStatus::Revoked, revoked_at));
    }

    // Tag 2 = unknown, or anything else.
    Ok((OcspStatus::Unknown, None))
}

// ---------------------------------------------------------------------------
// DER helpers
// ---------------------------------------------------------------------------

/// Minimal DER TLV wrapper (same as in crypto.rs).
fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 0x10000 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
    out.extend_from_slice(content);
    out
}

/// Compute SHA-1 hash of the input.
fn sha1_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Check if a BER object has a specific context-specific tag number.
///
/// Context-specific class has the two high bits of the tag byte = 0b10,
/// meaning the raw first byte (before length) has bits 7-6 = 10.
fn is_context_tagged(obj: &x509_parser::der_parser::ber::BerObject<'_>, tag_num: u32) -> bool {
    let tag = obj.header.tag();
    let class = obj.header.class();
    class == x509_parser::asn1_rs::Class::ContextSpecific && tag.0 == tag_num
}

/// Extract the raw content bytes from a context-tagged BER object.
fn get_context_content<'a>(
    obj: &'a x509_parser::der_parser::ber::BerObject<'a>,
) -> Option<&'a [u8]> {
    obj.content.as_slice().ok()
}

/// Parse a GeneralizedTime from a BER object.
///
/// OCSP responses encode timestamps as GeneralizedTime (tag 0x18).
/// We parse the raw content bytes as an ASCII time string in the format
/// `YYYYMMDDHHMMSSZ`.
fn parse_generalized_time_from_obj(
    obj: &x509_parser::der_parser::ber::BerObject<'_>,
) -> Option<DateTime<Utc>> {
    // If this object is a GeneralizedTime (tag 24 / 0x18), its content
    // bytes are the ASCII time string.
    if let Ok(bytes) = obj.content.as_slice()
        && let Some(dt) = parse_time_string(bytes)
    {
        return Some(dt);
    }

    None
}

/// Parse a GeneralizedTime from raw DER bytes (the content of an
/// explicitly tagged wrapper that contains a GeneralizedTime).
fn parse_generalized_time_from_bytes(bytes: &[u8]) -> Option<DateTime<Utc>> {
    use x509_parser::der_parser::parse_der;
    if let Ok((_, obj)) = parse_der(bytes) {
        return parse_generalized_time_from_obj(&obj);
    }
    None
}

/// Parse an ASN.1 time string (GeneralizedTime or UTCTime) into a
/// `DateTime<Utc>`.
///
/// Handles formats:
/// - `YYYYMMDDHHMMSSZ` (GeneralizedTime)
/// - `YYMMDDHHMMSSZ` (UTCTime)
fn parse_time_string(bytes: &[u8]) -> Option<DateTime<Utc>> {
    let s = std::str::from_utf8(bytes).ok()?;
    let s = s.trim_end_matches('Z');

    if s.len() >= 14 {
        // GeneralizedTime: YYYYMMDDHHMMSS
        let year: i32 = s[0..4].parse().ok()?;
        let month: u32 = s[4..6].parse().ok()?;
        let day: u32 = s[6..8].parse().ok()?;
        let hour: u32 = s[8..10].parse().ok()?;
        let min: u32 = s[10..12].parse().ok()?;
        let sec: u32 = s[12..14].parse().ok()?;

        use chrono::NaiveDate;
        let naive = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, min, sec)?;
        Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
    } else if s.len() >= 12 {
        // UTCTime: YYMMDDHHMMSS
        let year: i32 = s[0..2].parse().ok()?;
        let year = if year >= 50 { 1900 + year } else { 2000 + year };
        let month: u32 = s[2..4].parse().ok()?;
        let day: u32 = s[4..6].parse().ok()?;
        let hour: u32 = s[6..8].parse().ok()?;
        let min: u32 = s[8..10].parse().ok()?;
        let sec: u32 = s[10..12].parse().ok()?;

        use chrono::NaiveDate;
        let naive = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, min, sec)?;
        Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocsp_config_default() {
        let config = OcspConfig::default();
        assert!(!config.disable_stapling);
        assert!(config.replace_revoked);
    }

    #[test]
    fn test_ocsp_status_display() {
        assert_eq!(OcspStatus::Good.to_string(), "Good");
        assert_eq!(OcspStatus::Revoked.to_string(), "Revoked");
        assert_eq!(OcspStatus::Unknown.to_string(), "Unknown");
        assert_eq!(OcspStatus::ServerFailed.to_string(), "ServerFailed");
    }

    #[test]
    fn test_ocsp_status_eq() {
        assert_eq!(OcspStatus::Good, OcspStatus::Good);
        assert_ne!(OcspStatus::Good, OcspStatus::Revoked);
    }

    #[test]
    fn test_is_ocsp_fresh_with_next_update_in_future() {
        let response = OcspResponse {
            status: OcspStatus::Good,
            raw: vec![],
            this_update: Utc::now() - ChronoDuration::hours(1),
            next_update: Some(Utc::now() + ChronoDuration::hours(23)),
            produced_at: Utc::now() - ChronoDuration::hours(1),
            revoked_at: None,
        };
        assert!(is_ocsp_fresh(&response));
    }

    #[test]
    fn test_is_ocsp_fresh_with_next_update_in_past() {
        let response = OcspResponse {
            status: OcspStatus::Good,
            raw: vec![],
            this_update: Utc::now() - ChronoDuration::hours(48),
            next_update: Some(Utc::now() - ChronoDuration::hours(1)),
            produced_at: Utc::now() - ChronoDuration::hours(48),
            revoked_at: None,
        };
        assert!(!is_ocsp_fresh(&response));
    }

    #[test]
    fn test_is_ocsp_fresh_no_next_update_recent() {
        let response = OcspResponse {
            status: OcspStatus::Good,
            raw: vec![],
            this_update: Utc::now() - ChronoDuration::hours(1),
            next_update: None,
            produced_at: Utc::now() - ChronoDuration::hours(1),
            revoked_at: None,
        };
        assert!(is_ocsp_fresh(&response));
    }

    #[test]
    fn test_is_ocsp_fresh_no_next_update_old() {
        let response = OcspResponse {
            status: OcspStatus::Good,
            raw: vec![],
            this_update: Utc::now() - ChronoDuration::hours(25),
            next_update: None,
            produced_at: Utc::now() - ChronoDuration::hours(25),
            revoked_at: None,
        };
        assert!(!is_ocsp_fresh(&response));
    }

    #[test]
    fn test_ocsp_needs_update_stale() {
        let response = OcspResponse {
            status: OcspStatus::Good,
            raw: vec![],
            this_update: Utc::now() - ChronoDuration::hours(48),
            next_update: Some(Utc::now() - ChronoDuration::hours(1)),
            produced_at: Utc::now() - ChronoDuration::hours(48),
            revoked_at: None,
        };
        assert!(ocsp_needs_update(&response));
    }

    #[test]
    fn test_ocsp_needs_update_within_one_hour() {
        let response = OcspResponse {
            status: OcspStatus::Good,
            raw: vec![],
            this_update: Utc::now() - ChronoDuration::hours(23),
            next_update: Some(Utc::now() + ChronoDuration::minutes(30)),
            produced_at: Utc::now() - ChronoDuration::hours(23),
            revoked_at: None,
        };
        assert!(ocsp_needs_update(&response));
    }

    #[test]
    fn test_ocsp_needs_update_past_midpoint() {
        let response = OcspResponse {
            status: OcspStatus::Good,
            raw: vec![],
            this_update: Utc::now() - ChronoDuration::hours(18),
            next_update: Some(Utc::now() + ChronoDuration::hours(6)),
            produced_at: Utc::now() - ChronoDuration::hours(18),
            revoked_at: None,
        };
        // Total window: 24h, elapsed: 18h -> past midpoint (12h).
        assert!(ocsp_needs_update(&response));
    }

    #[test]
    fn test_ocsp_needs_update_fresh_and_before_midpoint() {
        let response = OcspResponse {
            status: OcspStatus::Good,
            raw: vec![],
            this_update: Utc::now() - ChronoDuration::hours(2),
            next_update: Some(Utc::now() + ChronoDuration::hours(22)),
            produced_at: Utc::now() - ChronoDuration::hours(2),
            revoked_at: None,
        };
        // Total window: 24h, elapsed: 2h -> before midpoint (12h).
        assert!(!ocsp_needs_update(&response));
    }

    #[test]
    fn test_ocsp_needs_update_no_next_update_recent() {
        let response = OcspResponse {
            status: OcspStatus::Good,
            raw: vec![],
            this_update: Utc::now() - ChronoDuration::hours(2),
            next_update: None,
            produced_at: Utc::now() - ChronoDuration::hours(2),
            revoked_at: None,
        };
        // Half of default 24h lifetime = 12h. Elapsed = 2h -> no update needed.
        assert!(!ocsp_needs_update(&response));
    }

    #[test]
    fn test_ocsp_needs_update_no_next_update_past_half() {
        let response = OcspResponse {
            status: OcspStatus::Good,
            raw: vec![],
            this_update: Utc::now() - ChronoDuration::hours(13),
            next_update: None,
            produced_at: Utc::now() - ChronoDuration::hours(13),
            revoked_at: None,
        };
        // Half of default 24h lifetime = 12h. Elapsed = 13h -> update needed.
        assert!(ocsp_needs_update(&response));
    }

    #[test]
    fn test_der_wrap_short() {
        let wrapped = der_wrap(0x04, &[0x01, 0x02, 0x03]);
        assert_eq!(wrapped, vec![0x04, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_der_wrap_long() {
        let content = vec![0xAA; 200];
        let wrapped = der_wrap(0x04, &content);
        assert_eq!(wrapped[0], 0x04);
        assert_eq!(wrapped[1], 0x81); // length > 127
        assert_eq!(wrapped[2], 200);
        assert_eq!(wrapped.len(), 200 + 3);
    }

    #[test]
    fn test_sha1_hash() {
        // SHA-1 of empty string.
        let hash = sha1_hash(b"");
        assert_eq!(hash.len(), 20);
        // Known SHA-1 of empty: da39a3ee5e6b4b0d3255bfef95601890afd80709
        assert_eq!(hash[0], 0xda);
        assert_eq!(hash[1], 0x39);
    }

    #[test]
    fn test_build_cert_id() {
        let name_hash = vec![0u8; 20];
        let key_hash = vec![1u8; 20];
        let serial = vec![0x01, 0x02, 0x03];
        let cert_id = build_cert_id(&name_hash, &key_hash, &serial);
        // Should be a valid DER fragment (not wrapped in outer SEQUENCE).
        assert!(!cert_id.is_empty());
    }

    #[test]
    fn test_parse_ocsp_response_raw_invalid() {
        let result = parse_ocsp_response_raw(b"not valid der");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ocsp_response_raw_empty_sequence() {
        // An empty SEQUENCE: 0x30 0x00
        let result = parse_ocsp_response_raw(&[0x30, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ocsp_response_unsuccessful_status() {
        // A minimal OCSP response with status = 1 (malformedRequest).
        // SEQUENCE { ENUMERATED 1 }
        let data = vec![
            0x30, 0x03, // SEQUENCE, length 3
            0x0A, 0x01, 0x01, // ENUMERATED, length 1, value 1
        ];
        let result = parse_ocsp_response_raw(&data).unwrap();
        assert_eq!(result.status, OcspStatus::ServerFailed);
    }
}
