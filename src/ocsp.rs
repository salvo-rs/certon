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
use x509_parser::asn1_rs::FromDer;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::{
    OID_HASH_SHA1, OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS, OID_PKIX_ACCESS_DESCRIPTOR_OCSP,
};
use x509_parser::prelude::*;
use x509_parser::verify::verify_signature;

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
#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug)]
struct ParsedOcspResponse<'a> {
    response: OcspResponse,
    basic: Option<ParsedBasicOcspResponse<'a>>,
}

#[derive(Debug)]
struct ParsedBasicOcspResponse<'a> {
    tbs_response_data: &'a [u8],
    signature_algorithm: x509_parser::x509::AlgorithmIdentifier<'a>,
    signature_value: x509_parser::asn1_rs::BitString<'a>,
    included_certs: Vec<&'a [u8]>,
    responder_id: OcspResponderId,
    cert_id: OcspCertId,
}

#[derive(Debug)]
struct ParsedResponseData {
    response: OcspResponse,
    responder_id: OcspResponderId,
    cert_id: OcspCertId,
}

#[derive(Debug)]
enum OcspResponderId {
    ByName(Vec<u8>),
    ByKey(Vec<u8>),
}

#[derive(Debug)]
struct OcspCertId {
    issuer_name_hash: Vec<u8>,
    issuer_key_hash: Vec<u8>,
    serial_number: Vec<u8>,
    uses_sha1: bool,
}

#[derive(Debug)]
struct DerTlv<'a> {
    tag: u8,
    full: &'a [u8],
    value: &'a [u8],
    rest: &'a [u8],
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
pub(crate) const DEFAULT_OCSP_LIFETIME_HOURS: i64 = 24;

/// Tolerate a small amount of clock skew without accepting future-dated status.
const OCSP_CLOCK_SKEW_SECONDS: i64 = 300;
const MAX_ISSUER_CERT_SIZE: usize = 1024 * 1024;

/// SHA-1 algorithm OID for OCSP request hashing: 1.3.14.3.2.26
const OID_SHA1: &[u8] = &[0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A];

/// id-pkix-ocsp-basic OID content bytes: 1.3.6.1.5.5.7.48.1.1
const OID_OCSP_BASIC_CONTENT: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

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

/// Skip OCSP for certificates with a total lifetime shorter than seven days.
const SHORT_LIVED_CERT_DAYS: i64 = 7;

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
/// Returns `Ok(true)` only when a current, signed Good response was attached.
/// `Ok(false)` means no usable staple is available. A verified revocation is
/// recorded in [`Certificate::ocsp_status`], never inferred from this boolean.
///
/// A verified `Revoked` status is retained on this certificate until it is
/// replaced. Refresh errors, Unknown responses and older Good responses cannot
/// undo it. Revoked certificates never receive staple bytes.
pub async fn staple_ocsp(
    storage: &dyn Storage,
    cert: &mut Certificate,
    _config: &OcspConfig,
) -> Result<bool> {
    // A failed refresh must never leave a stale response attached. A verified
    // revocation is sticky for this certificate: an outage, Unknown response or
    // replay of an older, still-fresh Good response cannot make it usable again.
    // Replacing the certificate creates a new Certificate with no OCSP status.
    cert.ocsp_response = None;
    if cert.ocsp_status == Some(OcspStatus::Revoked) {
        return Ok(false);
    }
    cert.ocsp_status = None;
    if _config.disable_stapling {
        return Ok(false);
    }
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
    let mut fresh_fallback = None;

    // Try loading a cached OCSP response from storage.
    match storage.load(&ocsp_storage_key).await {
        Ok(cached_bytes) => {
            match parse_ocsp_response_for_cert_chain(&cached_bytes, &cert.cert_chain).await {
                Ok(parsed) if is_ocsp_fresh(&parsed) => {
                    debug!(
                        name = %first_name,
                        status = %parsed.status,
                        "using cached OCSP staple"
                    );
                    if parsed.status != OcspStatus::Good || !ocsp_needs_update(&parsed) {
                        cert.ocsp_status = Some(parsed.status);
                        if parsed.status == OcspStatus::Good {
                            cert.ocsp_response = Some(cached_bytes);
                        }
                        return Ok(parsed.status == OcspStatus::Good);
                    }
                    // Proactively request a replacement, retaining this response
                    // only while it is still fresh if the responder is unavailable.
                    fresh_fallback = Some((cached_bytes, parsed));
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
                if let Some((raw, parsed)) = fresh_fallback
                    && is_ocsp_fresh(&parsed)
                {
                    cert.ocsp_status = Some(OcspStatus::Good);
                    cert.ocsp_response = Some(raw);
                    return Ok(true);
                }
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
    if parsed.status == OcspStatus::Good {
        cert.ocsp_response = Some(raw_response);
    }
    Ok(parsed.status == OcspStatus::Good)
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
    let latest = now + ChronoDuration::seconds(OCSP_CLOCK_SKEW_SECONDS);
    if response.this_update > latest || response.produced_at > latest {
        return false;
    }

    if let Some(next_update) = response.next_update {
        response.this_update < next_update && now < next_update
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
    let client = crate::http::client()?;

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

    let body = read_limited_response(response, MAX_ISSUER_CERT_SIZE).await?;

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

pub(crate) async fn parse_ocsp_response_for_cert_chain(
    data: &[u8],
    chain: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<OcspResponse> {
    if chain.is_empty() {
        return Err(CertError::OcspFailed("certificate chain is empty".into()).into());
    }

    let leaf_der = chain[0].as_ref();
    let (_, leaf) = X509Certificate::from_der(leaf_der).map_err(|e| {
        CryptoError::InvalidCertificate(format!("failed to parse leaf certificate: {e}"))
    })?;

    let fetched_issuer_der: Option<Vec<u8>>;
    let issuer_der_ref: &[u8] = if chain.len() >= 2 {
        chain[1].as_ref()
    } else {
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

    validate_certificate_issuer(&leaf, &issuer)?;

    parse_and_validate_ocsp_response_raw(data, &leaf, &issuer)
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

    validate_certificate_issuer(&leaf, &issuer)?;

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

    // Parse and validate the signed response before caching or stapling it.
    let parsed = parse_and_validate_ocsp_response_raw(&raw_response, &leaf, &issuer)?;

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
    let client = crate::http::client()?;

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

    read_limited_response(response, MAX_OCSP_RESPONSE_SIZE).await
}

async fn read_limited_response(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|size| size > limit as u64)
    {
        return Err(CertError::OcspFailed(format!("response exceeds {limit} byte limit")).into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| CertError::OcspFailed(format!("failed to read response body: {e}")))?
    {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(
                CertError::OcspFailed(format!("response exceeds {limit} byte limit")).into(),
            );
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn validate_certificate_issuer(
    leaf: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<()> {
    if leaf.issuer() != issuer.subject()
        || !issuer
            .basic_constraints()
            .ok()
            .flatten()
            .is_some_and(|bc| bc.value.ca)
        || issuer
            .key_usage()
            .ok()
            .flatten()
            .is_some_and(|ku| !ku.value.key_cert_sign())
        || leaf.verify_signature(Some(issuer.public_key())).is_err()
    {
        return Err(
            CertError::OcspFailed("OCSP issuer did not issue the leaf certificate".into()).into(),
        );
    }
    Ok(())
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
#[cfg(test)]
fn parse_ocsp_response_raw(data: &[u8]) -> Result<OcspResponse> {
    parse_ocsp_response_der(data).map(|parsed| parsed.response)
}

fn parse_and_validate_ocsp_response_raw(
    data: &[u8],
    leaf: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<OcspResponse> {
    let parsed = parse_ocsp_response_der(data)?;
    if let Some(basic) = &parsed.basic {
        validate_basic_ocsp_response(basic, leaf, issuer)?;
    } else {
        return Err(CertError::OcspFailed(
            "OCSP responder did not return a successful BasicOCSPResponse".into(),
        )
        .into());
    }
    if !is_ocsp_fresh(&parsed.response) {
        return Err(CertError::OcspFailed(
            "OCSP response is stale or has invalid update times".into(),
        )
        .into());
    }
    Ok(parsed.response)
}

fn parse_ocsp_response_der(data: &[u8]) -> Result<ParsedOcspResponse<'_>> {
    let outer_tlv = read_der_tlv(data)?;
    if outer_tlv.tag != 0x30 || !outer_tlv.rest.is_empty() {
        return Err(CertError::OcspFailed("OCSP response is not a single SEQUENCE".into()).into());
    }
    if outer_tlv.value.is_empty() {
        return Err(CertError::OcspFailed("OCSP response SEQUENCE is empty".into()).into());
    }

    // responseStatus: ENUMERATED
    let response_status_tlv = read_der_tlv(outer_tlv.value)?;
    if response_status_tlv.tag != 0x0a {
        return Err(CertError::OcspFailed("OCSP responseStatus is not ENUMERATED".into()).into());
    }
    let response_status = parse_der_u32(response_status_tlv.value)?;

    if response_status != OCSP_RESPONSE_STATUS_SUCCESSFUL as u32 {
        return Ok(ParsedOcspResponse {
            response: OcspResponse {
                status: OcspStatus::ServerFailed,
                raw: data.to_vec(),
                this_update: Utc::now(),
                next_update: None,
                produced_at: Utc::now(),
                revoked_at: None,
            },
            basic: None,
        });
    }

    if response_status_tlv.rest.is_empty() {
        return Err(
            CertError::OcspFailed("successful OCSP response missing responseBytes".into()).into(),
        );
    }

    // responseBytes: [0] EXPLICIT ResponseBytes
    // The context-tagged [0] wraps a SEQUENCE { OID, OCTET STRING }.
    let response_bytes_wrapper = read_der_tlv(response_status_tlv.rest)?;
    if response_bytes_wrapper.tag != 0xa0 || !response_bytes_wrapper.rest.is_empty() {
        return Err(
            CertError::OcspFailed("failed to unwrap responseBytes context tag".into()).into(),
        );
    }

    let response_bytes = read_der_tlv(response_bytes_wrapper.value)?;
    if response_bytes.tag != 0x30 || !response_bytes.rest.is_empty() {
        return Err(CertError::OcspFailed("ResponseBytes is not a SEQUENCE".into()).into());
    }

    let response_type = read_der_tlv(response_bytes.value)?;
    if response_type.tag != 0x06 || response_type.value != OID_OCSP_BASIC_CONTENT {
        return Err(
            CertError::OcspFailed("OCSP responseType is not id-pkix-ocsp-basic".into()).into(),
        );
    }

    let response_octet = read_der_tlv(response_type.rest)?;
    if response_octet.tag != 0x04 || !response_octet.rest.is_empty() {
        return Err(CertError::OcspFailed(
            "ResponseBytes response is not a single OCTET STRING".into(),
        )
        .into());
    }

    parse_basic_ocsp_response(response_octet.value, data)
}

/// Parse a BasicOCSPResponse structure.
fn parse_basic_ocsp_response<'a>(data: &'a [u8], raw: &[u8]) -> Result<ParsedOcspResponse<'a>> {
    use x509_parser::der_parser::parse_der;

    let basic_tlv = read_der_tlv(data)?;
    if basic_tlv.tag != 0x30 || !basic_tlv.rest.is_empty() {
        return Err(
            CertError::OcspFailed("BasicOCSPResponse is not a single SEQUENCE".into()).into(),
        );
    }

    let tbs_tlv = read_der_tlv(basic_tlv.value)?;
    let signature_algorithm_tlv = read_der_tlv(tbs_tlv.rest)?;
    let signature_value_tlv = read_der_tlv(signature_algorithm_tlv.rest)?;
    let included_certs = parse_basic_ocsp_included_certs(signature_value_tlv.rest)?;

    let (sig_alg_rest, signature_algorithm) = x509_parser::x509::AlgorithmIdentifier::from_der(
        signature_algorithm_tlv.full,
    )
    .map_err(|e| {
        CertError::OcspFailed(format!(
            "failed to parse BasicOCSPResponse signatureAlgorithm: {e}"
        ))
    })?;
    if !sig_alg_rest.is_empty() {
        return Err(CertError::OcspFailed(
            "BasicOCSPResponse signatureAlgorithm has trailing data".into(),
        )
        .into());
    }

    let (sig_rest, signature_value) =
        x509_parser::asn1_rs::BitString::from_der(signature_value_tlv.full).map_err(|e| {
            CertError::OcspFailed(format!(
                "failed to parse BasicOCSPResponse signature BIT STRING: {e}"
            ))
        })?;
    if !sig_rest.is_empty() {
        return Err(
            CertError::OcspFailed("BasicOCSPResponse signature has trailing data".into()).into(),
        );
    }

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

    let parsed_response_data = parse_tbs_response_data(tbs, raw)?;
    Ok(ParsedOcspResponse {
        response: parsed_response_data.response,
        basic: Some(ParsedBasicOcspResponse {
            tbs_response_data: tbs_tlv.full,
            signature_algorithm,
            signature_value,
            included_certs,
            responder_id: parsed_response_data.responder_id,
            cert_id: parsed_response_data.cert_id,
        }),
    })
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
) -> Result<ParsedResponseData> {
    // The version field is optional (context tag [0]). We need to handle
    // both cases: with and without version.
    let mut idx = 0;

    // Check if the first element is a context-tagged version.
    if !tbs.is_empty() && is_context_tagged(&tbs[0], 0) {
        idx += 1; // skip version
    }

    // responderID: can be byName [1] or byKey [2].
    if idx >= tbs.len() {
        return Err(CertError::OcspFailed("ResponseData too short".into()).into());
    }
    let responder_id = parse_responder_id(&tbs[idx])?;
    idx += 1;

    // producedAt: GeneralizedTime
    if idx >= tbs.len() {
        return Err(CertError::OcspFailed("ResponseData missing producedAt".into()).into());
    }
    let produced_at = parse_generalized_time_from_obj(&tbs[idx])
        .ok_or_else(|| CertError::OcspFailed("failed to parse producedAt".into()))?;
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
    let (response, cert_id) = parse_single_response(&responses[0], raw, produced_at)?;
    Ok(ParsedResponseData {
        response,
        responder_id,
        cert_id,
    })
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
) -> Result<(OcspResponse, OcspCertId)> {
    let seq = obj
        .as_sequence()
        .map_err(|e| CertError::OcspFailed(format!("SingleResponse is not a SEQUENCE: {e}")))?;

    if seq.len() < 3 {
        return Err(CertError::OcspFailed(
            "SingleResponse SEQUENCE too short (need certID, certStatus, thisUpdate)".into(),
        )
        .into());
    }

    let cert_id = parse_cert_id(&seq[0])?;

    // seq[1] = certStatus
    let (status, revoked_at) = parse_cert_status(&seq[1])?;

    // seq[2] = thisUpdate
    let this_update = parse_generalized_time_from_obj(&seq[2])
        .ok_or_else(|| CertError::OcspFailed("failed to parse thisUpdate".into()))?;

    // seq[3] = nextUpdate (optional, context-tagged [0])
    let next_update = if seq.len() > 3 && is_context_tagged(&seq[3], 0) {
        // Unwrap the context tag to get the GeneralizedTime inside.
        Some(
            get_context_content(&seq[3])
                .and_then(parse_generalized_time_from_bytes)
                .ok_or_else(|| CertError::OcspFailed("failed to parse nextUpdate".into()))?,
        )
    } else {
        None
    };

    Ok((
        OcspResponse {
            status,
            raw: raw.to_vec(),
            this_update,
            next_update,
            produced_at,
            revoked_at,
        },
        cert_id,
    ))
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

fn parse_responder_id(
    obj: &x509_parser::der_parser::ber::BerObject<'_>,
) -> Result<OcspResponderId> {
    if is_context_tagged(obj, 1) {
        let name = get_context_content(obj)
            .ok_or_else(|| CertError::OcspFailed("responderID byName is empty".into()))?;
        return Ok(OcspResponderId::ByName(name.to_vec()));
    }

    if is_context_tagged(obj, 2) {
        let key_hash = get_context_content(obj)
            .ok_or_else(|| CertError::OcspFailed("responderID byKey is empty".into()))?;
        let key_hash = x509_parser::der_parser::parse_der(key_hash)
            .ok()
            .and_then(|(_, inner)| inner.as_slice().ok().map(|bytes| bytes.to_vec()))
            .unwrap_or_else(|| key_hash.to_vec());
        return Ok(OcspResponderId::ByKey(key_hash));
    }

    Err(CertError::OcspFailed("unsupported responderID choice in OCSP response".into()).into())
}

fn parse_cert_id(obj: &x509_parser::der_parser::ber::BerObject<'_>) -> Result<OcspCertId> {
    let seq = obj
        .as_sequence()
        .map_err(|e| CertError::OcspFailed(format!("CertID is not a SEQUENCE: {e}")))?;
    if seq.len() < 4 {
        return Err(CertError::OcspFailed("CertID SEQUENCE too short".into()).into());
    }

    let hash_algorithm = seq[0]
        .as_sequence()
        .map_err(|e| CertError::OcspFailed(format!("CertID hashAlgorithm is invalid: {e}")))?;
    let hash_oid = hash_algorithm
        .first()
        .ok_or_else(|| CertError::OcspFailed("CertID hashAlgorithm is empty".into()))?
        .as_oid()
        .map_err(|e| CertError::OcspFailed(format!("CertID hashAlgorithm OID invalid: {e}")))?;

    let issuer_name_hash = seq[1]
        .as_slice()
        .map_err(|e| CertError::OcspFailed(format!("issuerNameHash is invalid: {e}")))?
        .to_vec();
    let issuer_key_hash = seq[2]
        .as_slice()
        .map_err(|e| CertError::OcspFailed(format!("issuerKeyHash is invalid: {e}")))?
        .to_vec();
    let serial_number = seq[3]
        .as_slice()
        .map_err(|e| CertError::OcspFailed(format!("CertID serialNumber is invalid: {e}")))?
        .to_vec();

    Ok(OcspCertId {
        issuer_name_hash,
        issuer_key_hash,
        serial_number,
        uses_sha1: *hash_oid == OID_HASH_SHA1,
    })
}

fn validate_basic_ocsp_response(
    basic: &ParsedBasicOcspResponse<'_>,
    leaf: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<()> {
    validate_certificate_issuer(leaf, issuer)?;
    validate_ocsp_cert_id(&basic.cert_id, leaf, issuer)?;

    if responder_matches_cert(&basic.responder_id, issuer)
        && verify_basic_ocsp_signature(basic, issuer).is_ok()
    {
        return Ok(());
    }

    for cert_der in &basic.included_certs {
        let (_, responder_cert) = match X509Certificate::from_der(cert_der) {
            Ok(parsed) => parsed,
            Err(e) => {
                debug!(error = %e, "skipping unparsable OCSP responder certificate");
                continue;
            }
        };

        if !responder_matches_cert(&basic.responder_id, &responder_cert) {
            continue;
        }
        if !is_authorized_ocsp_responder(&responder_cert, issuer) {
            continue;
        }
        if verify_basic_ocsp_signature(basic, &responder_cert).is_ok() {
            return Ok(());
        }
    }

    Err(CertError::OcspFailed(
        "BasicOCSPResponse signature or responder authorization could not be verified".into(),
    )
    .into())
}

fn validate_ocsp_cert_id(
    cert_id: &OcspCertId,
    leaf: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<()> {
    if !cert_id.uses_sha1 {
        return Err(
            CertError::OcspFailed("OCSP CertID uses an unsupported hash algorithm".into()).into(),
        );
    }

    let expected_issuer_name_hash = sha1_hash(issuer.subject().as_raw());
    let expected_issuer_key_hash = hash_issuer_public_key(issuer)?;
    if cert_id.issuer_name_hash != expected_issuer_name_hash
        || cert_id.issuer_key_hash != expected_issuer_key_hash
    {
        return Err(CertError::OcspFailed(
            "OCSP CertID issuer hashes do not match the certificate issuer".into(),
        )
        .into());
    }

    if normalize_der_integer(&cert_id.serial_number) != normalize_der_integer(leaf.raw_serial()) {
        return Err(CertError::OcspFailed(
            "OCSP CertID serial number does not match the leaf certificate".into(),
        )
        .into());
    }

    Ok(())
}

fn verify_basic_ocsp_signature(
    basic: &ParsedBasicOcspResponse<'_>,
    signer: &X509Certificate<'_>,
) -> Result<()> {
    verify_signature(
        signer.public_key(),
        &basic.signature_algorithm,
        &basic.signature_value,
        basic.tbs_response_data,
    )
    .map_err(|e| CertError::OcspFailed(format!("OCSP signature verification failed: {e}")).into())
}

fn responder_matches_cert(responder_id: &OcspResponderId, cert: &X509Certificate<'_>) -> bool {
    match responder_id {
        OcspResponderId::ByName(name) => name.as_slice() == cert.subject().as_raw(),
        OcspResponderId::ByKey(key_hash) => {
            key_hash.as_slice() == sha1_hash(&cert.public_key().subject_public_key.data)
        }
    }
}

fn is_authorized_ocsp_responder(
    responder_cert: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> bool {
    if responder_cert
        .verify_signature(Some(issuer.public_key()))
        .is_err()
    {
        return false;
    }

    // Reject expired or not-yet-valid delegated responder certificates so a
    // stale OCSP signing key cannot keep producing accepted responses after
    // the CA has rotated it.
    if !responder_cert.validity().is_valid() {
        debug!(
            not_before = %responder_cert.validity().not_before,
            not_after = %responder_cert.validity().not_after,
            "delegated OCSP responder certificate is outside its validity window"
        );
        return false;
    }

    let has_ocsp_signing_eku = responder_cert
        .extended_key_usage()
        .ok()
        .flatten()
        .map(|eku| eku.value.ocsp_signing)
        .unwrap_or(false);
    if !has_ocsp_signing_eku {
        return false;
    }

    responder_cert
        .key_usage()
        .ok()
        .flatten()
        .map(|key_usage| key_usage.value.digital_signature())
        .unwrap_or(true)
}

fn normalize_der_integer(bytes: &[u8]) -> &[u8] {
    let mut normalized = bytes;
    while normalized.len() > 1 && normalized[0] == 0 {
        normalized = &normalized[1..];
    }
    normalized
}

// ---------------------------------------------------------------------------
// DER helpers
// ---------------------------------------------------------------------------

fn read_der_tlv(input: &[u8]) -> Result<DerTlv<'_>> {
    if input.len() < 2 {
        return Err(CertError::OcspFailed("truncated DER object".into()).into());
    }

    let tag = input[0];
    let len_byte = input[1];
    let (len, header_len) = if len_byte & 0x80 == 0 {
        (len_byte as usize, 2)
    } else {
        let len_len = (len_byte & 0x7f) as usize;
        if len_len == 0 {
            return Err(
                CertError::OcspFailed("indefinite DER length is not allowed".into()).into(),
            );
        }
        if len_len > std::mem::size_of::<usize>() || input.len() < 2 + len_len {
            return Err(CertError::OcspFailed("invalid DER length".into()).into());
        }
        let mut len = 0usize;
        for byte in &input[2..2 + len_len] {
            len = (len << 8) | (*byte as usize);
        }
        (len, 2 + len_len)
    };

    let end = header_len
        .checked_add(len)
        .ok_or_else(|| CertError::OcspFailed("DER length overflow".into()))?;
    if input.len() < end {
        return Err(CertError::OcspFailed("truncated DER content".into()).into());
    }

    Ok(DerTlv {
        tag,
        full: &input[..end],
        value: &input[header_len..end],
        rest: &input[end..],
    })
}

fn parse_der_u32(input: &[u8]) -> Result<u32> {
    let input = normalize_der_integer(input);
    if input.is_empty() || input.len() > 4 {
        return Err(CertError::OcspFailed("invalid DER integer length".into()).into());
    }

    let mut value: u32 = 0;
    for byte in input {
        value = (value << 8) | (*byte as u32);
    }
    Ok(value)
}

fn parse_basic_ocsp_included_certs(mut input: &[u8]) -> Result<Vec<&[u8]>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let certs_wrapper = read_der_tlv(input)?;
    if certs_wrapper.tag != 0xa0 || !certs_wrapper.rest.is_empty() {
        return Err(CertError::OcspFailed(
            "BasicOCSPResponse certs field is not a single [0] EXPLICIT value".into(),
        )
        .into());
    }

    let certs_seq = read_der_tlv(certs_wrapper.value)?;
    if certs_seq.tag != 0x30 || !certs_seq.rest.is_empty() {
        return Err(CertError::OcspFailed(
            "BasicOCSPResponse certs field is not a SEQUENCE".into(),
        )
        .into());
    }

    input = certs_seq.value;
    let mut certs = Vec::new();
    while !input.is_empty() {
        let cert_tlv = read_der_tlv(input)?;
        if cert_tlv.tag != 0x30 {
            return Err(CertError::OcspFailed(
                "BasicOCSPResponse included cert is not a SEQUENCE".into(),
            )
            .into());
        }
        certs.push(cert_tlv.full);
        input = cert_tlv.rest;
    }

    Ok(certs)
}

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
    use x509_parser::der_parser::ber::BerObjectContent;
    let BerObjectContent::GeneralizedTime(value) = &obj.content else {
        return None;
    };
    if value.tz != x509_parser::asn1_rs::ASN1TimeZone::Z {
        return None;
    }
    let date = chrono::NaiveDate::from_ymd_opt(
        value.year.try_into().ok()?,
        value.month.into(),
        value.day.into(),
    )?;
    let time = date.and_hms_milli_opt(
        value.hour.into(),
        value.minute.into(),
        value.second.into(),
        value.millisecond.unwrap_or(0).into(),
    )?;
    Some(DateTime::from_naive_utc_and_offset(time, Utc))
}

/// Parse a GeneralizedTime from raw DER bytes (the content of an
/// explicitly tagged wrapper that contains a GeneralizedTime).
fn parse_generalized_time_from_bytes(bytes: &[u8]) -> Option<DateTime<Utc>> {
    use x509_parser::der_parser::parse_der;
    if let Ok(([], obj)) = parse_der(bytes) {
        return parse_generalized_time_from_obj(&obj);
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn signed_chain() -> (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rcgen::KeyPair,
        String,
    ) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca = params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(params, &ca_key);
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["ocsp.example.com".into()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        (
            vec![leaf.der().clone(), ca.der().clone()],
            ca_key,
            leaf_key.serialize_pem(),
        )
    }

    pub(crate) fn signed_response(
        chain: &[rustls::pki_types::CertificateDer<'static>],
        key: &rcgen::KeyPair,
        status: u8,
        this_update: DateTime<Utc>,
        next_update: DateTime<Utc>,
    ) -> Vec<u8> {
        signed_response_with_next_update(chain, key, status, this_update, Some(next_update))
    }

    pub(crate) fn signed_response_with_next_update(
        chain: &[rustls::pki_types::CertificateDer<'static>],
        key: &rcgen::KeyPair,
        status: u8,
        this_update: DateTime<Utc>,
        next_update: Option<DateTime<Utc>>,
    ) -> Vec<u8> {
        use rcgen::SigningKey;
        let (_, leaf) = X509Certificate::from_der(chain[0].as_ref()).unwrap();
        let (_, issuer) = X509Certificate::from_der(chain[1].as_ref()).unwrap();
        let time = |value: DateTime<Utc>| {
            der_wrap(0x18, value.format("%Y%m%d%H%M%SZ").to_string().as_bytes())
        };
        let id = der_wrap(
            0x30,
            &build_cert_id(
                &sha1_hash(issuer.subject().as_raw()),
                &hash_issuer_public_key(&issuer).unwrap(),
                leaf.raw_serial(),
            ),
        );
        let status = match status {
            0 => der_wrap(0x80, &[]),
            1 => der_wrap(0xa1, &time(this_update)),
            _ => der_wrap(0x82, &[]),
        };
        let mut single = [id, status, time(this_update)].concat();
        if let Some(next_update) = next_update {
            single.extend(der_wrap(0xa0, &time(next_update)));
        }
        let single = der_wrap(0x30, &single);
        let tbs = der_wrap(
            0x30,
            &[
                der_wrap(0xa1, issuer.subject().as_raw()),
                time(Utc::now()),
                der_wrap(0x30, &single),
            ]
            .concat(),
        );
        let algorithm = der_wrap(
            0x30,
            &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
        );
        let signature = key.sign(&tbs).unwrap();
        let signature = der_wrap(0x03, &[vec![0], signature].concat());
        let basic = der_wrap(0x30, &[tbs, algorithm, signature].concat());
        let bytes = der_wrap(
            0x30,
            &[
                der_wrap(0x06, OID_OCSP_BASIC_CONTENT),
                der_wrap(0x04, &basic),
            ]
            .concat(),
        );
        der_wrap(
            0x30,
            &[vec![0x0a, 0x01, 0], der_wrap(0xa0, &bytes)].concat(),
        )
    }

    #[test]
    fn rejects_stale_and_future_signed_responses() {
        let (chain, key, _) = signed_chain();
        let (_, leaf) = X509Certificate::from_der(chain[0].as_ref()).unwrap();
        let (_, issuer) = X509Certificate::from_der(chain[1].as_ref()).unwrap();
        let now = Utc::now();
        for (start, end, accepted) in [
            (
                now - ChronoDuration::hours(1),
                now + ChronoDuration::hours(1),
                true,
            ),
            (
                now - ChronoDuration::hours(2),
                now - ChronoDuration::hours(1),
                false,
            ),
            (
                now + ChronoDuration::hours(1),
                now + ChronoDuration::hours(2),
                false,
            ),
            (now, now - ChronoDuration::seconds(1), false),
        ] {
            let raw = signed_response(&chain, &key, 0, start, end);
            let result = parse_and_validate_ocsp_response_raw(&raw, &leaf, &issuer);
            assert_eq!(result.is_ok(), accepted, "{result:?}");
        }
    }

    #[test]
    fn rejects_self_consistent_response_from_wrong_issuer() {
        let (chain, ..) = signed_chain();
        let (attacker_chain, attacker_key, _) = signed_chain();
        let forged = vec![chain[0].clone(), attacker_chain[1].clone()];
        let raw = signed_response(
            &forged,
            &attacker_key,
            0,
            Utc::now() - ChronoDuration::hours(1),
            Utc::now() + ChronoDuration::hours(1),
        );
        let (_, leaf) = X509Certificate::from_der(forged[0].as_ref()).unwrap();
        let (_, attacker) = X509Certificate::from_der(forged[1].as_ref()).unwrap();
        assert!(
            parse_and_validate_ocsp_response_raw(&raw, &leaf, &attacker)
                .unwrap_err()
                .to_string()
                .contains("did not issue")
        );
    }

    #[tokio::test]
    async fn staples_only_good_and_preserves_verified_revocation_status() {
        let (chain, key, leaf_key_pem) = signed_chain();
        let leaf_pem = ::pem::encode(&::pem::Pem::new("CERTIFICATE", chain[0].as_ref()));
        let mut cert = Certificate::from_pem(leaf_pem.as_bytes(), leaf_key_pem.as_bytes()).unwrap();
        cert.cert_chain = chain.clone();
        let directory = tempfile::tempdir().unwrap();
        let storage = crate::FileStorage::new(directory.path());
        let cache_key = storage::ocsp_key(&cert.names[0], &cert.hash);
        for (wire_status, expected) in [
            (0, OcspStatus::Good),
            (1, OcspStatus::Revoked),
            (2, OcspStatus::Unknown),
        ] {
            // Each status is independently observed on a newly loaded certificate.
            cert.ocsp_status = None;
            let raw = signed_response(
                &chain,
                &key,
                wire_status,
                Utc::now() - ChronoDuration::hours(1),
                Utc::now() + ChronoDuration::hours(1),
            );
            storage.store(&cache_key, &raw).await.unwrap();
            assert_eq!(
                staple_ocsp(&storage, &mut cert, &OcspConfig::default())
                    .await
                    .unwrap(),
                expected == OcspStatus::Good
            );
            assert_eq!(cert.ocsp_status, Some(expected));
            assert_eq!(cert.ocsp_response.is_some(), expected == OcspStatus::Good);
        }
        storage.delete(&cache_key).await.unwrap();
        cert.ocsp_response = Some(vec![1, 2, 3]);
        cert.ocsp_status = Some(OcspStatus::Good);
        assert!(
            !staple_ocsp(&storage, &mut cert, &OcspConfig::default())
                .await
                .unwrap()
        );
        assert!(cert.ocsp_response.is_none());
        assert!(cert.ocsp_status.is_none());
    }

    async fn response_server(body: Vec<u8>, chunked: bool) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            let message = if chunked {
                [
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                        .to_vec(),
                    format!("{:x}\r\n", body.len()).into_bytes(),
                    body,
                    b"\r\n0\r\n\r\n".to_vec(),
                ]
                .concat()
            } else {
                [
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .into_bytes(),
                    body,
                ]
                .concat()
            };
            let _ = socket.write_all(&message).await;
        });
        url
    }

    #[tokio::test]
    async fn rejects_oversized_chunked_and_content_length_bodies() {
        for chunked in [true, false] {
            let url = response_server(vec![0; 256], chunked).await;
            let response = crate::http::client()
                .unwrap()
                .get(url)
                .send()
                .await
                .unwrap();
            assert!(read_limited_response(response, 128).await.is_err());
        }
    }

    #[tokio::test]
    async fn rejects_expired_response_downloaded_from_responder() {
        let (chain, key, _) = signed_chain();
        let raw = signed_response(
            &chain,
            &key,
            0,
            Utc::now() - ChronoDuration::hours(2),
            Utc::now() - ChronoDuration::hours(1),
        );
        let url = response_server(raw, false).await;
        let overrides = HashMap::from([("ocsp.example.com".to_string(), url)]);
        assert!(
            get_ocsp_for_cert_chain(&chain, &overrides)
                .await
                .unwrap_err()
                .to_string()
                .contains("stale")
        );
    }

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
