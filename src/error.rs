//! Error types for the certon ACME certificate management library.
//!
//! This module defines a hierarchy of error types used throughout certon:
//!
//! - [`AcmeError`] -- failures during ACME protocol interactions (directory fetch, account
//!   management, orders, authorizations, challenges).
//! - [`StorageError`] -- failures reading from or writing to persistent storage.
//! - [`CryptoError`] -- failures in key generation, signing, or PEM encoding/decoding.
//! - [`CertError`] -- certificate-specific validation issues (expiration, revocation, domain
//!   validation).
//! - [`enum@Error`] -- the top-level error that wraps all of the above, plus general-purpose
//!   `Config`, `Timeout`, and `Other` variants.
//!
//! A convenience [`Result<T>`] type alias is also provided.

use std::time::Duration;

use thiserror::Error;

/// A specialized `Result` type for certon operations.
pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// ACME protocol errors
// ---------------------------------------------------------------------------

/// Errors arising from ACME protocol interactions with a Certificate Authority.
#[derive(Debug, Error)]
pub enum AcmeError {
    /// Failed to fetch the ACME directory resource.
    #[error("failed to fetch ACME directory: {0}")]
    Directory(String),

    /// Failed to obtain or use a replay nonce.
    #[error("nonce error: {0}")]
    Nonce(String),

    /// Account creation or loading failed.
    #[error("account error: {0}")]
    Account(String),

    /// Order creation or finalization failed.
    #[error("order error: {0}")]
    Order(String),

    /// Authorization failed.
    #[error("authorization error: {0}")]
    Authorization(String),

    /// A specific challenge type failed.
    #[error("challenge `{challenge_type}` failed: {message}")]
    Challenge {
        /// The ACME challenge type (e.g. `"http-01"`, `"dns-01"`, `"tls-alpn-01"`).
        challenge_type: String,
        /// Human-readable description of the failure.
        message: String,
    },

    /// Certificate download failed.
    #[error("certificate download failed: {0}")]
    Certificate(String),

    /// The CA rate-limited the request.
    #[error("rate limited by CA (retry after {retry_after:?}): {message}")]
    RateLimited {
        /// Suggested duration to wait before retrying, if the CA provided one.
        retry_after: Option<Duration>,
        /// Human-readable description from the CA.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Storage errors
// ---------------------------------------------------------------------------

/// Errors that occur during storage operations (loading, saving, locking).
#[derive(Debug, Error)]
pub enum StorageError {
    /// The requested key was not found in storage.
    #[error("key not found: {0}")]
    NotFound(String),

    /// Could not acquire a storage lock.
    #[error("failed to acquire lock: {0}")]
    LockFailed(String),

    /// An underlying I/O error occurred.
    #[error("storage I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization of data for storage failed.
    #[error("serialization error: {0}")]
    Serialize(String),

    /// Deserialization of data from storage failed.
    #[error("deserialization error: {0}")]
    Deserialize(String),
}

// ---------------------------------------------------------------------------
// Cryptographic errors
// ---------------------------------------------------------------------------

/// Errors related to cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Key generation failed.
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    /// A signing operation failed.
    #[error("signing failed: {0}")]
    Signing(String),

    /// The provided key data is invalid or unsupported.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// The provided certificate data is invalid or could not be parsed.
    #[error("invalid certificate: {0}")]
    InvalidCertificate(String),

    /// PEM encoding failed.
    #[error("PEM encoding error: {0}")]
    PemEncode(String),

    /// PEM decoding failed.
    #[error("PEM decoding error: {0}")]
    PemDecode(String),
}

// ---------------------------------------------------------------------------
// Certificate-specific errors
// ---------------------------------------------------------------------------

/// Errors specific to certificate validation and status.
#[derive(Debug, Error)]
pub enum CertError {
    /// The certificate has expired.
    #[error("certificate has expired: {0}")]
    Expired(String),

    /// The certificate is not yet valid (its `notBefore` date is in the future).
    #[error("certificate is not yet valid: {0}")]
    NotYetValid(String),

    /// The certificate has been revoked.
    #[error("certificate was revoked: {0}")]
    Revoked(String),

    /// An OCSP status check failed.
    #[error("OCSP check failed: {0}")]
    OcspFailed(String),

    /// Domain name validation failed.
    #[error("invalid domain name: {0}")]
    InvalidDomain(String),
}

// ---------------------------------------------------------------------------
// Top-level error
// ---------------------------------------------------------------------------

/// The top-level error type for the certon library.
///
/// This enum wraps every category-specific error and adds a few
/// general-purpose variants (`Config`, `Timeout`, `Other`).
#[derive(Debug, Error)]
pub enum Error {
    /// An ACME protocol error.
    #[error(transparent)]
    Acme(#[from] AcmeError),

    /// A storage error.
    #[error(transparent)]
    Storage(#[from] StorageError),

    /// A cryptographic error.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// A certificate validation error.
    #[error(transparent)]
    Cert(#[from] CertError),

    /// A configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// An operation timed out.
    #[error("operation timed out: {0}")]
    Timeout(String),

    /// Catch-all for errors that do not fit another variant.
    #[error("{0}")]
    Other(String),

    /// An error that should not be retried, wrapping the original error
    /// message. Used to explicitly signal that retrying would be futile.
    #[error("no retry: {0}")]
    NoRetry(String),
}

// ---------------------------------------------------------------------------
// Convenience conversions
// ---------------------------------------------------------------------------

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Storage(StorageError::Io(err))
    }
}
