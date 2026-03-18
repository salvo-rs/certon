//! Cryptographic utilities for ACME certificate management.
//!
//! This module provides key generation, PEM encoding/decoding, key hashing,
//! and CSR (Certificate Signing Request) generation.
//!
//! # Supported key types
//!
//! | Variant | Algorithm | Notes |
//! |---|---|---|
//! | [`KeyType::EcdsaP256`] | ECDSA P-256 | Default; smallest key, fastest |
//! | [`KeyType::EcdsaP384`] | ECDSA P-384 | Larger curve, stronger security margin |
//! | [`KeyType::Rsa2048`] | RSA 2048-bit | Broad compatibility |
//! | [`KeyType::Rsa4096`] | RSA 4096-bit | Strong RSA |
//! | [`KeyType::Rsa8192`] | RSA 8192-bit | Maximum RSA strength |
//! | [`KeyType::Ed25519`] | Ed25519 | Modern EdDSA; compact, fast |
//!
//! # Key lifecycle
//!
//! 1. **Generate** a key with [`generate_private_key`].
//! 2. **Encode** to PEM for storage via [`encode_private_key_pem`].
//! 3. **Decode** back with [`decode_private_key_pem`].
//! 4. **Hash** for identification with [`hash_key`].
//! 5. **Create a CSR** with [`generate_csr`] for ACME order finalization.

use std::fmt;
use std::net::IpAddr;

use rcgen::{
    CertificateParams, CustomExtension, KeyPair as RcgenKeyPair, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384, PKCS_ED25519, PKCS_RSA_SHA256,
};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{CryptoError, Result};

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------

/// Enumerates the supported asymmetric key algorithms.
///
/// The default is [`KeyType::EcdsaP256`] (P-256 ECDSA).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    /// ECDSA using the NIST P-256 curve (a.k.a. `secp256r1` / `prime256v1`).
    EcdsaP256,
    /// ECDSA using the NIST P-384 curve (a.k.a. `secp384r1`).
    EcdsaP384,
    /// ECDSA using the NIST P-521 curve (a.k.a. `secp521r1`).
    EcdsaP521,
    /// RSA with a 2048-bit modulus.
    Rsa2048,
    /// RSA with a 4096-bit modulus.
    Rsa4096,
    /// RSA with an 8192-bit modulus.
    Rsa8192,
    /// Ed25519 (Edwards-curve Digital Signature Algorithm).
    Ed25519,
}

impl Default for KeyType {
    fn default() -> Self {
        Self::EcdsaP256
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EcdsaP256 => write!(f, "p256"),
            Self::EcdsaP384 => write!(f, "p384"),
            Self::EcdsaP521 => write!(f, "p521"),
            Self::Rsa2048 => write!(f, "rsa2048"),
            Self::Rsa4096 => write!(f, "rsa4096"),
            Self::Rsa8192 => write!(f, "rsa8192"),
            Self::Ed25519 => write!(f, "ed25519"),
        }
    }
}

// ---------------------------------------------------------------------------
// PrivateKey
// ---------------------------------------------------------------------------

/// A private key together with its algorithm metadata.
///
/// The key material is stored as a PKCS#8 DER-encoded byte vector so that
/// every key type has a single canonical representation.
#[derive(Clone, Serialize, Deserialize)]
pub struct PrivateKey {
    /// The algorithm that generated this key.
    key_type: KeyType,
    /// PKCS#8 v1/v2 DER-encoded private key bytes.
    #[serde(with = "base64_serde")]
    pkcs8_der: Vec<u8>,
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("key_type", &self.key_type)
            .field("pkcs8_der_len", &self.pkcs8_der.len())
            .finish()
    }
}

impl PrivateKey {
    /// Returns the algorithm that was used to generate this key.
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Returns the raw PKCS#8 DER bytes of the private key.
    pub fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8_der
    }

    /// Constructs a [`PrivateKey`] from raw PKCS#8 DER bytes and a
    /// [`KeyType`].
    ///
    /// No validation is performed on the bytes; prefer
    /// [`generate_private_key`] or [`decode_private_key_pem`] for safe
    /// construction.
    pub fn from_pkcs8_der(key_type: KeyType, der: Vec<u8>) -> Self {
        Self {
            key_type,
            pkcs8_der: der,
        }
    }

    /// Converts this key into an [`rcgen::KeyPair`] suitable for CSR
    /// generation and certificate signing.
    fn to_rcgen_key_pair(&self) -> Result<RcgenKeyPair> {
        let pkcs8 = PrivatePkcs8KeyDer::from(self.pkcs8_der.clone());

        match self.key_type {
            KeyType::EcdsaP256 => {
                RcgenKeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ECDSA_P256_SHA256)
            }
            KeyType::EcdsaP384 => {
                RcgenKeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ECDSA_P384_SHA384)
            }
            KeyType::EcdsaP521 => {
                // rcgen's P-521 constants require the aws_lc_rs feature.
                // Use from_pkcs8_pem or from_pkcs8_der which auto-detects the algo.
                RcgenKeyPair::try_from(&pkcs8)
            }
            KeyType::Ed25519 => RcgenKeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519),
            KeyType::Rsa2048 | KeyType::Rsa4096 | KeyType::Rsa8192 => {
                RcgenKeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_RSA_SHA256)
            }
        }
        .map_err(|e| CryptoError::InvalidKey(format!("failed to build rcgen key pair: {e}")).into())
    }
}

// ---------------------------------------------------------------------------
// Base64 serde helper (for serializing key bytes to JSON)
// ---------------------------------------------------------------------------

mod base64_serde {
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        bytes: &Vec<u8>,
        ser: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        ser.serialize_str(&BASE64_STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> std::result::Result<Vec<u8>, D::Error> {
        let s = String::deserialize(de)?;
        BASE64_STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generates a new random private key of the specified [`KeyType`].
///
/// The returned [`PrivateKey`] holds PKCS#8 DER-encoded key material.
///
/// # Errors
///
/// Returns [`CryptoError::KeyGeneration`] if the underlying RNG or key
/// derivation fails.
pub fn generate_private_key(key_type: KeyType) -> Result<PrivateKey> {
    let rng = SystemRandom::new();

    let pkcs8_der = match key_type {
        KeyType::EcdsaP256 => {
            let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                .map_err(|e| CryptoError::KeyGeneration(format!("ECDSA P-256: {e}")))?;
            doc.as_ref().to_vec()
        }
        KeyType::EcdsaP384 => {
            let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng)
                .map_err(|e| CryptoError::KeyGeneration(format!("ECDSA P-384: {e}")))?;
            doc.as_ref().to_vec()
        }
        KeyType::EcdsaP521 => generate_p521_pkcs8()?,
        KeyType::Ed25519 => {
            let doc = Ed25519KeyPair::generate_pkcs8(&rng)
                .map_err(|e| CryptoError::KeyGeneration(format!("Ed25519: {e}")))?;
            doc.as_ref().to_vec()
        }
        KeyType::Rsa2048 => generate_rsa_pkcs8(2048)?,
        KeyType::Rsa4096 => generate_rsa_pkcs8(4096)?,
        KeyType::Rsa8192 => generate_rsa_pkcs8(8192)?,
    };

    Ok(PrivateKey {
        key_type,
        pkcs8_der,
    })
}

/// Helper: generate an RSA private key as PKCS#8 DER.
///
/// `ring` does not expose RSA key generation, so we delegate to the
/// `rsa` crate and then serialise via `pkcs8`.
fn generate_rsa_pkcs8(bits: usize) -> Result<Vec<u8>> {
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::EncodePrivateKey;

    let mut rng = rsa::rand_core::OsRng;
    let key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| CryptoError::KeyGeneration(format!("RSA-{bits}: {e}")))?;
    let doc = key
        .to_pkcs8_der()
        .map_err(|e| CryptoError::KeyGeneration(format!("RSA-{bits} PKCS#8 encode: {e}")))?;
    Ok(doc.as_bytes().to_vec())
}

/// Helper: generate an ECDSA P-521 private key as PKCS#8 DER.
///
/// `ring` does not support P-521, so we use the `p521` crate from
/// RustCrypto and encode via the `elliptic-curve` PKCS#8 support.
fn generate_p521_pkcs8() -> Result<Vec<u8>> {
    use elliptic_curve::pkcs8::EncodePrivateKey;
    use p521::ecdsa::SigningKey;

    let signing_key = SigningKey::random(&mut elliptic_curve::rand_core::OsRng);
    let secret_key = signing_key.as_nonzero_scalar();
    let sk = p521::SecretKey::from(secret_key);
    let doc = sk
        .to_pkcs8_der()
        .map_err(|e| CryptoError::KeyGeneration(format!("ECDSA P-521 PKCS#8 encode: {e}")))?;
    Ok(doc.as_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// PEM encoding
// ---------------------------------------------------------------------------

/// PEM block tag used for each key type when encoding.
fn pem_tag_for(key_type: KeyType) -> &'static str {
    match key_type {
        KeyType::EcdsaP256 | KeyType::EcdsaP384 | KeyType::EcdsaP521 => "EC PRIVATE KEY",
        KeyType::Rsa2048 | KeyType::Rsa4096 | KeyType::Rsa8192 => "RSA PRIVATE KEY",
        KeyType::Ed25519 => "PRIVATE KEY",
    }
}

/// Encodes a [`PrivateKey`] into PEM format.
///
/// ECDSA keys use the `EC PRIVATE KEY` tag, RSA keys use
/// `RSA PRIVATE KEY`, and Ed25519 keys use the generic `PRIVATE KEY` tag
/// (PKCS#8).
///
/// # Errors
///
/// Returns [`CryptoError::PemEncode`] if encoding fails -- in practice this
/// should not happen for well-formed key material.
pub fn encode_private_key_pem(key: &PrivateKey) -> Result<String> {
    // For ECDSA keys we encode using the SEC 1 / EC-specific DER
    // format (tag "EC PRIVATE KEY"). For RSA, it uses PKCS#1 (tag "RSA
    // PRIVATE KEY"). For Ed25519 (and as a general fallback), PKCS#8
    // (tag "PRIVATE KEY") is used.
    //
    // We store everything internally as PKCS#8 DER, so for EC and RSA we
    // extract the inner type-specific DER where possible.

    let tag = pem_tag_for(key.key_type);
    let der_bytes = match key.key_type {
        KeyType::EcdsaP256 | KeyType::EcdsaP384 | KeyType::EcdsaP521 => {
            // Attempt to extract the SEC 1 EC private key from PKCS#8.
            extract_ec_private_key_from_pkcs8(&key.pkcs8_der)
                .unwrap_or_else(|| key.pkcs8_der.clone())
        }
        KeyType::Rsa2048 | KeyType::Rsa4096 | KeyType::Rsa8192 => {
            // Attempt to extract the PKCS#1 RSA key from PKCS#8.
            extract_rsa_private_key_from_pkcs8(&key.pkcs8_der)
                .unwrap_or_else(|| key.pkcs8_der.clone())
        }
        KeyType::Ed25519 => {
            // Ed25519 stays as PKCS#8.
            key.pkcs8_der.clone()
        }
    };

    let pem_obj = ::pem::Pem::new(tag, der_bytes);
    Ok(::pem::encode(&pem_obj))
}

/// Extracts the inner SEC 1 `ECPrivateKey` from a PKCS#8 wrapper.
///
/// PKCS#8 structure (simplified):
/// ```text
/// SEQUENCE {
///   INTEGER 0                       -- version
///   SEQUENCE { OID, OID }           -- algorithm identifier
///   OCTET STRING { ECPrivateKey }   -- the actual SEC 1 key
/// }
/// ```
fn extract_ec_private_key_from_pkcs8(pkcs8: &[u8]) -> Option<Vec<u8>> {
    // A minimal ASN.1 DER parser: walk into the outer SEQUENCE, skip the
    // version INTEGER and the algorithm SEQUENCE, then unwrap the OCTET
    // STRING payload.
    let (_, parsed) = x509_parser::der_parser::parse_der(pkcs8).ok()?;
    let seq = parsed.as_sequence().ok()?;
    if seq.len() < 3 {
        return None;
    }
    // seq[2] is the OCTET STRING wrapping the SEC 1 key.
    let octet = seq[2].as_slice().ok()?;
    Some(octet.to_vec())
}

/// Extracts the inner PKCS#1 `RSAPrivateKey` from a PKCS#8 wrapper.
fn extract_rsa_private_key_from_pkcs8(pkcs8: &[u8]) -> Option<Vec<u8>> {
    let (_, parsed) = x509_parser::der_parser::parse_der(pkcs8).ok()?;
    let seq = parsed.as_sequence().ok()?;
    if seq.len() < 3 {
        return None;
    }
    let octet = seq[2].as_slice().ok()?;
    Some(octet.to_vec())
}

// ---------------------------------------------------------------------------
// PEM decoding
// ---------------------------------------------------------------------------

/// Decodes a PEM-encoded private key string into a [`PrivateKey`].
///
/// The function recognises the following PEM tags:
///
/// - `EC PRIVATE KEY` -- interpreted as SEC 1 ECDSA (P-256 or P-384, detected from the curve OID).
/// - `RSA PRIVATE KEY` -- PKCS#1 RSA key (size detected from modulus length).
/// - `PRIVATE KEY` -- PKCS#8 (algorithm auto-detected).
/// - Any tag ending with `PRIVATE KEY` is also accepted.
///
/// # Errors
///
/// Returns [`CryptoError::PemDecode`] if the PEM data is malformed or the
/// key type cannot be determined.
pub fn decode_private_key_pem(pem_data: &str) -> Result<PrivateKey> {
    let parsed = ::pem::parse(pem_data)
        .map_err(|e| CryptoError::PemDecode(format!("failed to parse PEM: {e}")))?;

    let tag = parsed.tag().to_owned();
    let der = parsed.into_contents();

    if !tag.ends_with("PRIVATE KEY") {
        return Err(CryptoError::PemDecode(format!("unknown PEM header: {tag}")).into());
    }

    match tag.as_str() {
        "EC PRIVATE KEY" => decode_ec_private_key(&der),
        "RSA PRIVATE KEY" => decode_rsa_private_key(&der),
        "PRIVATE KEY" | "ED25519 PRIVATE KEY" => decode_pkcs8_private_key(&der),
        _ => {
            // Try PKCS#8 as a fallback for any "*PRIVATE KEY" tag.
            decode_pkcs8_private_key(&der)
        }
    }
}

/// Decode a SEC 1 encoded EC private key, wrap it into PKCS#8, and detect the
/// curve.
fn decode_ec_private_key(sec1_der: &[u8]) -> Result<PrivateKey> {
    // Detect curve from SEC 1 structure.
    // The SEC 1 ECPrivateKey may contain an optional `parameters` field
    // (context tag [0]) that holds the curve OID. If absent, we try both
    // P-256 and P-384 by attempting to load into ring.
    let key_type = detect_ec_curve_from_sec1(sec1_der);

    // Wrap SEC 1 DER into PKCS#8 for internal storage.
    let pkcs8_der = wrap_ec_sec1_in_pkcs8(sec1_der, key_type)?;

    // Validate by attempting to parse with ring.
    validate_ec_key(&pkcs8_der, key_type)?;

    Ok(PrivateKey {
        key_type,
        pkcs8_der,
    })
}

/// Detect the EC curve from SEC 1 DER bytes by examining key length and
/// optional parameters.
fn detect_ec_curve_from_sec1(sec1_der: &[u8]) -> KeyType {
    // Try parsing the SEC 1 structure to look for the parameters OID.
    if let Ok((_, parsed)) = x509_parser::der_parser::parse_der(sec1_der) {
        if let Ok(seq) = parsed.as_sequence() {
            // seq[0] = version, seq[1] = private key octet string,
            // seq[2..] = optional parameters/public key
            if seq.len() > 1 {
                if let Ok(privkey_bytes) = seq[1].as_slice() {
                    // P-256 private keys are 32 bytes, P-384 are 48, P-521 are 66.
                    return match privkey_bytes.len() {
                        32 => KeyType::EcdsaP256,
                        48 => KeyType::EcdsaP384,
                        66 => KeyType::EcdsaP521,
                        _ => KeyType::EcdsaP256, // default guess
                    };
                }
            }
        }
    }
    KeyType::EcdsaP256
}

/// OID for EC public key: 1.2.840.10045.2.1
const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

/// OID for P-256: 1.2.840.10045.3.1.7
const OID_P256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// OID for P-384: 1.3.132.0.34
const OID_P384: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];

/// OID for P-521: 1.3.132.0.35
const OID_P521: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23];

/// Wraps a SEC 1 EC private key in a PKCS#8 envelope.
fn wrap_ec_sec1_in_pkcs8(sec1_der: &[u8], key_type: KeyType) -> Result<Vec<u8>> {
    let curve_oid = match key_type {
        KeyType::EcdsaP256 => OID_P256,
        KeyType::EcdsaP384 => OID_P384,
        KeyType::EcdsaP521 => OID_P521,
        _ => {
            return Err(CryptoError::PemDecode("cannot wrap non-EC key as EC PKCS#8".into()).into());
        }
    };

    // Build the PKCS#8 structure manually:
    // SEQUENCE {
    //   INTEGER 0
    //   SEQUENCE { OID ecPublicKey, OID curve }
    //   OCTET STRING { sec1_der }
    // }
    let mut algo_seq_content = Vec::new();
    algo_seq_content.extend_from_slice(OID_EC_PUBLIC_KEY);
    algo_seq_content.extend_from_slice(curve_oid);
    let algo_seq = der_wrap(0x30, &algo_seq_content);

    let version = der_wrap(0x02, &[0x00]); // INTEGER 0
    let octet_string = der_wrap(0x04, sec1_der);

    let mut outer_content = Vec::new();
    outer_content.extend_from_slice(&version);
    outer_content.extend_from_slice(&algo_seq);
    outer_content.extend_from_slice(&octet_string);
    let pkcs8 = der_wrap(0x30, &outer_content);

    Ok(pkcs8)
}

/// Minimal DER TLV wrapper.
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

/// Validate that `pkcs8_der` can actually be loaded as an EC key of the
/// given curve.
fn validate_ec_key(pkcs8_der: &[u8], key_type: KeyType) -> Result<()> {
    let rng = SystemRandom::new();
    match key_type {
        KeyType::EcdsaP256 => {
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_der, &rng)
                .map_err(|e| CryptoError::InvalidKey(format!("P-256 validation failed: {e}")))?;
        }
        KeyType::EcdsaP384 => {
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8_der, &rng)
                .map_err(|e| CryptoError::InvalidKey(format!("P-384 validation failed: {e}")))?;
        }
        KeyType::EcdsaP521 => {
            // ring does not support P-521; validate using the p521 crate.
            use elliptic_curve::pkcs8::DecodePrivateKey;
            p521::SecretKey::from_pkcs8_der(pkcs8_der)
                .map_err(|e| CryptoError::InvalidKey(format!("P-521 validation failed: {e}")))?;
        }
        _ => {}
    }
    Ok(())
}

/// Decode a PKCS#1 RSA private key and convert to PKCS#8 for internal storage.
fn decode_rsa_private_key(pkcs1_der: &[u8]) -> Result<PrivateKey> {
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::traits::PublicKeyParts;

    let rsa_key = RsaPrivateKey::from_pkcs1_der(pkcs1_der)
        .map_err(|e| CryptoError::PemDecode(format!("invalid PKCS#1 RSA key: {e}")))?;

    let bits = rsa_key.n().bits();
    let key_type = if bits <= 2048 {
        KeyType::Rsa2048
    } else if bits <= 4096 {
        KeyType::Rsa4096
    } else {
        KeyType::Rsa8192
    };

    let pkcs8_doc = rsa_key
        .to_pkcs8_der()
        .map_err(|e| CryptoError::PemDecode(format!("RSA to PKCS#8 conversion: {e}")))?;

    Ok(PrivateKey {
        key_type,
        pkcs8_der: pkcs8_doc.as_bytes().to_vec(),
    })
}

/// Decode a PKCS#8 private key, auto-detecting the algorithm.
fn decode_pkcs8_private_key(pkcs8_der: &[u8]) -> Result<PrivateKey> {
    let rng = SystemRandom::new();

    // Try ECDSA P-256.
    if EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_der, &rng).is_ok() {
        return Ok(PrivateKey {
            key_type: KeyType::EcdsaP256,
            pkcs8_der: pkcs8_der.to_vec(),
        });
    }

    // Try ECDSA P-384.
    if EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8_der, &rng).is_ok() {
        return Ok(PrivateKey {
            key_type: KeyType::EcdsaP384,
            pkcs8_der: pkcs8_der.to_vec(),
        });
    }

    // Try ECDSA P-521 (not supported by ring, use p521 crate).
    {
        use elliptic_curve::pkcs8::DecodePrivateKey;
        if p521::SecretKey::from_pkcs8_der(pkcs8_der).is_ok() {
            return Ok(PrivateKey {
                key_type: KeyType::EcdsaP521,
                pkcs8_der: pkcs8_der.to_vec(),
            });
        }
    }

    // Try Ed25519.
    if Ed25519KeyPair::from_pkcs8(pkcs8_der).is_ok() {
        return Ok(PrivateKey {
            key_type: KeyType::Ed25519,
            pkcs8_der: pkcs8_der.to_vec(),
        });
    }

    // Try RSA.
    {
        use rsa::RsaPrivateKey;
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::traits::PublicKeyParts;

        if let Ok(rsa_key) = RsaPrivateKey::from_pkcs8_der(pkcs8_der) {
            let bits = rsa_key.n().bits();
            let key_type = if bits <= 2048 {
                KeyType::Rsa2048
            } else if bits <= 4096 {
                KeyType::Rsa4096
            } else {
                KeyType::Rsa8192
            };
            return Ok(PrivateKey {
                key_type,
                pkcs8_der: pkcs8_der.to_vec(),
            });
        }
    }

    Err(CryptoError::PemDecode("unknown or unsupported private key type in PKCS#8".into()).into())
}

// ---------------------------------------------------------------------------
// Certificate PEM helpers
// ---------------------------------------------------------------------------

/// Encodes a single DER-encoded certificate into PEM format.
///
/// The output uses the standard `CERTIFICATE` PEM tag and can be
/// concatenated with other PEM blocks to form a certificate chain bundle.
pub fn encode_certificate_pem(der: &[u8]) -> String {
    let pem_obj = ::pem::Pem::new("CERTIFICATE", der.to_vec());
    ::pem::encode(&pem_obj)
}

/// Parses all certificates from a PEM bundle (which may contain multiple
/// `CERTIFICATE` blocks).
///
/// # Errors
///
/// Returns [`CryptoError::InvalidCertificate`] if no certificates are found
/// or if any certificate fails to parse.
pub fn parse_certs_from_pem_bundle(pem_data: &str) -> Result<Vec<Vec<u8>>> {
    let pems: Vec<::pem::Pem> = ::pem::parse_many(pem_data)
        .map_err(|e| CryptoError::InvalidCertificate(format!("failed to parse PEM bundle: {e}")))?;

    let certs: Vec<Vec<u8>> = pems
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| p.into_contents())
        .collect();

    if certs.is_empty() {
        return Err(
            CryptoError::InvalidCertificate("no certificates found in bundle".into()).into(),
        );
    }

    Ok(certs)
}

// ---------------------------------------------------------------------------
// Key hashing
// ---------------------------------------------------------------------------

/// Computes a SHA-256 hash of the private key's PKCS#8 DER encoding and
/// returns it as a lowercase hexadecimal string.
///
/// This can be used as a stable, unique identifier for a key (e.g. for
/// storage or cache lookups).
pub fn hash_key(key: &PrivateKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&key.pkcs8_der);
    let digest = hasher.finalize();
    hex_encode(&digest)
}

/// Lowercase hex encoding of a byte slice.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// Fast hashing (FNV-32a)
// ---------------------------------------------------------------------------

/// Computes a fast, non-cryptographic FNV-1a 32-bit hash of `data`.
///
/// This is useful for quick fingerprinting, hash-table distribution, or
/// cache-key generation where cryptographic security is not required.
/// The algorithm is the standard Fowler-Noll-Vo 1a variant.
pub fn fast_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 2166136261; // FNV offset basis
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(16777619); // FNV prime
    }
    hash
}

// ---------------------------------------------------------------------------
// CSR generation
// ---------------------------------------------------------------------------

/// Generates a DER-encoded PKCS#10 Certificate Signing Request for the
/// given domains (SANs).
///
/// The first domain in the list is also set as the Common Name (CN) for
/// backwards compatibility with CAs that still require it.
///
/// IP addresses in the domain list are detected and added as IP SANs rather
/// than DNS SANs.
///
/// When `must_staple` is `true`, the OCSP Must-Staple TLS feature extension
/// (OID 1.3.6.1.5.5.7.1.24) is added to the CSR. This signals to the CA
/// that the certificate should include the Must-Staple indicator, requiring
/// servers to provide a valid OCSP staple in the TLS handshake.
///
/// # Errors
///
/// Returns [`CryptoError::Signing`] if CSR generation or signing fails.
pub fn generate_csr(key: &PrivateKey, domains: &[String], must_staple: bool) -> Result<Vec<u8>> {
    if domains.is_empty() {
        return Err(
            CryptoError::Signing("at least one domain is required for a CSR".into()).into(),
        );
    }

    let key_pair = key.to_rcgen_key_pair()?;

    let mut params = CertificateParams::default();

    // Set the Common Name to the first domain.
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, domains[0].clone());

    // Partition domains into DNS names, IP addresses, email addresses, and URIs.
    for domain in domains {
        if let Ok(ip) = domain.parse::<IpAddr>() {
            params.subject_alt_names.push(rcgen::SanType::IpAddress(ip));
        } else if let Some(email) = domain.strip_prefix("mailto:") {
            params.subject_alt_names.push(rcgen::SanType::Rfc822Name(
                email.to_string().try_into().map_err(|e: rcgen::Error| {
                    CryptoError::Signing(format!("invalid email SAN '{email}': {e}"))
                })?,
            ));
        } else if domain.starts_with("http:") || domain.starts_with("https:") {
            params
                .subject_alt_names
                .push(rcgen::SanType::URI(domain.clone().try_into().map_err(
                    |e: rcgen::Error| {
                        CryptoError::Signing(format!("invalid URI SAN '{domain}': {e}"))
                    },
                )?));
        } else {
            params.subject_alt_names.push(rcgen::SanType::DnsName(
                domain.clone().try_into().map_err(|e: rcgen::Error| {
                    CryptoError::Signing(format!("invalid DNS name '{domain}': {e}"))
                })?,
            ));
        }
    }

    // Add OCSP Must-Staple extension (OID 1.3.6.1.5.5.7.1.24) when requested.
    // The extension value is a DER-encoded SEQUENCE containing a single
    // INTEGER with value 5 (id-pe-tlsfeature status_request).
    if must_staple {
        let oid = vec![1, 3, 6, 1, 5, 5, 7, 1, 24];
        let value = vec![0x30, 0x03, 0x02, 0x01, 0x05];
        let ext = CustomExtension::from_oid_content(&oid, value);
        params.custom_extensions.push(ext);
    }

    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| CryptoError::Signing(format!("CSR serialization failed: {e}")))?;

    Ok(csr.der().to_vec())
}

// ---------------------------------------------------------------------------
// StandardKeyGenerator
// ---------------------------------------------------------------------------

/// A standard, in-memory key generator.
///
/// By default it generates ECDSA P-256 keys.
#[derive(Debug, Clone)]
pub struct StandardKeyGenerator {
    /// The type of keys this generator will produce.
    pub key_type: KeyType,
}

impl Default for StandardKeyGenerator {
    fn default() -> Self {
        Self {
            key_type: KeyType::EcdsaP256,
        }
    }
}

impl StandardKeyGenerator {
    /// Creates a new generator for the given key type.
    pub fn new(key_type: KeyType) -> Self {
        Self { key_type }
    }

    /// Generates a new private key using the configured key type.
    pub fn generate_key(&self) -> Result<PrivateKey> {
        generate_private_key(self.key_type)
    }
}

// ---------------------------------------------------------------------------
// IDN / domain normalization
// ---------------------------------------------------------------------------

/// Normalize a domain name to ASCII punycode (IDNA encoding).
///
/// International Domain Names (IDNs) containing non-ASCII characters are
/// converted to their ASCII-compatible encoding (ACE) form using the IDNA
/// standard.
///
/// # Errors
///
/// Returns [`CryptoError::Signing`] if the domain cannot be converted
/// (e.g. it contains invalid characters for IDNA).
pub fn normalize_domain(domain: &str) -> Result<String> {
    idna::domain_to_ascii(domain)
        .map_err(|_| CryptoError::Signing(format!("IDNA conversion failed for '{domain}'")).into())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_roundtrip_ecdsa_p256() {
        let key = generate_private_key(KeyType::EcdsaP256).unwrap();
        assert_eq!(key.key_type(), KeyType::EcdsaP256);

        let pem_str = encode_private_key_pem(&key).unwrap();
        assert!(pem_str.contains("EC PRIVATE KEY"));

        let decoded = decode_private_key_pem(&pem_str).unwrap();
        assert_eq!(decoded.key_type(), KeyType::EcdsaP256);
    }

    #[test]
    fn test_generate_and_roundtrip_ecdsa_p384() {
        let key = generate_private_key(KeyType::EcdsaP384).unwrap();
        assert_eq!(key.key_type(), KeyType::EcdsaP384);

        let pem_str = encode_private_key_pem(&key).unwrap();
        assert!(pem_str.contains("EC PRIVATE KEY"));

        let decoded = decode_private_key_pem(&pem_str).unwrap();
        assert_eq!(decoded.key_type(), KeyType::EcdsaP384);
    }

    #[test]
    fn test_generate_and_roundtrip_ed25519() {
        let key = generate_private_key(KeyType::Ed25519).unwrap();
        assert_eq!(key.key_type(), KeyType::Ed25519);

        let pem_str = encode_private_key_pem(&key).unwrap();
        assert!(pem_str.contains("PRIVATE KEY"));

        let decoded = decode_private_key_pem(&pem_str).unwrap();
        assert_eq!(decoded.key_type(), KeyType::Ed25519);
    }

    #[test]
    fn test_generate_and_roundtrip_rsa2048() {
        let key = generate_private_key(KeyType::Rsa2048).unwrap();
        assert_eq!(key.key_type(), KeyType::Rsa2048);

        let pem_str = encode_private_key_pem(&key).unwrap();
        assert!(pem_str.contains("RSA PRIVATE KEY"));

        let decoded = decode_private_key_pem(&pem_str).unwrap();
        assert_eq!(decoded.key_type(), KeyType::Rsa2048);
    }

    #[test]
    fn test_hash_key_deterministic() {
        let key = generate_private_key(KeyType::EcdsaP256).unwrap();
        let h1 = hash_key(&key);
        let h2 = hash_key(&key);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn test_encode_certificate_pem() {
        let fake_der = b"not-a-real-cert";
        let pem_str = encode_certificate_pem(fake_der);
        assert!(pem_str.contains("CERTIFICATE"));
    }

    #[test]
    fn test_csr_generation_ecdsa_p256() {
        let key = generate_private_key(KeyType::EcdsaP256).unwrap();
        let domains = vec!["example.com".to_string(), "www.example.com".to_string()];
        let csr_der = generate_csr(&key, &domains, false).unwrap();
        assert!(!csr_der.is_empty());
    }

    #[test]
    fn test_csr_generation_with_ip() {
        let key = generate_private_key(KeyType::EcdsaP256).unwrap();
        let domains = vec!["example.com".to_string(), "192.168.1.1".to_string()];
        let csr_der = generate_csr(&key, &domains, false).unwrap();
        assert!(!csr_der.is_empty());
    }

    #[test]
    fn test_csr_empty_domains_fails() {
        let key = generate_private_key(KeyType::EcdsaP256).unwrap();
        let result = generate_csr(&key, &[], false);
        assert!(result.is_err());
    }

    #[test]
    fn test_csr_with_must_staple() {
        let key = generate_private_key(KeyType::EcdsaP256).unwrap();
        let domains = vec!["example.com".to_string()];
        let csr_der = generate_csr(&key, &domains, true).unwrap();
        assert!(!csr_der.is_empty());
    }

    #[test]
    fn test_standard_key_generator_default() {
        let keygen = StandardKeyGenerator::default();
        assert_eq!(keygen.key_type, KeyType::EcdsaP256);
        let key = keygen.generate_key().unwrap();
        assert_eq!(key.key_type(), KeyType::EcdsaP256);
    }

    #[test]
    fn test_key_type_display() {
        assert_eq!(KeyType::EcdsaP256.to_string(), "p256");
        assert_eq!(KeyType::EcdsaP384.to_string(), "p384");
        assert_eq!(KeyType::EcdsaP521.to_string(), "p521");
        assert_eq!(KeyType::Rsa2048.to_string(), "rsa2048");
        assert_eq!(KeyType::Rsa4096.to_string(), "rsa4096");
        assert_eq!(KeyType::Rsa8192.to_string(), "rsa8192");
        assert_eq!(KeyType::Ed25519.to_string(), "ed25519");
    }

    #[test]
    fn test_key_type_default() {
        assert_eq!(KeyType::default(), KeyType::EcdsaP256);
    }

    #[test]
    fn test_private_key_serialization() {
        let key = generate_private_key(KeyType::EcdsaP256).unwrap();
        let json = serde_json::to_string(&key).unwrap();
        let deserialized: PrivateKey = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key_type(), key.key_type());
        assert_eq!(deserialized.pkcs8_der(), key.pkcs8_der());
    }

    #[test]
    fn test_decode_invalid_pem() {
        let result = decode_private_key_pem("not valid pem data");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_certs_empty_bundle() {
        let result =
            parse_certs_from_pem_bundle("-----BEGIN SOMETHING-----\n-----END SOMETHING-----\n");
        assert!(result.is_err());
    }
}
