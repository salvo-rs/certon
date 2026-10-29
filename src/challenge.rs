//! Shared distributed challenge wire format. Keys are case-safe even on Windows.
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result, StorageError};
use crate::storage::{Storage, safe_key};

pub(crate) fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 512
        && token
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

pub(crate) fn validate_auth(token: &str, auth: &str) -> Result<()> {
    if valid_token(token)
        && auth
            .strip_prefix(token)
            .and_then(|s| s.strip_prefix('.'))
            .is_some_and(valid_token)
    {
        Ok(())
    } else {
        Err(Error::Config(
            "invalid challenge token or key authorization".into(),
        ))
    }
}

pub(crate) fn domain(domain: &str) -> Result<String> {
    if domain.len() > 1024
        || domain.is_empty()
        || domain
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(Error::Config("invalid challenge domain".into()));
    }
    if let Ok(ip) = domain.parse::<std::net::IpAddr>() {
        return Ok(ip.to_string());
    }
    let (wildcard, domain) = domain
        .strip_prefix("*.")
        .map_or(("", domain), |d| ("*.", d));
    let ascii = idna::domain_to_ascii_strict(domain.strip_suffix('.').unwrap_or(domain))
        .map_err(|_| Error::Config("invalid challenge domain".into()))?
        .to_ascii_lowercase();
    if ascii.len() > 253
        || ascii.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(Error::Config("invalid challenge domain".into()));
    }
    Ok(format!("{wildcard}{ascii}"))
}

/// RFC 8738 section 6: IP validation uses a reverse-map DNS SNI while the
/// challenge certificate and stored identifier continue to contain the IP.
pub(crate) fn tls_alpn_server_name(identifier: &str) -> String {
    match identifier.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => {
            let [a, b, c, d] = address.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        Ok(std::net::IpAddr::V6(address)) => {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut name = String::with_capacity(72);
            for byte in address.octets().iter().rev() {
                name.push(HEX[(byte & 15) as usize] as char);
                name.push('.');
                name.push(HEX[(byte >> 4) as usize] as char);
                name.push('.');
            }
            name.push_str("ip6.arpa");
            name
        }
        Err(_) => identifier.to_owned(),
    }
}

pub(crate) fn host(host: &str) -> Result<String> {
    if host.len() > 1024 || host.contains('*') {
        return Err(Error::Config("invalid Host".into()));
    }
    let (name, port) = if let Some(rest) = host.strip_prefix('[') {
        let (ip, tail) = rest
            .split_once(']')
            .ok_or_else(|| Error::Config("invalid Host".into()))?;
        ip.parse::<std::net::Ipv6Addr>()
            .map_err(|_| Error::Config("invalid Host".into()))?;
        (
            ip,
            if tail.is_empty() {
                None
            } else {
                Some(
                    tail.strip_prefix(':')
                        .ok_or_else(|| Error::Config("invalid Host".into()))?,
                )
            },
        )
    } else if let Some((name, port)) = host.split_once(':') {
        (name, Some(port))
    } else {
        (host, None)
    };
    if port.is_some_and(|p| {
        p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || p.parse::<u16>().is_err()
    }) {
        return Err(Error::Config("invalid Host port".into()));
    }
    domain(name)
}

fn base(prefix: &str) -> String {
    if prefix.is_empty() {
        "challenge_tokens".into()
    } else {
        format!("{prefix}/challenge_tokens")
    }
}

fn hash(value: &str) -> String {
    Sha256::digest(value)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Lock backends may flatten a lock name into one filesystem component.
/// Hash the entire identity, including its issuer prefix, to keep it bounded.
pub(crate) fn lock_key(storage_key: &str) -> String {
    format!("challenge-{}", hash(storage_key))
}

pub(crate) fn key(prefix: &str, domain: &str, token: &str) -> String {
    format!("{}/v2/{}/{}.json", base(prefix), hash(domain), hash(token))
}

pub(crate) fn legacy_compatible(domain: &str) -> bool {
    // Canonical domains are ASCII. The old "<domain>.json" basename must
    // also fit the portable 255-byte filesystem component limit.
    domain.len() <= 250 && safe_key(domain) == domain
}

pub(crate) fn legacy_key(prefix: &str, domain: &str) -> String {
    format!("{}/{}.json", base(prefix), safe_key(domain))
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Entry {
    version: u8,
    domain: String,
    token: String,
    key_auth: String,
}

pub(crate) fn encode(domain: &str, token: &str, key_auth: &str) -> Result<Vec<u8>> {
    validate_auth(token, key_auth)?;
    serde_json::to_vec(&Entry {
        version: 2,
        domain: domain.into(),
        token: token.into(),
        key_auth: key_auth.into(),
    })
    .map_err(|e| StorageError::Serialize(e.to_string()).into())
}

pub(crate) fn legacy_map(data: &[u8]) -> Result<HashMap<String, String>> {
    if data.len() > 65536 {
        return Err(StorageError::Deserialize("legacy challenge map too large".into()).into());
    }
    serde_json::from_slice(data).map_err(|e| StorageError::Deserialize(e.to_string()).into())
}

pub(crate) async fn load(
    storage: &dyn Storage,
    prefix: &str,
    domain: &str,
    token: &str,
) -> Result<Option<String>> {
    match storage.load(&key(prefix, domain, token)).await {
        Ok(data) => {
            if data.len() > 4096 {
                return Err(StorageError::Deserialize("challenge entry too large".into()).into());
            }
            let entry: Entry = serde_json::from_slice(&data)
                .map_err(|e| StorageError::Deserialize(e.to_string()))?;
            if entry.version != 2 || entry.domain != domain || entry.token != token {
                return Err(StorageError::Deserialize("challenge identity mismatch".into()).into());
            }
            validate_auth(token, &entry.key_auth)?;
            Ok(Some(entry.key_auth))
        }
        Err(Error::Storage(StorageError::NotFound(_))) => {
            // Skip ambiguous aliases and legacy filenames beyond the portable
            // component limit; neither case may be used by v2 cleanup either.
            if !legacy_compatible(domain) {
                return Ok(None);
            }
            match storage.load(&legacy_key(prefix, domain)).await {
                Ok(data) => {
                    let auth = legacy_map(&data)?.remove(token);
                    if let Some(auth) = &auth {
                        validate_auth(token, auth)?;
                    }
                    Ok(auth)
                }
                Err(Error::Storage(StorageError::NotFound(_))) => Ok(None),
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}
