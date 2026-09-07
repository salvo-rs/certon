//! What certificate management should do — as data, and nothing else.
//!
//! Everything here is a value: it can be built, cloned, compared, printed,
//! stored in a struct of your own and passed around without dragging an
//! issuer, a storage backend, a cache and a job queue along with it.
//!
//! That distinction is the reason this module exists. What is now
//! [`CertManager`](crate::manager::CertManager) used to be called `CertManager`,
//! and held collaborators and a certificate lifecycle alongside these
//! settings. A type named `CertManager` that can revoke a certificate is not a
//! configuration, and the cost was not only the name: the settings could not
//! be inspected, defaulted, compared or logged without the machinery, and the
//! machinery could not be built without deciding every setting.
//!
//! Now `Policy` is the answer to "what should happen", and `CertManager` is
//! the thing that makes it happen.

use crate::certificates::{Certificate, DEFAULT_RENEWAL_WINDOW_RATIO};
use crate::crypto::KeyType;
use crate::ocsp::OcspConfig;

/// How issuers are chosen when more than one is configured.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IssuerPolicy {
    /// In the order they were given, first to last.
    #[default]
    UseFirstIssuer,
    /// Shuffled first, spreading load across certificate authorities.
    UseFirstRandomIssuer,
}

/// Choosing among several certificates that all match a handshake.
///
/// A hook rather than a setting, which is why it is not part of [`Policy`]:
/// it holds behaviour, and `Policy` holds values.
pub trait CertificateSelector: Send + Sync {
    /// Pick one of `choices` for this handshake by index, or `None` to leave
    /// the decision to the default rules.
    fn select_certificate(
        &self,
        hello: &rustls::server::ClientHello<'_>,
        choices: &[&Certificate],
    ) -> Option<usize>;
}

/// The settings that decide how certificates are obtained, renewed and served.
///
/// Every field is a value with a default. Construct it directly, or let
/// [`CertManager::builder`](crate::manager::CertManager::builder) set the
/// fields one at a time.
///
/// ```rust
/// use certon::{KeyType, Policy};
///
/// let policy = Policy {
///     // Renew once two thirds of the lifetime has gone.
///     renewal_window_ratio: 1.0 / 3.0,
///     key_type: KeyType::EcdsaP384,
///     ..Policy::default()
/// };
/// assert_eq!(policy.key_type, KeyType::EcdsaP384);
/// ```
#[derive(Debug, Clone)]
pub struct Policy {
    /// The fraction of a certificate's lifetime that must remain before it is
    /// left alone. `1.0 / 3.0` means "renew when a third of the life is left".
    pub renewal_window_ratio: f64,

    /// The kind of private key generated for a new certificate.
    pub key_type: KeyType,

    /// Ask for the OCSP Must-Staple extension on new certificates.
    ///
    /// Only turn this on if stapling is reliable: a certificate with
    /// Must-Staple and no staple is rejected by clients that honour it.
    pub must_staple: bool,

    /// Renew onto the existing private key instead of generating a new one.
    ///
    /// Needed for HPKP-style pinning, and a liability otherwise: a key that is
    /// never rotated is a key that is compromised for longer.
    pub reuse_private_keys: bool,

    /// Ignore the ACME Renewal Information extension and renew on the ratio
    /// alone, even when the certificate authority has said when to come back.
    pub disable_ari: bool,

    /// How to choose among several issuers.
    pub issuer_policy: IssuerPolicy,

    /// OCSP stapling.
    pub ocsp: OcspConfig,

    /// The name to assume when a TLS client sends no SNI.
    pub default_server_name: Option<String>,

    /// The name to fall back to when no certificate matches the SNI that was
    /// sent.
    pub fallback_server_name: Option<String>,

    /// Skip the storage health probe at start-up.
    pub disable_storage_check: bool,

    /// Whether a person is waiting for the result.
    ///
    /// This decides two things, and it is worth being explicit about both
    /// because the name only suggests one:
    ///
    /// - A failure is returned straight away rather than retried with backoff. Somebody watching a
    ///   terminal wants the error, not a wait.
    /// - Checks that may ask a question, such as agreeing to a certificate authority's terms, are
    ///   permitted.
    ///
    /// Leave it `false` in a server. A background renewal that gives up on the
    /// first network blip is worse than one that waits.
    pub interactive: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            renewal_window_ratio: DEFAULT_RENEWAL_WINDOW_RATIO,
            key_type: KeyType::default(),
            must_staple: false,
            reuse_private_keys: false,
            disable_ari: false,
            issuer_policy: IssuerPolicy::default(),
            ocsp: OcspConfig::default(),
            default_server_name: None,
            fallback_server_name: None,
            disable_storage_check: true,
            interactive: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_policy_is_a_value() {
        // The whole point. None of this was possible when these fields lived
        // on a struct that also held an issuer list, a storage backend, a
        // cache and a job queue.
        let policy = Policy::default();
        let copy = policy.clone();
        assert_eq!(copy.key_type, policy.key_type);
        assert!(format!("{policy:?}").contains("renewal_window_ratio"));
    }

    #[test]
    fn the_defaults_are_the_cautious_ones() {
        let policy = Policy::default();
        assert!(
            !policy.must_staple,
            "a missing staple must not break a site"
        );
        assert!(!policy.reuse_private_keys, "a key should get rotated");
        assert!(!policy.interactive, "a server has nobody watching it");
        assert!(!policy.disable_ari, "listen to the CA when it says when");
        assert!((policy.renewal_window_ratio - DEFAULT_RENEWAL_WINDOW_RATIO).abs() < f64::EPSILON);
    }

    #[test]
    fn one_field_can_be_changed_without_naming_the_others() {
        let policy = Policy {
            must_staple: true,
            ..Policy::default()
        };
        assert!(policy.must_staple);
        assert_eq!(policy.key_type, KeyType::default());
    }
}
