//! ACME account management.
//!
//! This module handles creating, loading, and saving ACME accounts to storage.
//!
//! Accounts are atomically stored as complete snapshots at
//! `acme/<ca_key>/users/<email>/_certon/account.v1.key`. Legacy registration JSON
//! and private-key files remain readable for upgrades.
//!
//! where `<username>` is the portion of the email address before `@`, or
//! `"default"` if no email is provided.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::crypto::{
    KeyType, decode_private_key_pem, encode_private_key_pem, generate_private_key,
};
use crate::error::{AcmeError, Result, StorageError};
use crate::storage::{Storage, account_key_prefix, legacy_account_key_prefix, safe_key};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The folder name used when no email address is provided.
const EMPTY_EMAIL: &str = "default";

/// Default filename stem for the registration JSON when no email/username can
/// be derived.
const DEFAULT_REG_FILENAME: &str = "registration";

/// Default filename stem for the private key when no email/username can be
/// derived.
const DEFAULT_KEY_FILENAME: &str = "private";

// ---------------------------------------------------------------------------
// AcmeAccount
// ---------------------------------------------------------------------------

/// Represents an ACME account, including its private key material and
/// registration metadata.
///
/// Standalone serialization omits the private key. Persistence wraps this
/// metadata together with the key in a private, versioned atomic snapshot.
///
/// Accounts are uniquely identified by their CA URL and email address.
/// A single application may have accounts on multiple CAs simultaneously
/// (e.g. Let's Encrypt production and ZeroSSL).
#[derive(Clone, Serialize, Deserialize)]
pub struct AcmeAccount {
    /// Account status as reported by the CA (e.g. `"valid"`, `"deactivated"`,
    /// `"revoked"`).
    #[serde(default)]
    pub status: String,

    /// Contact URIs associated with the account (e.g. `"mailto:user@example.com"`).
    #[serde(default)]
    pub contact: Vec<String>,

    /// The account URL at the CA (set after successful registration).
    #[serde(default)]
    pub location: String,

    /// Whether the account holder has agreed to the CA's terms of service.
    #[serde(default)]
    pub terms_of_service_agreed: bool,

    /// PEM-encoded private key for this account.
    ///
    /// Standalone registration JSON omits this field. The persistence snapshot
    /// includes it separately and is stored with private-key permissions.
    #[serde(skip)]
    pub private_key_pem: String,

    /// The key algorithm used for this account's private key.
    #[serde(default)]
    pub key_type: KeyType,
}

impl std::fmt::Debug for AcmeAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeAccount")
            .field("status", &self.status)
            .field("contact", &self.contact)
            .field("location", &self.location)
            .field("terms_of_service_agreed", &self.terms_of_service_agreed)
            .field("private_key_pem", &"[REDACTED]")
            .field("private_key_pem_len", &self.private_key_pem.len())
            .field("key_type", &self.key_type)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Email / username helpers
// ---------------------------------------------------------------------------

/// Normalise an email address for use in storage paths.
///
/// - Strips a leading `mailto:` scheme if present.
/// - Trims whitespace.
/// - Converts to lowercase.
/// - Returns [`EMPTY_EMAIL`] (`"default"`) if the result is empty.
fn normalise_email(email: &str) -> String {
    let email = email.strip_prefix("mailto:").unwrap_or(email);
    let email = email.trim().to_lowercase();
    if email.is_empty() {
        EMPTY_EMAIL.to_owned()
    } else {
        email
    }
}

/// The configured identity, distinct from its old filename spelling.
pub(crate) fn canonical_account_email(email: &str) -> Option<String> {
    let email = email
        .strip_prefix("mailto:")
        .unwrap_or(email)
        .trim()
        .to_lowercase();
    (!email.is_empty()).then_some(email)
}

fn canonical_account_ca(ca_url: &str) -> String {
    crate::storage::canonical_ca_url(ca_url).unwrap_or_else(|| ca_url.to_owned())
}

/// Extracts the username portion of an email address (the part before `@`).
///
/// If there is no `@` character the entire input is returned. If the `@` is
/// the first character, everything after it is returned.
fn email_username(email: &str) -> &str {
    match email.find('@') {
        None => email,
        Some(0) => &email[1..],
        Some(idx) => &email[..idx],
    }
}

/// Returns the primary contact from an account, stripped of any URI scheme
/// (e.g. `"mailto:"`).
///
/// If the account has no contacts, an empty string is returned.
pub fn get_primary_contact(account: &AcmeAccount) -> String {
    account
        .contact
        .first()
        .map(|c| {
            // Strip the scheme (everything up to and including the first `:`)
            match c.find(':') {
                Some(idx) => c[idx + 1..].to_owned(),
                None => c.clone(),
            }
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Storage key builders
// ---------------------------------------------------------------------------

/// Return the storage key for the account registration JSON.
///
/// Shape: `acme/<ca_key>/users/<email>/<username>.json`
fn storage_key_user_reg(issuer_key: &str, email: &str) -> String {
    let email = normalise_email(email);
    let username = email_username(&email);
    let filename = if username.is_empty() {
        DEFAULT_REG_FILENAME.to_owned()
    } else {
        safe_key(username)
    };
    format!(
        "{}/{}.json",
        account_key_prefix(issuer_key, &email),
        filename
    )
}

/// Return the storage key for the account private key PEM.
///
/// Shape: `acme/<ca_key>/users/<email>/<username>.key`
fn storage_key_user_private_key(issuer_key: &str, email: &str) -> String {
    let email = normalise_email(email);
    let username = email_username(&email);
    let filename = if username.is_empty() {
        DEFAULT_KEY_FILENAME.to_owned()
    } else {
        safe_key(username)
    };
    format!(
        "{}/{}.key",
        account_key_prefix(issuer_key, &email),
        filename
    )
}

#[derive(Serialize, Deserialize)]
struct AccountSnapshot {
    version: u32,
    #[serde(default)]
    ca_url: Option<String>,
    #[serde(default)]
    configured_email: RequiredEmail,
    registration: AcmeAccount,
    private_key_pem: String,
}

/// A missing binding is not the explicitly configured empty identity (`null`).
#[derive(Default)]
struct RequiredEmail {
    present: bool,
    value: Option<String>,
}

impl Serialize for RequiredEmail {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RequiredEmail {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Ok(Self {
            present: true,
            value: Option::<String>::deserialize(deserializer)?,
        })
    }
}

fn legacy_account_keys(issuer: &str, email: &str) -> [String; 3] {
    let email = normalise_email(email);
    let username = email_username(&email);
    let prefix = legacy_account_key_prefix(issuer, &email);
    let name = safe_key(username);
    let reg = if name.is_empty() {
        DEFAULT_REG_FILENAME
    } else {
        &name
    };
    let key = if name.is_empty() {
        DEFAULT_KEY_FILENAME
    } else {
        &name
    };
    [
        format!("{prefix}/_certon/account.v1.key"),
        format!("{prefix}/{reg}.json"),
        format!("{prefix}/{key}.key"),
    ]
}

fn account_migration_required() -> crate::Error {
    crate::Error::Config("an account exists in an unbound legacy CA namespace; explicitly call account::migrate_account_ca_identity with the original account key/registration after confirming its directory endpoint".into())
}

async fn account_bytes(storage: &dyn Storage, key: &str) -> Result<Option<Vec<u8>>> {
    match storage.load(key).await {
        Ok(bytes) => Ok(Some(bytes)),
        Err(crate::Error::Storage(StorageError::NotFound(_))) => Ok(None),
        Err(error) => Err(error),
    }
}

fn read_bound_snapshot(bytes: &[u8], ca_url: &str, email: &str) -> Result<AcmeAccount> {
    let snapshot: AccountSnapshot = serde_json::from_slice(bytes)
        .map_err(|error| AcmeError::Account(format!("invalid account snapshot: {error}")))?;
    if snapshot.version != 2 {
        return Err(account_migration_required());
    }
    if snapshot.ca_url.as_deref() != Some(canonical_account_ca(ca_url).as_str())
        || !snapshot.configured_email.present
        || snapshot.configured_email.value != canonical_account_email(email)
    {
        return Err(crate::Error::Config("account snapshot is bound to a different CA endpoint or configured identity, or lacks its required binding".into()));
    }
    validate_account(snapshot.registration, snapshot.private_key_pem)
}

async fn discovered_account(
    storage: &dyn Storage,
    ca_url: &str,
    issuer: &str,
    entry: &str,
) -> Result<Option<(Option<String>, AcmeAccount)>> {
    let key = format!("{entry}/_certon/account.v1.key");
    let Some(bytes) = account_bytes(storage, &key).await? else {
        return Ok(None);
    };
    let snapshot: AccountSnapshot = serde_json::from_slice(&bytes).map_err(|error| {
        AcmeError::Account(format!("invalid discovered account snapshot: {error}"))
    })?;
    if snapshot.version != 2 || !snapshot.configured_email.present {
        return Err(account_migration_required());
    }
    let email = snapshot.configured_email.value;
    if storage_key_account_snapshot(issuer, email.as_deref().unwrap_or_default()) != key {
        return Err(crate::Error::Config(
            "discovered account snapshot is in another configured identity's slot".into(),
        ));
    }
    let account = read_bound_snapshot(&bytes, ca_url, email.as_deref().unwrap_or_default())?;
    Ok(Some((email, account)))
}

async fn read_legacy_account(
    storage: &dyn Storage,
    issuer: &str,
    ca_url: &str,
    email: &str,
) -> Result<Option<AcmeAccount>> {
    let [snapshot, registration, key] = legacy_account_keys(issuer, email);
    if let Some(bytes) = account_bytes(storage, &snapshot).await? {
        let snapshot: AccountSnapshot = serde_json::from_slice(&bytes)
            .map_err(|error| AcmeError::Account(format!("invalid account snapshot: {error}")))?;
        if snapshot.version == 2 {
            return read_bound_snapshot(&bytes, ca_url, email).map(Some);
        }
        if snapshot.version != 1 {
            return Err(AcmeError::Account("unsupported account snapshot version".into()).into());
        }
        return validate_account(snapshot.registration, snapshot.private_key_pem).map(Some);
    }
    match (
        account_bytes(storage, &registration).await?,
        account_bytes(storage, &key).await?,
    ) {
        (None, None) => Ok(None),
        (Some(registration), Some(key)) => {
            let registration = serde_json::from_slice(&registration).map_err(|error| {
                AcmeError::Account(format!("invalid legacy account registration: {error}"))
            })?;
            let key = String::from_utf8(key).map_err(|error| {
                AcmeError::Account(format!("account private key is not UTF-8: {error}"))
            })?;
            validate_account(registration, key).map(Some)
        }
        _ => Err(AcmeError::Account("incomplete legacy account resources".into()).into()),
    }
}

fn storage_key_account_snapshot(issuer: &str, email: &str) -> String {
    format!(
        "{}/_certon/account.v1.key",
        account_key_prefix(issuer, &normalise_email(email))
    )
}

#[derive(Serialize, Deserialize)]
struct AccountMigrationReceipt {
    version: u32,
    ca_url: String,
    #[serde(default)]
    configured_email: RequiredEmail,
    source_issuer: String,
    source_email: String,
    public_key_identity: String,
    location: String,
}

fn public_account_identity(account: &AcmeAccount) -> Result<String> {
    let key = decode_private_key_pem(&account.private_key_pem)?;
    crate::acme_client::key_authorization("account-migration-v1", &key)
}

fn migration_receipt_key(target: &str, email: &str, source: &str) -> String {
    let identity = serde_json::to_string(&canonical_account_email(email))
        .expect("an optional string serializes");
    format!(
        "{}/_certon/account-migrations/{}/{}.key",
        crate::storage::acme_ca_prefix(target),
        crate::storage::storage_identity_hash(&format!("configured-email\0{identity}")),
        crate::storage::storage_identity_hash(&format!(
            "legacy-source\0{source}\0{}",
            normalise_email(email)
        )),
    )
}

pub(crate) async fn retired_account_matches(
    storage: &dyn Storage,
    target: &str,
    source: &str,
    ca_url: &str,
    email: &str,
    account: &AcmeAccount,
) -> Result<bool> {
    let Some(bytes) = account_bytes(storage, &migration_receipt_key(target, email, source)).await?
    else {
        return Ok(false);
    };
    let receipt: AccountMigrationReceipt = serde_json::from_slice(&bytes).map_err(|error| {
        AcmeError::Account(format!("invalid account migration receipt: {error}"))
    })?;
    if receipt.version != 1
        || receipt.ca_url != canonical_account_ca(ca_url)
        || !receipt.configured_email.present
        || receipt.configured_email.value != canonical_account_email(email)
        || receipt.source_issuer != source
        || receipt.source_email != normalise_email(email)
    {
        return Err(crate::Error::Config(
            "account migration receipt lacks its required identity binding".into(),
        ));
    }
    Ok(receipt.location == account.location
        && receipt.public_key_identity == public_account_identity(account)?)
}

pub(crate) async fn record_account_migration(
    storage: &dyn Storage,
    target: &str,
    source: &str,
    ca_url: &str,
    email: &str,
    account: &AcmeAccount,
) -> Result<()> {
    let receipt = AccountMigrationReceipt {
        version: 1,
        ca_url: canonical_account_ca(ca_url),
        configured_email: RequiredEmail {
            present: true,
            value: canonical_account_email(email),
        },
        source_issuer: source.into(),
        source_email: normalise_email(email),
        public_key_identity: public_account_identity(account)?,
        location: account.location.clone(),
    };
    let bytes = serde_json::to_vec(&receipt).map_err(|error| {
        AcmeError::Account(format!(
            "cannot serialize account migration receipt: {error}"
        ))
    })?;
    storage
        .store(&migration_receipt_key(target, email, source), &bytes)
        .await
}

fn validate_account(mut account: AcmeAccount, key_pem: String) -> Result<AcmeAccount> {
    let key = decode_private_key_pem(&key_pem)
        .map_err(|e| AcmeError::Account(format!("could not decode account's private key: {e}")))?;
    account.private_key_pem = key_pem;
    account.key_type = key.key_type();
    Ok(account)
}

// ---------------------------------------------------------------------------
// Account operations
// ---------------------------------------------------------------------------

/// Load an existing ACME account from storage.
///
/// Returns `Ok(Some(account))` if the account exists, `Ok(None)` if the
/// storage key was not found, or `Err(...)` for any other error.
pub async fn get_account(
    storage: &dyn Storage,
    ca_url: &str,
    email: &str,
) -> Result<Option<AcmeAccount>> {
    let issuer_key = crate::storage::issuer_key(ca_url);
    if let Some(bytes) =
        account_bytes(storage, &storage_key_account_snapshot(&issuer_key, email)).await?
    {
        return read_bound_snapshot(&bytes, ca_url, email).map(Some);
    }
    let legacy = crate::storage::legacy_issuer_key(ca_url);
    for source in [&issuer_key, &legacy] {
        if let Some(account) = read_legacy_account(storage, source, ca_url, email).await?
            && !retired_account_matches(storage, &issuer_key, source, ca_url, email, &account)
                .await?
        {
            return Err(account_migration_required());
        }
    }
    Ok(None)
}

/// Save an ACME account to storage transactionally.
///
/// Publishes registration and private key together in a versioned, private
/// snapshot. Failed or cancelled publication exposes a complete old or new
/// account, never metadata paired with another generation's private key.
pub async fn save_account(
    storage: &dyn Storage,
    ca_url: &str,
    account: &AcmeAccount,
) -> Result<()> {
    let email = get_primary_contact(account);
    save_account_for_email(storage, ca_url, &email, account).await
}

/// Explicitly bind a legacy account to its operator-confirmed CA endpoint.
///
/// The caller must verify the original full directory URL and configured email,
/// then supply that registered account's original key and URI as `expected`.
/// An old record alone cannot prove endpoint ownership. Stop old certon versions
/// first. Source records are retained; no ambiguous account is adopted on read.
///
/// A source-generation receipt allows later invalid-account recovery without
/// resurrecting or permanently blocking on that retired account. Both the new
/// complete snapshot and receipt must publish before this call returns success.
/// Failure or cancellation can leave a complete new snapshot: retry this call
/// to finish the receipt. It never overwrites a different destination account.
pub async fn migrate_account_ca_identity(
    storage: Arc<dyn Storage>,
    ca_url: &str,
    email: &str,
    expected: &AcmeAccount,
) -> Result<()> {
    if expected.location.is_empty() {
        return Err(AcmeError::Account(
            "migration requires the original registered account URI and key".into(),
        )
        .into());
    }
    let issuer = crate::storage::issuer_key(ca_url);
    let legacy = crate::storage::legacy_issuer_key(ca_url);
    let mut names = vec![
        format!("acme_account_{issuer}"),
        format!("acme_account_{legacy}"),
    ];
    names.sort_by_key(|name| crate::storage::lock_storage_identity(name));
    names.dedup_by(|first, second| {
        crate::storage::lock_storage_identity(first)
            == crate::storage::lock_storage_identity(second)
    });
    let mut locks = Vec::new();
    for name in names {
        locks.push(crate::storage::acquire(storage.clone(), &name).await?);
    }
    let target = storage_key_account_snapshot(&issuer, email);
    let mut publication = None;
    let mut target_bound = false;
    if let Some(bytes) = account_bytes(storage.as_ref(), &target).await? {
        let snapshot: AccountSnapshot = serde_json::from_slice(&bytes)
            .map_err(|error| AcmeError::Account(format!("invalid account snapshot: {error}")))?;
        let current = if snapshot.version == 1 {
            validate_account(snapshot.registration, snapshot.private_key_pem)?
        } else {
            read_bound_snapshot(&bytes, ca_url, email)?
        };
        if !same_registered_account(&current, expected)? {
            return Err(AcmeError::Account(
                "migration destination already contains another registered account".into(),
            )
            .into());
        }
        target_bound = snapshot.version == 2;
        publication = Some(current);
    }
    let mut sources = Vec::new();
    for source in [&legacy, &issuer] {
        if let Some(account) = read_legacy_account(storage.as_ref(), source, ca_url, email).await? {
            if !same_registered_account(&account, expected)? {
                return Err(AcmeError::Account(
                    "migration source or destination differs from the supplied registered account"
                        .into(),
                )
                .into());
            }
            if publication.is_none() {
                publication = Some(account);
            }
            sources.push(source);
        }
    }
    if sources.is_empty() {
        return Err(AcmeError::Account("no legacy account is available to migrate".into()).into());
    }
    if !target_bound {
        save_account_for_email(
            storage.as_ref(),
            ca_url,
            email,
            publication.as_ref().expect("a source was checked"),
        )
        .await?;
    }
    for source in sources {
        record_account_migration(storage.as_ref(), &issuer, source, ca_url, email, expected)
            .await?;
    }
    Ok(())
}

/// Issuer persistence uses the configured identity rather than mutable contacts.
pub(crate) async fn save_account_for_email(
    storage: &dyn Storage,
    ca_url: &str,
    email: &str,
    account: &AcmeAccount,
) -> Result<()> {
    let issuer_key = crate::storage::issuer_key(ca_url);

    let snapshot = AccountSnapshot {
        version: 2,
        ca_url: Some(canonical_account_ca(ca_url)),
        configured_email: RequiredEmail {
            present: true,
            value: canonical_account_email(email),
        },
        registration: account.clone(),
        private_key_pem: account.private_key_pem.clone(),
    };
    let bytes = serde_json::to_vec(&snapshot)
        .map_err(|e| AcmeError::Account(format!("failed to serialise account snapshot: {e}")))?;
    storage
        .store(&storage_key_account_snapshot(&issuer_key, email), &bytes)
        .await?;

    debug!(
        email = %email,
        ca = ca_url,
        "saved ACME account to storage"
    );

    Ok(())
}

pub(crate) fn same_account_slot(ca_url: &str, first: &str, second: &str) -> bool {
    let issuer = crate::storage::issuer_key(ca_url);
    storage_key_account_snapshot(&issuer, first) == storage_key_account_snapshot(&issuer, second)
}

/// ACME uses P-256 account keys. Compare their public JWK identities, so
/// equivalent SEC1/PKCS#8 PEM encodings are not mistaken for different accounts.
pub(crate) fn same_account_key(first: &AcmeAccount, second: &AcmeAccount) -> Result<bool> {
    let first = decode_private_key_pem(&first.private_key_pem)?;
    let second = decode_private_key_pem(&second.private_key_pem)?;
    Ok(
        crate::acme_client::key_authorization("account-identity", &first)?
            == crate::acme_client::key_authorization("account-identity", &second)?,
    )
}

pub(crate) fn same_registered_account(first: &AcmeAccount, second: &AcmeAccount) -> Result<bool> {
    Ok(first.location == second.location && same_account_key(first, second)?)
}

/// Called only after the configured slot was absent, under the CA account lock.
/// A matching contact alone is insufficient evidence to adopt an old account.
pub(crate) async fn migrate_contact_account(
    storage: &dyn Storage,
    ca_url: &str,
    email: &str,
    candidate: &AcmeAccount,
) -> Result<Option<AcmeAccount>> {
    let contact = get_primary_contact(candidate);
    if same_account_slot(ca_url, email, &contact) {
        return Ok(None);
    }
    let Some(legacy) = get_account(storage, ca_url, &contact).await? else {
        return Ok(None);
    };
    if !same_account_slot(ca_url, &contact, &get_primary_contact(&legacy)) {
        return Err(AcmeError::Account("callback contact points to another identity-bound account; migrate the account explicitly".into()).into());
    }
    if legacy.location.is_empty() || !matches!(legacy.status.as_str(), "" | "valid") {
        return Err(AcmeError::Account(
            "legacy account under callback contact is not an active registered account".into(),
        )
        .into());
    }
    if !same_account_key(candidate, &legacy)? {
        return Err(AcmeError::Account("legacy account under callback contact has a different key; configure its original account_key_pem or migrate the account explicitly".into()).into());
    }
    save_account_for_email(storage, ca_url, email, &legacy).await?;
    // Keep the old alias for compatibility. Confirmed accountDoesNotExist
    // recovery removes aliases proven to identify that same invalid account.
    Ok(Some(legacy))
}

/// Create a new ACME account in memory.
///
/// This generates a fresh private key but does **not** register the account
/// with any CA or save it to storage. The caller should register the account
/// via the ACME protocol and then call [`save_account`].
pub fn new_account(email: &str, key_type: KeyType) -> Result<AcmeAccount> {
    let private_key = generate_private_key(key_type)?;
    let private_key_pem = encode_private_key_pem(&private_key)?;

    let contact = if email.is_empty() {
        Vec::new()
    } else {
        let email_normalised = normalise_email(email);
        let email_addr = if email_normalised == EMPTY_EMAIL {
            // No actual email — leave contacts empty.
            return Ok(AcmeAccount {
                status: String::new(),
                contact: Vec::new(),
                location: String::new(),
                terms_of_service_agreed: false,
                private_key_pem,
                key_type,
            });
        } else {
            email_normalised
        };
        vec![format!("mailto:{email_addr}")]
    };

    Ok(AcmeAccount {
        status: String::new(),
        contact,
        location: String::new(),
        terms_of_service_agreed: false,
        private_key_pem,
        key_type,
    })
}

/// Load an existing account from storage, or create a new one if none is found.
///
/// Returns a tuple of `(account, is_new)` where `is_new` is `true` when a
/// fresh account was created (the caller is responsible for registering it
/// with the CA and then saving it via [`save_account`]).
pub async fn get_or_create_account(
    storage: &dyn Storage,
    ca_url: &str,
    email: &str,
    key_type: KeyType,
) -> Result<(AcmeAccount, bool)> {
    match get_account(storage, ca_url, email).await? {
        Some(account) => {
            debug!(
                email = email,
                ca = ca_url,
                "using existing ACME account from storage"
            );
            Ok((account, false))
        }
        None => {
            info!(
                email = email,
                ca = ca_url,
                "creating new ACME account (no existing account found in storage)"
            );
            let email = email.to_owned();
            let account =
                crate::crypto::run_key_generation(move || new_account(&email, key_type)).await?;
            Ok((account, true))
        }
    }
}

/// Delete the locally stored account data (registration JSON and private key)
/// for the given CA and account.
///
/// This does **not** deactivate the account with the CA — it only removes the
/// local storage entries.
pub async fn delete_account_locally(
    storage: &dyn Storage,
    ca_url: &str,
    account: &AcmeAccount,
) -> Result<()> {
    let email = get_primary_contact(account);
    delete_account_for_email(storage, ca_url, &email).await
}

pub(crate) async fn delete_account_for_email(
    storage: &dyn Storage,
    ca_url: &str,
    email: &str,
) -> Result<()> {
    let issuer_key = crate::storage::issuer_key(ca_url);

    let reg_key = storage_key_user_reg(&issuer_key, email);
    let pk_key = storage_key_user_private_key(&issuer_key, email);

    // Remove legacy resources first to prevent resurrection after a partial
    // deletion. The current snapshot remains usable until the final delete.
    for key in [
        reg_key,
        pk_key,
        storage_key_account_snapshot(&issuer_key, email),
    ] {
        match storage.delete(&key).await {
            Ok(()) | Err(crate::error::Error::Storage(StorageError::NotFound(_))) => {}
            Err(error) => return Err(error),
        }
    }

    debug!(
        email = %email,
        ca = ca_url,
        "deleted local ACME account data"
    );

    Ok(())
}

/// Find the email address of the most recently modified account for a given CA.
///
/// Enumerates account directories and ranks their authoritative snapshot's
/// modification time. Legacy accounts use the newer registration/key file
/// timestamp. Parent directory timestamps do not track snapshot overwrites.
///
/// Returns `Ok(None)` if no accounts exist for the given CA. The
/// `"default"` placeholder (used for accounts with no email) is filtered
/// out.
pub async fn most_recent_account_email(
    storage: &dyn Storage,
    ca_url: &str,
) -> Result<Option<String>> {
    let ik = crate::storage::issuer_key(ca_url);
    let prefix = format!("{}/users", crate::storage::acme_ca_prefix(&ik));

    let entries = match storage.list(&prefix, false).await {
        Ok(e) => e,
        Err(crate::error::Error::Storage(StorageError::NotFound(_))) => return Ok(None),
        Err(e) => return Err(e),
    };

    if entries.is_empty() {
        return Ok(None);
    }

    let mut best_email: Option<String> = None;
    let mut best_modified: Option<chrono::DateTime<chrono::Utc>> = None;

    for entry in &entries {
        // Extract the email component from the key path -- it is the last
        // segment of the entry key (which is a directory name under users/).
        let email_part = entry.rsplit('/').next().unwrap_or("").to_string();

        // Skip the "default" placeholder (represents an account with no email).
        if email_part == "default" || email_part.is_empty() {
            continue;
        }

        let info = match storage.stat(entry).await {
            Ok(info) => info,
            Err(crate::error::Error::Storage(StorageError::NotFound(_))) => continue,
            Err(error) => return Err(error),
        };
        if info.is_terminal {
            continue;
        }

        let Some(modified) = account_modified(storage, &ik, &email_part).await? else {
            continue;
        };
        let Some((Some(email), _)) = discovered_account(storage, ca_url, &ik, entry).await? else {
            return Err(account_migration_required());
        };
        let dominated = best_modified.is_some_and(|bm| modified <= bm);
        if !dominated {
            best_modified = Some(modified);
            best_email = Some(email);
        }
    }

    Ok(best_email)
}

async fn account_asset_modified(
    storage: &dyn Storage,
    key: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    match storage.stat(key).await {
        Ok(info) if info.is_terminal => Ok(Some(info.modified)),
        Ok(_) => Err(AcmeError::Account(format!("account resource is not a file: {key}")).into()),
        Err(crate::error::Error::Storage(StorageError::NotFound(_))) => Ok(None),
        Err(error) => Err(error),
    }
}

async fn account_modified(
    storage: &dyn Storage,
    issuer: &str,
    email: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    if let Some(modified) =
        account_asset_modified(storage, &storage_key_account_snapshot(issuer, email)).await?
    {
        return Ok(Some(modified));
    }
    let registration =
        account_asset_modified(storage, &storage_key_user_reg(issuer, email)).await?;
    let key = account_asset_modified(storage, &storage_key_user_private_key(issuer, email)).await?;
    match (registration, key) {
        (Some(registration), Some(key)) => Ok(Some(registration.max(key))),
        (None, None) => Ok(None),
        _ => Err(AcmeError::Account("incomplete legacy account resources".into()).into()),
    }
}

/// Find an ACME account whose private key PEM matches `key_pem`.
///
/// Lists all account directories for the given CA URL, loads each one,
/// and compares the stored private key PEM against `key_pem`. Returns
/// the first matching account, or `None` if no match is found.
///
/// This is useful for key-based account lookup when the email address
/// is unknown.
pub async fn get_account_by_key(
    storage: &dyn Storage,
    ca_url: &str,
    key_pem: &str,
) -> Result<Option<AcmeAccount>> {
    let ik = crate::storage::issuer_key(ca_url);
    let prefix = format!("{}/users", crate::storage::acme_ca_prefix(&ik));

    let entries = match storage.list(&prefix, false).await {
        Ok(e) => e,
        Err(crate::error::Error::Storage(StorageError::NotFound(_))) => return Ok(None),
        Err(e) => return Err(e),
    };

    for entry in &entries {
        // Each entry is a directory named after the email.
        let email_part = entry.rsplit('/').next().unwrap_or("").to_string();

        if email_part.is_empty() {
            continue;
        }

        match discovered_account(storage, ca_url, &ik, entry).await {
            Ok(Some((_, account))) => {
                if account.private_key_pem == key_pem {
                    return Ok(Some(account));
                }
            }
            Ok(None) => continue,
            Err(_) => continue,
        }
    }

    Ok(None)
}

/// Discover the email address of an existing account for the given CA.
///
/// Checks [`most_recent_account_email`] and returns the email if found.
/// This is a convenience wrapper for use in flows that need to discover
/// the email associated with a previously-registered account.
/// Storage failures are logged; use [`most_recent_account_email`] when the
/// caller needs the error returned.
pub async fn discover_email(storage: &dyn Storage, ca_url: &str) -> Option<String> {
    match most_recent_account_email(storage, ca_url).await {
        Ok(email) => email,
        Err(error) => {
            warn!(%error, "failed to discover stored ACME account email");
            None
        }
    }
}

/// Build a lock key name for ACME account registration.
///
/// This is used to coordinate distributed registration so that only one
/// node registers a given account at a time. The key includes the primary
/// contact (email) if available.
pub fn account_reg_lock_key(account: &AcmeAccount) -> String {
    let mut key = "register_acme_account".to_owned();
    if !account.contact.is_empty() {
        let primary = get_primary_contact(account);
        if !primary.is_empty() {
            key.push('_');
            key.push_str(&primary);
        }
    }
    key
}

// ---------------------------------------------------------------------------
// Interactive prompts
// ---------------------------------------------------------------------------

/// Prompt the user for an email address on stdin.
///
/// This is only called when `interactive` is true and no email is configured.
/// Returns `None` if stdin is not a terminal or the user enters empty input.
pub fn prompt_user_for_email() -> Option<String> {
    use std::io::{self, BufRead, Write};

    // Check if stdin is a terminal (not piped)
    if !atty_is_terminal() {
        return None;
    }

    eprint!("Your email address (for ACME account, Let's Encrypt notifications): ");
    io::stderr().flush().ok();

    let stdin = io::stdin();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).is_ok() {
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    } else {
        None
    }
}

/// Prompt the user for Terms of Service agreement.
///
/// Displays the given Terms of Service URL and asks the user whether they
/// agree. Returns `true` if the user answers "y" or "yes" (case-insensitive).
/// Returns `false` if stdin is not a terminal, the read fails, or the user
/// enters anything else.
pub fn prompt_user_agreement(tos_url: &str) -> bool {
    use std::io::{self, BufRead, Write};

    if !atty_is_terminal() {
        return false;
    }

    eprintln!("\nYour CA's Terms of Service:");
    eprintln!("  {tos_url}");
    eprint!("Do you agree to the Terms of Service? (y/N): ");
    io::stderr().flush().ok();

    let stdin = io::stdin();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).is_ok() {
        let answer = line.trim().to_lowercase();
        answer == "y" || answer == "yes"
    } else {
        false
    }
}

/// Check if stdin is likely a terminal.
fn atty_is_terminal() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdin())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn set_modified(path: &std::path::Path, seconds: u64) {
        let modified = std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds);
        #[cfg(windows)]
        let file = {
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_WRITE_ATTRIBUTES and FILE_FLAG_BACKUP_SEMANTICS also allow
            // setting directory timestamps without relying on timer precision.
            std::fs::OpenOptions::new()
                .access_mode(0x0100)
                .custom_flags(0x02000000)
                .open(path)
                .unwrap()
        };
        #[cfg(not(windows))]
        let file = std::fs::File::open(path).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
    }

    #[tokio::test]
    async fn account_discovery_uses_latest_snapshot_write() {
        let directory = tempfile::tempdir().unwrap();
        let storage = crate::FileStorage::new(directory.path());
        let ca = "https://acme.example.com/directory";
        let issuer = crate::storage::issuer_key(ca);
        let mut a = new_account("a@example.com", KeyType::EcdsaP256).unwrap();
        let b = new_account("b@example.com", KeyType::EcdsaP256).unwrap();
        save_account(&storage, ca, &a).await.unwrap();
        set_modified(
            &directory
                .path()
                .join(account_key_prefix(&issuer, "a@example.com")),
            1_700_000_000,
        );
        set_modified(
            &directory
                .path()
                .join(storage_key_account_snapshot(&issuer, "a@example.com")),
            1_700_000_000,
        );
        save_account(&storage, ca, &b).await.unwrap();
        set_modified(
            &directory
                .path()
                .join(account_key_prefix(&issuer, "b@example.com")),
            1_700_001_000,
        );
        set_modified(
            &directory
                .path()
                .join(storage_key_account_snapshot(&issuer, "b@example.com")),
            1_700_001_000,
        );
        a.status = "updated".into();
        save_account(&storage, ca, &a).await.unwrap();
        set_modified(
            &directory
                .path()
                .join(storage_key_account_snapshot(&issuer, "a@example.com")),
            1_700_002_000,
        );
        // A newer default account must still be excluded.
        let default = new_account("", KeyType::EcdsaP256).unwrap();
        save_account(&storage, ca, &default).await.unwrap();
        set_modified(
            &directory
                .path()
                .join(storage_key_account_snapshot(&issuer, "")),
            1_700_003_000,
        );
        assert_eq!(
            most_recent_account_email(&storage, ca)
                .await
                .unwrap()
                .as_deref(),
            Some("a@example.com")
        );
        assert_eq!(
            discover_email(&storage, ca).await.as_deref(),
            Some("a@example.com")
        );
    }

    #[tokio::test]
    async fn account_discovery_uses_explicitly_bound_legacy_imports() {
        let directory = tempfile::tempdir().unwrap();
        let storage = crate::FileStorage::new(directory.path());
        let ca = "https://acme.example.com/directory";
        let issuer = crate::storage::issuer_key(ca);
        let a = new_account("a@example.com", KeyType::EcdsaP256).unwrap();
        let b = new_account("b@example.com", KeyType::EcdsaP256).unwrap();
        let reg = storage_key_user_reg(&issuer, "a@example.com");
        let key = storage_key_user_private_key(&issuer, "a@example.com");
        storage
            .store(&reg, &serde_json::to_vec(&a).unwrap())
            .await
            .unwrap();
        storage
            .store(&key, a.private_key_pem.as_bytes())
            .await
            .unwrap();
        set_modified(&directory.path().join(&reg), 1_700_000_000);
        set_modified(&directory.path().join(&key), 1_700_002_000);
        // An operator-confirmed legacy import must publish its identity binding
        // before discovery can use it. Preserve the imported modification rank.
        save_account(&storage, ca, &a).await.unwrap();
        set_modified(
            &directory
                .path()
                .join(storage_key_account_snapshot(&issuer, "a@example.com")),
            1_700_002_000,
        );
        set_modified(
            &directory
                .path()
                .join(account_key_prefix(&issuer, "a@example.com")),
            1_700_000_000,
        );
        save_account(&storage, ca, &b).await.unwrap();
        set_modified(
            &directory
                .path()
                .join(storage_key_account_snapshot(&issuer, "b@example.com")),
            1_700_001_000,
        );
        set_modified(
            &directory
                .path()
                .join(account_key_prefix(&issuer, "b@example.com")),
            1_700_001_000,
        );
        assert_eq!(
            most_recent_account_email(&storage, ca)
                .await
                .unwrap()
                .as_deref(),
            Some("a@example.com")
        );
        // Once A has a snapshot, its old legacy files no longer determine age.
        save_account(&storage, ca, &a).await.unwrap();
        set_modified(
            &directory
                .path()
                .join(storage_key_account_snapshot(&issuer, "a@example.com")),
            1_699_999_000,
        );
        assert_eq!(
            most_recent_account_email(&storage, ca)
                .await
                .unwrap()
                .as_deref(),
            Some("b@example.com")
        );
        assert_eq!(
            discover_email(&storage, ca).await.as_deref(),
            Some("b@example.com")
        );
    }

    struct StatFailure<'a> {
        storage: &'a dyn Storage,
        key: String,
    }

    #[async_trait::async_trait]
    impl Storage for StatFailure<'_> {
        async fn stat(&self, key: &str) -> Result<crate::storage::KeyInfo> {
            if key == self.key {
                return Err(crate::Error::Other("stat is unavailable".into()));
            }
            self.storage.stat(key).await
        }
        async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
            self.storage.store(key, value).await
        }
        async fn load(&self, key: &str) -> Result<Vec<u8>> {
            self.storage.load(key).await
        }
        async fn delete(&self, key: &str) -> Result<()> {
            self.storage.delete(key).await
        }
        async fn exists(&self, key: &str) -> Result<bool> {
            self.storage.exists(key).await
        }
        async fn list(&self, prefix: &str, recursive: bool) -> Result<Vec<String>> {
            self.storage.list(prefix, recursive).await
        }
        async fn lock(&self, name: &str) -> Result<()> {
            self.storage.lock(name).await
        }
        async fn unlock(&self, name: &str) -> Result<()> {
            self.storage.unlock(name).await
        }
    }

    #[tokio::test]
    async fn account_discovery_propagates_snapshot_directory_and_legacy_stat_failures() {
        let directory = tempfile::tempdir().unwrap();
        let storage = crate::FileStorage::new(directory.path());
        let ca = "https://acme.example.com/directory";
        let issuer = crate::storage::issuer_key(ca);
        let account = new_account("a@example.com", KeyType::EcdsaP256).unwrap();
        save_account(&storage, ca, &account).await.unwrap();
        let snapshot = storage_key_account_snapshot(&issuer, "a@example.com");
        let registration = storage_key_user_reg(&issuer, "a@example.com");
        let key = storage_key_user_private_key(&issuer, "a@example.com");
        storage
            .store(&registration, &serde_json::to_vec(&account).unwrap())
            .await
            .unwrap();
        storage
            .store(&key, account.private_key_pem.as_bytes())
            .await
            .unwrap();
        let default = new_account("", KeyType::EcdsaP256).unwrap();
        save_account(&storage, ca, &default).await.unwrap();
        let excluded = StatFailure {
            storage: &storage,
            key: account_key_prefix(&issuer, ""),
        };
        assert_eq!(
            most_recent_account_email(&excluded, ca)
                .await
                .unwrap()
                .as_deref(),
            Some("a@example.com")
        );
        for fault in [
            account_key_prefix(&issuer, "a@example.com"),
            snapshot.clone(),
        ] {
            let failure = StatFailure {
                storage: &storage,
                key: fault,
            };
            let error = most_recent_account_email(&failure, ca).await.unwrap_err();
            assert!(error.to_string().contains("stat is unavailable"));
            assert!(discover_email(&failure, ca).await.is_none());
        }
        storage.delete(&snapshot).await.unwrap();
        for fault in [registration, key] {
            let failure = StatFailure {
                storage: &storage,
                key: fault,
            };
            assert!(
                most_recent_account_email(&failure, ca)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("stat is unavailable")
            );
        }
    }

    #[tokio::test]
    async fn account_discovery_skips_unknown_entries_but_rejects_incomplete_resources() {
        let directory = tempfile::tempdir().unwrap();
        let storage = crate::FileStorage::new(directory.path());
        let ca = "https://acme.example.com/directory";
        let issuer = crate::storage::issuer_key(ca);
        let users = format!("{}/users", crate::storage::acme_ca_prefix(&issuer));
        storage
            .store(&format!("{users}/unrelated.txt"), b"not an account")
            .await
            .unwrap();
        std::fs::create_dir_all(
            directory
                .path()
                .join(account_key_prefix(&issuer, "empty@example.com")),
        )
        .unwrap();
        assert!(
            most_recent_account_email(&storage, ca)
                .await
                .unwrap()
                .is_none()
        );
        let account = new_account("a@example.com", KeyType::EcdsaP256).unwrap();
        let registration = storage_key_user_reg(&issuer, "a@example.com");
        storage
            .store(&registration, &serde_json::to_vec(&account).unwrap())
            .await
            .unwrap();
        assert!(
            most_recent_account_email(&storage, ca)
                .await
                .unwrap_err()
                .to_string()
                .contains("incomplete legacy")
        );
        // A present but invalid snapshot must not silently fall back to legacy.
        storage
            .store(
                &storage_key_user_private_key(&issuer, "a@example.com"),
                account.private_key_pem.as_bytes(),
            )
            .await
            .unwrap();
        std::fs::create_dir_all(
            directory
                .path()
                .join(storage_key_account_snapshot(&issuer, "a@example.com")),
        )
        .unwrap();
        assert!(
            most_recent_account_email(&storage, ca)
                .await
                .unwrap_err()
                .to_string()
                .contains("not a file")
        );
    }

    // -- normalise_email ---------------------------------------------------

    #[test]
    fn normalise_strips_mailto() {
        assert_eq!(
            normalise_email("mailto:user@example.com"),
            "user@example.com"
        );
    }

    #[test]
    fn normalise_lowercases() {
        assert_eq!(normalise_email("User@Example.COM"), "user@example.com");
    }

    #[test]
    fn normalise_trims_whitespace() {
        assert_eq!(normalise_email("  user@example.com  "), "user@example.com");
    }

    #[test]
    fn normalise_empty_returns_default() {
        assert_eq!(normalise_email(""), EMPTY_EMAIL);
        assert_eq!(normalise_email("   "), EMPTY_EMAIL);
    }

    // -- email_username ----------------------------------------------------

    #[test]
    fn email_username_normal() {
        assert_eq!(email_username("user@example.com"), "user");
    }

    #[test]
    fn email_username_no_at() {
        assert_eq!(email_username("just-a-name"), "just-a-name");
    }

    #[test]
    fn email_username_at_start() {
        assert_eq!(email_username("@example.com"), "example.com");
    }

    // -- get_primary_contact -----------------------------------------------

    #[test]
    fn primary_contact_strips_mailto() {
        let account = AcmeAccount {
            status: String::new(),
            contact: vec!["mailto:user@example.com".into()],
            location: String::new(),
            terms_of_service_agreed: false,
            private_key_pem: String::new(),
            key_type: KeyType::EcdsaP256,
        };
        assert_eq!(get_primary_contact(&account), "user@example.com");
    }

    #[test]
    fn primary_contact_no_scheme() {
        let account = AcmeAccount {
            status: String::new(),
            contact: vec!["user@example.com".into()],
            location: String::new(),
            terms_of_service_agreed: false,
            private_key_pem: String::new(),
            key_type: KeyType::EcdsaP256,
        };
        assert_eq!(get_primary_contact(&account), "user@example.com");
    }

    #[test]
    fn primary_contact_empty_contacts() {
        let account = AcmeAccount {
            status: String::new(),
            contact: vec![],
            location: String::new(),
            terms_of_service_agreed: false,
            private_key_pem: String::new(),
            key_type: KeyType::EcdsaP256,
        };
        assert_eq!(get_primary_contact(&account), "");
    }

    // -- storage key builders -----------------------------------------------

    #[test]
    fn storage_key_user_reg_with_email() {
        let ik = crate::storage::issuer_key("https://acme.example.com/directory");
        let key = storage_key_user_reg(&ik, "user@example.com");
        assert!(key.starts_with("acme/"));
        assert!(key.contains("/users/"));
        assert!(key.ends_with("/user.json"));
    }

    #[test]
    fn storage_key_user_reg_empty_email() {
        let ik = crate::storage::issuer_key("https://acme.example.com/directory");
        let key = storage_key_user_reg(&ik, "");
        assert!(key.contains("/users/default/"));
        assert!(key.ends_with(".json"));
    }

    #[test]
    fn storage_key_user_private_key_with_email() {
        let ik = crate::storage::issuer_key("https://acme.example.com/directory");
        let key = storage_key_user_private_key(&ik, "user@example.com");
        assert!(key.starts_with("acme/"));
        assert!(key.contains("/users/"));
        assert!(key.ends_with("/user.key"));
    }

    // -- new_account -------------------------------------------------------

    #[test]
    fn new_account_with_email() {
        let acct = new_account("user@example.com", KeyType::EcdsaP256).unwrap();
        assert_eq!(acct.contact, vec!["mailto:user@example.com"]);
        assert!(!acct.private_key_pem.is_empty());
        assert_eq!(acct.key_type, KeyType::EcdsaP256);
        assert!(acct.status.is_empty());
    }

    #[test]
    fn new_account_empty_email() {
        let acct = new_account("", KeyType::EcdsaP256).unwrap();
        assert!(acct.contact.is_empty());
        assert!(!acct.private_key_pem.is_empty());
    }

    #[test]
    fn new_account_strips_mailto_prefix() {
        let acct = new_account("mailto:user@example.com", KeyType::EcdsaP256).unwrap();
        // Should normalise: the mailto: is stripped, then re-added as the
        // contact scheme.
        assert_eq!(acct.contact, vec!["mailto:user@example.com"]);
    }

    // -- account_reg_lock_key -----------------------------------------------

    #[test]
    fn lock_key_no_contact() {
        let acct = AcmeAccount {
            status: String::new(),
            contact: vec![],
            location: String::new(),
            terms_of_service_agreed: false,
            private_key_pem: String::new(),
            key_type: KeyType::EcdsaP256,
        };
        assert_eq!(account_reg_lock_key(&acct), "register_acme_account");
    }

    #[test]
    fn lock_key_with_contact() {
        let acct = AcmeAccount {
            status: String::new(),
            contact: vec!["mailto:admin@example.com".into()],
            location: String::new(),
            terms_of_service_agreed: false,
            private_key_pem: String::new(),
            key_type: KeyType::EcdsaP256,
        };
        assert_eq!(
            account_reg_lock_key(&acct),
            "register_acme_account_admin@example.com"
        );
    }
}
