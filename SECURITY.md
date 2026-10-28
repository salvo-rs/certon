# Security checks and dependency policy

CI checks RustSec advisories for two feature graphs. The minimal ECDSA build
(`--no-default-features --features ring`) has no advisory exceptions. The full
compatibility graph uses the single exception in `deny-rsa.toml`; licenses,
sources and duplicate-dependency checks always use `deny.toml`. The dependency
workflow also runs weekly so newly published advisories are checked without
requiring a source change. Security fixes should be applied to the latest release.

## RSA compatibility exception

`rsa-keys` remains enabled by default for compatibility. It includes `rsa`,
which is affected by [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)
(Marvin timing side channels). No patched version is currently available.
This exception acknowledges an unresolved dependency finding; it does not
assert that RSA operations are universally safe.

Certon's `rsa` call sites generate keys and decode/encode local private-key
formats in `src/crypto.rs`. TLS private-key operations use the selected rustls
crypto provider. The exception is permitted only while that separation holds:
do not expose `rsa` private-key operations to attacker-controlled timing
measurements. New signing/decryption call sites require a fresh review.
Deployments that do not need RSA key generation or import can disable default
features and select `ring` or `aws-lc-rs`, adding other optional features as needed.

Only the full-feature advisory command uses the exception. Its preceding
metadata check restricts `rsa` to the 0.9 series, directly used only by
`certon@0.3.0` through the unchanged `rsa-keys` feature. Another dependent crate,
a version change, an unused exception, or a different vulnerability fails the
checks and requires review. Remove the exception when a
patched compatible dependency is available, and re-review it on every release
and whenever RSA call sites change. The minimal graph must continue to pass
without this exception. `cargo audit` alone examines all packages in a lockfile,
including disabled optional dependencies, so the minimal check uses cargo-deny's
feature-aware graph instead.

## Resolution and license checks

This library does not track `Cargo.lock`. Each build job generates it once if
absent, then uses `--locked` for checks, tests, docs and publication. This holds
resolution steady within a job while continuing to exercise new compatible
dependency releases; separate jobs may resolve at different times. If a lockfile
is tracked in the future, CI preserves and checks it. Manifest and lockfile
changes both trigger build and dependency checks.

The direct rustls requirement starts at 0.23.46 to exclude known affected
versions. Applications should update and audit their own lockfiles as well:
compatible transitive dependencies can otherwise remain pinned to older
vulnerable versions even after upgrading this library.

The license allowlist covers the current permissive code licenses. The
`webpki-root-certs` exception applies its data license only to that package.
Unlisted licenses, unlicensed packages, unknown registries and Git sources fail
the policy check. Duplicate versions are reported as warnings because current
RustCrypto versions and TLS providers have incompatible transitive APIs; they
remain visible for review. Wildcard dependency requirements fail the check.

To reproduce the checks after generating a lockfile:

```sh
cargo deny --locked --no-default-features --features ring check advisories
cargo metadata --locked --all-features --format-version 1 | python .github/scripts/check-rsa-exception.py
cargo deny --locked --all-features --config deny-rsa.toml check advisories
cargo deny --locked --all-features check licenses bans sources
```

Use the pinned `cargo-deny` 0.20.2 version from the workflow.

## Local file storage trust boundary

`FileStorage` requires a storage root and parent directories controlled by
trusted operators. The tree contains certificate private keys and ACME account
credentials. Prevent other accounts from reading those secrets or replacing
files and directories: configure Unix ownership and permissions or Windows
ACLs before use, and verify inherited permissions on the deployment host.

Storage-key validation rejects lexical traversal such as `..` and absolute
paths. Filesystem operations can still follow symbolic links, Windows
junctions and other reparse points. An account able to replace the root, an
ancestor or a path within the tree can redirect operations; this backend is
not a sandbox against that local account. Keep untrusted uploads and other
attacker-writable content outside the storage tree. A startup path check alone
does not prevent later link-replacement races.

Unix writes use restricted file permissions and attempt to restrict the
immediate destination directory; this does not establish the ownership or
permissions of every ancestor. The backend does not configure Windows ACLs.
For shared storage, review access permissions and cross-host locking support
together; advisory locking is coordination, not access control.

## Outbound response budgets

ACME and ZeroSSL JSON responses are limited to 1 MiB. Error response bodies
are limited to 64 KiB before parsing or including diagnostic text in errors
and logs. The reader checks both declared Content-Length and each streamed
chunk, so chunked or unknown-length responses use the same budget. Oversized
bodies produce a bounded error message rather than including their contents.
Transport read errors omit the request URL to protect query credentials.

The default HTTP transports' 30-second request timeout includes body
consumption. A caller-supplied ACME client builder's timeout policy is preserved;
the response size limits apply to that transport as well. ACME validates every
operation URL and enforces its redirect policy when constructing the client,
so HTTPS-to-HTTP downgrade is rejected before contacting the redirect target.
The local HTTP directory exception is for development; it does not permit
downgrading an HTTPS directory or redirect chain. OCSP HTTP responders remain
supported by their separate shared transport.

Windows CI places Cargo artifacts, Cargo data and temporary files under
`D:/BuildCache/certon-ci`; its setup checks the target directory with Cargo
metadata. Linux/macOS hosted runners use their native runner filesystems and
do not have a Windows D drive. Local checks on the maintainer's Windows machine
must set `CARGO_TARGET_DIR`, `CARGO_HOME`, `TEMP` and `TMP` to D-drive paths
before running Cargo or the audit tools.
