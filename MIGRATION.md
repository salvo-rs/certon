# Migrating to CertManager and Policy

Version 0.3.0 introduces the following breaking API changes from 0.2.x.

Replace `Config` / `ConfigBuilder` with `CertManager` / `CertManagerBuilder`.
Settings such as `config.key_type` and `config.ocsp` now live under
`manager.policy`. Builder setters remain available. Use `.policy(policy)`
to supply a complete policy. Policy supports cloning, debugging and equality.

| Old method | New method |
| --- | --- |
| manage_sync / manage_async | manage / manage_in_background |
| obtain_cert_sync / obtain_cert_async | obtain / obtain_in_background |
| renew_cert_sync / renew_cert_async | renew / renew_in_background |
| revoke_cert | revoke |
| tls_config | server_config |
| client_tls_config | client_config |
| load_cert_from_storage | load_certificate |

At the crate root, replace `tls_config` with `manage`, `manage_sync` with
`obtain`, and `manage_async` with `obtain_in_background`.
Immediate operations are still async Rust functions and must be awaited.

Import `IssuerPolicy` and `CertificateSelector` from the crate root or
`certon::policy` instead of `certon::config`.
