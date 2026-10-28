# Migrating to CertManager and Policy

Version 0.3.0 introduces the following breaking API changes from 0.2.x.

Construct `BoundTlsListener` with `BoundTlsListener::new(listener, acceptor)`
instead of a struct literal. It now owns bounded handshake state. Its public
`listener` and `acceptor` fields and `into_parts()` remain available for custom
accept loops. `accept()` runs up to 256 handshakes with a ten-second deadline
by default, skips invalid/timed-out handshakes, and returns the next completed
connection. Use `BoundTlsListener::with_limits(listener, acceptor, limits)` for
custom nonzero limits. Cancelling `accept()` preserves admitted workers and
their original deadlines. Dropping the wrapper or taking its parts aborts
pending convenience handshakes. Custom loops using the raw parts must supply
their own concurrency and handshake deadlines.

`CertManager::client_config(domain, roots)` now requires the server trust roots
as its second argument (`rustls::RootCertStore` or `Arc<RootCertStore>`). Populate
them with the CAs trusted by your application. Previously this convenience
method constructed an empty trust store, causing normal TLS servers to fail
with `UnknownIssuer`. The managed certificate still supplies the client's mTLS
identity; it is not used to infer server trust. Use `client_credentials()` to
build a custom rustls configuration when you need other verification policies.

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


Certificate lifecycle corrections:

- `listen()` now returns `BoundTlsListener`, which owns both the bound TCP
  listener and `TlsAcceptor`. Use `.accept().await`, its public `.listener` and
  `.acceptor` fields, or `.into_parts()`. Previously the bound socket was dropped
  before returning.
- Crate-level `manage()` / `obtain()` now configure a default ACME issuer and
  HTTP-01 / TLS-ALPN-01 solvers. They keep CA agreement disabled. For a new
  account, review the CA's terms and explicitly use
  `manage_with_agreement(domains, true)` / `obtain_with_agreement(domains, true)`
  (or `listen_with_agreement(domains, addr, true)`),
  or configure `AcmeIssuer::agreed(true)` on your own manager. Existing accounts
  and certificates can still be loaded without asserting new consent.
- First issuance and renewal publish validated certificates to the live cache
  before returning. A mismatched key or SAN is rejected before saving.
- Manager maintenance uses its configured `CertStore` and renewal window.
  Low-level callers can use `maintain::start_maintenance_with_policy` with
  `ReasonedRenewFn` / `RenewalReason` to distinguish expiration from revocation.
  The legacy low-level callback remains supported; callbacks using that API
  must implement their own revocation handling.
- `manage_in_background` now applies backpressure and may wait while its
  manager family's queue is full. A manager and its detached copies share
  four execution slots and capacity for 68 admitted jobs (four running plus
  64 pending). Cancelling the caller drops its not-yet-admitted submissions;
  already-admitted jobs continue running.
- Queued management retries acquire execution capacity per attempt; backoff
  does not keep an execution slot or a domain/leaf transaction lock. Each
  attempt reacquires its locks and rechecks current storage and revocation.
  At most 64 admitted jobs retain retry records, reserving four admission
  records for new work. If retention is full, another failed job ends with a
  `cert_failed` event containing `background: true` and
  `error_kind: "retry_backlog_full"`, as well as an error log; resubmit it later.
  A successful `manage_in_background` return confirms submission, not final
  issuance. No extra tasks are spawned to bypass these bounds.
- Set `CertManagerBuilder::background_retry_config(RetryConfig)` to configure
  queued management retries. The default remains 30 days. One absolute budget
  starts at admission and includes execution-queue waits and every backoff;
  attempts do not restart it. Empty intervals or overflowing durations return
  a configuration error before any submissions. Direct `obtain_in_background`,
  `renew_in_background`, and arbitrary public `JobQueue::submit` futures keep
  their existing semantics.
- Each maintenance loop has a separate four-execution, 68-admitted expiration
  renewal budget. These are not process-wide limits: foreground operations,
  handshake on-demand work, and sequential OCSP force-renewals are independent.
  Renewal admission cannot block OCSP checks. Stopping maintenance cancels
  waiting submissions, aborts admitted renewals, and awaits their cleanup.
  Owned revocation workers still continue if their caller is dropped.
- Public `JobQueue::new` and `with_max_concurrent` keep unbounded admission.
  Use `JobQueue::with_limits` for bounded admission; `submit` waits before
  registering or spawning. Dropping a bounded queue aborts its admitted work;
  `shutdown().await` also waits for cleanup.


Revocation now records durable, fail-closed intent before contacting the CA.
Once intent is written, that leaf is removed from the local cache and cannot
be loaded by manager or managed reload APIs, even after a provider error or
caller cancellation. Pending and confirmed markers live at
`revocations/<leaf-sha256>.json` in `Storage`, including when using a custom
`CertStore`. Keep them when migrating storage; deleting a marker can re-enable
a revoked certificate. Alternate chains with the same leaf are also blocked.

`revoke()` runs an owned task and shares the issuance/renewal domain lock.
Renewal and revocation also share a leaf lock when custom stores expose
multiple domain aliases for the same certificate. Dropping
its future does not cancel the task; await it to observe errors. A confirmed
revocation with failed certificate cleanup can be retried without a second CA
request. Process/runtime shutdown, or failure to record confirmation, may
leave pending intent and an uncertain provider outcome: reconcile with the CA
and retry cleanup. Provider retries must tolerate an already revoked leaf.
Use `renew(domain, true)` to replace a pending/confirmed resource with a new
leaf when cleanup has not completed; normal loads and non-forced renewal
continue to reject the old leaf. After cleanup, use `obtain()` to issue afresh.
Never restore the old leaf.
Issuers without revocation support now return an error instead of silently
removing local files and reporting success.

Instances must share both `Storage` (markers and locks) and their compatible
`CertStore`. An already active cache in another process is invalidated on its
next renewal/OCSP maintenance tick, or after an explicit
`manager.refresh_revocations().await`. Applications requiring prompt cluster
invalidation should broadcast their own event and call that method. Existing
TLS sessions and independently cloned signing keys are not withdrawn. Marker
read errors prevent storage reload. A custom store writer that bypasses the
shared lock must provide its own atomic compare-and-delete coordination;
certon's leaf recheck protects replacements already visible before cleanup,
but its current `CertStore` trait cannot implement CAS against external writers.

`Revoker` has a default `revoke_resource(&CertificateResource, reason)` method
which delegates to the existing PEM `revoke` method. Existing implementations
need no changes. ZeroSSL REST overrides it to use
`resource.issuer_data["certificate_id"]`; call the resource method when using
that issuer directly. Passing JSON metadata in the PEM argument is no longer
supported. A successful HTTP status alone is not provider confirmation:
ZeroSSL's response must contain a positive success field and no error.


ACME revocation retries treat only HTTP 400 with the exact RFC 8555
`urn:ietf:params:acme:error:alreadyRevoked` problem as provider confirmation.
This lets pending intent recover when the CA succeeded but recording local
confirmation failed. Other problem types and HTTP statuses remain errors.
See [RFC 8555 section 7.6](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.6).
Detached revocation workers log operation errors even when their caller no
longer awaits the result. Revocation refresh reports partial failures while
continuing to quarantine other leaves with readable intent markers.

The Result-returning unmanaged cache helpers reject a quarantined leaf with
an error. Replacing admission checks revocation and updates membership under
one lock, so stale input cannot delete a valid replacement before rejection.
The low-level `CertCache::add()` signature stays unchanged and silently ignores
quarantined leaves.

## Retry budgets and dynamic rate limits

`do_with_retry` rejects an empty `RetryConfig::intervals` before running the
operation. `max_duration` now covers both backoff and the in-flight async
operation; reaching it drops that operation's future, so custom operations must
be cancellation-safe. Like other Tokio timeouts it cannot preempt blocking code
that does not yield. The historical `max_retries` setting still counts failed
attempts, including the initial attempt; zero means unlimited.

`RateLimiter::configure(max_events, window).await` updates both settings
atomically and returns a configuration error without changing state for invalid
pairs. Use `(0, Duration::ZERO)` to disable limiting. Existing individual setters
retain their signatures and now reject invalid pairs with the same panic policy
as `new`, rather than leaving a waiter spinning forever. All updates wake
existing waiters to recheck the policy; recorded event history is retained.

Distributed HTTP-01 challenge storage:

- `DistributedSolver` now writes version-2 JSON entries at
  `<issuer-prefix>/challenge_tokens/v2/<SHA256(canonical-domain)>/<SHA256(token)>.json`.
  The payload binds the original case-sensitive token to its canonical domain.
  Tokens for one domain no longer share a read/modify/write JSON map.
- `HttpChallengeHandler::handle_http_request` looks up the exact Host and token
  without listing unrelated challenges. It returns 503 on storage failures;
  `try_handle_http_request` exposes the underlying error. Malformed tokens and
  Hosts are rejected before storage access. The local token map must be bound
  with `.with_domain("example.com")` to serve Host-aware requests. The legacy
  path-only API still supports local maps; bind a domain to enable storage.
- Readers also accept the previous `<safe-domain>.json` token map for canonical
  DNS names and IPv4 addresses up to 250 ASCII bytes, leaving five bytes for
  `.json` within a portable 255-byte filename component. Longer domains use v2
  only; impossible legacy filenames are skipped during both reads and cleanup.
  Ambiguous legacy IPv6 keys are not accepted.
  Legacy cleanup preserves sibling tokens under a storage lock and reports
  backend or corrupt-JSON errors instead of treating them as empty data.
  Stop old distributed writers before upgrading the cluster: old writers do
  not honor the new cleanup locks, and old readers cannot consume v2 entries.
  Finish or retry pending challenges during this coordinated upgrade.
- Challenge tokens/thumbprints are limited to 512 base64url characters. New
  entry JSON is limited to 4 KiB on reading; legacy maps to 64 KiB. Storage is
  a whole-value API, so backends must separately enforce allocation limits.

HTTP redirect listener resource limits:

- `HttpsRedirectHandler` defaults to 256 admitted connections per listener,
  a 10-second total acceptance-to-response deadline, and a 16 KiB header cap.
  Configure these with `.with_limits(RedirectLimits { ... })`. Over-budget
  connections are closed without spawning tasks; oversized headers receive
  431 when the connection can write within its remaining deadline.
- The deadline includes fragmented/slow header reads and response writes;
  incoming bytes do not extend it. The listener waits for complete headers.
- Abort the `JoinHandle` returned by `.start()` and await it to stop the
  listener. Its owned connection tasks are cancelled on shutdown. Dropping
  that handle only detaches the server, following Tokio's normal semantics.


## ACME transport policy

`AcmeClient::with_http_client` has been replaced by
`AcmeClient::with_http_client_builder(directory_url, builder)`. This is a
breaking API change: calls passing an already-built client must be migrated.
Pass a configured
`reqwest::ClientBuilder` without calling `.build()`. Certon preserves its roots,
proxies, resolver, headers and timeouts, then overrides its redirect policy
before building. An opaque, already-built client cannot expose or replace its
redirect policy, so that entry point was removed rather than permit a request
to be sent before detecting a downgrade.

ACME directory fields and all subsequent operation URLs are checked before
sending. HTTPS directories require HTTPS endpoints, including for localhost.
Each redirect hop is checked before following; an HTTPS-to-HTTP redirect is
rejected even when its destination is local. A directory explicitly served
over HTTP retains the existing localhost, 127.0.0.1, ::1, .localhost and
.internal development exceptions. If that directory upgrades to HTTPS, its
returned endpoints must also use HTTPS. Redirect chains are limited to ten
hops. Custom CA roots configured on `AcmeIssuer` continue to work.

ACME uses its own cached issuer transport with the common HTTP defaults.
OCSP's shared transport still supports HTTP responders; no global HTTPS-only
restriction is applied to it.

## Async key generation

Async certificate issuance/renewal and account creation now offload new-key
computation to Tokio's blocking pool. All configurable key algorithms share a
process-wide budget of two admitted jobs, including jobs waiting for a blocking
thread. Cancelling a caller does not interrupt submitted CPU work or release
its admission early; the actual worker holds it until completion.

Use `crypto::generate_private_key_async` in Tokio async applications. The
existing synchronous `generate_private_key`, `StandardKeyGenerator::generate_key`
and `account::new_account` remain synchronous and outside that budget. The
fixed P-256 TLS-ALPN challenge-key generation path is unchanged.


## Initial certificate loading and validity

`CertManager::cache_certificate` now returns `CertError::NotYetValid` or
`CertError::Expired` before adding invalid-time credentials to the serving
cache. An existing usable certificate remains available when that load fails.
`load_certificate` is a read-only view of the best stored resource; it may
return a certificate that needs renewal and does not publish it.

`manage` and `obtain` repair future/expired stored certificates through the
normal renewal path, publishing only after the replacement is validated.
A failed CA request returns an error without caching the unusable resource.
Already-managed fast paths keep invalid-time entries as lifecycle metadata so
maintenance retains their SAN coverage. TLS selection filters these entries,
including custom certificate selectors, while metadata lookups still return
them. Maintenance repairs future certificates as well as expiring ones.
Valid cached siblings remain available during failed repairs. Background
management uses the same checks.
