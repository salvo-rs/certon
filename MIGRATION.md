# Migrating to CertManager and Policy

Ordinary maintenance renewal attempts now retain a retry deadline for each
current issuer and DER leaf after failure (including interrupted marker or
storage preflight work). Transient failure delays are 60, 120, 240, then at most
300 seconds from completion, using the monotonic clock. Callback errors classified
as permanent by the existing retry policy wait at least the normalized renewal
check interval (normally 600 seconds), so disabling ARI does not make those failures
retry more aggressively than the periodic scan. Other certificates' ARI selected times
still admit their first attempts promptly; they no longer retry an already
failed leaf. The retry timer also wakes maintenance without waiting for a new
ARI recommendation or the normal periodic scan. Same-leaf metadata updates and
alternate chains preserve the deadline. A different replacement leaf starts
independently. Success clears the failure record; removed or unmanaged leaves
are discarded on the next scan or their in-flight completion. Queued work
cancelled before execution does not count as a failed attempt. Shutdown and
maintenance restart discard this process-local state.

The existing execution/admission limits remain shared across these attempts.
Old and new leaves for one name can have separate jobs; the built-in manager
continues to serialize its transactions with the domain lifecycle lock. Custom
renewal callbacks still receive the observed name and must recheck their own
current resource after asynchronous waits, and publish their replacement on
success. A callback that reports success without replacing a still-due leaf
can be invoked again on a later renewal wakeup. Independent periodic revocation
marker scans and forced OCSP revocation recovery are not gated by this ordinary
renewal backoff. This state belongs only to each automatic maintenance loop;
explicit renewal and background management retain their own retry policies.

ACME endpoint diagnostics now show only the HTTP origin (scheme, host and
port), omitting user information, private paths, query strings and fragments.
Client/issuer/account Debug output follows the same rule; issued-certificate
metadata and stored-resource issuer data are redacted in Debug output.
Actual request URLs, JWS protected URLs,
returned metadata and persistent account identities retain their original
values. ACME problem details supplied by the CA remain available for diagnosis;
this change does not sanitize arbitrary provider text or application logging.
Optional ARI HTTP error diagnostics retain the status without logging the body.

`client_credentials` and `client_config` now select a time-valid client identity
that is not locally known to be revoked, falling back to usable cached or
stored siblings. Every construction reads persisted revocation intent, including
with a warm cache; marker backend errors propagate. These methods do not query
OCSP responders or require a server Must-Staple response for client authentication.
Client-auth-only certificates remain supported, and `client_config` still uses
the explicitly supplied roots to authenticate the server. Returned keys and
configurations are snapshots: later revocation or expiry requires constructing
fresh credentials; existing connections/configurations are not invalidated.

Short-lived certificates containing the actual TLS Feature `status_request`
(Must-Staple, feature 5) now receive OCSP staples even below seven days of
validity. Other short-lived certificates retain the existing skip optimization.
The certificate's extension is authoritative, independently of the CSR policy.
Managed obtain/renew rejects an unusable Must-Staple response before saving,
and managed cache publication rechecks that a verified Good staple is still
current before replacing a working entry.

After a Must-Staple response expires, the certificate remains tracked for
maintenance but is excluded from default and custom TLS candidate selection.
A usable compatible sibling or configured fallback can take over. Without a
usable candidate, an already-configured OCSP callback may request recovery for
a signature-compatible key, with the same concurrency cap and cooldown; a
cached Must-Staple leaf does not trigger duplicate on-demand issuance. A fresh
authenticated in-memory response survives storage/responder failure only until
its original expiry.
The public reload helper obtains a required staple before guarded admission;
ordinary certificate reloads keep their existing behavior.

Live OCSP staples now have a verified serving deadline. New certificate
lookups omit responses after `nextUpdate` (or 24 hours after `thisUpdate` when
`nextUpdate` is absent), and configured handshake refresh callbacks become
eligible at the response's refresh time. Cache publication validates supplied
raw staples outside its lock; arbitrary unverified response bytes are no longer
attached to TLS keys. No fields were added to the public `Certificate` struct.

Maintenance must still be started separately. Once running, it wakes for
individual staple deadlines and newly published staples even when its periodic
interval is one hour. It proactively fetches replacements, keeps an existing
Good response only while fresh during responder outages, and backs off repeated
failures or unchanged responses. Both serving containers share the signing-key
`Arc`; handshakes perform no OCSP parsing or verification. A key already captured
by an in-flight handshake remains an immutable snapshot, as across certificate
replacement or removal.

Managed publication now rechecks certificate validity under the cache's write
lock after asynchronous OCSP/AIA preparation. Failure returns a typed validity
error and preserves existing working entries. Low-level `CertCache::add` and
`replace` still allow historical certificate imports. The OCSP deadline index
stores at most one record per scheduled certificate; unrelated imports do not
wake maintenance. Deadline wakes inspect only due entries, while periodic
polls retain the original cadence for certificates without OCSP support.

Same-hash replacement preserves an OCSP update that arrived during asynchronous
preparation, including its serving containers and retry deadline. Verified
Revoked status stays sticky, and rejecting a stale response still advances a
scheduled retry to avoid an immediate refresh loop.

A leaf marked Revoked is excluded from both default and custom TLS selection;
its metadata remains available for maintenance. A usable sibling can still
serve the name. `replace_revoked` controls automatic replacement, not permission
to serve a known revoked leaf.

`Certificate::with_ocsp` responses are verified when entering the cache. Their
verified status and serving deadline come from the same parse; a signed Revoked
response quarantines the cached entry even during duplicate publication or a
concurrent Good refresh. Invalid or unsigned bytes cannot assert revocation.
Already-verified status supplied by `staple_ocsp` remains authoritative after
that function clears the non-Good response bytes.

Version 0.3.0 introduces the following breaking API changes from 0.2.x.

For external configuration, use `CertManagerBuilder::try_build()` to receive
missing-storage and invalid-policy errors. `build()` remains a convenience
wrapper that panics on invalid configuration. Renewal ratios must be finite
and no greater than one; finite non-positive values keep selecting the default.
Low-level renewal-window checks safely use the default for non-finite or
out-of-range input, so malformed ratios cannot panic maintenance tasks.

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

Subject transformers now run once at the start of each obtain or management
operation, before validating the actual subject, checking storage or acquiring
locks. The result is normalized to lowercase and is the certificate's
managed/storage identifier.
Different aliases for one subject therefore share its lifecycle lock and stored
resource and background queue entry. Retries keep their resolved identity;
explicit resubmission resolves it again. Explicit renew/revoke calls continue
to take managed identifiers.

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
  renewal budget, including its own leaf's revocation-marker check, storage
  preflight and per-domain deduplication. Marker read failures skip that job
  without invoking renewal; a matching marker quarantines that leaf. Jobs
  recheck management after the marker await before starting storage preflight.
  A slow preflight holds one execution slot rather than blocking the scan.
  Queued jobs recheck current management and renewal eligibility before doing
  I/O and before calling renewal; a withdrawn or replaced identity cannot be
  reintroduced by a delayed reload. These are not process-wide limits:
  foreground operations, handshake on-demand work, and OCSP force-renewals are independent.
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

## Invalid certificate responses and issuer fallback

Obtain and renewal now try the next configured issuer when a successful issuer
response contains an invalid certificate, mismatched key, missing requested SAN,
or an expired/future validity period. These responses are never saved or
published. Exhausted attempts still return the last issuer error; `cert_failed`
events now also include `issuer_errors` with every attempted issuer's error.

Revocation checks and certificate-store writes remain outside this fallback:
their errors abort the operation, including errors from custom backends. A
failed operation preserves any existing working cached certificate.

## Bounded revocation refresh reads

Explicit and periodic revocation refreshes read up to eight unique leaf markers
concurrently. A slow marker no longer delays quarantine of other ready leaves;
the refresh still waits for every read and returns the first snapshot-order
error on partial failure. The success count is the number of revoked leaves,
with alternate chains sharing one lookup and quarantine operation.

The full-cache scan is independent of expiration/ARI renewal submission. Renewal
ticks, ARI notifications and OCSP periodic checks coalesce requests into one
scanner with at most one waiting scan; a slow unrelated marker cannot block a
healthy domain's bounded renewal job. The scanner's eight reads and the renewal
jobs' four execution slots are separate budgets, so at most twelve marker reads
from these paths may be in flight in one maintenance loop. Each job still
checks its own marker and fails closed on read errors. Explicit refresh calls
retain their existing behavior of waiting for the complete scan.

Cancelling a refresh or stopping maintenance drops all in-flight read futures;
the scanner spawns no detached work. Renewal and OCSP refresh intervals are
unchanged.

## Certificate revocation target selection

`CertManager::revoke(domain, reason)` now selects the stored resource by time
validity, then latest `notBefore` and `notAfter`, instead of taking the first
configured issuer with a resource. After renewal falls back from CA A to CA B,
the newer B resource is selected even when A's older snapshot remains stored.
The selected issuer/leaf is rechecked after acquiring the shared leaf lock.

Pending and confirmed revocation markers do not affect this ranking: writing
intent alone cannot redirect a retry to an older backup. A confirmed marker
continues to skip the provider call during cleanup retries. Every invocation
selects from current storage and validity state; if another operation replaces
resources or their validity changes, a later call can target a different leaf.

For an explicit issuer, use
`manager.revoke_from_issuer(domain, &issuer.issuer_key(), reason).await`.
This retains the old ability to revoke an issuer's certificate even when its
private key is damaged or its SAN/time validity is unsuitable for serving.
Other issuers are neither consulted nor used as fallbacks for this operation.
Unknown issuers, unsupported selected providers and backend failures return
errors. This binds the issuer, not an overwritten historical leaf.

Both methods revoke one selected stored resource. They do not revoke every
issuer resource or an independently imported cache sibling, close existing TLS
sessions, or invalidate exported keys. Applications that require a domain-wide
shutdown must also stop issuance and explicitly handle all their credentials.

## Concurrent OCSP maintenance

Maintenance refreshes up to eight distinct certificate hashes concurrently. A
slow responder no longer holds up the other admitted refreshes. Refresh futures
are borrowed by the maintenance loop and are dropped when it stops or is aborted.

Verified revocation is still published to the cache before requesting renewal.
Force-renewal requests use an independent queue with four executions and at most
64 waiting requests, deduplicated by leaf identity. Full admission is logged and
retried on the next OCSP deadline (30 seconds for a revoked leaf); OCSP refreshes
never wait for queue capacity or for a CA renewal. Shutdown cancels these requests
and drops their callback futures before releasing their deduplication records.

The built-in manager callback rechecks both the cached observation and shared
storage after lifecycle lock waits. A healthy replacement is only reloaded;
a replacement independently verified revoked or due follows its own single
renewal attempt. Custom
`maintain::start_maintenance*` callbacks retain their existing signature and
receive the domain observed at dispatch; they must recheck their own resource
identity after asynchronous waits before forcing a replacement. Maintenance
does not wrap a callback in a long retry/backoff loop.


## Emergency renewal for short-lived certificates

The emergency window now uses the smaller of 24 hours and the default renewal
fraction (1/3) of the certificate's total validity. A six-hour certificate enters
this window with two hours left, a 24-hour certificate with eight hours left,
and a 48-hour certificate with 16 hours left. Certificates valid for at least
three days retain the existing 24-hour ceiling. Expiration and the final 1/50
of the lifetime remain independent safety fallbacks.

Fresh short-lived certificates no longer trigger repeated non-forced renewals
merely because their entire lifetime is below 24 hours. The configured ordinary
ratio and ARI selected time still apply before the emergency window. Emergency
renewal continues to override a later ARI point or a smaller configured ratio;
the cap uses the default ratio rather than weakening that safety rule. Future
or nonpositive validity intervals need repair, while raw metadata APIs remain
available for lifecycle planning.

## Automatic ARI renewal scheduling

The default manager lifecycle now fetches RFC 9773 renewal information after
successfully saving and publishing a newly issued certificate. Maintenance also
refreshes existing managed leaves at the CA's `Retry-After` deadline, independently
of the normal ten-minute renewal scan. This integrates renewal scheduling only;
ACME order `replaces` support is not included.

`CertIssuer::renewal_info` is an optional async extension with a default `None`
implementation, so existing custom issuers continue to work. `AcmeIssuer` uses an
unauthenticated GET and does not register an account just to read ARI. HTTPS and
response limits are the same as other ACME endpoints. `AcmeError` adds the
`RenewalInfoTemporary` variant to classify temporary ARI server failures;
exhaustive matches on that enum must account for the new variant.

Local state lives at `ari/<sha256-issuer>/<leaf-hash>/state.json` in `Storage`,
independently of `CertificateResource` and issuer-specific metadata. The selected
time is stably derived from the leaf and normalized window and is explicitly
persisted; unchanged windows retain their point across refreshes, restarts and
instances. A changed valid window selects a new point. Shared instances use the
existing storage lock contract. Alternate chains of one leaf share this state.

Valid ARI takes precedence over the ordinary renewal ratio, while expiration and
the emergency rules (the smaller of 24 hours and the default lifetime fraction,
or the final 1/50 of lifetime)
remain safety fallbacks. Invalid/unavailable ARI uses the ordinary ratio. A
transient refresh failure retains the previous valid point and backs off, reaching
the six-hour fallback after eight failures. `Retry-After` is bounded to one minute
through one day; unsupported/invalid responses use a six-hour negative cache.

All advisory refresh work has a 30-second total deadline, including lock/storage
waits; its endpoint request has a 20-second deadline so timeouts can persist their
backoff. The initial best-effort fetch runs after publication and may add up to
30 seconds to a successful obtain/renew call. Sidecar reads while planning are
bounded to five seconds, and forced/revoked renewal planning bypasses them.
Maintenance owns at most four concurrent ARI refreshes and cancels them on stop.

ARI failures never turn an already saved certificate into a failed issuance or
cause a duplicate CA order. A failed sidecar write keeps the current process's
accepted point across reload/renew, but a subsequently changed persisted record
from another instance wins. Late responses are bound to their original issuer
and leaf and cannot modify a replacement's schedule. Certificate storage,
validation and revocation-marker failures retain their existing error behavior.

`Policy::disable_ari` now fully bypasses fetching, sidecar I/O and ARI decisions,
including previously cached suggestions. It does not erase suggestions needed by
another enabled manager sharing the cache. The public low-level
`Certificate::needs_renewal` has no policy argument and continues to use attached
ARI, with a stable derived point if a valid window has no explicit local choice.

## ARI sidecar retention

Version-1 ARI sidecars now include an optional `leaf_not_after`, derived from
the actual leaf certificate DER. Positive recommendations, unsupported-response
negative caches and request-error records all carry it. Active ARI refreshes
upgrade existing records under the ARI storage lock, including records with a
future retry deadline or an issuer no longer configured. This metadata-only
upgrade does not fetch renewal information or change the selected time, retry
deadline or failure count. Planning/attach reads remain read-only, and expiry
metadata alone does not override a locally accepted, not-yet-persisted choice.

`clean_storage` also collects version-1 records at the exact
`ari/<64-lowercase-hex-issuer-hash>/<64-lowercase-hex-leaf-hash>/state.json`
path when their identity matches and `leaf_not_after` plus the existing
`expired_cert_grace_period` is strictly before the run's timestamp. A record can
be collected after its certificate resource has been replaced or removed. ARI
deletions are logged separately; public cleanup options and certificate/OCSP
counters are unchanged.

The borrowed cleanup API does not acquire ARI locks or provide atomic
compare-and-delete. Coordinate cleanup externally with issuance/renewal, every
instance's ARI refresh and metadata upgrade, and completion of already submitted
storage writes. Unknown versions, malformed or mismatched records, expiry/grace
arithmetic overflow and legacy records without an expiry are retained. Live
legacy records are upgraded gradually through refresh; legacy orphan records
whose leaf DER is gone cannot be upgraded automatically. Mixed deployments with
older writers may still produce records without an expiry and retain those
records until the writers are upgraded.

## Recovery after a shared Must-Staple replacement

An OCSP recovery queued for an old revoked leaf now plans against the resource
currently selected from shared storage. A verified revoked replacement receives
one forced renewal attempt; a due or time-invalid replacement follows normal
renewal even if its required staple is unavailable. A fresh replacement with
Unknown or unavailable OCSP does not cause forced issuance, and the Must-Staple
serving requirement is unchanged.

Recovery rechecks the stored identity after asynchronous preparation and admits
management only while the original revoked observation is still managed. Removing
or unmanaging that observation during issuer discovery cannot let a stale job
create another managed entry. Independently verified revocation of an existing
incoming cache entry still quarantines it and emits its notification.


## OCSP responses containing multiple certificate statuses

Verified OCSP paths now select the unique `SingleResponse` matching the requested
certificate's full CertID: the existing SHA-1 request hash algorithm, issuer name
hash, issuer key hash and serial number. An unrelated entry may appear before the
target or have expired without making a fresh target unusable. Missing or duplicate
target entries, including conflicting statuses, are rejected.

The complete original response remains the TLS staple. Its full ResponseData
signature, responder authorization and the selected target's time/status checks
are still validated; selection does not re-encode or sign a reduced response.
No public API signatures or supported CertID hash algorithms change.

## OCSP status across cached chains

An authenticated OCSP Revoked result applies to every live cached encoding of
that leaf, including unmanaged chains and different store aliases. Status and
serving containers change atomically under the cache publication lock. Each
retained affected chain receives its update notification and recovery deadline;
unrelated leaves retain their own status and signing key.

Managed and raw publication recheck live leaf evidence after asynchronous OCSP
preparation, and stale Good refreshes cannot restore a revoked sibling. The
Result-returning unmanaged import/replacement helpers reject such a leaf before
removing any existing certificate. This does not change persistent explicit
revocation intent or introduce a new lifetime deny-list for OCSP metadata.

## ZeroSSL ACME renewal information

`ZeroSslIssuer` now delegates renewal-information queries to its inner ACME
issuer. An advertised ARI endpoint can supply a renewal window and retry delay
without registering an account or provisioning new EAB credentials. Unsupported
ARI still returns no recommendation, and temporary ARI errors retain the existing
retry handling. This change applies to the ACME issuer; the separate ZeroSSL REST
API issuer is unchanged.

## ACME IP identifiers and challenge names

`AcmeClient::new_order` and `new_order_with_options` now encode parsed IPv4 and
IPv6 addresses as RFC 8738 `ip` identifiers. Address values use canonical text
(including compressed lowercase IPv6); DNS values retain their previous wire
representation. A mixed order preserves its input order and profile/validity
options. This requires a CA and, where applicable, a profile that supports IP
issuance; it does not make every ACME CA accept IP certificates.

IP authorizations never select DNS-01. HTTP-01 remains preferred when offered
and enabled. TLS-ALPN-01 proof certificates keep a single IP SAN, but their
challenge lookup uses the RFC 8738 reverse-map SNI (`in-addr.arpa` or
`ip6.arpa`). Both the standalone solver and `CertResolver` challenge-certificate
set/remove APIs use the same mapping. Distributed challenge storage and global
proof ownership retain the canonical IP identifier, not its reverse DNS name;
the distributed wrapper delegates to the same standalone solver. There is no
new automatic cross-instance TLS proof reader.

The built-in HTTP/TLS challenge listeners still bind IPv4. Native IPv6
validation needs an IPv6-facing proxy or a custom listener/solver that forwards
the appropriate HTTP Host or reverse-map TLS SNI. No dual-stack binding change
is included. For ordinary application TLS, IP clients do not send DNS SNI;
configure `CertManagerBuilder::default_server_name` with the canonical IP for
that listener instead of relying on a DNS SNI cache lookup.

## Runtime certificate cache resizing

`CertCache::set_options` now applies a finite `capacity` immediately, randomly
evicting managed certificates until the total cached count fits or no managed
entries remain. Eviction uses the normal removal bookkeeping and emits removal
events after releasing the cache and configuration locks. An in-flight publisher
uses the latest capacity when it acquires the publication lock, even if it
captured older callback options before the resize.

Capacity still counts all entries, and unmanaged certificates remain protected
from eviction. If protected entries alone exceed the limit, the total can remain
above it; the existing insertion policy also permits a new entry while evicting
one older managed entry when available. A capacity of zero remains unlimited
and does not evict existing certificates. Raising the limit does not restore
previously evicted entries.

## OCSP revocation timestamps

`OcspResponse::revoked_at` now reads the GeneralizedTime directly from RFC 6960's
IMPLICIT RevokedInfo content, including responses with an optional revocation
reason. An extra inner SEQUENCE is no longer mistaken for the required encoding.
Missing or invalid time metadata remains `None` while the status stays Revoked.
Certificate identity, full signed-envelope verification and freshness checks
retain their existing behavior.

## Explicit Must-Staple recovery

Explicit foreground and background management can recover a still-valid leaf
whose previously signed Good OCSP staple has expired, without obtaining another
certificate. Background shortcuts require the same candidate to be serviceable
and not due for renewal; a due cached leaf remains eligible for resubmission.

Managed duplicate admission may install an authenticated fresh Good response
into an unusable Must-Staple entry only when its leaf identity and original
metadata version still match. It retains the existing signing key and unrelated
management metadata. A healthy current staple, concurrent status publication,
verified revocation and leaf quarantine keep their existing protections. Raw
metadata-only duplicate imports do not gain this recovery behavior.

## DNS-01 provider zone discovery

`Dns01Solver` now discovers the provider zone through SOA queries before creating
TXT records. Queries use the solver's configured resolvers and absolute names,
with a ten-second total discovery budget. Only an SOA owned by the queried name
selects a zone. Missing SOA, invalid resolver configuration, transport failures
and unrelated CNAME/SOA answers fail before any provider write; configure the
challenge override domain explicitly for CNAME delegation. Cleanup uses the
zone and relative name remembered at presentation, without another DNS lookup.

The public synchronous zone helper remains a last-two-label heuristic, and the
public asynchronous helper retains its best-effort fallback. Neither heuristic
populates the confirmed SOA cache. Only successful system-resolver discoveries
use that bounded five-minute cache; custom resolver views are uncached. Clear
it with `clear_zone_cache` after system DNS configuration or delegation changes.
Challenge names and overrides are normalized to lowercase fully qualified names.

## ACME account identity and mutable contacts

`AcmeIssuer` now consistently loads, saves and recovers an account under its
configured email identity. Changing or clearing contacts in `new_account_func`
does not move that storage slot, generate another account key on restart, or
cause another instance with the same configuration to register again. Existing
snapshots in the configured slot keep their current key; supplied keys and the
new-account callback continue to apply only when that slot is absent. Public
`account::save_account` and `delete_account_locally` retain their contact-based
storage behavior and signatures.

For an old account saved under a callback-modified contact, migration examines
only that exact contact slot. It reuses the account only when the post-callback
key has the same public identity, the stored account has a registration URI,
and its contact identifies that legacy slot. Equivalent private-key PEM formats
are accepted. Missing proof, mismatched keys, malformed resources or a contact
pointing to another identity-bound slot produce an account error rather than
guessing an account or registering a replacement. Configure the original
`account_key_pem` (or provide the same key through the callback) to prove ownership
when migrating an old account whose generated key otherwise cannot be inferred.
The original alias remains readable after the complete identity snapshot is saved.

An `accountDoesNotExist` response carries its failed account snapshot into
recovery. Under the CA registration lock, recovery preserves newer stored/cache
generations, removes only contact aliases with the same failed key and URI, and
removes the configured snapshot last. Failed or cancelled alias cleanup can be
retried without reviving the invalid account. Verified legacy registration/key
pairs in either slot first receive an atomic snapshot, so interruption between
deleting their old files retains the complete proof needed for a retry.
Use upgraded writers for consistent
recovery; older versions still remove accounts using their primary contact.

## Storage cleanup retention overflow

`clean_storage` now retains certificate and OCSP assets when their configured
retention duration or resulting deletion timestamp cannot be represented.
Very large durations such as `Duration::MAX` no longer silently use the shorter
default retention period, and timestamp arithmetic no longer panics. This
matches the conservative overflow behavior already used for ARI sidecars.

Default, finite and zero durations keep their existing meaning: cleanup deletes
an asset only when its expiration or modification time plus retention is strictly
before the cleanup run's timestamp. The public options and result counters are
unchanged. Callers must still coordinate cleanup with writers as documented.

## Public ACME polling budgets

The timeout passed to `AcmeClient::poll_authorization` or `poll_order` now
bounds the complete operation, including an in-flight request, nonce retry,
response-body read and backoff. Timeout errors retain the `Error::Timeout`
classification; terminal ACME statuses and their error details are unchanged.
A timed-out request is cancelled, and a subsequent call can reuse the client.
Large duration budgets do not use unchecked `Instant` addition.

The existing high-level issuer deadline remains in place. Callers of these
lower-level polling APIs now receive their requested total budget even when
a CA stalls before headers or while sending the response body.

## Capacity when taking over imported certificates

Promoting an existing unmanaged certificate to managed now reclaims older
managed entries until the total cache count fits its finite capacity, or no
other managed entry can be evicted. The newly promoted certificate and remaining
unmanaged imports stay protected, matching the existing admission exception.
Once no unmanaged entries remain, the cache converges to its configured limit.
Promotion preserves the retained certificate's signing key, OCSP and ARI state,
and merges management metadata as before. Evictions use the normal removal
indexes and events; a metadata-only duplicate of an already managed entry does
not gain a new eviction side effect. Zero capacity remains unlimited.


## Long certificate names in filesystem storage

Derived certificate and OCSP keys now fit the common 255-byte filename-component
limit, including accepted 253-character ASCII DNS names and long wildcards.
`safe_key` itself is unchanged. Ordinary site folders, legacy filenames and locks
retain their previous paths.

A sanitized site component longer than 255 bytes uses
`certificates/<issuer>/_certon-long-v1/<sha256(sanitized-name)>`.
Legacy `.crt`, `.key` and `.json` basenames longer than 250 bytes use
`_certon-long-v1-<sha256(sanitized-name)>`; private snapshots still end in
`_certon/resource.v1.key`. OCSP filenames longer than 255 bytes use
`ocsp/_certon-long-v1/<sha256(original-OCSP-filename)>`. Digests cover the full
previously derived identity, with no truncation of DNS names. The existing
`CertificateResource::names_key` normalization remains unchanged.

Readers prefer the canonical complete snapshot, then the old long-path snapshot,
then compatible legacy assets. Generic storage backends can still read their old
long keys. Missing assets allow fallback; malformed snapshots, partial legacy
sets and backend errors do not. Deletion removes every legacy generation before
any snapshot, with the canonical snapshot last. Cleanup groups physical layouts
by verified identity so an expired old copy cannot delete a current snapshot.
Digest directories without a readable snapshot are retained conservatively:
cleanup cannot recover their original identity from a digest alone.

FileStorage uses `locks/_certon-long-v1/<sha256(sanitized-lock-name)>.lock` only
when the old lock filename exceeds 255 bytes; logical distributed lock names are
unchanged. Its compatibility reads recognize an unrepresentable old component
only after an actual OS filename-length error, leaving permission and whole-path
errors visible. Upgrade all FileStorage writers before using these long names;
older versions do not understand the bounded layout or long lock paths. Existing
atomic publication, private-file permissions and cancellation behavior are retained.

## Exact ACME account-missing recovery

The issuer deletes and recreates a stored account only when order creation
returns HTTP 400 with the exact parsed problem type
`urn:ietf:params:acme:error:accountDoesNotExist`. Human-readable details, request
URLs, malformed JSON, nonstandard problem URIs and other HTTP statuses cannot
trigger account replacement. This also applies after the one `badNonce` retry.
The account lookup helper likewise recognizes only that exact HTTP 400 problem
as an absent account.

Public order methods keep returning their existing errors for account-missing
responses; the issuer uses a private classified result to enter recovery. The
existing shared account lock and newer-account identity checks remain in place,
and order creation is retried only once after recovery. Other failures propagate
without deleting the stored account. No public error variants or signatures
change.


## Same-order ACME finalization recovery

`AcmeIssuer` now continues the existing order when finalization receives HTTP
403 with exactly `urn:ietf:params:acme:error:orderNotReady`. It reads that order's
current state and waits for readiness before retrying the same CSR, account and
finalization URL. It does not register a replacement account, create another
order or replay solved challenges for this recoverable response.

Pending and processing orders use bounded backoff; ready orders that repeatedly
reject finalization also back off. Valid orders proceed to download, while invalid
and unknown states return their available CA error details. Requests, nonce
retries, response bodies and sleeps share the remaining issuance deadline and
the existing 120-second order-operation cap. Cancellation drops the active
operation. The normal successful finalization path has no extra order request.

Public low-level `finalize_order` still returns `orderNotReady` as an error, and
`poll_order` still waits for `valid`, rather than stopping at `ready`. Only the
issuer's internal flow performs this recovery. Other problem types, similar
human-readable text, JSON status fields and responses with other HTTP statuses
do not trigger it. Account-missing and already-revoked recognition remain
restricted to their existing exact HTTP 400 problem contracts.

## Challenge selection follows configured solver capabilities

HTTP-01 and TLS-ALPN-01 are considered only when enabled and their solver is
configured. A TLS-only integration no longer needs to explicitly disable HTTP
just because the CA also advertises an HTTP challenge. The existing preference
among usable solvers remains DNS, HTTP, then TLS; DNS is still excluded for IP
identifiers. A missing intersection produces a no-suitable-challenge error
before any solver is presented.

This check runs only for authorizations that need validation. Already-valid
authorizations can still complete issuance with no configured solver. Public
builder and solver APIs are unchanged.

## ARI deadlines retain periodic revocation scan cadence

An ARI-only renewal wakeup checks revocation markers for the due jobs, rather
than requesting a global backend marker scan for every unrelated cached leaf.
Renewal and OCSP periodic ticks still request global scans, including when OCSP
stapling is disabled. The existing scan concurrency, coalescing and cancellation
limits are unchanged. ARI wakeups still evaluate cached renewal eligibility;
this change removes redundant backend reads, not that in-memory walk.

## OCSP endpoint diagnostics

OCSP responder overrides and AIA issuer-fetch diagnostics now show only the
endpoint's scheme, host and port. User information, paths, query parameters and
fragments are omitted; malformed endpoints use a static diagnostic label.
Transport and response-body errors strip reqwest's embedded URL as well.

This affects logs and error text only. Requests still use the configured URL
and credentials, and retain their existing timeout, size-limit, signature and
serving-admission behavior. Error categories, HTTP statuses and operation labels
remain available for troubleshooting.

## Full ACME directory storage identities

ACME `issuer_key()` now identifies the complete normalized directory URL with
`_certon-ca-v2/<sha256>`. Scheme, non-default port, user information, path and
query distinguish endpoints; fragments do not, and URL-equivalent host case,
default ports and dot segments normalize together. Certificate and account
storage use an additional versioned directory level, so an old URL-derived
slug cannot masquerade as a new digest identity. Account locks use that same
separate namespace. Ordinary custom issuer keys and fixed ZeroSSL wrapper keys
are unchanged. The exact `_certon-ca-v2/<64 lowercase hexadecimal characters>`
identity syntax is now reserved for this namespace; custom issuers must not
choose that syntax for an unrelated provider.

Existing ACME accounts and certificate resources are **not automatically
adopted**. Old records do not identify which full directory endpoint owned their
lossy namespace. If only old resources are found, management and account loading
return a migration error rather than silently sharing them or creating another
account/certificate. Review the full original URL and configured account identity
before upgrading, especially when directories differed by port, query or a path
whose separators collapsed to hyphens. Stop old certon versions first.

After confirming ownership, migrate an account with
`account::migrate_account_ca_identity(storage.clone(), directory_url, email,
&original_account).await?`. Supply the original registered account's key and
registration URI, obtained from your trusted backup/export. Matching that
generation protects against stale migration input; it does not prove which CA
owned an ambiguous old slot. A different destination account is never replaced.
The new private snapshot binds both the normalized directory and configured email
independently of mutable CA contacts. Missing bindings are errors; an explicit
`null` configured identity represents the no-email account.

Migration retains the old record and writes a private, source-generation receipt.
That receipt lets later account-missing recovery retire the known old account
without resurrecting it or blocking re-registration. A changed old generation,
malformed receipt or backend error still fails closed. Migration succeeds only
after both new snapshot and receipt are stored. A failure/cancellation can leave
the complete new snapshot; retry the migration with the same verified account
to finish its receipt. Do not remove legacy records until all old readers are
retired and you have retained an appropriate backup.

For certificates, copying is **not a completed migration**. The operator must
confirm the original full endpoint, pause **all** issuance, renewal, revocation
and maintenance writers for the affected resources (including new managers),
back up the complete old generation outside every active `CertStore`, verify
the new copy and then retire the old active partition. Do not resume writers
until retirement succeeds. Arbitrary public lock names do not coordinate
certon's private lifecycle locks; the offline procedure below requires writers
to stay paused, and its comparisons are not a cross-store compare-and-swap.

Keeping an active old copy would make a later revoke delete only the new copy;
the retained old copy would then correctly trigger the legacy guard and block
another obtain. A complete migration avoids that recurring manual intervention.
Do not bypass the guard for arbitrary old or revoked credentials. Keep a private
backup, rather than the active old partition, for rollback or audit.

This callable procedure uses existing APIs for both key-value and custom stores.
Supply the exact, unmodified source resource you verified, its canonical lookup
name (`expected.names_key()`), a **separate protected backup backend**, and a
generation-specific backup key ending in `.key`. `CertificateResource` serialization omits credential bytes,
so the backup explicitly includes both PEM and private-key fields. Generic backup
backends must protect those secrets; `FileStorage` uses private permissions for
`.key` values on Unix and requires operator-configured Windows ACLs.
Reserve that backup key exclusively for this migration; a preexisting different
backup generation is an error, never an invitation to overwrite the backup.

The procedure first republishes and verifies the complete old generation as a
recovery checkpoint before deleting any old assets. `KeyValueCertStore::save`
atomically publishes a private snapshot; `remove` deletes legacy three-file
assets first and that authoritative snapshot last. An error or cancellation
between legacy deletes therefore leaves the complete source readable for retry.
Custom stores must provide atomic removal, or equivalent snapshot-last cleanup
that keeps the verified full generation readable until retirement completes.
For an opaque non-atomic custom backend without this property, use its own
backend-specific retirement procedure; this example cannot guarantee its recovery.

```rust
use certon::{CertStore, CertificateResource, Error, Result, Storage};

async fn migrate_certificate_offline(
    store: &dyn CertStore, backup: &dyn Storage, backup_key: &str,
    directory_url: &str, name: &str, expected: &CertificateResource,
) -> Result<()> {
    if name != expected.names_key() {
        return Err(Error::Config("migration requires the canonical resource name".into()));
    }
    if !backup_key.ends_with(".key") {
        return Err(Error::Config("private backup key must end in .key".into()));
    }
    let old = certon::storage::legacy_issuer_key(directory_url);
    let new = certon::storage::issuer_key(directory_url);
    let same = |a: &CertificateResource, b: &CertificateResource| {
        a.sans == b.sans && a.certificate_pem == b.certificate_pem
            && a.private_key_pem == b.private_key_pem
            && a.issuer_data == b.issuer_data
    };
    let source = store.load(&old, name).await?;
    let target = store.load(&new, name).await?;
    if source.as_ref().is_some_and(|r| !same(r, expected)
        || r.issuer_key != expected.issuer_key)
        || target.as_ref().is_some_and(|r| !same(r, expected) || r.issuer_key != new)
        || (source.is_none() && target.is_none())
    {
        return Err(Error::Config("migration generation mismatch".into()));
    }
    let bytes = serde_json::to_vec(&serde_json::json!({
        "metadata": expected, "certificate_pem": expected.certificate_pem,
        "private_key_pem": expected.private_key_pem,
    })).map_err(|_| Error::Config("cannot encode private backup".into()))?;
    match backup.load(backup_key).await {
        Ok(existing) if existing != bytes => {
            return Err(Error::Config("backup key contains another generation".into()));
        }
        Ok(_) => {}
        Err(Error::Storage(certon::error::StorageError::NotFound(_))) => {
            backup.store(backup_key, &bytes).await?;
        }
        Err(error) => return Err(error),
    }
    if target.is_none() {
        let mut migrated = expected.clone();
        migrated.issuer_key = new.clone(); // Required for custom stores too.
        store.save(&new, &migrated).await?;
    }
    let current = store.load(&new, name).await?
        .ok_or_else(|| Error::Config("migration destination disappeared".into()))?;
    if !same(&current, expected) || current.issuer_key != new {
        return Err(Error::Config("migration destination changed".into()));
    }
    if let Some(current) = store.load(&old, name).await? {
        if !same(&current, expected) || current.issuer_key != expected.issuer_key {
            return Err(Error::Config("migration source changed".into()));
        }
        // Preserve a complete authoritative source until the final delete.
        store.save(&old, &current).await?;
        let checkpoint = store.load(&old, name).await?
            .ok_or_else(|| Error::Config("source checkpoint disappeared".into()))?;
        if !same(&checkpoint, expected) || checkpoint.issuer_key != expected.issuer_key {
            return Err(Error::Config("source checkpoint changed".into()));
        }
        store.remove(&old, name).await?;
    }
    if store.load(&old, name).await?.is_some() {
        return Err(Error::Config("legacy retirement is incomplete".into()));
    }
    Ok(())
}
```

Publication, backup or retirement errors and cancellation do not imply rollback:
the complete new copy may already exist. Keep writers paused and retry this
procedure with the same verified generation until it succeeds. A matching
destination is reused, a different destination/source is never overwritten or
retired, and an already retired source makes the final retry harmless without
recreating the source checkpoint. A partial source with no verified checkpoint
is still an error: a matching backup or destination alone does not prove the
ownership of its remaining files. Do not ignore load errors or manually delete
those unverified remnants. Preserve the backup after success; no active legacy record needs restoring for an ordinary
later revoke or obtain. ARI advice is fetched again for the new issuer identity;
do not blindly copy old CA advice.
Global leaf revocation markers remain unchanged and still block revoked leaves
across all namespaces and chains.


## Configured ACME email identities

Account paths now use
`acme/<versioned-ca>/users/_certon-account-v2/<sha256>/_certon/account.v1.key`.
The extra namespace layer separates new paths from every old escaped email
spelling. The bounded digest covers the normalized configured identity, with a
separate encoding for no email. It does not use the account's mutable contacts.
The v2 snapshot still verifies both the complete CA binding and configured email.

Mailbox case, a leading lowercase `mailto:` and surrounding address whitespace
keep their existing normalization. Distinct addresses such as
`operator+prod@example.com` and `operator_plus_prod@example.com` no longer share
storage or deletion targets. An empty configured identity and the literal
`default` are now distinct; `new_account("default", ...)` therefore retains
`mailto:default` as its contact instead of treating that string as no email.
Callers remain responsible for configuring a valid CA-supported contact address.
Use an empty string for no email. An old unbound `default` folder cannot prove
whether its original configuration was empty or the literal value; its owner
must confirm that distinction during explicit migration.

Existing accounts in escaped-email folders require the explicit
`account::migrate_account_ca_identity` procedure described above, including
verification of the original configured identity, key and registration URI.
This also applies to v2 snapshots written in the earlier email layout. Migration
retains the source and publishes a source-generation receipt; account-missing
recovery can then replace the account without resurrecting the retired source.
When both an old CA-slug copy and a current-CA bound email source identify the
same account, migration retains the current-CA source's contact and status data.
A completely bound same-CA source belonging to a different email does not block
a fresh independent account, but it cannot be imported as that new identity.
Unbound, changed or unreadable matching sources continue to fail closed.

`most_recent_account_email`, `discover_email` and `get_account_by_key` enumerate
only authoritative snapshots in the new account namespace. Explicitly upgrade
legacy accounts before using these discovery helpers; retained old sources do
not compete with the current account's modification time. Discovery reads and
validates the snapshot's configured identity, never a digest directory name or
the account's contact list. Empty identities remain excluded from email
discovery, while the separate literal `default` identity is discoverable.

## ZeroSSL REST email validation recipients

`ZeroSslApiIssuer` now requires an explicit validation email for every requested
domain. Configure these with the fallible, repeatable
`with_validation_email(domain, email)` method. For example:

```rust,no_run
# use std::sync::Arc;
# use certon::{FileStorage, ZeroSslApiIssuer};
let issuer = ZeroSslApiIssuer::new("your-api-key", Arc::new(FileStorage::default()))
    .with_validation_email("example.com", "admin@example.com")?
    .with_validation_email("*.example.com", "hostmaster@example.com")?;
# Ok::<(), certon::Error>(())
```

Missing recipients fail before creating an order. Duplicate domains and email
list delimiters are rejected; DNS case and a trailing dot are ignored, while a
wildcard remains a separate domain. An issuer may retain selections for domains
outside the current request. After creation, each selected address must appear
in that domain's `validation.email_validation` candidate list. No recipient is
chosen automatically. A human must still approve the validation emails.

The request sends `validation_method=EMAIL` and `validation_email` containing one
selected address per requested domain, in domain order. Validation must be
confirmed before polling or downloading. A matching certificate object with
`pending_validation` or `issued` status is accepted, as is an explicit
`success: true` or `success: 1` confirmation. Explicit failures, contradictory
objects, incomplete responses and invalid JSON stop issuance. Responses are
bounded; diagnostics retain safe error identifiers without echoing provider
bodies or API-key URLs.

The candidate fields are described by ZeroSSL's
[Get Certificate documentation](https://zerossl.com/documentation/api/get-certificate).
The form field and certificate-object response follow the original
[ZeroSSL Go SDK's VerifyIdentifiers implementation](https://github.com/caddyserver/zerossl/blob/d35655e3db16c1a450ccaeeac443b05abbe47993/endpoints.go#L42).
This change applies to the REST issuer; `ZeroSslIssuer` continues to use ACME.

## Maintenance retries for unchanged OCSP Good responses

The first proactive OCSP refresh still occurs at the signed response's existing
refresh deadline. If the responder successfully returns the same verified,
still-fresh Good bytes, maintenance now retries after 60, 120, 240, then at most
300 seconds, with 80–100% jitter. This reduces repeated requests when a CA has
not published a replacement response yet. The retry also remains within one
eighth of the remaining validity and cannot postpone entry into the final hour
before expiry. During that final hour, the existing 1–30 second retry applies.

This is a maintenance scheduling policy, not an extension of signed OCSP
validity. A changed response, network/validation failure, cached fallback,
Unknown or Revoked status resets the longer retry. A successful public
`staple_ocsp` call can still return a fresh cached Good response after a network
failure; that boolean does not authorize this backoff. Only internal evidence
of a verified responder success does. A response already in flight cannot
authorize a longer retry for a newer cache publication.

For a long-lived, unchanged Good response, this can delay the next proactive
revocation check by up to five minutes. Expiry checks, Must-Staple serving
requirements, verified revocation quarantine, and the refresh concurrency limit
are unchanged. Explicit user refresh calls and custom handshake refresh
callbacks retain their existing behavior; they do not share this retry policy.

## ACME HTTP error classification

Unsuccessful signed ACME requests now return
`Error::Acme(AcmeError::HttpResponse { status, problem_type, message })`.
Previously these responses were flattened into `Order`, `Account` or
`Certificate` strings. Account lookup preserves this structured error too;
local account errors, including a missing successful `Location`, still use
`Account`. Successful responses and exact protocol recovery outcomes are
unchanged.

`AcmeError` has a new public variant. Downstream exhaustive matches must add
an `HttpResponse { .. }` arm (or an appropriate fallback). Consumers that
matched HTTP failures as `Order(_)`, `Account(_)` or `Certificate(_)` should
match the new variant and inspect `status` and `problem_type` instead of
parsing the display message. `status` always comes from HTTP, even when a
problem document contains a contradictory `status` field. `problem_type`
retains the full URI and is absent for malformed or unrecognized documents.

`should_retry` and `do_with_retry` stop on HTTP 4xx other than 429 and the
exact HTTP 400 `urn:ietf:params:acme:error:badNonce` problem. The ACME client
still retries that nonce problem once with its dedicated response nonce;
an exhausted nonce retry retains its previous transient classification for
an outer retry loop. Exact account-missing recovery, order-not-ready recovery
and already-revoked confirmation occur before generic HTTP classification.
HTTP 5xx, 429 and transport failures remain retryable. A problem URI or the
document's `status` cannot override the actual HTTP status.

The existing `RateLimited { retry_after, .. }` variant remains supported.
This change does not introduce parsing or scheduling of HTTP `Retry-After`
headers for signed requests: the retry loop continues using its configured
intervals. ARI's separate `Retry-After` handling is unchanged.
