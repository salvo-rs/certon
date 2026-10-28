//! Async job queue with retry logic for ACME operations.
//!
//! This module provides:
//!
//! - [`RetryConfig`] — configurable retry intervals, maximum duration, and maximum retry count.
//! - [`do_with_retry`] — execute an async closure with automatic retries and exponential-ish
//!   backoff.
//! - [`JobQueue`] — a lightweight manager for background tasks (backed by
//!   [`tokio::task::JoinHandle`]) that deduplicates by name and supports cancellation.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::AbortHandle;
use tokio::time::Instant;

use crate::error::{AcmeError, Error, Result};

// ---------------------------------------------------------------------------
// Default retry intervals
// ---------------------------------------------------------------------------

/// Default retry intervals.
///
/// The progression is:
/// `[1m, 2m, 2m, 5m, 10m, 10m, 10m, 20m, 20m, 20m, 20m, 30m, 30m, 30m,
///   30m, 30m, 30m, 1h, 1h, 1h, 2h, 2h, 3h, 3h, 6h]`
///
/// Once all intervals have been exhausted the **last** interval is repeated
/// until `max_duration` elapses.
pub const DEFAULT_RETRY_INTERVALS: &[Duration] = &[
    Duration::from_secs(60),    // 1m
    Duration::from_secs(120),   // 2m
    Duration::from_secs(120),   // 2m
    Duration::from_secs(300),   // 5m
    Duration::from_secs(600),   // 10m
    Duration::from_secs(600),   // 10m
    Duration::from_secs(600),   // 10m
    Duration::from_secs(1200),  // 20m
    Duration::from_secs(1200),  // 20m
    Duration::from_secs(1200),  // 20m
    Duration::from_secs(1200),  // 20m
    Duration::from_secs(1800),  // 30m
    Duration::from_secs(1800),  // 30m
    Duration::from_secs(1800),  // 30m
    Duration::from_secs(1800),  // 30m
    Duration::from_secs(1800),  // 30m
    Duration::from_secs(1800),  // 30m
    Duration::from_secs(3600),  // 1h
    Duration::from_secs(3600),  // 1h
    Duration::from_secs(3600),  // 1h
    Duration::from_secs(7200),  // 2h
    Duration::from_secs(7200),  // 2h
    Duration::from_secs(10800), // 3h
    Duration::from_secs(10800), // 3h
    Duration::from_secs(21600), // 6h
];

/// Default maximum total duration for retries (30 days).
pub const DEFAULT_MAX_DURATION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

// ---------------------------------------------------------------------------
// RetryConfig
// ---------------------------------------------------------------------------

/// Configuration for retry behaviour.
///
/// Controls the timing and limits for [`do_with_retry`]. The default
/// configuration uses escalating intervals from 1 minute to 6 hours,
/// with a maximum total duration of 30 days and unlimited retries.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Intervals between successive retries.
    ///
    /// When the index exceeds the length of this slice, the **last** element
    /// is reused for all subsequent attempts.
    pub intervals: Vec<Duration>,

    /// Maximum total wall-clock time to keep retrying. Once this duration has
    /// elapsed since the first attempt, the in-flight operation or backoff is cancelled.
    pub max_duration: Duration,

    /// Maximum number of failed attempts, including the initial attempt.
    /// The historical field name is retained for compatibility. `0` means
    /// unlimited — the retry loop is governed solely by `max_duration`.
    pub max_retries: usize,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            intervals: DEFAULT_RETRY_INTERVALS.to_vec(),
            max_duration: DEFAULT_MAX_DURATION,
            max_retries: 0,
        }
    }
}

impl RetryConfig {
    /// Validate retry intervals and monotonic-clock bounds without panicking.
    pub fn validate(&self) -> Result<()> {
        if self.intervals.is_empty() {
            return Err(Error::Config("retry intervals must not be empty".into()));
        }
        let now = Instant::now();
        if now.checked_add(self.max_duration).is_none()
            || self
                .intervals
                .iter()
                .any(|interval| now.checked_add(*interval).is_none())
        {
            return Err(Error::Config(
                "retry duration exceeds the monotonic clock range".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Error classification for retry
// ---------------------------------------------------------------------------

/// Determine whether `err` represents a transient failure that should be
/// retried.
///
/// The classification follows common ACME / HTTP conventions:
///
/// | Error kind                         | Retry? |
/// |------------------------------------|--------|
/// | Rate limited (HTTP 429)            | yes    |
/// | Server errors (5xx-class)          | yes    |
/// | Network / I/O errors               | yes    |
/// | Timeout                            | yes    |
/// | Client errors (4xx except 429)     | **no** |
/// | Crypto / cert / config errors      | **no** |
pub fn should_retry(err: &Error) -> bool {
    match err {
        // Explicitly marked as non-retriable.
        Error::NoRetry(_) => false,

        // Rate-limit responses are always retryable.
        Error::Acme(AcmeError::RateLimited { .. }) => true,

        // Other ACME errors: treat as server-side / transient by default,
        // *except* challenge and authorization failures which usually indicate
        // a permanent misconfiguration (analogous to 4xx).
        Error::Acme(AcmeError::Challenge { .. }) => false,
        Error::Acme(AcmeError::Authorization(_)) => false,
        Error::Acme(_) => true,

        // Storage I/O failures are transient (network file-system glitch, etc.).
        Error::Storage(_) => true,

        // Crypto and certificate errors are deterministic -- retrying won't help.
        Error::Crypto(_) => false,
        Error::Cert(_) => false,

        // Configuration errors are permanent.
        Error::Config(_) => false,

        // Timeouts are inherently transient.
        Error::Timeout(_) => true,

        // Catch-all: assume transient so we don't silently drop retriable work.
        Error::Other(_) => true,
    }
}

/// Wrap an error to signal that it should not be retried.
///
/// This is useful when the caller knows that a particular error is permanent
/// and retrying would be futile, even if the error type would normally be
/// classified as retriable by [`should_retry`].
pub fn no_retry(err: Error) -> Error {
    Error::NoRetry(err.to_string())
}

// ---------------------------------------------------------------------------
// do_with_retry
// ---------------------------------------------------------------------------

/// Execute the async closure `f` with automatic retries according to `config`.
///
/// On each failure the error is inspected via [`should_retry`]. If the error
/// is classified as non-retriable, it is returned immediately. Otherwise the
/// function sleeps for the next interval and tries again.
///
/// The closure receives the current attempt number (0-based) as its argument,
/// allowing it to adjust behaviour on retries.
///
/// Returns `Ok(())` on success, or the last [`Error`] once retries are
/// exhausted.
pub async fn do_with_retry<F, Fut>(config: &RetryConfig, f: F) -> Result<()>
where
    F: Fn(usize) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    if config.intervals.is_empty() {
        return Err(Error::Config("retry intervals must not be empty".into()));
    }
    let start = Instant::now();
    let deadline = start
        .checked_add(config.max_duration)
        .ok_or_else(|| Error::Config("retry duration exceeds the monotonic clock range".into()))?;
    let mut attempts: usize = 0;
    // One timer covers backoff and every operation. Cancelling the operation
    // drops its future, allowing its RAII guards to release resources.
    let result = tokio::time::timeout_at(deadline, async {
        loop {
            if Instant::now() >= deadline {
                return Err(retry_budget_error(config, attempts));
            }
            match f(attempts).await {
                Ok(()) => return Ok(()),
                Err(err) => {
                    attempts = attempts.saturating_add(1);
                    if !should_retry(&err)
                        || (config.max_retries > 0 && attempts >= config.max_retries)
                    {
                        return Err(err);
                    }
                    let idx = (attempts - 1).min(config.intervals.len() - 1);
                    let next_wait = config.intervals[idx];
                    tracing::error!(
                        %err,
                        attempts,
                        retrying_in = ?next_wait,
                        elapsed = ?start.elapsed(),
                        max_duration = ?config.max_duration,
                        "will retry",
                    );
                    if next_wait.is_zero() {
                        tokio::task::yield_now().await;
                    } else {
                        tokio::time::sleep(next_wait).await;
                    }
                }
            }
        }
    })
    .await;
    match result {
        Ok(result) => result,
        Err(_) => Err(retry_budget_error(config, attempts)),
    }
}

fn retry_budget_error(config: &RetryConfig, attempts: usize) -> Error {
    Error::Timeout(format!(
        "retry budget of {:?} exhausted after {attempts} failed attempts",
        config.max_duration,
    ))
}

// ---------------------------------------------------------------------------
// JobQueue
// ---------------------------------------------------------------------------

/// A lightweight manager for background async tasks with deduplication.
///
/// Jobs are identified by name; submitting a job whose name is already tracked
/// (and still running) is a no-op. This prevents duplicate work when, e.g.,
/// multiple connections trigger a certificate renewal for the same domain at
/// the same time.
///
/// Completion guards remove tasks on success, panic, and cancellation.
pub struct JobQueue {
    jobs: Arc<Mutex<HashMap<String, Job>>>,
    name: String,
    semaphore: Option<Arc<Semaphore>>,
    admission: Option<Arc<Semaphore>>,
    retry_records: Option<Arc<Semaphore>>,
    changed: watch::Sender<()>,
    closed: AtomicBool,
}

pub(crate) const CERTIFICATE_JOB_CONCURRENCY: usize = 4;
pub(crate) const CERTIFICATE_JOB_PENDING: usize = 64;

pub(crate) struct RetryFailure {
    pub error: Error,
    pub kind: &'static str,
}

struct RetryOperation<F> {
    operation: Option<F>,
    retained: Option<OwnedSemaphorePermit>,
}

impl<F> Drop for RetryOperation<F> {
    fn drop(&mut self) {
        drop(self.operation.take());
        drop(self.retained.take());
    }
}

async fn scheduled_retry<F, Fut>(
    config: RetryConfig,
    admitted_at: Instant,
    execution: Arc<Semaphore>,
    retry_records: Arc<Semaphore>,
    operation: F,
) -> std::result::Result<(), RetryFailure>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let deadline = admitted_at
        .checked_add(config.max_duration)
        .ok_or_else(|| RetryFailure {
            error: Error::Config("retry duration exceeds the monotonic clock range".into()),
            kind: "invalid_retry_config",
        })?;
    let mut attempts = 0;
    let mut retry = RetryOperation {
        operation: Some(operation),
        retained: None,
    };
    let work = async {
        // Retaining a retry must not consume every admission record. The
        // execution-sized remainder is reserved for new first attempts.
        loop {
            if Instant::now() >= deadline {
                return Err(RetryFailure {
                    error: retry_budget_error(&config, attempts),
                    kind: "retry_budget_exhausted",
                });
            }
            let result = {
                let permit = execution
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| RetryFailure {
                        error: Error::Other("background job queue is closed".into()),
                        kind: "queue_closed",
                    })?;
                // Timeout polls the inner future first. If a permit and the
                // deadline become ready together, do not start a late attempt.
                if Instant::now() >= deadline {
                    return Err(RetryFailure {
                        error: retry_budget_error(&config, attempts),
                        kind: "retry_budget_exhausted",
                    });
                }
                let mut attempt = QueuedWork {
                    create: Some(|| {
                        retry.operation.as_mut().expect("retry operation missing")(attempts)
                    }),
                    execution: Some(permit),
                    completion: None,
                };
                let future = attempt.create.take().expect("retry factory missing")();
                RunningWork {
                    future: Some(Box::pin(future)),
                    execution: attempt.execution.take(),
                    completion: None,
                }
                .await
            };
            match result {
                Ok(()) => return Ok(()),
                Err(error) => {
                    attempts = attempts.saturating_add(1);
                    if !should_retry(&error)
                        || (config.max_retries > 0 && attempts >= config.max_retries)
                    {
                        return Err(RetryFailure {
                            error,
                            kind: "operation_failed",
                        });
                    }
                    if retry.retained.is_none() {
                        retry.retained = Some(retry_records.clone().try_acquire_owned().map_err(|error| {
                            let (message, kind) = match error {
                                tokio::sync::TryAcquireError::Closed => ("background job queue is closed", "queue_closed"),
                                tokio::sync::TryAcquireError::NoPermits => ("background retry backlog is full; resubmit this domain later", "retry_backlog_full"),
                            };
                            RetryFailure { error: Error::Other(message.into()), kind }
                        })?);
                    }
                    let delay = config.intervals[(attempts - 1).min(config.intervals.len() - 1)];
                    tracing::error!(%error, attempts, retrying_in = ?delay, "background attempt failed; releasing execution until retry");
                    if delay.is_zero() {
                        tokio::task::yield_now().await;
                    } else {
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
    };
    tokio::time::timeout_at(deadline, work)
        .await
        .unwrap_or_else(|_| {
            Err(RetryFailure {
                error: retry_budget_error(&config, attempts),
                kind: "retry_budget_exhausted",
            })
        })
}

struct Job {
    abort: Option<AbortHandle>,
    cancelled: bool,
    completion: watch::Receiver<bool>,
    identity: Arc<()>,
}

/// Cleanup runs on success, panic, or cancellation, including before first poll.
struct JobCompletion {
    jobs: Weak<Mutex<HashMap<String, Job>>>,
    name: String,
    identity: Arc<()>,
    done: watch::Sender<bool>,
    changed: watch::Sender<()>,
    admission: Option<OwnedSemaphorePermit>,
}

impl Drop for JobCompletion {
    fn drop(&mut self) {
        if let Some(jobs) = self.jobs.upgrade() {
            let mut jobs = jobs.lock().unwrap_or_else(|e| e.into_inner());
            if jobs
                .get(&self.name)
                .is_some_and(|job| Arc::ptr_eq(&job.identity, &self.identity))
            {
                jobs.remove(&self.name);
            }
        }
        drop(self.admission.take());
        self.done.send_replace(true);
        self.changed.send_replace(());
    }
}

// Before first poll and while awaiting execution, the user's factory remains
// captured here. Its destructor must finish before acknowledging completion.
struct QueuedWork<F> {
    create: Option<F>,
    execution: Option<OwnedSemaphorePermit>,
    completion: Option<JobCompletion>,
}

impl<F> Drop for QueuedWork<F> {
    fn drop(&mut self) {
        drop(self.create.take());
        drop(self.execution.take());
        drop(self.completion.take());
    }
}

// The running future needs the same explicit drop order. Generator capture
// order alone is not a cleanup guarantee, especially before its first poll.
struct RunningWork<Fut: Future> {
    future: Option<Pin<Box<Fut>>>,
    execution: Option<OwnedSemaphorePermit>,
    completion: Option<JobCompletion>,
}

impl<Fut: Future> Future for RunningWork<Fut> {
    type Output = Fut::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut()
            .future
            .as_mut()
            .expect("running future missing")
            .as_mut()
            .poll(cx)
    }
}

impl<Fut: Future> Drop for RunningWork<Fut> {
    fn drop(&mut self) {
        drop(self.future.take());
        drop(self.execution.take());
        drop(self.completion.take());
    }
}

impl JobQueue {
    /// An unbounded-concurrency queue, deduplicated by name.
    pub fn new(name: impl Into<String>) -> Self {
        Self::with_max_concurrent(name, 0)
    }

    /// Limit concurrent execution. Submissions wait in the spawned tasks;
    /// zero means unlimited concurrency.
    pub fn with_max_concurrent(name: impl Into<String>, max_concurrent: usize) -> Self {
        Self {
            jobs: Arc::new(Mutex::new(HashMap::new())),
            name: name.into(),
            semaphore: (max_concurrent > 0).then(|| Arc::new(Semaphore::new(max_concurrent))),
            admission: None,
            retry_records: None,
            changed: watch::channel(()).0,
            closed: AtomicBool::new(false),
        }
    }

    /// Bound both execution and registered work. At most `max_concurrent`
    /// callbacks execute and `max_concurrent + max_pending` jobs are admitted.
    /// Additional submissions wait in the caller before registration or spawn.
    /// Dropping such a submission leaves no queued job. Running tasks are
    /// aborted when this bounded queue is dropped; use `shutdown` to await them.
    ///
    /// `max_concurrent` must be nonzero, and the total must fit a Tokio semaphore.
    pub fn with_limits(name: impl Into<String>, max_concurrent: usize, max_pending: usize) -> Self {
        assert!(max_concurrent > 0, "job execution limit must be nonzero");
        let capacity = max_concurrent
            .checked_add(max_pending)
            .expect("job capacity overflow");
        let mut queue = Self::with_max_concurrent(name, max_concurrent);
        queue.admission = Some(Arc::new(Semaphore::new(capacity)));
        queue.retry_records = Some(Arc::new(Semaphore::new(max_pending)));
        queue
    }

    pub(crate) fn certificate_jobs(name: impl Into<String>) -> Self {
        Self::with_limits(name, CERTIFICATE_JOB_CONCURRENCY, CERTIFICATE_JOB_PENDING)
    }

    /// Submit work unless a task of the same name is still registered.
    pub async fn submit<F, Fut>(&self, name: String, f: F)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.submit_inner(name, move |_| f(), self.semaphore.clone())
            .await;
    }

    pub(crate) async fn submit_retrying<F, Fut, C>(
        &self,
        name: String,
        config: RetryConfig,
        operation: F,
        complete: C,
    ) where
        F: FnMut(usize) -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
        C: FnOnce(std::result::Result<(), RetryFailure>) + Send + 'static,
    {
        if let Err(error) = config.validate() {
            complete(Err(RetryFailure {
                error,
                kind: "invalid_retry_config",
            }));
            return;
        }
        let (Some(execution), Some(records)) = (&self.semaphore, &self.retry_records) else {
            complete(Err(RetryFailure {
                error: Error::Config("retry scheduling requires bounded admission".into()),
                kind: "invalid_retry_config",
            }));
            return;
        };
        let execution = execution.clone();
        let records = records.clone();
        self.submit_inner(
            name,
            move |admitted_at| async move {
                complete(scheduled_retry(config, admitted_at, execution, records, operation).await);
            },
            None,
        )
        .await;
    }

    async fn submit_inner<F, Fut>(&self, name: String, f: F, semaphore: Option<Arc<Semaphore>>)
    where
        F: FnOnce(Instant) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let runtime = tokio::runtime::Handle::current();
        // Subscribe before checking the registry, so a same-name submission
        // admitted while this call waits can promptly deduplicate even at cap.
        let mut changed = self.changed.subscribe();
        let admission = if let Some(capacity) = &self.admission {
            let acquire = Arc::clone(capacity).acquire_owned();
            tokio::pin!(acquire);
            loop {
                if self.closed.load(Ordering::Acquire)
                    || self
                        .jobs
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .contains_key(&name)
                {
                    return;
                }
                tokio::select! {
                    permit = &mut acquire => match permit {
                        Ok(permit) => break Some(permit),
                        Err(_) => return,
                    },
                    _ = changed.changed() => {},
                }
                // Keep the same semaphore future pinned across notifications:
                // unrelated registry changes must not reset FIFO admission.
            }
        } else {
            None
        };
        let (done, completion) = watch::channel(false);
        let admitted_at = Instant::now();
        let identity = Arc::new(());
        {
            let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
            if self.closed.load(Ordering::Acquire) || jobs.contains_key(&name) {
                return;
            }
            jobs.insert(
                name.clone(),
                Job {
                    abort: None,
                    cancelled: false,
                    completion,
                    identity: Arc::clone(&identity),
                },
            );
        }
        // Never spawn or run a destructor while holding the registry lock:
        // a runtime shutting down can drop an unpolled future immediately.
        let cleanup = JobCompletion {
            jobs: Arc::downgrade(&self.jobs),
            name: name.clone(),
            identity: Arc::clone(&identity),
            done,
            changed: self.changed.clone(),
            admission,
        };
        let queued = QueuedWork {
            create: Some(move || f(admitted_at)),
            execution: None,
            completion: Some(cleanup),
        };
        self.changed.send_replace(());
        tracing::debug!(queue = %self.name, job = %name, "submitting background job");
        let handle = runtime.spawn(async move {
            let mut queued = queued;
            queued.execution = match semaphore {
                Some(sem) => match sem.acquire_owned().await {
                    Ok(permit) => Some(permit),
                    Err(_) => return,
                },
                None => None,
            };
            // The execution permit already belongs to queued while invoking
            // the factory, including a synchronous factory panic.
            let future = queued.create.take().expect("job factory missing")();
            RunningWork {
                future: Some(Box::pin(future)),
                execution: queued.execution.take(),
                completion: queued.completion.take(),
            }
            .await;
        });
        let abort = handle.abort_handle();
        let cancelled = {
            let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(job) = jobs
                .get_mut(&name)
                .filter(|job| Arc::ptr_eq(&job.identity, &identity))
            {
                job.abort = Some(abort.clone());
                job.cancelled
            } else {
                false
            }
        };
        if cancelled {
            abort.abort();
        }
    }

    /// Wait for the currently registered generation without removing it.
    /// Other waiters, deduplication and cancellation remain available.
    pub async fn wait(&self, name: &str) {
        let completion = self
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .map(|job| job.completion.clone());
        if let Some(mut completion) = completion {
            while !*completion.borrow_and_update() {
                if completion.changed().await.is_err() {
                    break;
                }
            }
        }
    }

    /// Whether the named job is registered and not yet completed.
    pub async fn is_running(&self, name: &str) -> bool {
        self.jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(name)
    }

    /// Abort a job. It remains registered until its future has actually been
    /// dropped, so a replacement cannot overlap the cancelled generation.
    pub async fn cancel(&self, name: &str) {
        let cancelled = {
            let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
            jobs.get_mut(name).map(|job| {
                job.cancelled = true;
                (job.completion.clone(), job.abort.clone())
            })
        };
        if let Some((mut completion, abort)) = cancelled {
            if let Some(abort) = abort {
                abort.abort();
            }
            while !*completion.borrow_and_update() {
                if completion.changed().await.is_err() {
                    break;
                }
            }
        }
    }

    /// Number of currently registered jobs.
    pub async fn len(&self) -> usize {
        self.jobs.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether no jobs are registered.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    fn close_and_abort(&self) -> Vec<watch::Receiver<bool>> {
        let (completions, aborts) = {
            let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
            self.closed.store(true, Ordering::Release);
            let mut completions = Vec::with_capacity(jobs.len());
            let mut aborts = Vec::with_capacity(jobs.len());
            for job in jobs.values_mut() {
                job.cancelled = true;
                completions.push(job.completion.clone());
                aborts.extend(job.abort.clone());
            }
            (completions, aborts)
        };
        if let Some(capacity) = &self.admission {
            capacity.close();
        }
        if let Some(execution) = &self.semaphore {
            execution.close();
        }
        if let Some(records) = &self.retry_records {
            records.close();
        }
        self.changed.send_replace(());
        for abort in aborts {
            abort.abort();
        }
        completions
    }

    /// Stop admission, abort every admitted job, and await actual future cleanup.
    /// New submissions become no-ops. This also wakes pending submissions.
    pub async fn shutdown(&self) {
        for mut completion in self.close_and_abort() {
            while !*completion.borrow_and_update() {
                if completion.changed().await.is_err() {
                    break;
                }
            }
        }
    }
}

impl Drop for JobQueue {
    fn drop(&mut self) {
        if self.admission.is_some() {
            self.close_and_abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn default_retry_config() {
        let cfg = RetryConfig::default();
        assert_eq!(cfg.intervals.len(), 25);
        assert_eq!(cfg.intervals[0], Duration::from_secs(60));
        assert_eq!(*cfg.intervals.last().unwrap(), Duration::from_secs(21600));
        assert_eq!(cfg.max_duration, Duration::from_secs(30 * 24 * 3600));
        assert_eq!(cfg.max_retries, 0);
    }

    #[test]
    fn should_retry_rate_limited() {
        let err = Error::Acme(AcmeError::RateLimited {
            retry_after: None,
            message: "slow down".into(),
        });
        assert!(should_retry(&err));
    }

    #[test]
    fn should_not_retry_config() {
        let err = Error::Config("bad".into());
        assert!(!should_retry(&err));
    }

    #[test]
    fn should_not_retry_challenge() {
        let err = Error::Acme(AcmeError::Challenge {
            challenge_type: "http-01".into(),
            message: "failed".into(),
        });
        assert!(!should_retry(&err));
    }

    #[test]
    fn should_retry_timeout() {
        let err = Error::Timeout("timed out".into());
        assert!(should_retry(&err));
    }

    #[test]
    fn should_retry_storage() {
        let err = Error::Storage(crate::error::StorageError::NotFound("x".into()));
        assert!(should_retry(&err));
    }

    #[tokio::test]
    async fn retry_succeeds_on_first_try() {
        let cfg = RetryConfig {
            intervals: vec![Duration::from_millis(10)],
            max_duration: Duration::from_secs(5),
            max_retries: 3,
        };
        let result: Result<()> = do_with_retry(&cfg, |_| async { Ok(()) }).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn retry_succeeds_after_transient_failures() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        let cfg = RetryConfig {
            intervals: vec![Duration::from_millis(10)],
            max_duration: Duration::from_secs(5),
            max_retries: 5,
        };

        let result = do_with_retry(&cfg, move |_| {
            let c = Arc::clone(&counter_clone);
            async move {
                let attempt = c.fetch_add(1, Ordering::SeqCst);
                if attempt < 2 {
                    Err(Error::Timeout("transient".into()))
                } else {
                    Ok(())
                }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_stops_on_non_retriable() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        let cfg = RetryConfig {
            intervals: vec![Duration::from_millis(10)],
            max_duration: Duration::from_secs(5),
            max_retries: 10,
        };

        let result = do_with_retry(&cfg, move |_| {
            let c = Arc::clone(&counter_clone);
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err(Error::Config("permanent".into()))
            }
        })
        .await;

        assert!(result.is_err());
        // Should have been called only once (no retries for CertManager errors).
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retry_respects_max_retries() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        let cfg = RetryConfig {
            intervals: vec![Duration::from_millis(10)],
            max_duration: Duration::from_secs(60),
            max_retries: 3,
        };

        let result = do_with_retry(&cfg, move |_| {
            let c = Arc::clone(&counter_clone);
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err(Error::Timeout("always fails".into()))
            }
        })
        .await;

        assert!(result.is_err());
        // 1 initial + 2 retries = 3 calls (max_retries = 3 means at most 3 attempts).
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn job_queue_submit_and_wait() {
        let queue = JobQueue::new("test");
        let flag = Arc::new(AtomicUsize::new(0));
        let flag_clone = Arc::clone(&flag);

        queue
            .submit("job1".into(), move || {
                let f = Arc::clone(&flag_clone);
                async move {
                    f.store(42, Ordering::SeqCst);
                }
            })
            .await;

        queue.wait("job1").await;
        assert_eq!(flag.load(Ordering::SeqCst), 42);
    }

    #[tokio::test]
    async fn job_queue_deduplicates() {
        let queue = JobQueue::new("test");
        let counter = Arc::new(AtomicUsize::new(0));

        let c1 = Arc::clone(&counter);
        queue
            .submit("dup".into(), move || {
                let c = Arc::clone(&c1);
                async move {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    c.fetch_add(1, Ordering::SeqCst);
                }
            })
            .await;

        // Submit again with same name — should be ignored.
        let c2 = Arc::clone(&counter);
        queue
            .submit("dup".into(), move || {
                let c = Arc::clone(&c2);
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                }
            })
            .await;

        queue.wait("dup").await;
        // Only the first job should have run.
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn job_queue_cancel() {
        let queue = JobQueue::new("test");
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);

        queue
            .submit("slow".into(), move || {
                let c = Arc::clone(&c);
                async move {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    c.fetch_add(1, Ordering::SeqCst);
                }
            })
            .await;

        // Give the task a moment to be spawned.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(queue.is_running("slow").await);

        queue.cancel("slow").await;
        // After cancellation the task should no longer be tracked.
        assert!(!queue.is_running("slow").await);
        // And the counter should not have been incremented.
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn job_queue_is_running() {
        let queue = JobQueue::new("test");
        assert!(!queue.is_running("nope").await);

        queue
            .submit("task".into(), || async {
                tokio::time::sleep(Duration::from_millis(200)).await;
            })
            .await;

        assert!(queue.is_running("task").await);
        queue.wait("task").await;
        assert!(!queue.is_running("task").await);
    }

    #[tokio::test]
    async fn job_queue_len() {
        let queue = JobQueue::new("test");
        assert!(queue.is_empty().await);

        queue
            .submit("a".into(), || async {
                tokio::time::sleep(Duration::from_millis(200)).await;
            })
            .await;
        queue
            .submit("b".into(), || async {
                tokio::time::sleep(Duration::from_millis(200)).await;
            })
            .await;

        assert_eq!(queue.len().await, 2);

        queue.wait("a").await;
        queue.wait("b").await;
        assert!(queue.is_empty().await);
    }

    #[tokio::test]
    async fn waiting_preserves_deduplication_and_cancellation_for_all_waiters() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let queue = Arc::new(JobQueue::new("wait-regression"));
        let calls = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Notify::new());
        queue
            .submit("domain".into(), {
                let calls = Arc::clone(&calls);
                let started = Arc::clone(&started);
                move || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    started.notify_one();
                    std::future::pending::<()>().await;
                }
            })
            .await;
        started.notified().await;
        let first = tokio::spawn({
            let queue = Arc::clone(&queue);
            async move {
                queue.wait("domain").await;
            }
        });
        let second = tokio::spawn({
            let queue = Arc::clone(&queue);
            async move {
                queue.wait("domain").await;
            }
        });
        tokio::task::yield_now().await;
        assert!(queue.is_running("domain").await);
        queue
            .submit("domain".into(), {
                let calls = Arc::clone(&calls);
                move || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            })
            .await;
        assert_eq!(queue.len().await, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        queue.cancel("domain").await;
        tokio::time::timeout(Duration::from_secs(1), first)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .unwrap()
            .unwrap();
        assert!(queue.is_empty().await);
        queue
            .submit("domain".into(), {
                let calls = Arc::clone(&calls);
                move || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            })
            .await;
        queue.wait("domain").await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn panic_and_abort_before_first_poll_release_queue_entries() {
        let queue = JobQueue::new("cleanup");
        queue
            .submit("panic".into(), || async {
                panic!("expected test panic");
            })
            .await;
        tokio::time::timeout(Duration::from_secs(1), queue.wait("panic"))
            .await
            .unwrap();
        assert!(!queue.is_running("panic").await);
        queue
            .submit("abort".into(), || async {
                std::future::pending::<()>().await;
            })
            .await;
        queue.cancel("abort").await;
        assert!(queue.is_empty().await);
    }

    struct Dropped(Arc<AtomicUsize>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn bounded_admission_deduplicates_at_capacity_and_drops_waiting_submissions() {
        let queue = Arc::new(JobQueue::with_limits("admission", 1, 1));
        for name in ["running", "pending"] {
            queue.submit(name.into(), std::future::pending).await;
        }
        assert_eq!(queue.len().await, 2);
        tokio::time::timeout(
            Duration::from_secs(1),
            queue.submit("pending".into(), || async {
                panic!("duplicate ran");
            }),
        )
        .await
        .unwrap();

        let dropped = Arc::new(AtomicUsize::new(0));
        let token = Dropped(dropped.clone());
        assert!(
            tokio::time::timeout(
                Duration::from_millis(1),
                queue.submit("discarded".into(), move || async move {
                    let _token = token;
                    panic!("unadmitted callback ran");
                })
            )
            .await
            .is_err()
        );
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(!queue.is_running("discarded").await);
        assert_eq!(queue.len().await, 2);

        let token = Dropped(dropped.clone());
        let caller = tokio::spawn({
            let queue = queue.clone();
            async move {
                queue
                    .submit("aborted".into(), move || async move {
                        let _token = token;
                    })
                    .await
            }
        });
        tokio::task::yield_now().await;
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
        assert!(!queue.is_running("aborted").await);

        queue.cancel("running").await;
        assert_eq!(queue.admission.as_ref().unwrap().available_permits(), 1);
        queue
            .submit("replacement".into(), std::future::pending)
            .await;
        assert_eq!(queue.len().await, 2);
        queue.shutdown().await;
        assert!(queue.is_empty().await);
        assert_eq!(queue.admission.as_ref().unwrap().available_permits(), 2);
        queue
            .submit("closed".into(), || async {
                panic!("closed queue ran");
            })
            .await;
        assert!(queue.is_empty().await);
    }

    #[tokio::test(start_paused = true)]
    async fn waiting_same_name_deduplicates_when_another_waiter_is_admitted() {
        let queue = JobQueue::with_limits("waiting-dedup", 1, 0);
        queue.submit("blocker".into(), std::future::pending).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let work = || {
            let calls = calls.clone();
            move || async move {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<()>().await;
            }
        };
        let first = queue.submit("same".into(), work());
        let second = queue.submit("same".into(), work());
        tokio::pin!(first, second);
        // Poll both submissions into the semaphore's wait queue before freeing
        // a slot; the second must then return while the first still holds it.
        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut first)
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut second)
                .await
                .is_err()
        );
        queue.cancel("blocker").await;
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(first, second);
        })
        .await
        .unwrap();
        tokio::task::yield_now().await;
        assert_eq!(queue.len().await, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        queue.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn bounded_queue_caps_execution_and_registry_for_large_batches() {
        let queue = Arc::new(JobQueue::with_limits("batch", 2, 3));
        let active = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let caller = tokio::spawn({
            let queue = queue.clone();
            let active = active.clone();
            let dropped = dropped.clone();
            async move {
                for index in 0..1000 {
                    let active = active.clone();
                    let dropped = dropped.clone();
                    queue
                        .submit(index.to_string(), move || async move {
                            assert!(active.fetch_add(1, Ordering::SeqCst) < 2);
                            let _drop = Dropped(dropped);
                            std::future::pending::<()>().await;
                        })
                        .await;
                }
            }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while queue.len().await < 5 || active.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            !caller.is_finished(),
            "large submission must apply backpressure"
        );
        assert_eq!(queue.len().await, 5);
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        queue.shutdown().await;
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
        assert!(queue.is_empty().await);
    }

    #[tokio::test]
    async fn bounded_panic_and_abort_release_capacity_and_drop_aborts_children() {
        let queue = JobQueue::with_limits("bounded-cleanup", 1, 0);
        queue
            .submit("panic".into(), || async {
                panic!("expected bounded panic");
            })
            .await;
        queue.wait("panic").await;
        queue.submit("unpolled".into(), std::future::pending).await;
        queue.cancel("unpolled").await;
        let dropped = Arc::new(AtomicUsize::new(0));
        let token = Dropped(dropped.clone());
        queue
            .submit("drop".into(), move || async move {
                let _token = token;
                std::future::pending::<()>().await;
            })
            .await;
        drop(queue);
        tokio::time::timeout(Duration::from_secs(1), async {
            while dropped.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn completion_waits_for_user_work_destructors_in_every_task_state() {
        struct DropBarrier {
            entered: std::sync::mpsc::Sender<()>,
            release: std::sync::mpsc::Receiver<()>,
        }
        impl Drop for DropBarrier {
            fn drop(&mut self) {
                self.entered.send(()).unwrap();
                self.release
                    .recv_timeout(Duration::from_secs(3))
                    .expect("Drop barrier was not released");
            }
        }
        for state in ["unpolled", "queued", "running", "factory-panic"] {
            let queue = Arc::new(JobQueue::with_limits(
                "drop-order",
                1,
                usize::from(state == "queued"),
            ));
            if state == "queued" {
                queue.submit("blocker".into(), std::future::pending).await;
                tokio::task::yield_now().await;
            }
            let (entered, entered_rx) = std::sync::mpsc::channel();
            let (release, released) = std::sync::mpsc::channel();
            let resource = DropBarrier {
                entered,
                release: released,
            };
            let started = Arc::new(tokio::sync::Notify::new());
            if state == "factory-panic" {
                queue
                    .submit("probe".into(), move || -> std::future::Ready<()> {
                        let _resource = resource;
                        panic!("expected synchronous factory panic");
                    })
                    .await;
            } else {
                queue
                    .submit("probe".into(), {
                        let started = started.clone();
                        move || async move {
                            let _resource = resource;
                            started.notify_one();
                            std::future::pending::<()>().await;
                        }
                    })
                    .await;
            }
            if state == "running" {
                started.notified().await;
            } else if state == "queued" {
                tokio::task::yield_now().await;
                assert_eq!(queue.semaphore.as_ref().unwrap().available_permits(), 0);
            }
            let (completion, abort) = {
                let jobs = queue.jobs.lock().unwrap();
                let job = &jobs["probe"];
                (job.completion.clone(), job.abort.clone().unwrap())
            };
            // On this current-thread runtime no child is polled between submit
            // and abort, making the first state deterministic.
            if state != "factory-panic" {
                abort.abort();
            }
            let (finished, result) = tokio::sync::oneshot::channel();
            let observer_queue = queue.clone();
            let runtime = tokio::runtime::Handle::current();
            std::thread::spawn(move || {
                let waiter_queue = observer_queue.clone();
                let waiter = std::thread::spawn(move || {
                    runtime.block_on(async {
                        if state == "factory-panic" {
                            waiter_queue.wait("probe").await;
                        } else if state == "queued" {
                            waiter_queue.shutdown().await;
                        } else {
                            waiter_queue.cancel("probe").await;
                        }
                    });
                });
                entered_rx
                    .recv_timeout(Duration::from_secs(2))
                    .expect("user Drop never started");
                // The resource is still alive and blocked here. Its generation
                // must neither acknowledge cleanup nor return its capacity yet.
                let acknowledged = *completion.borrow();
                let capacity = observer_queue
                    .admission
                    .as_ref()
                    .unwrap()
                    .available_permits();
                let execution = observer_queue
                    .semaphore
                    .as_ref()
                    .unwrap()
                    .available_permits();
                release.send(()).unwrap();
                waiter.join().unwrap();
                let _ = finished.send((acknowledged, capacity, execution));
            });
            let (acknowledged, capacity, execution) =
                tokio::time::timeout(Duration::from_secs(4), result)
                    .await
                    .unwrap()
                    .unwrap();
            assert!(
                !acknowledged,
                "{state} acknowledged while user Drop was blocked"
            );
            if state != "queued" {
                assert_eq!(
                    capacity, 0,
                    "{state} returned capacity before dropping work"
                );
            }
            if matches!(state, "running" | "factory-panic") {
                assert_eq!(
                    execution, 0,
                    "{state} returned execution permit before dropping work"
                );
            }
            queue.shutdown().await;
        }
    }

    fn background_config() -> RetryConfig {
        RetryConfig {
            intervals: vec![Duration::from_secs(3600)],
            max_duration: Duration::from_secs(2 * 86400),
            max_retries: 0,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn retained_retries_leave_room_for_new_work_and_reject_overflow_explicitly() {
        let queue = JobQueue::with_limits("fair-retries", 4, 64);
        let attempts = Arc::new(AtomicUsize::new(0));
        let failures = Arc::new(Mutex::new(Vec::new()));
        for index in 0..68 {
            queue
                .submit_retrying(
                    index.to_string(),
                    background_config(),
                    {
                        let attempts = attempts.clone();
                        move |_| {
                            attempts.fetch_add(1, Ordering::SeqCst);
                            std::future::ready(Err(Error::Other("temporary".into())))
                        }
                    },
                    {
                        let failures = failures.clone();
                        move |result| failures.lock().unwrap().push(result.unwrap_err().kind)
                    },
                )
                .await;
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while attempts.load(Ordering::SeqCst) != 68 || failures.lock().unwrap().len() != 4 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(queue.len().await, 64);
        assert_eq!(*failures.lock().unwrap(), vec!["retry_backlog_full"; 4]);
        assert_eq!(queue.semaphore.as_ref().unwrap().available_permits(), 4);
        assert_eq!(queue.admission.as_ref().unwrap().available_permits(), 4);
        assert_eq!(queue.retry_records.as_ref().unwrap().available_permits(), 0);
        let duplicate = queue.jobs.lock().unwrap().keys().next().unwrap().clone();
        queue
            .submit_retrying(
                duplicate.clone(),
                background_config(),
                |_| async { panic!("duplicate attempt ran") },
                |_| panic!("duplicate completed"),
            )
            .await;
        let healthy = Arc::new(AtomicUsize::new(0));
        queue
            .submit_retrying(
                "healthy".into(),
                background_config(),
                {
                    let healthy = healthy.clone();
                    move |_| {
                        healthy.fetch_add(1, Ordering::SeqCst);
                        std::future::ready(Ok(()))
                    }
                },
                |result| assert!(result.is_ok()),
            )
            .await;
        queue.wait("healthy").await;
        assert_eq!(healthy.load(Ordering::SeqCst), 1);
        assert_eq!(queue.len().await, 64);

        for index in 0..4 {
            queue
                .submit_retrying(
                    format!("active-{index}"),
                    background_config(),
                    |_| std::future::pending(),
                    |_| {},
                )
                .await;
        }
        assert_eq!(queue.len().await, 68);
        let dropped = Arc::new(AtomicUsize::new(0));
        let token = Dropped(dropped.clone());
        assert!(
            tokio::time::timeout(
                Duration::from_millis(1),
                queue.submit_retrying(
                    "unadmitted".into(),
                    background_config(),
                    move |_| {
                        std::hint::black_box(&token);
                        std::future::ready(Ok(()))
                    },
                    |_| {}
                )
            )
            .await
            .is_err()
        );
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(!queue.is_running("unadmitted").await);
        queue.cancel(&duplicate).await;
        assert_eq!(queue.retry_records.as_ref().unwrap().available_permits(), 1);
        queue.shutdown().await;
        assert!(queue.is_empty().await);
        assert_eq!(
            queue.retry_records.as_ref().unwrap().available_permits(),
            64
        );
        assert_eq!(queue.admission.as_ref().unwrap().available_permits(), 68);
    }

    #[tokio::test(start_paused = true)]
    async fn retry_deadline_is_absolute_and_includes_execution_wait() {
        let queue = JobQueue::with_limits("deadline", 1, 2);
        let attempts = Arc::new(AtomicUsize::new(0));
        let outcome = Arc::new(Mutex::new(None));
        queue
            .submit_retrying(
                "retries".into(),
                RetryConfig {
                    intervals: vec![Duration::from_secs(4)],
                    max_duration: Duration::from_secs(12),
                    max_retries: 0,
                },
                {
                    let attempts = attempts.clone();
                    move |_| {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        std::future::ready(Err(Error::Other("temporary".into())))
                    }
                },
                {
                    let outcome = outcome.clone();
                    move |result| *outcome.lock().unwrap() = Some(result.unwrap_err().kind)
                },
            )
            .await;
        for expected in 1..=3 {
            for _ in 0..20 {
                tokio::task::yield_now().await;
            }
            assert_eq!(attempts.load(Ordering::SeqCst), expected);
            assert!(outcome.lock().unwrap().is_none());
            tokio::time::advance(Duration::from_secs(if expected < 3 { 5 } else { 3 })).await;
        }
        queue.wait("retries").await;
        assert_eq!(*outcome.lock().unwrap(), Some("retry_budget_exhausted"));
        assert_eq!(attempts.load(Ordering::SeqCst), 3);

        queue.submit("blocker".into(), std::future::pending).await;
        let outcome = Arc::new(Mutex::new(None));
        queue
            .submit_retrying(
                "waiting".into(),
                RetryConfig {
                    max_duration: Duration::from_secs(2),
                    ..background_config()
                },
                |_| async { panic!("expired waiting attempt ran") },
                {
                    let outcome = outcome.clone();
                    move |result| *outcome.lock().unwrap() = Some(result.unwrap_err().kind)
                },
            )
            .await;
        tokio::time::advance(Duration::from_secs(3)).await;
        queue.wait("waiting").await;
        assert_eq!(*outcome.lock().unwrap(), Some("retry_budget_exhausted"));
        queue.shutdown().await;
    }

    #[tokio::test]
    async fn retry_attempt_failures_and_panics_release_all_budgets() {
        let queue = JobQueue::with_limits("retry-errors", 1, 1);
        let calls = Arc::new(AtomicUsize::new(0));
        queue
            .submit_retrying(
                "finite".into(),
                RetryConfig {
                    intervals: vec![Duration::ZERO],
                    max_retries: 2,
                    ..background_config()
                },
                {
                    let calls = calls.clone();
                    move |_| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        std::future::ready(Err(Error::Other("temporary".into())))
                    }
                },
                |result| assert_eq!(result.unwrap_err().kind, "operation_failed"),
            )
            .await;
        queue.wait("finite").await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        queue
            .submit_retrying(
                "factory-panic".into(),
                background_config(),
                |_| -> std::future::Ready<Result<()>> { panic!("retry factory panic") },
                |_| {},
            )
            .await;
        queue.wait("factory-panic").await;
        queue
            .submit_retrying(
                "future-panic".into(),
                background_config(),
                |_| async { panic!("retry future panic") },
                |_| {},
            )
            .await;
        queue.wait("future-panic").await;
        assert!(queue.is_empty().await);
        assert_eq!(queue.admission.as_ref().unwrap().available_permits(), 2);
        assert_eq!(queue.semaphore.as_ref().unwrap().available_permits(), 1);
        assert_eq!(queue.retry_records.as_ref().unwrap().available_permits(), 1);
    }

    #[tokio::test]
    async fn cancelling_backoff_drops_the_factory_before_retention_and_completion() {
        struct Barrier {
            entered: std::sync::mpsc::Sender<()>,
            release: std::sync::mpsc::Receiver<()>,
        }
        impl Drop for Barrier {
            fn drop(&mut self) {
                self.entered.send(()).unwrap();
                self.release.recv_timeout(Duration::from_secs(3)).unwrap();
            }
        }
        let queue = Arc::new(JobQueue::with_limits("retry-drop", 1, 1));
        let (entered, dropped) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let resource = Barrier {
            entered,
            release: released,
        };
        queue
            .submit_retrying(
                "probe".into(),
                background_config(),
                move |_| {
                    std::hint::black_box(&resource);
                    std::future::ready(Err(Error::Other("temporary".into())))
                },
                |_| {},
            )
            .await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while queue.retry_records.as_ref().unwrap().available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let completion = queue.jobs.lock().unwrap()["probe"].completion.clone();
        let (finished, receive) = tokio::sync::oneshot::channel();
        let observer_queue = queue.clone();
        let runtime = tokio::runtime::Handle::current();
        std::thread::spawn(move || {
            let worker_queue = observer_queue.clone();
            let worker = std::thread::spawn(move || runtime.block_on(worker_queue.cancel("probe")));
            dropped.recv_timeout(Duration::from_secs(2)).unwrap();
            let state = (
                *completion.borrow(),
                observer_queue
                    .retry_records
                    .as_ref()
                    .unwrap()
                    .available_permits(),
                observer_queue
                    .admission
                    .as_ref()
                    .unwrap()
                    .available_permits(),
            );
            release.send(()).unwrap();
            worker.join().unwrap();
            let _ = finished.send(state);
        });
        let observed = tokio::time::timeout(Duration::from_secs(4), receive)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(observed, (false, 0, 1));
        assert_eq!(queue.retry_records.as_ref().unwrap().available_permits(), 1);
        assert_eq!(queue.admission.as_ref().unwrap().available_permits(), 2);
        queue.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_permit_arriving_after_deadline_cannot_start_an_attempt() {
        let execution = Arc::new(Semaphore::new(1));
        let permit = execution.clone().acquire_owned().await.unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let future = scheduled_retry(
            RetryConfig {
                max_duration: Duration::from_secs(1),
                ..background_config()
            },
            Instant::now(),
            execution,
            Arc::new(Semaphore::new(1)),
            {
                let calls = calls.clone();
                move |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Ok(()))
                }
            },
        );
        tokio::pin!(future);
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(std::task::Waker::noop()))
                .is_pending()
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        drop(permit);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(std::task::Waker::noop()))
        {
            Poll::Ready(Err(error)) => assert_eq!(error.kind, "retry_budget_exhausted"),
            _ => panic!("expired queued retry was not rejected"),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
