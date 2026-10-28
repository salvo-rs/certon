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
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use tokio::sync::{Semaphore, watch};
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
        self.done.send_replace(true);
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
        }
    }

    /// Submit work unless a task of the same name is still registered.
    pub async fn submit<F, Fut>(&self, name: String, f: F)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let runtime = tokio::runtime::Handle::current();
        let (done, completion) = watch::channel(false);
        let identity = Arc::new(());
        {
            let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
            if jobs.contains_key(&name) {
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
        };
        let semaphore = self.semaphore.clone();
        tracing::debug!(queue = %self.name, job = %name, "submitting background job");
        let handle = runtime.spawn(async move {
            let _cleanup = cleanup;
            let _permit = match &semaphore {
                Some(sem) => Some(sem.acquire().await.expect("semaphore should not be closed")),
                None => None,
            };
            f().await;
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
}
