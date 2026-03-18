//! Async job queue with retry logic for ACME operations.
//!
//! This module provides:
//!
//! - [`RetryConfig`] — configurable retry intervals, maximum duration, and
//!   maximum retry count.
//! - [`do_with_retry`] — execute an async closure with automatic retries and
//!   exponential-ish backoff.
//! - [`JobQueue`] — a lightweight manager for background tasks (backed by
//!   [`tokio::task::JoinHandle`]) that deduplicates by name and supports
//!   cancellation.
//!

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinHandle;
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
    Duration::from_secs(60),        // 1m
    Duration::from_secs(120),       // 2m
    Duration::from_secs(120),       // 2m
    Duration::from_secs(300),       // 5m
    Duration::from_secs(600),       // 10m
    Duration::from_secs(600),       // 10m
    Duration::from_secs(600),       // 10m
    Duration::from_secs(1200),      // 20m
    Duration::from_secs(1200),      // 20m
    Duration::from_secs(1200),      // 20m
    Duration::from_secs(1200),      // 20m
    Duration::from_secs(1800),      // 30m
    Duration::from_secs(1800),      // 30m
    Duration::from_secs(1800),      // 30m
    Duration::from_secs(1800),      // 30m
    Duration::from_secs(1800),      // 30m
    Duration::from_secs(1800),      // 30m
    Duration::from_secs(3600),      // 1h
    Duration::from_secs(3600),      // 1h
    Duration::from_secs(3600),      // 1h
    Duration::from_secs(7200),      // 2h
    Duration::from_secs(7200),      // 2h
    Duration::from_secs(10800),     // 3h
    Duration::from_secs(10800),     // 3h
    Duration::from_secs(21600),     // 6h
];

/// Default maximum total duration for retries (30 days).
pub const DEFAULT_MAX_DURATION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

// ---------------------------------------------------------------------------
// RetryConfig
// ---------------------------------------------------------------------------

/// Configuration for retry behaviour.
///
/// Controls the timing and limits for [`do_with_retry`]. The default
/// configuration uses escalating intervals from 1 second to 10 minutes,
/// with a maximum total duration of 30 days and unlimited retries.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Intervals between successive retries.
    ///
    /// When the index exceeds the length of this slice, the **last** element
    /// is reused for all subsequent attempts.
    pub intervals: Vec<Duration>,

    /// Maximum total wall-clock time to keep retrying. Once this duration has
    /// elapsed since the first attempt, no more retries are made.
    pub max_duration: Duration,

    /// Maximum number of retries.  `0` means unlimited — the retry loop is
    /// governed solely by `max_duration`.
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
    let start = Instant::now();
    // Start at -1 so the first attempt executes without any delay.
    let mut interval_index: isize = -1;
    let mut attempts: usize = 0;

    loop {
        // --- wait before this attempt (skip wait on the very first try) ---
        if interval_index >= 0 {
            let idx = (interval_index as usize).min(config.intervals.len().saturating_sub(1));
            let wait = config.intervals[idx];
            tokio::time::sleep(wait).await;
        }

        // --- check whether we've exceeded the time budget ---
        if start.elapsed() >= config.max_duration {
            tracing::error!(
                attempts,
                elapsed = ?start.elapsed(),
                max_duration = ?config.max_duration,
                "retry budget exhausted; giving up",
            );
            // If we had a previous error we would have returned it below on
            // the prior iteration. Reaching here means the timer expired
            // between attempts, so just return a timeout.
            return Err(Error::Timeout(format!(
                "retry budget of {:?} exhausted after {attempts} attempts",
                config.max_duration,
            )));
        }

        // --- execute the operation ---
        match f(attempts).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                attempts += 1;

                // Non-retriable errors are returned immediately.
                if !should_retry(&err) {
                    tracing::warn!(
                        %err,
                        attempts,
                        "non-retriable error; will not retry",
                    );
                    return Err(err);
                }

                // Respect max_retries (0 = unlimited).
                if config.max_retries > 0 && attempts >= config.max_retries {
                    tracing::error!(
                        %err,
                        attempts,
                        max_retries = config.max_retries,
                        "max retries reached; giving up",
                    );
                    return Err(err);
                }

                // Advance to the next interval (clamped to the last element).
                if interval_index < config.intervals.len() as isize - 1 {
                    interval_index += 1;
                }

                let next_wait = config.intervals
                    [interval_index.max(0) as usize];

                tracing::error!(
                    %err,
                    attempts,
                    retrying_in = ?next_wait,
                    elapsed = ?start.elapsed(),
                    max_duration = ?config.max_duration,
                    "will retry",
                );
            }
        }
    }
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
/// Finished tasks are automatically reaped when new jobs are submitted or
/// when the queue length is queried.
pub struct JobQueue {
    /// Active jobs indexed by name.
    jobs: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
    /// Human-readable label for log messages.
    name: String,
    /// Optional concurrency limiter. When set, at most `max_concurrent` jobs
    /// may run simultaneously. Additional submissions block until a permit
    /// becomes available.
    semaphore: Option<Arc<Semaphore>>,
}

impl JobQueue {
    /// Create a new, empty `JobQueue` with the given descriptive `name`.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            jobs: Arc::new(Mutex::new(HashMap::new())),
            name: name.into(),
            semaphore: None,
        }
    }

    /// Create a new `JobQueue` with a maximum number of concurrently running
    /// jobs.
    ///
    /// When the limit is reached, [`submit`](JobQueue::submit) will still
    /// accept the job but the spawned task will wait for a semaphore permit
    /// before executing the closure.
    pub fn with_max_concurrent(name: impl Into<String>, max_concurrent: usize) -> Self {
        Self {
            jobs: Arc::new(Mutex::new(HashMap::new())),
            name: name.into(),
            semaphore: if max_concurrent > 0 {
                Some(Arc::new(Semaphore::new(max_concurrent)))
            } else {
                None
            },
        }
    }

    /// Submit a background job.
    ///
    /// If a job with the same `name` is already running, this call is a no-op
    /// and the closure is **not** spawned.
    ///
    /// The closure receives no arguments; any required state should be moved
    /// into it via `move ||`.
    pub async fn submit<F, Fut>(&self, name: String, f: F)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut jobs = self.jobs.lock().await;

        // Reap finished tasks while we hold the lock.
        jobs.retain(|_, handle| !handle.is_finished());

        if jobs.contains_key(&name) {
            tracing::debug!(
                queue = %self.name,
                job = %name,
                "job already running; skipping duplicate submission",
            );
            return;
        }

        tracing::debug!(queue = %self.name, job = %name, "submitting background job");

        let job_name = name.clone();
        let queue_name = self.name.clone();
        let jobs_ref = Arc::clone(&self.jobs);
        let semaphore = self.semaphore.clone();

        let handle = tokio::spawn(async move {
            // Acquire a semaphore permit if concurrency limiting is enabled.
            let _permit = match &semaphore {
                Some(sem) => Some(
                    sem.acquire()
                        .await
                        .expect("semaphore should not be closed"),
                ),
                None => None,
            };

            f().await;

            // Remove ourselves from the map once complete.
            // The permit is dropped automatically when `_permit` goes out of
            // scope, allowing another job to proceed.
            let mut jobs = jobs_ref.lock().await;
            jobs.remove(&job_name);

            tracing::debug!(
                queue = %queue_name,
                job = %job_name,
                "background job completed",
            );
        });

        jobs.insert(name, handle);
    }

    /// Wait for the job with the given `name` to complete.
    ///
    /// Returns immediately if no job with that name is currently tracked.
    pub async fn wait(&self, name: &str) {
        let handle = {
            let mut jobs = self.jobs.lock().await;
            jobs.remove(name)
        };

        if let Some(handle) = handle {
            // We intentionally ignore the JoinError (panic / cancellation) —
            // the important thing is that the task is done.
            let _ = handle.await;
        }
    }

    /// Check whether a job with the given `name` is currently running.
    pub async fn is_running(&self, name: &str) -> bool {
        let jobs = self.jobs.lock().await;
        match jobs.get(name) {
            Some(handle) => !handle.is_finished(),
            None => false,
        }
    }

    /// Cancel (abort) the job with the given `name`.
    ///
    /// If no job with that name exists, this is a no-op.
    pub async fn cancel(&self, name: &str) {
        let mut jobs = self.jobs.lock().await;
        if let Some(handle) = jobs.remove(name) {
            handle.abort();
            tracing::debug!(
                queue = %self.name,
                job = %name,
                "background job cancelled",
            );
        }
    }

    /// Returns the number of currently tracked (potentially still-running)
    /// jobs.
    pub async fn len(&self) -> usize {
        let mut jobs = self.jobs.lock().await;
        jobs.retain(|_, handle| !handle.is_finished());
        jobs.len()
    }

    /// Returns `true` if there are no tracked jobs.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        // Should have been called only once (no retries for Config errors).
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
}
