//! Rate limiting for ACME operations.
//!
//! This module provides a sliding-window rate limiter backed by a ring buffer,
//! backed by a ring buffer. It is used to throttle
//! certificate obtain and renewal requests so that the ACME CA is not
//! overwhelmed.

use std::collections::VecDeque;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// RateLimiter
// ---------------------------------------------------------------------------

/// A sliding-window rate limiter backed by a ring buffer of timestamps.
///
/// At most `max_events` events are permitted within any contiguous `window` of
/// time. When the limit has been reached, [`RateLimiter::wait`] will sleep
/// until the oldest event falls outside the window.
///
/// If both `max_events` and `window` are zero, rate limiting is effectively
/// disabled and every call to [`wait`](RateLimiter::wait) returns immediately.
///
/// This is used internally to prevent accidentally overwhelming a CA's ACME
/// endpoints with too many requests. The internal rate limits are **not**
/// intended to replace or replicate the CA's actual rate limits -- they
/// simply provide a basic safeguard against bursts of thousands of requests.
pub struct RateLimiter {
    /// Ring buffer holding the timestamps of the most recent events, plus the
    /// current `max_events` and `window` settings (stored together so they
    /// can be atomically updated).
    inner: Mutex<RateLimiterInner>,
}

/// Internal state for [`RateLimiter`], protected by a single mutex.
struct RateLimiterInner {
    events: VecDeque<Instant>,
    max_events: usize,
    window: Duration,
}

impl RateLimiter {
    /// Create a new `RateLimiter` that allows up to `max_events` within
    /// `window`.
    ///
    /// # Panics
    ///
    /// Panics if `max_events` is `0` while `window` is non-zero, because that
    /// configuration would never allow any events.
    pub fn new(max_events: usize, window: Duration) -> Self {
        assert!(
            max_events != 0 || window.is_zero(),
            "invalid configuration: max_events = 0 and window != 0 would never allow any events"
        );

        Self {
            inner: Mutex::new(RateLimiterInner {
                events: VecDeque::with_capacity(max_events),
                max_events,
                window,
            }),
        }
    }

    /// Update the maximum number of events allowed in the sliding window.
    ///
    /// Takes effect on the next call to [`wait`](RateLimiter::wait) or
    /// [`try_allow`](RateLimiter::try_allow).
    pub async fn set_max_events(&self, max_events: usize) {
        let mut inner = self.inner.lock().await;
        inner.max_events = max_events;
    }

    /// Update the size of the sliding window.
    ///
    /// Takes effect on the next call to [`wait`](RateLimiter::wait) or
    /// [`try_allow`](RateLimiter::try_allow).
    pub async fn set_window(&self, window: Duration) {
        let mut inner = self.inner.lock().await;
        inner.window = window;
    }

    /// Wait until the rate limit permits the next event.
    ///
    /// If the sliding window already contains `max_events` events, this
    /// method sleeps until the oldest event is outside the window. The event
    /// is then recorded and the method returns the [`Duration`] it spent
    /// waiting (which is [`Duration::ZERO`] when no delay was needed).
    pub async fn wait(&self) -> Duration {
        let start = Instant::now();

        loop {
            let wait_duration = {
                let mut inner = self.inner.lock().await;

                // Rate limiting disabled.
                if inner.max_events == 0 && inner.window.is_zero() {
                    return Duration::ZERO;
                }

                // Evict timestamps that have fallen outside the window.
                let cutoff = Instant::now().checked_sub(inner.window);
                if let Some(cutoff) = cutoff {
                    while let Some(&front) = inner.events.front() {
                        if front <= cutoff {
                            inner.events.pop_front();
                        } else {
                            break;
                        }
                    }
                }

                if inner.events.len() < inner.max_events {
                    // There is capacity -- record this event and return.
                    inner.events.push_back(Instant::now());
                    return start.elapsed();
                }

                // The window is full. Compute how long we must wait until the
                // oldest event expires from the window.
                if let Some(&oldest) = inner.events.front() {
                    let expires_at = oldest + inner.window;
                    let now = Instant::now();
                    if expires_at > now {
                        expires_at - now
                    } else {
                        Duration::ZERO
                    }
                } else {
                    Duration::ZERO
                }
            };
            // Lock is released here while we sleep.

            if wait_duration.is_zero() {
                // Shouldn't normally happen, but avoid a busy-spin just in
                // case of timing jitter.
                tokio::task::yield_now().await;
            } else {
                tokio::time::sleep(wait_duration).await;
            }
        }
    }

    /// Try to allow an event without blocking.
    ///
    /// Returns `true` if the event was permitted (and has been recorded),
    /// `false` if the rate limit is currently exhausted.
    pub async fn try_allow(&self) -> bool {
        let mut inner = self.inner.lock().await;

        if inner.max_events == 0 && inner.window.is_zero() {
            return true;
        }

        // Evict expired timestamps.
        let cutoff = Instant::now().checked_sub(inner.window);
        if let Some(cutoff) = cutoff {
            while let Some(&front) = inner.events.front() {
                if front <= cutoff {
                    inner.events.pop_front();
                } else {
                    break;
                }
            }
        }

        if inner.events.len() < inner.max_events {
            inner.events.push_back(Instant::now());
            true
        } else {
            false
        }
    }

    /// Returns the maximum number of events allowed in the sliding window.
    pub async fn max_events(&self) -> usize {
        let inner = self.inner.lock().await;
        inner.max_events
    }

    /// Returns the size of the sliding window.
    pub async fn window(&self) -> Duration {
        let inner = self.inner.lock().await;
        inner.window
    }
}

// ---------------------------------------------------------------------------
// Default rate limiters
// ---------------------------------------------------------------------------

/// Default maximum number of certificate operations per window.
const DEFAULT_MAX_EVENTS: usize = 10;

/// Default sliding-window duration for certificate operations.
const DEFAULT_WINDOW: Duration = Duration::from_secs(60);

/// Returns the global rate limiter for certificate **obtain** operations
/// (default: 10 per minute).
pub fn cert_obtain_limiter() -> &'static RateLimiter {
    static LIMITER: OnceLock<RateLimiter> = OnceLock::new();
    LIMITER.get_or_init(|| RateLimiter::new(DEFAULT_MAX_EVENTS, DEFAULT_WINDOW))
}

/// Returns the global rate limiter for certificate **renewal** operations
/// (default: 10 per minute).
pub fn cert_renew_limiter() -> &'static RateLimiter {
    static LIMITER: OnceLock<RateLimiter> = OnceLock::new();
    LIMITER.get_or_init(|| RateLimiter::new(DEFAULT_MAX_EVENTS, DEFAULT_WINDOW))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unlimited_returns_immediately() {
        let rl = RateLimiter::new(0, Duration::ZERO);
        let waited = rl.wait().await;
        assert_eq!(waited, Duration::ZERO);
    }

    #[tokio::test]
    async fn allows_up_to_max_events_immediately() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            let waited = rl.wait().await;
            // Should be essentially instant (well under 50 ms).
            assert!(waited < Duration::from_millis(50));
        }
    }

    #[tokio::test]
    async fn try_allow_respects_limit() {
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        assert!(rl.try_allow().await);
        assert!(rl.try_allow().await);
        assert!(!rl.try_allow().await);
    }

    #[tokio::test]
    async fn blocks_when_window_full() {
        let window = Duration::from_millis(200);
        let rl = RateLimiter::new(1, window);

        // First event: immediate.
        let w1 = rl.wait().await;
        assert!(w1 < Duration::from_millis(50));

        // Second event: must wait roughly `window`.
        let w2 = rl.wait().await;
        assert!(
            w2 >= Duration::from_millis(100),
            "expected >= 100ms wait, got {w2:?}"
        );
    }

    #[tokio::test]
    async fn accessors() {
        let rl = RateLimiter::new(5, Duration::from_secs(30));
        assert_eq!(rl.max_events().await, 5);
        assert_eq!(rl.window().await, Duration::from_secs(30));
    }

    #[test]
    #[should_panic(expected = "would never allow any events")]
    fn panics_on_invalid_config() {
        let _ = RateLimiter::new(0, Duration::from_secs(1));
    }

    #[tokio::test]
    async fn global_limiters_are_valid() {
        let obtain = cert_obtain_limiter();
        assert_eq!(obtain.max_events().await, DEFAULT_MAX_EVENTS);
        assert_eq!(obtain.window().await, DEFAULT_WINDOW);

        let renew = cert_renew_limiter();
        assert_eq!(renew.max_events().await, DEFAULT_MAX_EVENTS);
        assert_eq!(renew.window().await, DEFAULT_WINDOW);
    }
}
