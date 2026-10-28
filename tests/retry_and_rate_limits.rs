use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use certon::Error;
use certon::async_jobs::{RetryConfig, do_with_retry};
use certon::rate_limiter::RateLimiter;

#[tokio::test(start_paused = true)]
async fn empty_retry_intervals_are_rejected_before_running_the_operation() {
    let calls = AtomicUsize::new(0);
    let config = RetryConfig {
        intervals: vec![],
        max_duration: Duration::from_secs(1),
        max_retries: 0,
    };
    let result = do_with_retry(&config, |_| {
        calls.fetch_add(1, Ordering::SeqCst);
        async { Err(Error::Other("transient".into())) }
    })
    .await;
    assert!(matches!(result, Err(Error::Config(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn retry_budget_cancels_an_in_flight_operation() {
    let config = RetryConfig {
        intervals: vec![Duration::from_millis(1)],
        max_duration: Duration::from_millis(30),
        max_retries: 0,
    };
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        do_with_retry(&config, |_| std::future::pending()),
    )
    .await
    .expect("the retry budget must terminate an in-flight operation");
    assert!(matches!(result, Err(Error::Timeout(_))));
}

#[tokio::test(start_paused = true)]
async fn retry_budget_interrupts_backoff_without_starting_another_attempt() {
    let calls = AtomicUsize::new(0);
    let config = RetryConfig {
        intervals: vec![Duration::from_millis(150)],
        max_duration: Duration::from_millis(10),
        max_retries: 0,
    };
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        do_with_retry(&config, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err(Error::Other("transient".into())) }
        }),
    )
    .await
    .expect("backoff must not extend the total budget");
    assert!(matches!(result, Err(Error::Timeout(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalid_dynamic_rate_limits_are_rejected_without_mutating_state() {
    let limiter = Arc::new(RateLimiter::new(1, Duration::from_secs(60)));
    let update = Arc::clone(&limiter);
    let outcome = tokio::spawn(async move { update.set_max_events(0).await }).await;
    assert!(outcome.is_err_and(|error| error.is_panic()));
    assert_eq!(limiter.max_events().await, 1);
    assert_eq!(limiter.window().await, Duration::from_secs(60));
    assert!(limiter.try_allow().await);

    let disabled = Arc::new(RateLimiter::new(0, Duration::ZERO));
    let update = Arc::clone(&disabled);
    let outcome =
        tokio::spawn(async move { update.set_window(Duration::from_secs(1)).await }).await;
    assert!(outcome.is_err_and(|error| error.is_panic()));
    assert_eq!(disabled.window().await, Duration::ZERO);
    assert_eq!(disabled.wait().await, Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn atomic_rate_configuration_rejects_invalid_pairs_and_wakes_waiters() {
    let limiter = Arc::new(RateLimiter::new(1, Duration::from_secs(60)));
    assert!(limiter.try_allow().await);
    assert!(matches!(
        limiter.configure(0, Duration::from_secs(1)).await,
        Err(Error::Config(_))
    ));
    assert_eq!(limiter.max_events().await, 1);
    assert_eq!(limiter.window().await, Duration::from_secs(60));
    assert!(
        !limiter.try_allow().await,
        "invalid updates must preserve history"
    );
    let waiting = Arc::clone(&limiter);
    let task = tokio::spawn(async move { waiting.wait().await });
    tokio::task::yield_now().await;
    limiter.configure(0, Duration::ZERO).await.unwrap();
    tokio::time::timeout(Duration::from_millis(1), task)
        .await
        .expect("disabling must wake an existing waiter")
        .unwrap();
    limiter.configure(2, Duration::from_secs(60)).await.unwrap();
    assert!(limiter.try_allow().await);
    assert!(!limiter.try_allow().await);
}

#[tokio::test(start_paused = true)]
async fn individual_rate_updates_wake_waiters_and_preserve_the_window() {
    let limiter = Arc::new(RateLimiter::new(1, Duration::from_secs(60)));
    assert!(limiter.try_allow().await);
    let waiting = Arc::clone(&limiter);
    let task = tokio::spawn(async move { waiting.wait().await });
    tokio::task::yield_now().await;
    limiter.set_max_events(2).await;
    tokio::time::timeout(Duration::from_millis(1), task)
        .await
        .expect("raising capacity must wake a waiter")
        .unwrap();
    assert!(!limiter.try_allow().await);
    limiter.set_window(Duration::ZERO).await;
    assert!(limiter.try_allow().await);
}

#[tokio::test(start_paused = true)]
async fn retry_timeout_drops_operation_guards_and_zero_budget_never_calls_it() {
    struct Guard(Arc<AtomicUsize>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let mut config = RetryConfig {
        intervals: vec![Duration::from_millis(1)],
        max_duration: Duration::from_millis(10),
        max_retries: 0,
    };
    let result = do_with_retry(&config, |_| async {
        let _guard = Guard(Arc::clone(&drops));
        std::future::pending().await
    })
    .await;
    assert!(matches!(result, Err(Error::Timeout(_))));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    config.max_duration = Duration::ZERO;
    let result = do_with_retry(&config, |_| async {
        panic!("an expired budget must not run the operation");
    })
    .await;
    assert!(matches!(result, Err(Error::Timeout(_))));
    config.max_duration = Duration::MAX;
    assert!(matches!(
        do_with_retry(&config, |_| async { Ok(()) }).await,
        Err(Error::Config(_))
    ));
}

#[tokio::test(start_paused = true)]
async fn zero_backoff_is_cooperative_and_retry_counts_remain_compatible() {
    let config = RetryConfig {
        intervals: vec![Duration::ZERO],
        max_duration: Duration::from_secs(60),
        max_retries: 3,
    };
    let calls = AtomicUsize::new(0);
    let result = do_with_retry(&config, |attempt| {
        assert_eq!(attempt, calls.fetch_add(1, Ordering::SeqCst));
        async { Err(Error::Other("last failure".into())) }
    })
    .await;
    assert!(matches!(result, Err(Error::Other(message)) if message == "last failure"));
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}
