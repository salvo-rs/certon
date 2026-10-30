use super::*;

#[test]
fn unchanged_refresh_delays_are_bounded_and_enter_the_urgent_window_on_time() {
    let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let validity = |remaining| {
        Some(OcspValidity {
            expires_at: now + chrono::Duration::seconds(remaining),
            refresh_at: now - chrono::Duration::hours(1),
        })
    };
    for (streak, expected) in [(1, 60), (2, 120), (3, 240), (4, 300), (255, 300)] {
        assert_eq!(
            ocsp_retry_delay(now, validity(47 * 3600), streak, 100),
            chrono::Duration::seconds(expected)
        );
        assert_eq!(
            ocsp_retry_delay(now, validity(47 * 3600), streak, 80),
            chrono::Duration::seconds(expected * 80 / 100)
        );
    }
    // Freshness remaining alone must not authorize the longer retry.
    assert_eq!(
        ocsp_retry_delay(now, validity(47 * 3600), 0, 100),
        chrono::Duration::seconds(30)
    );
    assert_eq!(
        ocsp_retry_delay(now, None, 4, 100),
        chrono::Duration::seconds(30)
    );
    assert_eq!(
        ocsp_retry_delay(now, validity(3601), 4, 100),
        chrono::Duration::seconds(1)
    );
    assert_eq!(
        ocsp_retry_delay(now, validity(3600), 4, 100),
        chrono::Duration::seconds(30)
    );
    assert_eq!(
        ocsp_retry_delay(now, validity(10), 4, 100),
        chrono::Duration::seconds(5)
    );
    assert_eq!(
        ocsp_retry_delay(now, validity(1), 4, 100),
        chrono::Duration::seconds(1)
    );
    assert_eq!(
        ocsp_retry_delay(now, validity(-1), 4, 100),
        chrono::Duration::seconds(1)
    );
}
