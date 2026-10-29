use super::*;

fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(1_800_000_000, 0).unwrap()
}

fn certificate(lifetime: ChronoDuration, remaining: ChronoDuration) -> Certificate {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["short.example".into()]).unwrap();
    let signed = params.self_signed(&key).unwrap();
    let mut cert =
        Certificate::from_pem(signed.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap();
    cert.not_after = now() + remaining;
    cert.not_before = cert.not_after - lifetime;
    cert
}

fn future_ari(cert: &mut Certificate) {
    let selected = now() + ChronoDuration::minutes(10);
    cert.ari = Some(crate::RenewalInfo {
        suggested_window: Some(crate::RenewalWindow {
            start: selected.to_rfc3339(),
            end: (selected + ChronoDuration::minutes(10)).to_rfc3339(),
        }),
        selected_time: Some(selected),
        ..Default::default()
    });
}

#[test]
fn emergency_boundaries_scale_only_for_validity_shorter_than_three_days() {
    // Explicit policy boundaries, including the ASN.1 one-second tolerance.
    for (lifetime_hours, emergency_hours) in [(6, 2), (24, 8), (48, 16), (72, 24), (7 * 24, 24)] {
        let mut cert = certificate(
            ChronoDuration::hours(lifetime_hours),
            ChronoDuration::hours(emergency_hours),
        );
        future_ari(&mut cert);
        assert!(
            !cert.needs_renewal_at(0.001, true, now()),
            "{lifetime_hours}h at the boundary"
        );
        assert!(!cert.needs_renewal_at(0.001, true, now() + ChronoDuration::seconds(1)));
        assert!(
            cert.needs_renewal_at(0.001, true, now() + ChronoDuration::seconds(2)),
            "{lifetime_hours}h must keep its emergency override"
        );
    }
}

#[test]
fn fresh_hourly_daily_and_long_certificates_are_not_emergencies() {
    for hours in [1, 6, 24, 48, 72, 90 * 24] {
        let cert = certificate(ChronoDuration::hours(hours), ChronoDuration::hours(hours));
        assert!(
            !cert.needs_renewal_at(DEFAULT_RENEWAL_WINDOW_RATIO, true, now()),
            "{hours}h"
        );
    }
}

#[test]
fn ari_still_overrides_the_ordinary_ratio_until_its_selected_point() {
    let mut cert = certificate(ChronoDuration::hours(6), ChronoDuration::hours(3));
    assert!(cert.needs_renewal_at(0.75, true, now()));
    future_ari(&mut cert);
    let selected = cert.ari.as_ref().unwrap().selected_time.unwrap();
    assert!(!cert.needs_renewal_at(0.75, true, now()));
    assert!(!cert.needs_renewal_at(0.75, true, selected - ChronoDuration::nanoseconds(1)));
    assert!(cert.needs_renewal_at(0.75, true, selected));
    assert!(cert.needs_renewal_at(0.75, false, now()));
}

#[test]
fn expiration_and_final_one_fiftieth_remain_independent_of_late_ari() {
    let mut expired = certificate(ChronoDuration::hours(6), ChronoDuration::seconds(-2));
    future_ari(&mut expired);
    assert!(expired.needs_renewal_at(0.001, true, now()));
    let mut long = certificate(ChronoDuration::days(90), ChronoDuration::hours(48));
    future_ari(&mut long);
    assert!(!long.needs_renewal_at(0.001, true, now()));
    long.not_after -= ChronoDuration::hours(6);
    long.not_before -= ChronoDuration::hours(6);
    assert!(
        long.needs_renewal_at(0.001, true, now()),
        "90-day final 1/50 must still trigger before the 24h ceiling"
    );
    let mut short = certificate(ChronoDuration::hours(6), ChronoDuration::minutes(5));
    future_ari(&mut short);
    assert!(short.needs_renewal_at(0.001, true, now()));
}

#[test]
fn future_and_nonpositive_validity_need_repair_without_changing_raw_metadata() {
    for (before, after) in [(1, 7), (1, 1), (7, 1)] {
        let mut cert = certificate(ChronoDuration::hours(6), ChronoDuration::hours(after));
        cert.not_before = now() + ChronoDuration::hours(before);
        future_ari(&mut cert);
        assert!(cert.needs_renewal_at(0.001, true, now()));
    }
}
