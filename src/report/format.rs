//! Shared formatting utilities for the `report` module family.
//!
//! Currently holds the one piece of logic that was duplicated between
//! `report` (HTML) and `report_pdf` (PDF): the millisecond-UTC-timestamp →
//! `"YYYY-MM-DD HH:MM:SS"` formatter built on Howard Hinnant's
//! `civil_from_days` algorithm.
//!
//! # Why no date/time crate
//!
//! Both renderers intentionally avoid pulling in `chrono` / `time` for this
//! one conversion. The algorithm is ten lines of pure integer arithmetic
//! (public-domain, from <http://howardhinnant.github.io/date_algorithms.html>),
//! it never needs to understand timezones or locale, and adding a date crate
//! solely for `YYYY-MM-DD HH:MM:SS` UTC would be dead weight.

/// Convert a Unix millisecond timestamp to a `"YYYY-MM-DD HH:MM:SS"` string
/// in UTC, without pulling in a date/time crate.
///
/// Uses Howard Hinnant's `civil_from_days` algorithm (public domain) for the
/// calendar half; the time-of-day half is plain modular arithmetic on the
/// seconds-since-midnight remainder.
pub(crate) fn format_timestamp(timestamp_ms: u64) -> String {
    let total_secs = (timestamp_ms / 1000) as i64;
    let days = total_secs.div_euclid(86_400);
    let secs_of_day = total_secs.rem_euclid(86_400);

    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let min = (secs_of_day % 3600) / 60;
    let sec = secs_of_day % 60;

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hour, min, sec
    )
}

/// Days-since-epoch (1970-01-01) → (year, month, day). Standard
/// civil-from-days conversion; see
/// <http://howardhinnant.github.io/date_algorithms.html>.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_formats_known_epoch() {
        // 1_700_000_000_000 ms == 2023-11-14 22:13:20 UTC
        assert_eq!(format_timestamp(1_700_000_000_000), "2023-11-14 22:13:20");
    }

    #[test]
    fn timestamp_epoch_zero() {
        assert_eq!(format_timestamp(0), "1970-01-01 00:00:00");
    }

    #[test]
    fn timestamp_midnight_boundary() {
        // 86_400_000 ms == exactly 1970-01-02 00:00:00 — tests the day
        // boundary rollover in both div_euclid and civil_from_days.
        assert_eq!(format_timestamp(86_400_000), "1970-01-02 00:00:00");
    }

    #[test]
    fn timestamp_leap_day_2000() {
        // 2000-02-29 00:00:00 UTC — 951_782_400 seconds since epoch.
        assert_eq!(format_timestamp(951_782_400_000), "2000-02-29 00:00:00");
    }
}
