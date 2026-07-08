//! Time-based blind SQL injection active scan check.
//!
//! Unlike `sqli.rs` (error-based — looks for a DB error string reflected in
//! the response body), this check has no reflected signal to look for at
//! all: a vulnerable blind endpoint returns the same page either way. The
//! only observable side effect is that the database actually pauses before
//! answering, so detection is purely timing-based.
//!
//! For each parameter: measure one baseline (unmodified request), then try
//! each DB-specific sleep payload and compare its response time against
//! that baseline. A finding requires the delayed response to be BOTH at
//! least `RATIO_THRESHOLD`x the baseline AND at least `MIN_ABSOLUTE_DELTA`
//! longer in absolute terms — the ratio alone would false-positive on a
//! fast baseline (e.g. 50ms -> 300ms is 6x but not a 5s SQL sleep), and the
//! absolute delta alone would false-positive on a slow baseline under
//! normal network jitter.

use async_trait::async_trait;
use reqwest::Client;
use std::time::{Duration, Instant};

use crate::logger;
use crate::scanner::{ScanCheck, ScanFinding, ScanTarget, Severity};

/// DB-specific sleep payloads, all targeting the same delay so one
/// threshold works for all of them. Each is tried in turn per parameter;
/// the first one that produces a significant delay stops further payloads
/// against that parameter (matches the early-`break` pattern in
/// `sqli.rs`/`xss.rs`).
const BLIND_PAYLOADS: &[&str] = &[
    "' AND SLEEP(5)-- -",             // MySQL
    "'; WAITFOR DELAY '0:0:5'-- ",    // MSSQL
    "' AND pg_sleep(5)-- ",           // PostgreSQL
];

/// Every payload above sleeps for this many seconds; used only in log/
/// evidence text, not in the detection math itself (which is baseline-
/// relative, not tied to a specific expected delay).
const PAYLOAD_SLEEP_SECS: u64 = 5;

/// Delay enforced between consecutive probes against a target (mirrors
/// `sqli.rs::PROBE_DELAY`).
const PROBE_DELAY: Duration = Duration::from_millis(300);

/// Payloaded response must be at least this many times the baseline...
const RATIO_THRESHOLD: f64 = 4.0;
/// ...AND at least this much slower in absolute terms.
const MIN_ABSOLUTE_DELTA: Duration = Duration::from_secs(4);

pub struct SqliBlindCheck;

impl SqliBlindCheck {
    pub fn new() -> Self {
        Self
    }

    /// Core timing-delta decision, factored out so it can be unit-tested
    /// with fabricated `Duration`s instead of driving real sleeps through
    /// a live check.
    fn is_delay_significant(baseline: Duration, payloaded: Duration) -> bool {
        if payloaded <= baseline {
            return false;
        }
        let delta = payloaded - baseline;
        let ratio_ok = payloaded.as_secs_f64() >= baseline.as_secs_f64() * RATIO_THRESHOLD;
        let absolute_ok = delta >= MIN_ABSOLUTE_DELTA;
        ratio_ok && absolute_ok
    }

    /// Send `target`'s request completely unmodified and return how long it
    /// took (send + full body read, so it's measured the same way as
    /// `timed_probe` below). `None` on any network/read failure.
    async fn baseline_probe(client: &Client, target: &ScanTarget) -> Option<Duration> {
        let method = target.method.to_uppercase();
        let mut req = client.request(
            method.parse().unwrap_or(reqwest::Method::GET),
            &target.url,
        );

        for (k, v) in &target.headers {
            req = req.header(k.as_str(), v.as_str());
        }

        if !target.params.is_empty() {
            req = if method == "GET" || method == "HEAD" {
                req.query(&target.params)
            } else {
                req.form(&target.params)
            };
        }

        let start = Instant::now();
        match req.send().await {
            Ok(resp) => match resp.text().await {
                Ok(_) => Some(start.elapsed()),
                Err(e) => {
                    logger::debug(&format!("sqli_blind check: baseline body read failed: {e}"));
                    None
                }
            },
            Err(e) => {
                logger::debug(&format!("sqli_blind check: baseline request failed: {e}"));
                None
            }
        }
    }

    /// Build a request for `target` with `param_name` replaced by `payload`
    /// (all other params left at their original value), send it, and time
    /// how long the full round trip (send + body read) took.
    async fn timed_probe(
        client: &Client,
        target: &ScanTarget,
        param_name: &str,
        payload: &str,
    ) -> Option<(String, Duration)> {
        let substituted_params: Vec<(String, String)> = target
            .params
            .iter()
            .map(|(k, v)| {
                if k == param_name {
                    (k.clone(), payload.to_string())
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect();

        let method = target.method.to_uppercase();
        let mut req = client.request(
            method.parse().unwrap_or(reqwest::Method::GET),
            &target.url,
        );

        for (k, v) in &target.headers {
            req = req.header(k.as_str(), v.as_str());
        }

        req = if method == "GET" || method == "HEAD" {
            req.query(&substituted_params)
        } else {
            req.form(&substituted_params)
        };

        let request_raw = format!(
            "{} {} param={} payload={}",
            method, target.url, param_name, payload
        );

        let start = Instant::now();
        match req.send().await {
            Ok(resp) => match resp.text().await {
                Ok(_) => Some((request_raw, start.elapsed())),
                Err(e) => {
                    logger::debug(&format!("sqli_blind check: failed to read response body: {e}"));
                    None
                }
            },
            Err(e) => {
                logger::debug(&format!("sqli_blind check: request failed: {e}"));
                None
            }
        }
    }
}

impl Default for SqliBlindCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanCheck for SqliBlindCheck {
    fn name(&self) -> &str {
        "SQL Injection (time-based blind)"
    }

    async fn check(&self, client: &Client, target: &ScanTarget) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        if target.params.is_empty() {
            return findings;
        }

        // Single baseline for the whole target — every probe below only
        // touches one param at a time, so one unmodified-request timing is
        // a fair reference for all of them.
        let Some(baseline) = Self::baseline_probe(client, target).await else {
            return findings;
        };

        let mut first_probe = true;

        for (param_name, _) in &target.params {
            let mut found_for_param = false;

            for payload in BLIND_PAYLOADS {
                if found_for_param {
                    break;
                }

                if !first_probe {
                    tokio::time::sleep(PROBE_DELAY).await;
                }
                first_probe = false;

                let Some((request_raw, elapsed)) =
                    Self::timed_probe(client, target, param_name, payload).await
                else {
                    continue;
                };

                if Self::is_delay_significant(baseline, elapsed) {
                    logger::warn(&format!(
                        "sqli_blind check: possible time-based blind SQLi on param '{}' (payload `{}`) — baseline {:.2}s, response {:.2}s",
                        param_name, payload, baseline.as_secs_f64(), elapsed.as_secs_f64()
                    ));

                    findings.push(ScanFinding {
                        check_name: self.name().to_string(),
                        severity: Severity::High,
                        evidence: format!(
                            "baseline {:.2}s vs payloaded {:.2}s (expected sleep ~{}s), payload: {}",
                            baseline.as_secs_f64(),
                            elapsed.as_secs_f64(),
                            PAYLOAD_SLEEP_SECS,
                            payload
                        ),
                        request_raw,
                        response_snippet: String::new(),
                        url: target.url.clone(),
                        parameter: Some(param_name.clone()),
                    });

                    found_for_param = true;
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_clear_delay() {
        let baseline = Duration::from_millis(100);
        let payloaded = Duration::from_secs(5);
        assert!(SqliBlindCheck::is_delay_significant(baseline, payloaded));
    }

    #[test]
    fn ignores_normal_latency_jitter() {
        // Ratio is high (50ms -> 300ms is 6x) but absolute delta is tiny —
        // this is the exact false-positive case the absolute floor guards.
        let baseline = Duration::from_millis(50);
        let payloaded = Duration::from_millis(300);
        assert!(!SqliBlindCheck::is_delay_significant(baseline, payloaded));
    }

    #[test]
    fn ignores_slow_baseline_without_ratio() {
        // Absolute delta is large (10s) but ratio is under 4x — a
        // uniformly slow endpoint, not injected sleep.
        let baseline = Duration::from_secs(8);
        let payloaded = Duration::from_secs(12);
        assert!(!SqliBlindCheck::is_delay_significant(baseline, payloaded));
    }

    #[test]
    fn boundary_exactly_at_thresholds_passes() {
        // 4x ratio AND exactly 4s absolute delta — both floors are
        // inclusive (`>=`), so this should flag.
        let baseline = Duration::from_secs(1);
        let payloaded = Duration::from_secs(5); // ratio 5x, delta 4s
        assert!(SqliBlindCheck::is_delay_significant(baseline, payloaded));
    }

    #[test]
    fn payloaded_faster_than_baseline_never_flags() {
        let baseline = Duration::from_secs(5);
        let payloaded = Duration::from_millis(100);
        assert!(!SqliBlindCheck::is_delay_significant(baseline, payloaded));
    }

    #[test]
    fn zero_baseline_still_requires_absolute_floor() {
        // Ratio check is trivially satisfied against a zero baseline, so
        // the absolute floor is what actually protects here.
        let baseline = Duration::from_millis(0);
        let short = Duration::from_millis(500);
        let long = Duration::from_secs(5);
        assert!(!SqliBlindCheck::is_delay_significant(baseline, short));
        assert!(SqliBlindCheck::is_delay_significant(baseline, long));
    }

    #[test]
    fn equal_durations_never_flag() {
        let d = Duration::from_secs(3);
        assert!(!SqliBlindCheck::is_delay_significant(d, d));
    }
}