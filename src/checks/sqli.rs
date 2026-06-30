//! SQL injection active scan check.
//!
//! For every parameter on a `ScanTarget`, substitutes a small set of classic
//! SQLi probe payloads one at a time, sends the resulting request, and scans
//! the response body for common database error signatures. A fixed delay is
//! enforced between individual probes to avoid hammering the target and to
//! reduce the chance of tripping IDS/WAF rate-based detection.

use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;

use crate::logger;
use crate::scanner::{ScanCheck, ScanFinding, ScanTarget, Severity};

/// Payloads tried against each parameter, in order.
const PAYLOADS: &[&str] = &["'", "''", "1 OR 1=1", "1; SELECT 1", "\")"];

/// Response-body substrings indicating a database error leaked back to the
/// client (case-sensitive — these are taken verbatim from real DB error
/// strings, so casing is meaningful and false-positive-reducing).
const ERROR_SIGNATURES: &[&str] = &[
    "SQL syntax",
    "mysql_fetch",
    "ORA-",
    "SQLite",
    "syntax error",
    "Unclosed quotation",
    "pg_query",
    "SQLSTATE",
];

/// Delay enforced between consecutive probes against a target.
const PROBE_DELAY: Duration = Duration::from_millis(300);

pub struct SqliCheck;

impl SqliCheck {
    pub fn new() -> Self {
        Self
    }

    /// Scan `body` for any configured error signature. Returns the first
    /// matching signature together with up to 200 chars of context starting
    /// at the match, if found.
    fn find_error_signature(body: &str) -> Option<(&'static str, String)> {
        for sig in ERROR_SIGNATURES {
            if let Some(idx) = body.find(sig) {
                let evidence: String = body[idx..].chars().take(200).collect();
                return Some((sig, evidence));
            }
        }
        None
    }

    /// Build a request for `target` with `param_name` replaced by `payload`
    /// (all other params left at their original value), send it, and return
    /// the response body as text. Network/parse failures yield `None` so the
    /// caller can simply skip this probe rather than propagate an error.
    async fn probe(
        client: &Client,
        target: &ScanTarget,
        param_name: &str,
        payload: &str,
    ) -> Option<(String, String)> {
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

        // GET/HEAD/DELETE-style requests carry params on the query string;
        // everything else goes as a urlencoded form body. This mirrors how
        // the params most likely arrived (query string vs form submission)
        // without needing to track the original encoding per-target.
        req = if method == "GET" || method == "HEAD" {
            req.query(&substituted_params)
        } else {
            req.form(&substituted_params)
        };

        let request_raw = format!("{} {} param={} payload={}", method, target.url, param_name, payload);

        match req.send().await {
            Ok(resp) => match resp.text().await {
                Ok(body) => Some((request_raw, body)),
                Err(e) => {
                    logger::debug(&format!("sqli check: failed to read response body: {e}"));
                    None
                }
            },
            Err(e) => {
                logger::debug(&format!("sqli check: request failed: {e}"));
                None
            }
        }
    }
}

impl Default for SqliCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanCheck for SqliCheck {
    fn name(&self) -> &str {
        "SQL Injection (error-based)"
    }

    async fn check(&self, client: &Client, target: &ScanTarget) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        if target.params.is_empty() {
            return findings;
        }

        let mut first_probe = true;

        for (param_name, _) in &target.params {
            for payload in PAYLOADS {
                // Throttle between probes (skip the wait before the very
                // first request so a single-param/single-payload scan isn't
                // needlessly delayed).
                if !first_probe {
                    tokio::time::sleep(PROBE_DELAY).await;
                }
                first_probe = false;

                let Some((request_raw, body)) =
                    Self::probe(client, target, param_name, payload).await
                else {
                    continue;
                };

                if let Some((sig, evidence)) = Self::find_error_signature(&body) {
                    logger::warn(&format!(
                        "sqli check: possible SQLi on param '{}' (payload `{}`) — matched signature '{}'",
                        param_name, payload, sig
                    ));

                    findings.push(ScanFinding {
                        check_name: self.name().to_string(),
                        severity: Severity::High,
                        evidence,
                        request_raw,
                        response_snippet: body.chars().take(200).collect(),
                        url: target.url.clone(),
                        parameter: Some(param_name.clone()),
                    });

                    // One confirmed finding per parameter is enough signal;
                    // move on to the next parameter rather than burning
                    // through the remaining payloads against it.
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

    #[test]
    fn finds_known_signature() {
        let body = "Warning: You have an error in your SQL syntax; check the manual";
        let (sig, evidence) = SqliCheck::find_error_signature(body).unwrap();
        assert_eq!(sig, "SQL syntax");
        assert!(evidence.starts_with("SQL syntax"));
    }

    #[test]
    fn evidence_capped_at_200_chars() {
        let tail = "x".repeat(500);
        let body = format!("ORA-{}", tail);
        let (_, evidence) = SqliCheck::find_error_signature(&body).unwrap();
        assert_eq!(evidence.chars().count(), 200);
    }

    #[test]
    fn no_signature_returns_none() {
        let body = "Everything is fine, nothing to see here.";
        assert!(SqliCheck::find_error_signature(body).is_none());
    }

    #[test]
    fn picks_first_matching_signature_in_priority_order() {
        // Body contains both "SQLite" and "SQLSTATE" — PAYLOADS list order
        // means "SQLite" (earlier in ERROR_SIGNATURES) should win.
        let body = "near \"x\": SQLite error, also SQLSTATE[42000]";
        let (sig, _) = SqliCheck::find_error_signature(body).unwrap();
        assert_eq!(sig, "SQLite");
    }
}