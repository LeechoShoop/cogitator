//! Reflected/stored XSS active scan check.
//!
//! For every parameter on a `ScanTarget`, substitutes a unique marker payload
//! (`<cogitator-xss-{id}>` with a random `id` generated per probe so stale
//! matches from a previous run can never be mistaken for a fresh reflection)
//! one at a time, sends the resulting request, and checks whether the exact
//! payload string comes back unescaped in the response body.
//!
//! If the payload reflects immediately, that's a `High`-severity finding
//! (classic reflected XSS). If the original request was a `POST`, a
//! follow-up `GET` against the same URL is issued afterwards — if the same
//! payload is still present in that follow-up response, the payload has
//! persisted server-side (e.g. stored in a database and rendered back on a
//! plain page load), which is escalated to `Critical` (stored XSS).

use async_trait::async_trait;
use reqwest::Client;

use crate::logger;
use crate::scanner::{ScanCheck, ScanFinding, ScanTarget, Severity};

/// Number of characters of context to capture around the reflected payload,
/// split evenly before/after, for the `evidence` field.
const CONTEXT_WINDOW: usize = 80;

pub struct XssCheck;

impl XssCheck {
    pub fn new() -> Self {
        Self
    }

    /// Build today's unique probe payload.
    fn make_payload() -> String {
        let id: u32 = rand::random();
        format!("<cogitator-xss-{id}>")
    }

    /// If `payload` appears verbatim (unescaped) in `body`, return up to
    /// `CONTEXT_WINDOW` chars of surrounding context, centered on the match.
    fn find_reflection(body: &str, payload: &str) -> Option<String> {
        let idx = body.find(payload)?;

        let half = CONTEXT_WINDOW / 2;
        // Walk back/forward in char (not byte) steps so we never slice in the
        // middle of a multi-byte UTF-8 sequence.
        let start_char = body[..idx].chars().count().saturating_sub(half);
        let end_byte = idx + payload.len();
        let end_char = body[..end_byte].chars().count() + half;

        let evidence: String = body
            .chars()
            .skip(start_char)
            .take(end_char - start_char)
            .collect();
        Some(evidence)
    }

    /// Build a request for `target` with `param_name` replaced by `payload`
    /// (all other params left at their original value), send it, and return
    /// the response body as text. Network/parse failures yield `None` so the
    /// caller can simply skip this probe rather than propagate an error.
    async fn probe(
        client: &Client,
        target: &ScanTarget,
        method_override: Option<&str>,
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

        let method = method_override
            .map(|m| m.to_uppercase())
            .unwrap_or_else(|| target.method.to_uppercase());

        let mut req = client.request(
            method.parse().unwrap_or(reqwest::Method::GET),
            &target.url,
        );

        for (k, v) in &target.headers {
            req = req.header(k.as_str(), v.as_str());
        }

        // GET/HEAD/DELETE-style requests carry params on the query string;
        // everything else goes as a urlencoded form body, mirroring sqli.rs.
        req = if method == "GET" || method == "HEAD" {
            req.query(&substituted_params)
        } else {
            req.form(&substituted_params)
        };

        let request_raw = format!(
            "{} {} param={} payload={}",
            method, target.url, param_name, payload
        );

        match req.send().await {
            Ok(resp) => match resp.text().await {
                Ok(body) => Some((request_raw, body)),
                Err(e) => {
                    logger::debug(&format!("xss check: failed to read response body: {e}"));
                    None
                }
            },
            Err(e) => {
                logger::debug(&format!("xss check: request failed: {e}"));
                None
            }
        }
    }
}

impl Default for XssCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanCheck for XssCheck {
    fn name(&self) -> &str {
        "Cross-Site Scripting (reflected/stored)"
    }

    async fn check(&self, client: &Client, target: &ScanTarget) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        if target.params.is_empty() {
            return findings;
        }

        let original_method = target.method.to_uppercase();

        for (param_name, _) in &target.params {
            let payload = Self::make_payload();

            let Some((request_raw, body)) =
                Self::probe(client, target, None, param_name, &payload).await
            else {
                continue;
            };

            let Some(evidence) = Self::find_reflection(&body, &payload) else {
                continue;
            };

            // Reflected immediately — at minimum a High finding.
            let mut severity = Severity::High;
            let mut check_label = "reflected";

            logger::warn(&format!(
                "xss check: reflected payload for param '{}' (payload `{}`)",
                param_name, payload
            ));

            // If the probe that produced the reflection was a POST, follow
            // up with a plain GET against the same URL — if the marker is
            // still present with no params resubmitted, it was persisted
            // server-side rather than merely echoed back in this response.
            if original_method == "POST" {
                if let Some((_, followup_body)) =
                    Self::probe(client, target, Some("GET"), param_name, &payload).await
                {
                    if Self::find_reflection(&followup_body, &payload).is_some() {
                        severity = Severity::Critical;
                        check_label = "stored";
                        logger::warn(&format!(
                            "xss check: payload for param '{}' persisted across GET — stored XSS",
                            param_name
                        ));
                    }
                }
            }

            findings.push(ScanFinding {
                check_name: format!("{} ({})", self.name(), check_label),
                severity,
                evidence,
                request_raw,
                response_snippet: body.chars().take(200).collect(),
                url: target.url.clone(),
                parameter: Some(param_name.clone()),
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_reflection_with_context() {
        let payload = "<cogitator-xss-12345>";
        let body = format!(
            "some prefix text here {} some suffix text here",
            payload
        );
        let evidence = XssCheck::find_reflection(&body, payload).unwrap();
        assert!(evidence.contains(payload));
    }

    #[test]
    fn no_reflection_returns_none() {
        let body = "nothing interesting in this response body";
        assert!(XssCheck::find_reflection(body, "<cogitator-xss-99999>").is_none());
    }

    #[test]
    fn reflection_near_start_does_not_panic() {
        let payload = "<cogitator-xss-1>";
        let body = format!("{}trailing", payload);
        let evidence = XssCheck::find_reflection(&body, payload).unwrap();
        assert!(evidence.contains(payload));
    }

    #[test]
    fn reflection_near_end_does_not_panic() {
        let payload = "<cogitator-xss-2>";
        let body = format!("leading{}", payload);
        let evidence = XssCheck::find_reflection(&body, payload).unwrap();
        assert!(evidence.contains(payload));
    }

    #[test]
    fn payload_format_is_marker_style() {
        let p = XssCheck::make_payload();
        assert!(p.starts_with("<cogitator-xss-"));
        assert!(p.ends_with('>'));
    }

    #[test]
    fn payloads_are_unique_per_call() {
        let a = XssCheck::make_payload();
        let b = XssCheck::make_payload();
        // Astronomically unlikely to collide with a fresh random u32 each time.
        assert_ne!(a, b);
    }
}