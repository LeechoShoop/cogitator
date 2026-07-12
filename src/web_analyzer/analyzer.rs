use reqwest::header::HeaderMap;
use reqwest::redirect::Policy;
use reqwest::Client;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::scrap_analyze::{audit_html, parse_csp_strength};
use crate::crypto_forensic::audit_crypto;
use crate::dns_guard::{audit_email_security, EmailSecurityRecords};

use super::types::{WebAnalysisResult, SCHEMA_VERSION};
use super::redirects::collect_redirects;
use super::cors::audit_cors;
use super::http_methods::probe_http_methods;
use super::clickjacking::{audit_clickjacking, ClickjackingAudit};
use super::fingerprint::probe_passive_fingerprint;
use super::scoring::compute_overall_score;
use super::formatter::format_analysis;
use super::utils::extract_header;

// ─── Site analyser abstraction (DI seam for proxy_guard) ─────────────────────

/// The analysis contract that `proxy_guard` depends on.
///
/// Consumers call [`SiteAnalyzer::analyze`] to run the full audit and
/// [`SiteAnalyzer::format`] to turn the result into a human-readable report.
/// The separation makes both sides independently testable:
///
/// * Real code: [`DefaultSiteAnalyzer`] — wraps the two reqwest clients.
/// * Tests: any struct that returns canned [`WebAnalysisResult`] values.
#[async_trait::async_trait]
pub trait SiteAnalyzer: Send + Sync {
    async fn analyze(&self, domain: &str) -> WebAnalysisResult;
    fn format(&self, result: &WebAnalysisResult) -> String;
}

/// Production implementation — delegates straight to [`analyze_site`] and
/// [`format_analysis`].  Constructed once in `main` and shared via `Arc`.
pub struct DefaultSiteAnalyzer {
    no_follow: Arc<Client>,
    follow: Arc<Client>,
}

impl DefaultSiteAnalyzer {
    pub fn new(no_follow: Arc<Client>, follow: Arc<Client>) -> Self {
        Self { no_follow, follow }
    }
}

#[async_trait::async_trait]
impl SiteAnalyzer for DefaultSiteAnalyzer {
    async fn analyze(&self, domain: &str) -> WebAnalysisResult {
        analyze_site(domain, &self.no_follow, &self.follow).await
    }

    fn format(&self, result: &WebAnalysisResult) -> String {
        format_analysis(result)
    }
}

// ─── Client construction ─────────────────────────────────────────────────────

/// Builds both async HTTP clients used by `analyze_site`.
/// Call once at startup (e.g. in `main`) and share the pair via `Arc`.
/// Returns an error if reqwest rejects the configuration -- this should never
/// happen in practice, but must not be a panic in a long-running process.
pub fn build_clients() -> Result<(Client, Client), reqwest::Error> {
    let no_follow = Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(Policy::none())
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .danger_accept_invalid_certs(true)
        .build()?;

    let follow = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/120.0.0.0")
        .danger_accept_invalid_certs(true)
        .build()?;

    Ok((no_follow, follow))
}

/// Returns a failure-mode `WebAnalysisResult` when client construction itself fails.
/// This path should be extremely rare (invalid TLS config, OS resource exhaustion).
fn client_build_failure(target_url: String, reason: reqwest::Error) -> WebAnalysisResult {
    WebAnalysisResult {
        schema_version: SCHEMA_VERSION.to_string(),
        target_url,
        status_code: format!("Client Init Failed ({})", reason),
        response_time_ms: 0,
        web_server: "Unknown".to_string(),
        has_hsts: false,
        has_csp: false,
        clickjacking_audit: ClickjackingAudit {
            x_frame_options: None,
            csp_frame_ancestors: false,
            frame_ancestors_value: None,
            is_protected: false,
            verdict: "Not checked (client init failed)".to_string(),
        },
        x_content_type: None,
        referrer_policy: None,
        permissions_policy: false,
        html_audit: None,
        crypto_audit: None,
        redirect_chain: Vec::new(),
        cors_audit: None,
        csp_strength: None,
        email_security: None,
        overall_score: 0,
        overall_grade: "F".to_string(),
        http_method_audit: None,
        passive_fingerprint: None,
        cve_matches: Vec::new(),
    }
}

// ─── Core analysis ───────────────────────────────────────────────────────────

/// Async entry point. Called directly from async contexts (proxy_guard, TUI
/// command handler). No `spawn_blocking` wrapper needed at the call site.
///
/// `no_follow` must be built with `redirect::Policy::none()` — it is used for
/// the redirect-chain collector, OPTIONS probe, and passive fingerprinting.
/// `follow` uses the default redirect policy and is used for the main request
/// and the CORS probe.
///
/// Both clients should be constructed once at startup (see `build_clients`) and
/// shared across calls via `Arc<Client>`.
pub async fn analyze_site(
    domain: &str,
    no_follow_client: &Client,
    follow_client: &Client,
) -> WebAnalysisResult {
    let clean_domain = domain.split(':').next().unwrap_or(domain);
    let target_url = format!("https://{}", clean_domain);

    // ── Step 1: Collect redirect chain (no-follow client) ────────────────────
    let redirect_chain = collect_redirects(&no_follow_client, &target_url, 10).await;

    // ── Step 2: CORS probe -- send with a suspicious Origin ──────────────────
    let cors_probe_origin = "https://evil.example.com";
    let cors_audit = follow_client
        .get(&target_url)
        .header("Origin", cors_probe_origin)
        .send()
        .await
        .ok()
        .map(|r| audit_cors(r.headers(), cors_probe_origin));

    // ── Step 3: HTTP method enumeration -- OPTIONS probe ─────────────────────
    let http_method_audit = Some(probe_http_methods(&no_follow_client, &target_url).await);

    // ── Step 4: Passive tech fingerprinting -- robots, sitemap, 404 ──────────
    let passive_fingerprint = Some(probe_passive_fingerprint(&no_follow_client, &target_url).await);

    // ── Step 4b: CVE lookup against detected technologies ────────────────────
    // Best-effort and slow (one external HTTP round-trip per mapped
    // technology against a third-party mirror) -- failures/timeouts on
    // individual lookups are swallowed inside `lookup_cves`, never fatal to
    // the rest of the analysis.
    let cve_matches = match &passive_fingerprint {
        Some(fp) if !fp.detected_technologies.is_empty() => {
            crate::cve::lookup_cves(&fp.detected_technologies).await
        }
        _ => Vec::new(),
    };

    // ── Step 5: Main request (follows redirects) for headers + HTML ──────────
    let start_time = Instant::now();
    match follow_client.get(&target_url).send().await {
        Ok(response) => {
            let response_time_ms = start_time.elapsed().as_millis();
            let status_code = response.status().to_string();
            let headers: HeaderMap = response.headers().clone();

            let web_server = headers.get("server")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("Protected / Hidden")
                .to_string();

            let has_hsts = headers.get("strict-transport-security").is_some();
            let has_csp  = headers.get("content-security-policy").is_some();

            let x_content_type  = extract_header(&headers, "x-content-type-options");
            let referrer_policy = extract_header(&headers, "referrer-policy");
            let permissions_policy = headers.get("permissions-policy").is_some();

            let clickjacking_audit = audit_clickjacking(&headers);

            let csp_strength = headers.get("content-security-policy")
                .and_then(|v| v.to_str().ok())
                .map(|csp| parse_csp_strength(csp));

            let crypto_audit = Some(audit_crypto(&headers));

            let html_audit = match response.text().await {
                Ok(html_text) => Some(audit_html(&html_text)),
                Err(_) => None,
            };

            // Email security records (DNS-based): blocking I/O -- run on
            // a dedicated blocking thread so the Tokio runtime isn't stalled.
            let clean_domain_owned = clean_domain.to_string();
            let email_security = Some(
                tokio::task::spawn_blocking(move || audit_email_security(&clean_domain_owned))
                    .await
                    .unwrap_or_else(|_| EmailSecurityRecords {
                        spf: None,
                        dmarc: None,
                        dkim_selector_found: false,
                        summary: "spawn_blocking panicked".to_string(),
                    })
            );

            let (overall_score, overall_grade) = compute_overall_score(
                has_hsts,
                has_csp,
                clickjacking_audit.is_protected,
                x_content_type.is_some(),
                permissions_policy,
                cors_audit.as_ref(),
                csp_strength.as_ref(),
                crypto_audit.as_ref(),
                email_security.as_ref(),
                http_method_audit.as_ref(),
            );

            WebAnalysisResult {
                schema_version: SCHEMA_VERSION.to_string(),
                target_url,
                status_code,
                response_time_ms,
                web_server,
                has_hsts,
                has_csp,
                clickjacking_audit,
                x_content_type,
                referrer_policy,
                permissions_policy,
                html_audit,
                crypto_audit,
                redirect_chain,
                cors_audit,
                csp_strength,
                email_security,
                overall_score,
                overall_grade,
                http_method_audit,
                passive_fingerprint,
                cve_matches,
            }
        }
        Err(e) => WebAnalysisResult {
            schema_version: SCHEMA_VERSION.to_string(),
            target_url,
            status_code: format!(
                "Connection Failed ({})",
                if e.is_timeout() { "Timeout" } else { "Error/Refused" }
            ),
            response_time_ms: 0,
            web_server: "Unknown".to_string(),
            has_hsts: false,
            has_csp: false,
            clickjacking_audit: ClickjackingAudit {
                x_frame_options: None,
                csp_frame_ancestors: false,
                frame_ancestors_value: None,
                is_protected: false,
                verdict: "Not checked (connection failed)".to_string(),
            },
            x_content_type: None,
            referrer_policy: None,
            permissions_policy: false,
            html_audit: None,
            crypto_audit: None,
            redirect_chain,
            cors_audit: None,
            csp_strength: None,
            email_security: None,
            overall_score: 0,
            overall_grade: "F".to_string(),
            http_method_audit,
            passive_fingerprint,
            cve_matches,
        },
    }
}
