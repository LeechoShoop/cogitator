use reqwest::header::HeaderMap;
use reqwest::redirect::Policy;
use reqwest::Client;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::fs::File;
use std::io::Write;
use serde::Serialize;
use crate::scrap_analyze::{audit_html, parse_csp_strength, CspStrength, HtmlAuditResult};
use crate::crypto_forensic::{audit_crypto, CryptoAuditResult};
use crate::dns_guard::{audit_email_security, EmailSecurityRecords};

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

// ─── Schema version ───────────────────────────────────────────────────────────

/// Bump this whenever `WebAnalysisResult` gains, removes, or renames a field.
/// Consumers can reject or adapt payloads whose version they don't recognise.
/// Format: `"MAJOR.MINOR"` — increment MAJOR on breaking changes (field removed
/// or type changed), MINOR on additive changes (new optional field added).
pub const SCHEMA_VERSION: &str = "1.0";

// ─── Redirect chain ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct RedirectHop {
    pub url: String,
    pub status: String,
}

// ─── CORS audit ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct CorsAudit {
    pub acao_header: Option<String>,       // Access-Control-Allow-Origin
    pub acac_header: Option<String>,       // Access-Control-Allow-Credentials
    pub wildcard_origin: bool,
    pub credentials_with_wildcard: bool,   // Worst-case misconfiguration
    pub reflects_origin: bool,             // Server echoes back arbitrary Origin
    pub risk: String,
}

// ─── HTTP method enumeration ──────────────────────────────────────────────────

#[derive(Serialize)]
pub struct HttpMethodAudit {
    pub allowed_methods: Vec<String>,   // everything the Allow header lists
    pub dangerous_methods: Vec<String>, // subset: PUT, DELETE, TRACE, CONNECT, PATCH
    pub options_responded: bool,        // false if server ignored/blocked OPTIONS
    pub risk: String,
}

// ─── Clickjacking protection audit ───────────────────────────────────────────

/// The W3C spec (and all modern browsers) treat `frame-ancestors` in CSP as the
/// authoritative clickjacking defence; `X-Frame-Options` is only a fallback for
/// legacy browsers that pre-date CSP Level 2.  We must cross-reference both
/// before deciding whether the site is actually protected.
#[derive(Serialize)]
pub struct ClickjackingAudit {
    /// Raw value of X-Frame-Options if present.
    pub x_frame_options: Option<String>,
    /// Whether CSP contains a `frame-ancestors` directive.
    pub csp_frame_ancestors: bool,
    /// The extracted `frame-ancestors` value (e.g. `'none'`, `'self'`).
    pub frame_ancestors_value: Option<String>,
    /// True when at least one effective control is in place.
    pub is_protected: bool,
    /// Human-readable verdict.
    pub verdict: String,
}

/// Cross-reference `X-Frame-Options` and `Content-Security-Policy: frame-ancestors`
/// to produce a single, accurate clickjacking verdict.
fn audit_clickjacking(headers: &HeaderMap) -> ClickjackingAudit {
    let xfo = headers.get("x-frame-options")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Extract `frame-ancestors` from CSP.  A CSP header may contain multiple
    // semicolon-separated directives; we find the one starting with
    // "frame-ancestors" (case-insensitive) and capture its value.
    let (csp_frame_ancestors, frame_ancestors_value) = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .map(|csp| {
            let directive = csp
                .split(';')
                .map(|d| d.trim())
                .find(|d| d.to_lowercase().starts_with("frame-ancestors"));

            match directive {
                Some(d) => {
                    // Everything after the directive name is the value.
                    let value = d
                        .splitn(2, char::is_whitespace)
                        .nth(1)
                        .map(|s| s.trim().to_string());
                    (true, value)
                }
                None => (false, None),
            }
        })
        .unwrap_or((false, None));

    // Protection logic:
    //   * `frame-ancestors` in CSP  -> protected (supersedes XFO in modern browsers)
    //   * `X-Frame-Options` present -> protected (legacy fallback; still honoured)
    //   * Neither                   -> vulnerable
    let is_protected = csp_frame_ancestors || xfo.is_some();

    let verdict = if csp_frame_ancestors && xfo.is_some() {
        format!(
            "Protected -- CSP frame-ancestors ({}) + X-Frame-Options ({}) both present (belt-and-suspenders)",
            frame_ancestors_value.as_deref().unwrap_or("?"),
            xfo.as_deref().unwrap_or("?"),
        )
    } else if csp_frame_ancestors {
        format!(
            "Protected -- CSP frame-ancestors: {} (X-Frame-Options absent but not required)",
            frame_ancestors_value.as_deref().unwrap_or("?"),
        )
    } else if xfo.is_some() {
        format!(
            "Partial -- X-Frame-Options: {} only (no CSP frame-ancestors; legacy browsers protected, modern browsers rely on XFO fallback)",
            xfo.as_deref().unwrap_or("?"),
        )
    } else {
        "VULNERABLE -- neither X-Frame-Options nor CSP frame-ancestors is set".to_string()
    };

    ClickjackingAudit {
        x_frame_options: xfo,
        csp_frame_ancestors,
        frame_ancestors_value,
        is_protected,
        verdict,
    }
}

// ─── Passive tech fingerprinting ─────────────────────────────────────────────

/// Signals extracted from robots.txt, sitemap.xml, and a deliberate 404 probe.
/// All three are purely passive (no auth, no mutation) and extremely low-noise.
#[derive(Serialize)]
pub struct PassiveTechFingerprint {
    // robots.txt
    pub robots_found: bool,
    pub robots_disallow_paths: Vec<String>, // paths that leak app structure
    pub robots_cms_hints: Vec<String>,      // CMS/platform inferences from paths

    // sitemap.xml
    pub sitemap_found: bool,
    pub sitemap_url_sample: Vec<String>,    // up to 5 URLs for structure clues
    pub sitemap_cms_hints: Vec<String>,

    // 404 error page
    pub error_page_server_leak: Option<String>, // e.g. "Apache/2.4.41"
    pub error_page_framework_hints: Vec<String>, // Rails, Django, Laravel, etc.
    pub error_page_stack_trace: bool,            // any stack trace visible?

    // Combined verdict
    pub detected_technologies: Vec<String>, // deduplicated union of all hints
    pub confidence_note: String,
}

/// Probe /robots.txt, /sitemap.xml, and a deliberately bad path for tech signals.
///
/// Uses the no-follow client so redirects don't silently consume the 404 body.
/// All requests time out independently -- a blocked probe never stalls the rest.
async fn probe_passive_fingerprint(client: &Client, base_url: &str) -> PassiveTechFingerprint {
    // ── robots.txt ────────────────────────────────────────────────────────────

    // Path segments in robots.txt Disallow rules that betray a specific platform.
    // (pattern_substring, technology_name)
    const ROBOTS_HINTS: &[(&str, &str)] = &[
        ("/wp-admin",         "WordPress"),
        ("/wp-content",       "WordPress"),
        ("/wp-includes",      "WordPress"),
        ("/administrator",    "Joomla"),
        ("/components",       "Joomla"),
        ("/modules",          "Joomla"),
        ("/typo3",            "TYPO3"),
        ("/user/login",       "Drupal"),
        ("/sites/default",    "Drupal"),
        ("/magento",          "Magento"),
        ("/catalog/product",  "Magento"),
        ("/checkout/cart",    "Magento / Shopify"),
        ("/collections",      "Shopify"),
        ("/products",         "Shopify / e-commerce"),
        ("/_next",            "Next.js"),
        ("/.well-known",      "ACME / cert automation"),
        ("/rails",            "Ruby on Rails"),
        ("/django",           "Django"),
        ("/laravel",          "Laravel"),
        ("/phpmyadmin",       "phpMyAdmin (exposed admin)"),
        ("/adminer",          "Adminer (exposed DB UI)"),
        ("/.git",             "Git repository (exposed VCS)"),
        ("/backup",           "Backup directory"),
        ("/staging",          "Staging environment hint"),
        ("/api/v",            "REST API versioning"),
    ];

    let robots_url = format!("{}/robots.txt", base_url.trim_end_matches('/'));
    let (robots_found, robots_disallow_paths, robots_cms_hints) =
        match client.get(&robots_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let body = resp.text().await.unwrap_or_default();
                let mut disallows = Vec::new();
                let mut hints = Vec::new();

                for line in body.lines() {
                    let line_lower = line.trim().to_lowercase();
                    if line_lower.starts_with("disallow:") {
                        let path = line.trim()
                            .trim_start_matches("Disallow:")
                            .trim_start_matches("disallow:")
                            .trim()
                            .to_string();
                        if !path.is_empty() && path != "/" {
                            disallows.push(path.clone());
                            for (pattern, tech) in ROBOTS_HINTS {
                                if path.to_lowercase().contains(pattern) {
                                    let tech_s = tech.to_string();
                                    if !hints.contains(&tech_s) {
                                        hints.push(tech_s);
                                    }
                                }
                            }
                        }
                    }
                }

                // Cap disallow list to keep the report readable.
                disallows.truncate(20);
                (true, disallows, hints)
            }
            _ => (false, Vec::new(), Vec::new()),
        };

    // ── sitemap.xml ───────────────────────────────────────────────────────────

    const SITEMAP_HINTS: &[(&str, &str)] = &[
        ("/wp-content",    "WordPress"),
        ("/wp-includes",   "WordPress"),
        ("?p=",            "WordPress (query param)"),
        ("/node/",         "Drupal"),
        ("/category/",     "WordPress / blog CMS"),
        ("/collections/",  "Shopify"),
        ("/products/",     "Shopify / e-commerce"),
        ("/_next/",        "Next.js"),
        ("/blog/",         "Blog platform"),
        ("/en/",           "i18n multi-lang site"),
        ("/api/",          "API-driven frontend"),
    ];

    let sitemap_url = format!("{}/sitemap.xml", base_url.trim_end_matches('/'));
    let (sitemap_found, sitemap_url_sample, sitemap_cms_hints) =
        match client.get(&sitemap_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let body = resp.text().await.unwrap_or_default();
                let mut urls: Vec<String> = Vec::new();
                let mut hints = Vec::new();

                // Simple line-by-line <loc> extractor -- avoids an XML parser dep.
                for line in body.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("<loc>") || trimmed.contains("<loc>") {
                        let inner = trimmed
                            .replace("<loc>", "")
                            .replace("</loc>", "")
                            .trim()
                            .to_string();
                        if inner.starts_with("http") && urls.len() < 5 {
                            for (pattern, tech) in SITEMAP_HINTS {
                                if inner.contains(pattern) {
                                    let tech_s = tech.to_string();
                                    if !hints.contains(&tech_s) {
                                        hints.push(tech_s);
                                    }
                                }
                            }
                            urls.push(inner);
                        }
                    }
                }

                (true, urls, hints)
            }
            _ => (false, Vec::new(), Vec::new()),
        };

    // ── Deliberate 404 ────────────────────────────────────────────────────────
    //
    // A unique path ensures we hit the app's own error handler rather than a
    // cached CDN response.  We parse the body for framework signatures and the
    // headers for a leaked Server banner.

    const ERROR_BODY_HINTS: &[(&str, &str)] = &[
        // Rails
        ("ActionController",       "Ruby on Rails"),
        ("ActionView",             "Ruby on Rails"),
        ("No route matches",       "Ruby on Rails"),
        // Django
        ("Django",                 "Django (Python)"),
        ("Page not found (404)",   "Django (Python)"),
        ("Using the URLconf",      "Django (Python)"),
        // Laravel / PHP
        ("Laravel",                "Laravel (PHP)"),
        ("Symfony",                "Symfony (PHP)"),
        ("Whoops!",                "PHP framework (Whoops handler)"),
        ("NotFoundHttpException",  "Laravel / Symfony"),
        // Express / Node
        ("Cannot GET",             "Express.js (Node)"),
        ("Express",                "Express.js (Node)"),
        // Spring / Java
        ("Whitelabel Error Page",  "Spring Boot (Java)"),
        ("org.springframework",    "Spring Framework (Java)"),
        ("javax.servlet",          "Java Servlet container"),
        // ASP.NET
        ("ASP.NET",                "ASP.NET"),
        ("Server Error in",        "ASP.NET"),
        ("System.Web",             "ASP.NET"),
        // Flask
        ("Werkzeug",               "Flask / Werkzeug (Python)"),
        // FastAPI
        ("FastAPI",                "FastAPI (Python)"),
        // WordPress
        ("wp-includes",            "WordPress"),
        // Generic stack trace tells
        ("stack trace",            "Stack trace exposed"),
        ("traceback",              "Python traceback exposed"),
        ("at com.",                "JVM stack trace exposed"),
        ("Exception in thread",    "JVM exception exposed"),
        ("Caused by:",             "JVM / Spring exception"),
    ];

    // Use a path that is effectively guaranteed not to exist.
    let not_found_url = format!("{}/cogitator-404-probe-xqz", base_url.trim_end_matches('/'));
    let (error_page_server_leak, error_page_framework_hints, error_page_stack_trace) =
        match client.get(&not_found_url).send().await {
            Ok(resp) => {
                // Capture Server header from the 404 response -- sometimes differs
                // from the main page (CDN fronting, etc.)
                let server_leak = resp.headers()
                    .get("server")
                    .and_then(|v| v.to_str().ok())
                    .filter(|s| {
                        // Only flag if it contains a version number -- bare "nginx"
                        // is expected; "nginx/1.14.0 (Ubuntu)" is a disclosure.
                        s.contains('/') || s.chars().any(|c| c.is_ascii_digit())
                    })
                    .map(|s| s.to_string());

                let body = resp.text().await.unwrap_or_default();
                let body_lower = body.to_lowercase();
                let mut hints = Vec::new();
                let mut stack_trace = false;

                for (pattern, tech) in ERROR_BODY_HINTS {
                    let pat_lower = pattern.to_lowercase();
                    if body_lower.contains(&pat_lower) {
                        let tech_s = tech.to_string();
                        if tech_s.contains("exposed") {
                            stack_trace = true;
                        }
                        if !hints.contains(&tech_s) {
                            hints.push(tech_s);
                        }
                    }
                }

                (server_leak, hints, stack_trace)
            }
            _ => (None, Vec::new(), false),
        };

    // ── Combine all signals ───────────────────────────────────────────────────

    let mut all_tech: Vec<String> = Vec::new();
    for hint in robots_cms_hints.iter()
        .chain(sitemap_cms_hints.iter())
        .chain(error_page_framework_hints.iter())
    {
        if !all_tech.contains(hint) {
            all_tech.push(hint.clone());
        }
    }
    if let Some(ref srv) = error_page_server_leak {
        let entry = format!("Server: {}", srv);
        if !all_tech.contains(&entry) {
            all_tech.push(entry);
        }
    }

    let confidence_note = if !robots_found && !sitemap_found {
        "Neither robots.txt nor sitemap.xml responded -- fingerprint based on 404 only".to_string()
    } else if all_tech.is_empty() {
        "Probes returned data but no known technology signatures matched".to_string()
    } else {
        format!("{} technology signal(s) detected across {} probe(s)",
                all_tech.len(),
                [robots_found, sitemap_found, true].iter().filter(|&&b| b).count()
        )
    };

    PassiveTechFingerprint {
        robots_found,
        robots_disallow_paths,
        robots_cms_hints,
        sitemap_found,
        sitemap_url_sample,
        sitemap_cms_hints,
        error_page_server_leak,
        error_page_framework_hints,
        error_page_stack_trace,
        detected_technologies: all_tech,
        confidence_note,
    }
}

// ─── Main result ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct WebAnalysisResult {
    /// Schema version of this payload -- see `SCHEMA_VERSION`.
    pub schema_version: String,
    pub target_url: String,
    pub status_code: String,
    pub response_time_ms: u128,
    pub web_server: String,
    pub has_hsts: bool,
    pub has_csp: bool,
    pub clickjacking_audit: ClickjackingAudit,
    pub x_content_type: Option<String>,
    pub referrer_policy: Option<String>,
    pub permissions_policy: bool,
    pub html_audit: Option<HtmlAuditResult>,
    pub crypto_audit: Option<CryptoAuditResult>,
    pub redirect_chain: Vec<RedirectHop>,
    pub cors_audit: Option<CorsAudit>,
    pub csp_strength: Option<CspStrength>,
    pub email_security: Option<EmailSecurityRecords>,
    pub overall_score: u8,   // 0-100
    pub overall_grade: String, // A / B / C / D / F
    pub http_method_audit: Option<HttpMethodAudit>,
    pub passive_fingerprint: Option<PassiveTechFingerprint>,
    pub cve_matches: Vec<crate::cve::CveMatch>,
}

// ─── JSON export ─────────────────────────────────────────────────────────────

pub fn export_to_json(result: &WebAnalysisResult) -> String {
    serde_json::to_string_pretty(result)
        .unwrap_or_else(|_| "{\"error\": \"serialization failed\"}".to_string())
}

pub fn save_to_file(result: &WebAnalysisResult, file_path: &str) -> Result<(), std::io::Error> {
    let json_data = export_to_json(result);
    let mut file = File::create(file_path)?;
    file.write_all(json_data.as_bytes())?;
    Ok(())
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
                    .unwrap_or_else(|_| crate::dns_guard::EmailSecurityRecords {
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

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn extract_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name).and_then(|v| v.to_str().ok()).map(|s| s.to_string())
}

/// Follow redirects manually to build a hop chain.
///
/// A `HashSet` of visited URLs is maintained so that a cycle (A->B->A) is
/// detected before the next request is issued, rather than burning all
/// remaining hops or looping forever.
async fn collect_redirects(client: &Client, start_url: &str, max_hops: usize) -> Vec<RedirectHop> {
    let mut chain = Vec::new();
    let mut current = start_url.to_string();
    let mut visited = std::collections::HashSet::new();

    for _ in 0..max_hops {
        // Cycle guard: if we have already visited this URL, stop immediately.
        if !visited.insert(current.clone()) {
            chain.push(RedirectHop {
                url: current,
                status: "Loop detected".to_string(),
            });
            break;
        }

        match client.get(&current).send().await {
            Ok(resp) => {
                let status = resp.status();
                chain.push(RedirectHop { url: current.clone(), status: status.to_string() });

                if status.is_redirection() {
                    if let Some(loc) = resp.headers().get("location")
                        .and_then(|v| v.to_str().ok())
                    {
                        // Handle relative redirects
                        if loc.starts_with("http://") || loc.starts_with("https://") {
                            current = loc.to_string();
                        } else {
                            let base = current.trim_end_matches('/');
                            current = format!("{}/{}", base, loc.trim_start_matches('/'));
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    chain
}

/// Inspect response headers for CORS misconfiguration.
fn audit_cors(headers: &HeaderMap, probed_origin: &str) -> CorsAudit {
    let acao = headers.get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let acac = headers.get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let wildcard_origin = acao.as_deref() == Some("*");
    let reflects_origin = acao.as_deref() == Some(probed_origin);
    let credentials_with_wildcard = wildcard_origin && acac.as_deref() == Some("true");

    let risk = if credentials_with_wildcard {
        "CRITICAL -- wildcard + credentials: data theft possible".to_string()
    } else if reflects_origin && acac.as_deref() == Some("true") {
        "HIGH -- origin reflected with credentials: CORS hijacking risk".to_string()
    } else if reflects_origin {
        "MEDIUM -- server reflects arbitrary Origin header".to_string()
    } else if wildcard_origin {
        "LOW-MEDIUM -- wildcard origin (no credentials, read-only risk)".to_string()
    } else {
        "No obvious CORS misconfiguration detected".to_string()
    };

    CorsAudit { acao_header: acao, acac_header: acac, wildcard_origin, credentials_with_wildcard, reflects_origin, risk }
}

/// Send an OPTIONS request and classify the methods the server advertises.
///
/// Checks both `Allow` (standard) and `Public` (WebDAV) response headers.
/// The no-follow client is reused so we don't chase redirects on the probe.
async fn probe_http_methods(client: &Client, url: &str) -> HttpMethodAudit {
    // Verbs that represent meaningful attack surface when enabled on a web app.
    const DANGEROUS: &[&str] = &["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"];

    let resp = client
        .request(reqwest::Method::OPTIONS, url)
        .send()
        .await;

    let (allowed_methods, options_responded) = match resp {
        Ok(r) => {
            // Some servers put the list in `Public` (WebDAV) instead of `Allow`.
            let allow_value = r.headers()
                .get("allow")
                .or_else(|| r.headers().get("public"))
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            let methods: Vec<String> = allow_value
                .split(',')
                .map(|m| m.trim().to_uppercase())
                .filter(|m| !m.is_empty())
                .collect();

            let responded = !methods.is_empty() || r.status().is_success();
            (methods, responded)
        }
        Err(_) => (Vec::new(), false),
    };

    let dangerous_methods: Vec<String> = DANGEROUS.iter()
        .filter(|&&d| allowed_methods.iter().any(|m| m == d))
        .map(|&d| d.to_string())
        .collect();

    let risk = if !options_responded {
        "Server did not respond to OPTIONS (filtered or disabled)".to_string()
    } else if dangerous_methods.contains(&"TRACE".to_string()) {
        "CRITICAL -- TRACE enabled: cross-site tracing (XST) attack possible".to_string()
    } else if dangerous_methods.contains(&"PUT".to_string())
        || dangerous_methods.contains(&"DELETE".to_string())
    {
        format!(
            "HIGH -- write verbs enabled ({}): potential file upload / resource deletion",
            dangerous_methods.join(", ")
        )
    } else if !dangerous_methods.is_empty() {
        format!(
            "MEDIUM -- non-standard verbs present ({}): review server config",
            dangerous_methods.join(", ")
        )
    } else {
        "No dangerous HTTP methods advertised".to_string()
    };

    HttpMethodAudit { allowed_methods, dangerous_methods, options_responded, risk }
}

/// Aggregate security posture score (0-100).
fn compute_overall_score(
    has_hsts: bool,
    has_csp: bool,
    has_x_frame: bool,
    has_x_content: bool,
    has_permissions: bool,
    cors: Option<&CorsAudit>,
    csp_strength: Option<&CspStrength>,
    crypto: Option<&CryptoAuditResult>,
    email: Option<&EmailSecurityRecords>,
    http_methods: Option<&HttpMethodAudit>,
) -> (u8, String) {
    let mut score: i32 = 100;

    if !has_hsts       { score -= 15; }
    if !has_csp        { score -= 15; }
    if !has_x_frame    { score -= 10; }
    if !has_x_content  { score -= 5; }
    if !has_permissions { score -= 5; }

    if let Some(cors) = cors {
        if cors.credentials_with_wildcard { score -= 25; }
        else if cors.reflects_origin && cors.acac_header.as_deref() == Some("true") { score -= 15; }
        else if cors.reflects_origin      { score -= 8; }
    }

    if let Some(csp) = csp_strength {
        if csp.has_unsafe_inline  { score -= 10; }
        if csp.has_unsafe_eval    { score -= 8; }
        if csp.has_wildcard_source { score -= 8; }
    }

    if let Some(c) = crypto {
        let issues = c.insecure_cookie_flags.len() as i32;
        score -= issues * 3;
        if !c.hsts_preload { score -= 2; }
    }

    if let Some(e) = email {
        if e.spf.is_none()   { score -= 5; }
        if e.dmarc.is_none() { score -= 5; }
    }

    if let Some(m) = http_methods {
        if m.dangerous_methods.contains(&"TRACE".to_string())  { score -= 20; }
        if m.dangerous_methods.contains(&"PUT".to_string())
            || m.dangerous_methods.contains(&"DELETE".to_string()) { score -= 15; }
        else if !m.dangerous_methods.is_empty()                 { score -= 8; }
    }

    let score = score.clamp(0, 100) as u8;
    let grade = match score {
        90..=100 => "A",
        75..=89  => "B",
        60..=74  => "C",
        45..=59  => "D",
        _        => "F",
    }.to_string();

    (score, grade)
}

// ─── Report formatter ────────────────────────────────────────────────────────

// ── Section builder ──────────────────────────────────────────────────────────
//
// Usage:
//   Section::new("SECURITY HEADERS")
//       .row("HSTS", "Present")
//       .row("CSP",  "MISSING")
//       .render(&mut r);
//
// `render` appends to an existing String so callers never allocate a temporary.
// The `empty` variant lets callers emit a single "[Not checked]" footer
// without building rows at all.

struct Row {
    label: String,
    value: String,
}

struct Section {
    title:     String,
    rows:      Vec<Row>,
    /// Raw freeform lines appended after all rows (sub-bullets, etc.).
    extra:     Vec<String>,
    /// When set, rows are suppressed and this message is emitted instead.
    empty_msg: Option<String>,
}

impl Section {
    fn new(title: &str) -> Self {
        Self {
            title:     title.to_string(),
            rows:      Vec::new(),
            extra:     Vec::new(),
            empty_msg: None,
        }
    }

    /// Append a `│  ├─ <label>:  <value>` row.
    fn row(mut self, label: &str, value: impl std::fmt::Display) -> Self {
        self.rows.push(Row { label: label.to_string(), value: value.to_string() });
        self
    }

    /// Append a row only when `cond` is true.
    fn row_if(self, cond: bool, label: &str, value: impl std::fmt::Display) -> Self {
        if cond { self.row(label, value) } else { self }
    }

    /// Append a raw indented line (`│  <text>`).
    /// Used for sub-trees that don't fit a plain label/value pair.
    fn line(mut self, text: impl Into<String>) -> Self {
        self.extra.push(text.into());
        self
    }

    /// Replace all rows with a single `[<msg>]` footer.
    fn empty(mut self, msg: &str) -> Self {
        self.empty_msg = Some(msg.to_string());
        self
    }

    /// Write the fully-rendered section into `out`.
    fn render(self, out: &mut String) {
        let header = format!("┌─[ {} ]", self.title);
        let pad_width = 56usize.saturating_sub(header.len());
        out.push('\n');
        out.push_str(&header);
        out.push_str(&"─".repeat(pad_width));
        out.push('\n');

        if let Some(msg) = self.empty_msg {
            out.push_str(&format!("│  └─ [{}]\n", msg));
            return;
        }

        let row_count   = self.rows.len();
        let extra_count = self.extra.len();
        let has_extra   = extra_count > 0;

        for (i, row) in self.rows.into_iter().enumerate() {
            let is_last   = i + 1 == row_count && !has_extra;
            let connector = if is_last { "└─" } else { "├─" };
            out.push_str(&format!(
                "│  {} {:<20} {}\n",
                connector,
                format!("{}:", row.label),
                row.value,
            ));
        }

        for (i, line) in self.extra.into_iter().enumerate() {
            let is_last   = i + 1 == extra_count;
            let connector = if is_last { "└─" } else { "├─" };
            out.push_str(&format!("│  {} {}\n", connector, line));
        }
    }
}

#[cfg(test)]
mod section_tests {
    use super::Section;

    fn render(s: Section) -> String {
        let mut out = String::new();
        s.render(&mut out);
        out
    }

    #[test]
    fn single_row_uses_closing_connector() {
        let out = render(Section::new("X").row("Foo", "bar"));
        assert!(out.contains("└─"), "single row should use └─");
        assert!(!out.contains("├─"), "single row must not use ├─");
    }

    #[test]
    fn multiple_rows_last_uses_closing_connector() {
        let out = render(
            Section::new("X")
                .row("A", "1")
                .row("B", "2")
                .row("C", "3"),
        );
        assert_eq!(out.match_indices("└─").count(), 1, "exactly one └─");
        assert_eq!(out.match_indices("├─").count(), 2, "two ├─ for first two rows");
    }

    #[test]
    fn empty_msg_suppresses_rows() {
        let out = render(
            Section::new("X")
                .row("A", "1")
                .empty("Not checked"),
        );
        assert!(out.contains("[Not checked]"));
        assert!(!out.contains("A:"));
    }

    #[test]
    fn row_if_skips_when_false() {
        let out = render(Section::new("X").row_if(false, "Skip", "me").row("Keep", "v"));
        assert!(!out.contains("Skip"));
        assert!(out.contains("Keep"));
    }
}

pub fn format_analysis(result: &WebAnalysisResult) -> String {
    let mut r = String::new();

    // ── Header banner ────────────────────────────────────────────────────────
    r.push_str(&format!("╔══════════════════════════════════════════════════════╗\n"));
    r.push_str(&format!("║  TARGET: {:<43} ║\n", result.target_url));
    r.push_str(&format!("╠══════════════════════════════════════════════════════╣\n"));
    r.push_str(&format!("║  Status:      {:<38} ║\n", result.status_code));
    r.push_str(&format!("║  Response:    {:<35} ms  ║\n", result.response_time_ms));
    r.push_str(&format!("║  Web Server:  {:<38} ║\n", result.web_server));
    r.push_str(&format!("║  Score:       {}/100  Grade: {:<28} ║\n",
                        result.overall_score, result.overall_grade));
    r.push_str(&format!("╚══════════════════════════════════════════════════════╝\n"));

    // ── Redirect chain ───────────────────────────────────────────────────────
    if !result.redirect_chain.is_empty() {
        r.push_str("\n┌─[ REDIRECT CHAIN ]────────────────────────────────────\n");
        for (i, hop) in result.redirect_chain.iter().enumerate() {
            let arrow = if i + 1 < result.redirect_chain.len() { "├→" } else { "└→" };
            r.push_str(&format!("│  {} [{}] {}\n", arrow, hop.status, hop.url));
        }
        // Flag HTTP->HTTPS upgrade (good) or missing HTTPS (bad)
        if let (Some(first), Some(last)) = (result.redirect_chain.first(), result.redirect_chain.last()) {
            if first.url.starts_with("http://") && last.url.starts_with("https://") {
                r.push_str("│  HTTP->HTTPS upgrade detected\n");
            } else if last.url.starts_with("http://") {
                r.push_str("│  Final destination is still HTTP!\n");
            }
        }
    }

    // ── Security headers ─────────────────────────────────────────────────────
    {
        let mut sec = Section::new("SECURITY HEADERS")
            .row("HSTS", if result.has_hsts { "Present" } else { "MISSING" })
            .row("CSP",  if result.has_csp  { "Present" } else { "MISSING" });

        if let Some(ref csp) = result.csp_strength {
            sec = sec.line(format!("│  ├─ Grade:          {}", csp.grade));
            if csp.has_unsafe_inline   { sec = sec.line("│  ├─ unsafe-inline present"); }
            if csp.has_unsafe_eval     { sec = sec.line("│  ├─ unsafe-eval present"); }
            if csp.has_wildcard_source { sec = sec.line("│  ├─ wildcard source present"); }
            if csp.allows_data_uris    { sec = sec.line("│  └─ data: URIs allowed"); }
        }

        sec = sec
            .row("Clickjacking",       &result.clickjacking_audit.verdict)
            .row("X-Content-Type",     result.x_content_type.as_deref().unwrap_or("MISSING"))
            .row("Referrer-Policy",    result.referrer_policy.as_deref().unwrap_or("Not set"))
            .row("Permissions-Policy", if result.permissions_policy { "Present" } else { "Not set" });

        sec.render(&mut r);
    }

    // ── CORS ─────────────────────────────────────────────────────────────────
    {
        let sec = if let Some(ref cors) = result.cors_audit {
            Section::new("CORS AUDIT")
                .row("ACAO", cors.acao_header.as_deref().unwrap_or("Not set"))
                .row("ACAC", cors.acac_header.as_deref().unwrap_or("Not set"))
                .row("Risk", &cors.risk)
        } else {
            Section::new("CORS AUDIT").empty("Not checked")
        };
        sec.render(&mut r);
    }

    // ── HTTP methods ─────────────────────────────────────────────────────────
    {
        let sec = if let Some(ref m) = result.http_method_audit {
            let mut sec = Section::new("HTTP METHODS");
            if !m.allowed_methods.is_empty() {
                sec = sec.row("Allowed", m.allowed_methods.join(", "));
            }
            if !m.dangerous_methods.is_empty() {
                sec = sec.row("Dangerous", m.dangerous_methods.join(", "));
            }
            sec.row("Risk", &m.risk)
        } else {
            Section::new("HTTP METHODS").empty("Not checked")
        };
        sec.render(&mut r);
    }

    // ── Crypto forensic ──────────────────────────────────────────────────────
    {
        let sec = if let Some(ref crypto) = result.crypto_audit {
            let grade_label = match crypto.grade.as_str() {
                "A" => "A  Strong crypto posture",
                "B" => "B  Good -- minor gaps",
                "C" => "C  Fair -- several issues",
                "D" => "D  Weak -- significant issues",
                _   => "F  Critical -- major failures",
            };

            let mut sec = Section::new("CRYPTO FORENSIC")
                .row("TLS",               &crypto.tls_version)
                .row("Cookie Score",      &crypto.cookie_security_score)
                .row("Cookies Found",     crypto.cookies_found)
                .row("HSTS Preload",      if crypto.hsts_preload { "Yes" } else { "No" })
                .row("HSTS Max-Age",      crypto.hsts_max_age_secs
                    .map(|s| format!("{}s", s))
                    .as_deref()
                    .unwrap_or("Not set"))
                .row("includeSubdomains", if crypto.hsts_includes_subdomains { "Yes" } else { "No" });

            // Cookie flag sub-bullets
            for (i, issue) in crypto.insecure_cookie_flags.iter().take(3).enumerate() {
                let conn = if i + 1 < crypto.insecure_cookie_flags.len().min(3) { "├─" } else { "└─" };
                sec = sec.line(format!("│  {} {}", conn, issue));
            }
            if crypto.insecure_cookie_flags.len() > 3 {
                sec = sec.line(format!("│  └─ ... and {} more flag issues",
                                       crypto.insecure_cookie_flags.len() - 3));
            }

            if !crypto.jwt_cookies_detected.is_empty() {
                sec = sec.row("JWT Cookies", crypto.jwt_cookies_detected.join(", "));
            }
            sec = sec.row_if(
                crypto.hpkp_detected,
                "HPKP detected",
                "deprecated header present (may cause lockout)",
            );

            sec.row("Crypto Grade", grade_label)
        } else {
            Section::new("CRYPTO FORENSIC").empty("No crypto data available")
        };
        sec.render(&mut r);
    }

    // ── Email security ───────────────────────────────────────────────────────
    {
        let sec = if let Some(ref email) = result.email_security {
            Section::new("EMAIL SECURITY (DNS)")
                .row("SPF",                    email.spf.as_deref().unwrap_or("Not found"))
                .row("DMARC",                  email.dmarc.as_deref().unwrap_or("Not found"))
                .row("DKIM (common selectors)", if email.dkim_selector_found { "Found" } else { "Not detected" })
                .row("Summary",                &email.summary)
        } else {
            Section::new("EMAIL SECURITY (DNS)").empty("Not checked")
        };
        sec.render(&mut r);
    }

    // ── HTML & content audit ─────────────────────────────────────────────────
    r.push_str("\n┌─[ HTML STRUCTURE & LEAK AUDIT ]──────────────────────\n");
    if let Some(ref html) = result.html_audit {
        r.push_str(&format!("│  ├─ Forms:              {}\n", html.forms_count));

        if !html.attack_vectors.is_empty() {
            r.push_str("│  ├─ Attack Vectors (Inputs/Textareas):\n");
            for (i, v) in html.attack_vectors.iter().enumerate().take(5) {
                r.push_str(&format!("│  │  {:>2}. [{}] -> {}\n", i+1, v.input_type, v.form_action));
            }
            if html.attack_vectors.len() > 5 {
                r.push_str(&format!("│  │  └─ ... and {} more\n", html.attack_vectors.len() - 5));
            }
        }

        // JS Fingerprint
        let fp = &html.js_fingerprint;
        if !fp.detected_frameworks.is_empty() {
            r.push_str(&format!("│  ├─ JS Frameworks:      {}\n", fp.detected_frameworks.join(", ")));
        }
        if !fp.detected_analytics.is_empty() {
            r.push_str(&format!("│  ├─ Analytics/Track:    {}\n", fp.detected_analytics.join(", ")));
        }
        if !fp.open_redirect_patterns.is_empty() {
            r.push_str(&format!("│  ├─ Open Redirect Patterns: {}\n", fp.open_redirect_patterns.len()));
            for pat in fp.open_redirect_patterns.iter().take(2) {
                r.push_str(&format!("│  │  └─ {}\n", &pat[..pat.len().min(100)]));
            }
        }

        r.push_str("│  ├─ SQL Surface:\n");
        r.push_str(&format!("│  │  ├─ Search Forms:     {}\n", html.sql_audit.potential_search_forms));
        r.push_str(&format!("│  │  └─ Debug Keywords:   {}\n",
                            if html.sql_audit.debug_comments_found { "SQL keywords in HTML!" } else { "Clean" }));

        r.push_str(&format!("│  ├─ Hidden Inputs:      {}\n", html.hidden_inputs_count));
        r.push_str(&format!("│  ├─ Inline JS:          {} blocks ({} bytes)\n",
                            html.inline_scripts_count, html.inline_scripts_bytes));
        r.push_str(&format!("│  ├─ Stylesheets:        {} (CDN: {})\n",
                            html.stylesheet_links_count, html.external_stylesheets_count));
        r.push_str(&format!("│  ├─ Links:              {} internal / {} external\n",
                            html.internal_links_count, html.external_links_count));

        if let Some(ref cms) = html.cms_generator {
            r.push_str(&format!("│  ├─ CMS Generator:      {}\n", cms));
        }

        if !html.detected_api_routes.is_empty() {
            r.push_str(&format!("│  ├─ API Endpoints:      {}\n", html.detected_api_routes.len()));
            for route in html.detected_api_routes.iter().take(3) {
                r.push_str(&format!("│  │  ├─ {}\n", route));
            }
        }

        if !html.potential_tokens.is_empty() {
            r.push_str(&format!("│  ├─ KEY LEAKS:          {}\n", html.potential_tokens.len()));
            for token in html.potential_tokens.iter().take(2) {
                r.push_str(&format!("│  │  └─ {}\n", token));
            }
        } else {
            r.push_str("│  ├─ Key Leaks:          Clean\n");
        }

        if html.insecure_scripts_count > 0 || !html.suspicious_http_links.is_empty() {
            r.push_str("│  ├─ MIXED CONTENT:\n");
            if html.insecure_scripts_count > 0 {
                r.push_str(&format!("│  │  ├─ HTTP scripts: {}\n", html.insecure_scripts_count));
            }
            if !html.suspicious_http_links.is_empty() {
                r.push_str(&format!("│  │  └─ HTTP links:   {}\n", html.suspicious_http_links.len()));
            }
        }
    } else {
        r.push_str("│  └─ [No HTML content parsed]\n");
    }

    // ── Passive tech fingerprint ─────────────────────────────────────────────
    r.push_str("\n┌─[ PASSIVE TECH FINGERPRINT ]─────────────────────────\n");
    if let Some(ref fp) = result.passive_fingerprint {
        // robots.txt
        r.push_str(&format!("│  ├─ robots.txt:    {}\n",
                            if fp.robots_found { "Found" } else { "Not found" }));
        if fp.robots_found {
            if !fp.robots_cms_hints.is_empty() {
                r.push_str(&format!("│  │  ├─ Hints:      {}\n", fp.robots_cms_hints.join(", ")));
            }
            if !fp.robots_disallow_paths.is_empty() {
                r.push_str(&format!("│  │  └─ Disallows:  {} paths\n", fp.robots_disallow_paths.len()));
                for path in fp.robots_disallow_paths.iter().take(5) {
                    r.push_str(&format!("│  │     └─ {}\n", path));
                }
            }
        }

        // sitemap.xml
        r.push_str(&format!("│  ├─ sitemap.xml:   {}\n",
                            if fp.sitemap_found { "Found" } else { "Not found" }));
        if fp.sitemap_found {
            if !fp.sitemap_cms_hints.is_empty() {
                r.push_str(&format!("│  │  ├─ Hints:      {}\n", fp.sitemap_cms_hints.join(", ")));
            }
            if !fp.sitemap_url_sample.is_empty() {
                r.push_str("│  │  └─ URL sample:\n");
                for url in &fp.sitemap_url_sample {
                    r.push_str(&format!("│  │     └─ {}\n", url));
                }
            }
        }

        // 404 probe
        r.push_str("│  ├─ 404 probe:\n");
        if let Some(ref srv) = fp.error_page_server_leak {
            r.push_str(&format!("│  │  ├─ Server banner: {}\n", srv));
        }
        if fp.error_page_stack_trace {
            r.push_str("│  │  ├─ Stack trace / exception detail exposed in error page!\n");
        }
        if !fp.error_page_framework_hints.is_empty() {
            r.push_str(&format!("│  │  └─ Framework hints: {}\n", fp.error_page_framework_hints.join(", ")));
        }

        // Combined
        if !fp.detected_technologies.is_empty() {
            r.push_str(&format!("│  ├─ Detected:      {}\n", fp.detected_technologies.join(" | ")));
        }
        r.push_str(&format!("│  └─ {}\n", fp.confidence_note));
    } else {
        r.push_str("│  └─ [Probe not performed]\n");
    }

    // ── CVE matches ───────────────────────────────────────────────────────────
    r.push_str("\n┌─[ CVE MATCHES ]──────────────────────────────────────\n");
    if result.cve_matches.is_empty() {
        r.push_str("│  └─ No known CVEs matched against detected technologies\n");
    } else {
        let last_idx = result.cve_matches.len() - 1;
        for (i, cve) in result.cve_matches.iter().enumerate() {
            let branch = if i == last_idx { "└─" } else { "├─" };
            let desc_snippet: String = cve.description.chars().take(80).collect();
            r.push_str(&format!(
                "│  {} {}  (CVSS {:.1})  {}\n",
                branch, cve.cve_id, cve.cvss, desc_snippet
            ));
        }
    }

    r.push_str("\n└──────────────────────────────────────────────────────\n");
    r.push_str("   scroll  |  any other key: close\n");
    r
}
#[cfg(test)]
mod format_analysis_tests {
    use super::{
        format_analysis,
        ClickjackingAudit, CorsAudit, HttpMethodAudit, PassiveTechFingerprint,
        RedirectHop, WebAnalysisResult, SCHEMA_VERSION,
    };
    use crate::crypto_forensic::CryptoAuditResult;
    use crate::scrap_analyze::{
        AttackVector, CspStrength, HtmlAuditResult, JsFingerprint, SqlAuditResult,
    };
    use crate::dns_guard::EmailSecurityRecords;

    // ── Fixture ───────────────────────────────────────────────────────────────
    //
    // Build a maximally-populated WebAnalysisResult so that every optional
    // branch in format_analysis is exercised.  Field values are chosen to be
    // distinctive strings that cannot appear from surrounding boilerplate,
    // making substring assertions unambiguous.

    fn full_result() -> WebAnalysisResult {
        WebAnalysisResult {
            schema_version: SCHEMA_VERSION.to_string(),
            target_url:     "https://target.example.com".to_string(),
            status_code:    "200 OK".to_string(),
            response_time_ms: 137,
            web_server:     "nginx/1.24.0".to_string(),
            has_hsts:       true,
            has_csp:        true,
            clickjacking_audit: ClickjackingAudit {
                x_frame_options:      Some("DENY".to_string()),
                csp_frame_ancestors:  true,
                frame_ancestors_value: Some("'none'".to_string()),
                is_protected:         true,
                verdict: "Protected -- CSP frame-ancestors ('none') + X-Frame-Options (DENY) both present (belt-and-suspenders)".to_string(),
            },
            x_content_type:    Some("nosniff".to_string()),
            referrer_policy:   Some("strict-origin-when-cross-origin".to_string()),
            permissions_policy: true,
            overall_score:  82,
            overall_grade:  "B".to_string(),

            redirect_chain: vec![
                RedirectHop { url: "http://target.example.com".to_string(),  status: "301".to_string() },
                RedirectHop { url: "https://target.example.com".to_string(), status: "200".to_string() },
            ],

            cors_audit: Some(CorsAudit {
                acao_header:              Some("https://trusted.example.com".to_string()),
                acac_header:              Some("true".to_string()),
                wildcard_origin:          false,
                credentials_with_wildcard: false,
                reflects_origin:          false,
                risk:                     "Low".to_string(),
            }),

            csp_strength: Some(CspStrength {
                has_unsafe_inline:   false,
                has_unsafe_eval:     false,
                has_wildcard_source: false,
                allows_data_uris:    false,
                grade:               "A".to_string(),
                directives_found:    vec!["default-src".to_string(), "script-src".to_string()],
            }),

            http_method_audit: Some(HttpMethodAudit {
                allowed_methods:   vec!["GET".to_string(), "POST".to_string(), "TRACE".to_string()],
                dangerous_methods: vec!["TRACE".to_string()],
                options_responded: true,
                risk:              "High -- TRACE enabled".to_string(),
            }),

            crypto_audit: Some(CryptoAuditResult {
                tls_version:            "TLS 1.2/1.3 (negotiated via reqwest/rustls)".to_string(),
                cookie_security_score:  "❌ Weak (2 issues)".to_string(),
                cookies_found:          3,
                insecure_cookie_flags:  vec!["Missing HttpOnly".to_string(), "Missing Secure".to_string()],
                jwt_cookies_detected:   vec!["session_jwt".to_string()],
                hsts_preload:           true,
                hsts_max_age_secs:      Some(31536000),
                hsts_includes_subdomains: true,
                hpkp_detected:          true,
                grade:                  "B".to_string(),
            }),

            email_security: Some(EmailSecurityRecords {
                spf:                  Some("v=spf1 include:_spf.example.com ~all".to_string()),
                dmarc:                Some("v=DMARC1; p=reject; rua=mailto:dmarc@example.com".to_string()),
                dkim_selector_found:  true,
                summary:              "SPF + DMARC + DKIM: strong email posture".to_string(),
            }),

            html_audit: Some(HtmlAuditResult {
                forms_count:             2,
                form_actions:            vec!["/login".to_string(), "/search".to_string()],
                attack_vectors: vec![
                    AttackVector {
                        name:       "username".to_string(),
                        input_type: "text".to_string(),
                        form_action: "/login".to_string(),
                    },
                ],
                external_scripts:        vec!["https://cdn.example.com/app.js".to_string()],
                insecure_scripts_count:  1,
                hidden_inputs_count:     2,
                hidden_input_names:      vec!["csrf_token".to_string(), "_method".to_string()],
                internal_links_count:    10,
                external_links_count:    3,
                suspicious_http_links:   vec!["http://insecure.example.com".to_string()],
                cms_generator:           Some("WordPress 6.4".to_string()),
                inline_scripts_count:    4,
                inline_scripts_bytes:    1024,
                detected_api_routes:     vec!["/api/v1/users".to_string()],
                potential_tokens:        vec!["AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567".to_string()],
                stylesheet_links_count:  3,
                external_stylesheets_count: 2,
                sql_audit: SqlAuditResult {
                    potential_search_forms: 1,
                    query_param_patterns:   vec!["id=123".to_string()],
                    debug_comments_found:   false,
                },
                js_fingerprint: JsFingerprint {
                    detected_frameworks: vec!["React".to_string(), "jQuery".to_string()],
                    detected_analytics:  vec!["Google Analytics (GA4)".to_string()],
                    open_redirect_patterns: vec!["/?redirect=https://evil.com".to_string()],
                },
            }),

            passive_fingerprint: Some(PassiveTechFingerprint {
                robots_found:            true,
                robots_disallow_paths:   vec!["/wp-admin".to_string(), "/private".to_string()],
                robots_cms_hints:        vec!["WordPress".to_string()],
                sitemap_found:           true,
                sitemap_url_sample:      vec!["https://target.example.com/blog/post-1".to_string()],
                sitemap_cms_hints:       vec!["Blog platform".to_string()],
                error_page_server_leak:  Some("Apache/2.4.41 (Ubuntu)".to_string()),
                error_page_framework_hints: vec!["Django (Python)".to_string()],
                error_page_stack_trace:  true,
                detected_technologies:   vec!["WordPress".to_string(), "Blog platform".to_string()],
                confidence_note:         "Passive only — no active probing".to_string(),
            }),

            cve_matches: vec![
                crate::cve::CveMatch {
                    cve_id: "CVE-2023-1234".to_string(),
                    description: "A vulnerability allowing remote attackers to do bad things via crafted input to the admin panel.".to_string(),
                    cvss: 8.8,
                    url: "https://example.com/advisories/CVE-2023-1234".to_string(),
                },
            ],
        }
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    fn assert_contains(report: &str, needle: &str) {
        assert!(
            report.contains(needle),
            "expected to find {:?} in report:\n{}", needle, report
        );
    }

    fn assert_not_contains(report: &str, needle: &str) {
        assert!(
            !report.contains(needle),
            "expected NOT to find {:?} in report:\n{}", needle, report
        );
    }

    // ── Banner ────────────────────────────────────────────────────────────────

    #[test]
    fn banner_contains_target_url() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "https://target.example.com");
    }

    #[test]
    fn banner_contains_status_and_server() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "200 OK");
        assert_contains(&r, "nginx/1.24.0");
    }

    #[test]
    fn banner_contains_score_and_grade() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "82/100");
        assert_contains(&r, "Grade:");
        assert_contains(&r, "B");
    }

    #[test]
    fn banner_contains_response_time() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "137");
    }

    // ── Redirect chain ────────────────────────────────────────────────────────

    #[test]
    fn redirect_chain_section_present() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "REDIRECT CHAIN");
    }

    #[test]
    fn redirect_chain_shows_hops() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "[301]");
        assert_contains(&r, "[200]");
        assert_contains(&r, "http://target.example.com");
    }

    #[test]
    fn redirect_chain_detects_http_to_https_upgrade() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "HTTP->HTTPS upgrade detected");
    }

    #[test]
    fn no_redirect_section_when_chain_empty() {
        let mut result = full_result();
        result.redirect_chain = Vec::new();
        let r = format_analysis(&result);
        assert_not_contains(&r, "REDIRECT CHAIN");
    }

    // ── Security headers ──────────────────────────────────────────────────────

    #[test]
    fn security_headers_section_present() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "SECURITY HEADERS");
    }

    #[test]
    fn hsts_present_shown() {
        let r = format_analysis(&full_result());
        // has_hsts = true → "Present"
        assert_contains(&r, "Present");
    }

    #[test]
    fn hsts_missing_shown() {
        let mut result = full_result();
        result.has_hsts = false;
        let r = format_analysis(&result);
        assert_contains(&r, "MISSING");
    }

    #[test]
    fn csp_grade_from_csp_strength() {
        let r = format_analysis(&full_result());
        // csp_strength.grade = "A"
        assert_contains(&r, "Grade:          A");
    }

    #[test]
    fn clickjacking_verdict_in_report() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "belt-and-suspenders");
    }

    #[test]
    fn x_content_type_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "nosniff");
    }

    #[test]
    fn referrer_policy_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "strict-origin-when-cross-origin");
    }

    #[test]
    fn permissions_policy_present() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "Permissions-Policy");
        assert_contains(&r, "Present");
    }

    // ── CORS ──────────────────────────────────────────────────────────────────

    #[test]
    fn cors_section_present() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "CORS AUDIT");
    }

    #[test]
    fn cors_acao_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "https://trusted.example.com");
    }

    #[test]
    fn cors_risk_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "Low");
    }

    #[test]
    fn cors_not_checked_when_none() {
        let mut result = full_result();
        result.cors_audit = None;
        let r = format_analysis(&result);
        assert_contains(&r, "Not checked");
    }

    // ── HTTP methods ──────────────────────────────────────────────────────────

    #[test]
    fn http_methods_section_present() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "HTTP METHODS");
    }

    #[test]
    fn dangerous_methods_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "TRACE");
        assert_contains(&r, "High -- TRACE enabled");
    }

    #[test]
    fn http_methods_not_checked_when_none() {
        let mut result = full_result();
        result.http_method_audit = None;
        let r = format_analysis(&result);
        assert_contains(&r, "Not checked");
    }

    // ── Crypto forensic ───────────────────────────────────────────────────────

    #[test]
    fn crypto_section_present() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "CRYPTO FORENSIC");
    }

    #[test]
    fn crypto_cookie_score_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "Weak (2 issues)");
    }

    #[test]
    fn crypto_hsts_max_age_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "31536000s");
    }

    #[test]
    fn crypto_insecure_cookie_flags_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "Missing HttpOnly");
        assert_contains(&r, "Missing Secure");
    }

    #[test]
    fn crypto_jwt_cookies_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "session_jwt");
    }

    #[test]
    fn crypto_hpkp_shown_when_detected() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "HPKP detected");
    }

    #[test]
    fn crypto_grade_label_shown() {
        let r = format_analysis(&full_result());
        // grade "B" → "B  Good -- minor gaps"
        assert_contains(&r, "B  Good -- minor gaps");
    }

    #[test]
    fn crypto_not_available_when_none() {
        let mut result = full_result();
        result.crypto_audit = None;
        let r = format_analysis(&result);
        assert_contains(&r, "No crypto data available");
    }

    // ── Email security ────────────────────────────────────────────────────────

    #[test]
    fn email_section_present() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "EMAIL SECURITY (DNS)");
    }

    #[test]
    fn email_spf_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "v=spf1 include:_spf.example.com ~all");
    }

    #[test]
    fn email_dmarc_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "v=DMARC1; p=reject");
    }

    #[test]
    fn email_dkim_found() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "Found");
    }

    #[test]
    fn email_summary_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "strong email posture");
    }

    #[test]
    fn email_not_checked_when_none() {
        let mut result = full_result();
        result.email_security = None;
        let r = format_analysis(&result);
        assert_contains(&r, "Not checked");
    }

    // ── HTML audit ────────────────────────────────────────────────────────────

    #[test]
    fn html_section_present() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "HTML STRUCTURE & LEAK AUDIT");
    }

    #[test]
    fn html_forms_count_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "Forms:              2");
    }

    #[test]
    fn html_attack_vector_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "[text] -> /login");
    }

    #[test]
    fn html_js_frameworks_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "React");
        assert_contains(&r, "jQuery");
    }

    #[test]
    fn html_analytics_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "Google Analytics (GA4)");
    }

    #[test]
    fn html_open_redirect_patterns_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "Open Redirect Patterns: 1");
        assert_contains(&r, "redirect=https://evil.com");
    }

    #[test]
    fn html_cms_generator_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "WordPress 6.4");
    }

    #[test]
    fn html_api_endpoints_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "/api/v1/users");
    }

    #[test]
    fn html_key_leaks_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "KEY LEAKS:");
        assert_contains(&r, "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567");
    }

    #[test]
    fn html_key_leaks_clean_when_empty() {
        let mut result = full_result();
        result.html_audit.as_mut().unwrap().potential_tokens = Vec::new();
        let r = format_analysis(&result);
        assert_contains(&r, "Key Leaks:          Clean");
    }

    #[test]
    fn html_mixed_content_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "MIXED CONTENT");
        assert_contains(&r, "HTTP scripts: 1");
        assert_contains(&r, "HTTP links:   1");
    }

    #[test]
    fn html_inline_scripts_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "4 blocks (1024 bytes)");
    }

    #[test]
    fn html_not_parsed_when_none() {
        let mut result = full_result();
        result.html_audit = None;
        let r = format_analysis(&result);
        assert_contains(&r, "[No HTML content parsed]");
    }

    // ── Passive tech fingerprint ──────────────────────────────────────────────

    #[test]
    fn passive_fingerprint_section_present() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "PASSIVE TECH FINGERPRINT");
    }

    #[test]
    fn passive_robots_found() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "robots.txt:    Found");
    }

    #[test]
    fn passive_robots_disallow_paths_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "Disallows:  2 paths");
        assert_contains(&r, "/wp-admin");
    }

    #[test]
    fn passive_sitemap_found() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "sitemap.xml:   Found");
    }

    #[test]
    fn passive_sitemap_url_sample_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "https://target.example.com/blog/post-1");
    }

    #[test]
    fn passive_error_page_server_leak_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "Apache/2.4.41 (Ubuntu)");
    }

    #[test]
    fn passive_stack_trace_warning_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "Stack trace / exception detail exposed");
    }

    #[test]
    fn passive_detected_technologies_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "WordPress");
    }

    #[test]
    fn passive_confidence_note_shown() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "Passive only — no active probing");
    }

    #[test]
    fn cve_matches_section_present() {
        let r = format_analysis(&full_result());
        assert_contains(&r, "CVE MATCHES");
        assert_contains(&r, "CVE-2023-1234");
        assert_contains(&r, "8.8");
    }

    #[test]
    fn cve_matches_description_truncated_to_80_chars() {
        let r = format_analysis(&full_result());
        // Fixture description is longer than 80 chars -- the report should
        // show only the first 80, not the full sentence.
        assert!(!r.contains("admin panel."));
    }

    #[test]
    fn cve_matches_empty_shows_no_matches_message() {
        let mut result = full_result();
        result.cve_matches = Vec::new();
        let r = format_analysis(&result);
        assert_contains(&r, "No known CVEs matched");
    }

    #[test]
    fn passive_not_performed_when_none() {
        let mut result = full_result();
        result.passive_fingerprint = None;
        let r = format_analysis(&result);
        assert_contains(&r, "[Probe not performed]");
    }

    // ── Regression guard: all top-level sections always appear ────────────────

    #[test]
    fn all_section_headers_present() {
        let r = format_analysis(&full_result());
        for header in &[
            "SECURITY HEADERS",
            "CORS AUDIT",
            "HTTP METHODS",
            "CRYPTO FORENSIC",
            "EMAIL SECURITY (DNS)",
            "HTML STRUCTURE & LEAK AUDIT",
            "PASSIVE TECH FINGERPRINT",
        ] {
            assert_contains(&r, header);
        }
    }
}