use super::types::{WebAnalysisResult, SCHEMA_VERSION};
use super::clickjacking::ClickjackingAudit;
use super::cors::CorsAudit;
use super::http_methods::HttpMethodAudit;
use super::fingerprint::PassiveTechFingerprint;
use super::redirects::RedirectHop;


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