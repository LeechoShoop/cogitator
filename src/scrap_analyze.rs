use scraper::{Html, Selector};
use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

// ─── Compiled regexes (compiled once, reused on every call) ─────────────────

fn re_api() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(
        r#"(?i)(/api/v[0-9]/[a-zA-Z0-9_\-\.\/]+|\.[a-z0-9\-_]+(?:\?|\b)callback=|\b[a-z0-9_\-\.]+?\.json\b)"#
    ).expect("api regex"))
}

fn re_token() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(
        r#"(?i)(bearer\s+[a-z0-9_\-\.\~\+\/=]{20,}|AIzaSy[a-z0-9_\-]{35}|[a-z0-9]{32,64}(?:_key|_token|secret))"#
    ).expect("token regex"))
}

fn re_param() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(
        r#"(?i)(id=|cat=|page=|prod=|view=)[0-9a-z]+"#
    ).expect("param regex"))
}

fn re_open_redirect() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(
        r#"(?i)[?&](redirect|return|next|url|goto|dest|destination|target|redir|forward|continue|redirect_uri)=https?://"#
    ).expect("open_redirect regex"))
}

#[derive(Debug, Clone, Serialize)]
pub struct AttackVector {
    pub name: String,
    pub input_type: String,
    pub form_action: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SqlAuditResult {
    pub potential_search_forms: usize,
    pub query_param_patterns: Vec<String>,
    pub debug_comments_found: bool,
}

// NEW: JavaScript framework/library fingerprinting
#[derive(Debug, Clone, Serialize)]
pub struct JsFingerprint {
    pub detected_frameworks: Vec<String>,
    pub detected_analytics: Vec<String>,
    pub open_redirect_patterns: Vec<String>,
}

// NEW: CSP policy strength assessment
#[derive(Debug, Clone, Serialize)]
pub struct CspStrength {
    pub has_unsafe_inline: bool,
    pub has_unsafe_eval: bool,
    pub has_wildcard_source: bool,
    pub allows_data_uris: bool,
    pub grade: String, // A / B / C / F
    pub directives_found: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HtmlAuditResult {
    pub forms_count: usize,
    pub form_actions: Vec<String>,
    pub attack_vectors: Vec<AttackVector>,
    pub external_scripts: Vec<String>,
    pub insecure_scripts_count: usize,
    pub hidden_inputs_count: usize,
    pub hidden_input_names: Vec<String>,
    pub internal_links_count: usize,
    pub external_links_count: usize,
    pub suspicious_http_links: Vec<String>,
    pub cms_generator: Option<String>,
    pub inline_scripts_count: usize,
    pub inline_scripts_bytes: usize,
    pub detected_api_routes: Vec<String>,
    pub potential_tokens: Vec<String>,
    pub stylesheet_links_count: usize,
    pub external_stylesheets_count: usize,
    pub sql_audit: SqlAuditResult,
    // NEW fields
    pub js_fingerprint: JsFingerprint,
}

pub fn audit_html(html_content: &str) -> HtmlAuditResult {
    let document = Html::parse_document(html_content);

    let form_selector = Selector::parse("form").ok();
    let input_selector = Selector::parse("input, textarea").ok();
    let script_with_src = Selector::parse("script[src]").ok();
    let inline_script_selector = Selector::parse("script:not([src])").ok();
    let hidden_input_selector = Selector::parse("input[type='hidden']").ok();
    let link_selector = Selector::parse("a[href]").ok();
    let meta_generator_selector = Selector::parse("meta[name='generator']").ok();
    let stylesheet_selector = Selector::parse("link[rel='stylesheet']").ok();
    let search_selector = Selector::parse("form[id*='search'], form[class*='search']").ok();

    let api_regex = re_api();
    let token_regex = re_token();
    let param_regex = re_param();
    // NEW: open redirect sink patterns in link hrefs
    let open_redirect_regex = re_open_redirect();

    let mut form_actions = Vec::new();
    let mut attack_vectors = Vec::new();
    let mut external_scripts = Vec::new();
    let mut all_script_srcs: Vec<String> = Vec::new();
    let mut insecure_scripts_count = 0;
    let mut hidden_input_names = Vec::new();
    let mut internal_links_count = 0;
    let mut external_links_count = 0;
    let mut suspicious_http_links = Vec::new();
    let mut open_redirect_patterns: Vec<String> = Vec::new();

    // Forms + attack vectors
    if let (Some(f_sel), Some(i_sel)) = (form_selector, input_selector) {
        for form in document.select(&f_sel) {
            let action = form.value().attr("action").unwrap_or("[No Action Defined]").to_string();
            form_actions.push(action.clone());
            for input in form.select(&i_sel) {
                let name = input.value().attr("name").unwrap_or("unnamed").to_string();
                let input_type = input.value().attr("type").unwrap_or("text").to_string();
                attack_vectors.push(AttackVector { name, input_type, form_action: action.clone() });
            }
        }
    }

    // External scripts — collect all srcs for framework fingerprinting
    if let Some(sel) = script_with_src {
        for element in document.select(&sel) {
            if let Some(src) = element.value().attr("src") {
                all_script_srcs.push(src.to_string());
                external_scripts.push(src.to_string());
                if src.starts_with("http://") { insecure_scripts_count += 1; }
            }
        }
    }

    // Inline scripts
    let mut inline_scripts_count = 0;
    let mut inline_scripts_bytes = 0;
    let mut potential_tokens = Vec::new();
    let mut inline_script_text = String::new();
    if let Some(sel) = inline_script_selector {
        for element in document.select(&sel) {
            inline_scripts_count += 1;
            let script_text = element.text().collect::<Vec<_>>().join("");
            inline_scripts_bytes += script_text.len();
            inline_script_text.push_str(&script_text);
            for mat in token_regex.find_iter(&script_text) {
                let token = mat.as_str().trim().to_string();
                if !potential_tokens.contains(&token) { potential_tokens.push(token); }
            }
        }
    }

    if let Some(sel) = hidden_input_selector {
        for element in document.select(&sel) {
            let name = element.value().attr("name")
                .or_else(|| element.value().attr("id"))
                .unwrap_or("[unnamed]").to_string();
            hidden_input_names.push(name);
        }
    }

    let mut query_param_patterns = Vec::new();
    if let Some(sel) = link_selector {
        for element in document.select(&sel) {
            let href = element.value().attr("href").unwrap_or("");
            if href.starts_with("http://") { suspicious_http_links.push(href.to_string()); }
            if href.starts_with("http://") || href.starts_with("https://") || href.starts_with("//") {
                external_links_count += 1;
            } else if !href.starts_with('#') && !href.starts_with("javascript:") && !href.is_empty() {
                internal_links_count += 1;
            }
            if param_regex.is_match(href) {
                if let Some(mat) = param_regex.find(href) {
                    let capture = mat.as_str().to_string();
                    if !query_param_patterns.contains(&capture) { query_param_patterns.push(capture); }
                }
            }
            // Open redirect detection
            if open_redirect_regex.is_match(href) {
                let snippet = href.chars().take(120).collect::<String>();
                if !open_redirect_patterns.contains(&snippet) {
                    open_redirect_patterns.push(snippet);
                }
            }
        }
    }

    let cms_generator = meta_generator_selector.and_then(|sel| {
        document.select(&sel).next()
            .and_then(|el| el.value().attr("content").map(|s| s.to_string()))
    });

    let mut detected_api_routes = Vec::new();
    for mat in api_regex.find_iter(html_content) {
        let route = mat.as_str().trim().to_string();
        if !detected_api_routes.contains(&route) && route.len() < 120 { detected_api_routes.push(route); }
    }

    let mut stylesheet_links_count = 0;
    let mut external_stylesheets_count = 0;
    if let Some(sel) = stylesheet_selector {
        for element in document.select(&sel) {
            stylesheet_links_count += 1;
            if let Some(href) = element.value().attr("href") {
                if href.starts_with("http://") || href.starts_with("https://") || href.starts_with("//") {
                    external_stylesheets_count += 1;
                }
            }
        }
    }

    let potential_search_forms = search_selector.map(|sel| document.select(&sel).count()).unwrap_or(0);
    let debug_comments_found = html_content.contains("SELECT ") || html_content.contains("FROM ") || html_content.contains("WHERE ");

    // NEW: JS fingerprinting
    let js_fingerprint = fingerprint_js(&all_script_srcs, &inline_script_text, open_redirect_patterns);

    HtmlAuditResult {
        forms_count: form_actions.len(),
        form_actions,
        attack_vectors,
        external_scripts,
        insecure_scripts_count,
        hidden_inputs_count: hidden_input_names.len(),
        hidden_input_names,
        internal_links_count,
        external_links_count,
        suspicious_http_links,
        cms_generator,
        inline_scripts_count,
        inline_scripts_bytes,
        detected_api_routes,
        potential_tokens,
        stylesheet_links_count,
        external_stylesheets_count,
        sql_audit: SqlAuditResult {
            potential_search_forms,
            query_param_patterns,
            debug_comments_found,
        },
        js_fingerprint,
    }
}

// ─── JS Framework Fingerprinting ────────────────────────────────────────────

struct FpRule { name: &'static str, pattern: &'static str }

const FRAMEWORK_RULES: &[FpRule] = &[
    FpRule { name: "React",      pattern: "react" },
    FpRule { name: "Vue.js",     pattern: "vue" },
    FpRule { name: "Angular",    pattern: "angular" },
    FpRule { name: "jQuery",     pattern: "jquery" },
    FpRule { name: "Next.js",    pattern: "/_next/" },
    FpRule { name: "Nuxt.js",    pattern: "/_nuxt/" },
    FpRule { name: "Svelte",     pattern: "svelte" },
    FpRule { name: "Ember.js",   pattern: "ember" },
    FpRule { name: "Backbone.js",pattern: "backbone" },
    FpRule { name: "Lodash",     pattern: "lodash" },
    FpRule { name: "Bootstrap",  pattern: "bootstrap" },
    FpRule { name: "Tailwind",   pattern: "tailwind" },
    FpRule { name: "Alpine.js",  pattern: "alpinejs" },
    FpRule { name: "htmx",       pattern: "htmx" },
];

const ANALYTICS_RULES: &[FpRule] = &[
    FpRule { name: "Google Analytics (GA4)", pattern: "gtag" },
    FpRule { name: "Google Analytics (UA)",  pattern: "analytics.js" },
    FpRule { name: "Google Tag Manager",     pattern: "googletagmanager" },
    FpRule { name: "Hotjar",                 pattern: "hotjar" },
    FpRule { name: "Segment",                pattern: "segment.io" },
    FpRule { name: "Mixpanel",               pattern: "mixpanel" },
    FpRule { name: "Amplitude",              pattern: "amplitude" },
    FpRule { name: "Heap",                   pattern: "heap-analytics" },
    FpRule { name: "Facebook Pixel",         pattern: "fbq(" },
    FpRule { name: "Clarity (Microsoft)",    pattern: "clarity.ms" },
];

fn fingerprint_js(
    script_srcs: &[String],
    inline_text: &str,
    open_redirect_patterns: Vec<String>,
) -> JsFingerprint {
    let combined_srcs = script_srcs.join(" ").to_lowercase();
    let inline_lower = inline_text.to_lowercase();
    let all_text = format!("{} {}", combined_srcs, inline_lower);

    let detected_frameworks = FRAMEWORK_RULES.iter()
        .filter(|r| all_text.contains(r.pattern))
        .map(|r| r.name.to_string())
        .collect();

    let detected_analytics = ANALYTICS_RULES.iter()
        .filter(|r| all_text.contains(r.pattern))
        .map(|r| r.name.to_string())
        .collect();

    JsFingerprint { detected_frameworks, detected_analytics, open_redirect_patterns }
}

// ─── CSP Strength Parser ─────────────────────────────────────────────────────

/// Parse and grade a Content-Security-Policy header value.
pub fn parse_csp_strength(csp_value: &str) -> CspStrength {
    let lower = csp_value.to_lowercase();

    let has_unsafe_inline   = lower.contains("'unsafe-inline'");
    let has_unsafe_eval     = lower.contains("'unsafe-eval'");
    let has_wildcard_source = lower.contains(" * ") || lower.contains("src *") || lower.contains("src: *");
    let allows_data_uris    = lower.contains("data:");

    let directives_found: Vec<String> = csp_value
        .split(';')
        .map(|d| d.trim().split_whitespace().next().unwrap_or("").to_string())
        .filter(|d| !d.is_empty())
        .collect();

    let mut deductions = 0i32;
    if has_unsafe_inline   { deductions += 30; }
    if has_unsafe_eval     { deductions += 20; }
    if has_wildcard_source { deductions += 25; }
    if allows_data_uris    { deductions += 10; }

    let grade = match 100 - deductions {
        90..=i32::MAX => "A",
        70..=89        => "B",
        50..=69        => "C",
        _              => "F",
    }.to_string();

    CspStrength {
        has_unsafe_inline,
        has_unsafe_eval,
        has_wildcard_source,
        allows_data_uris,
        grade,
        directives_found,
    }
}
#[cfg(test)]
mod csp_tests {
    use super::parse_csp_strength;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn grade(csp: &str) -> String {
        parse_csp_strength(csp).grade.clone()
    }

    // ── flag detection ────────────────────────────────────────────────────────

    #[test]
    fn detects_unsafe_inline() {
        let r = parse_csp_strength("script-src 'unsafe-inline' https://cdn.example.com");
        assert!(r.has_unsafe_inline);
        assert!(!r.has_unsafe_eval);
        assert!(!r.has_wildcard_source);
        assert!(!r.allows_data_uris);
    }

    #[test]
    fn detects_unsafe_eval() {
        let r = parse_csp_strength("script-src 'unsafe-eval'");
        assert!(!r.has_unsafe_inline);
        assert!(r.has_unsafe_eval);
    }

    #[test]
    fn detects_wildcard_source_space_delimited() {
        // " * " pattern (space on both sides)
        let r = parse_csp_strength("img-src *");
        // "img-src *" ends without trailing space, so check "src *" variant
        let r2 = parse_csp_strength("img-src * ;");
        assert!(r2.has_wildcard_source, "space-delimited wildcard not detected");
        // ensure the raw " * " variant also works
        let r3 = parse_csp_strength("default-src * ; script-src 'self'");
        assert!(r3.has_wildcard_source);
    }

    #[test]
    fn detects_data_uri() {
        let r = parse_csp_strength("img-src data: https:");
        assert!(r.allows_data_uris);
        assert!(!r.has_unsafe_inline);
    }

    #[test]
    fn clean_policy_no_flags() {
        let r = parse_csp_strength(
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'"
        );
        assert!(!r.has_unsafe_inline);
        assert!(!r.has_unsafe_eval);
        assert!(!r.has_wildcard_source);
        assert!(!r.allows_data_uris);
    }

    // ── flag detection is case-insensitive ────────────────────────────────────

    #[test]
    fn case_insensitive_unsafe_inline() {
        let r = parse_csp_strength("script-src 'UNSAFE-INLINE'");
        assert!(r.has_unsafe_inline);
    }

    #[test]
    fn case_insensitive_unsafe_eval() {
        let r = parse_csp_strength("script-src 'Unsafe-Eval'");
        assert!(r.has_unsafe_eval);
    }

    // ── directives_found ─────────────────────────────────────────────────────

    #[test]
    fn directives_extracted_correctly() {
        let r = parse_csp_strength(
            "default-src 'self'; script-src 'self' https://cdn.example.com; img-src data:"
        );
        assert_eq!(r.directives_found, vec!["default-src", "script-src", "img-src"]);
    }

    #[test]
    fn empty_policy_gives_no_directives() {
        let r = parse_csp_strength("");
        assert!(r.directives_found.is_empty());
    }

    // ── grade boundaries ──────────────────────────────────────────────────────

    // score 100 → A
    #[test]
    fn grade_a_clean_policy() {
        assert_eq!(grade("default-src 'self'"), "A");
    }

    // score 90 (data: only, -10) → A  (boundary: lowest A)
    #[test]
    fn grade_a_data_uri_only() {
        assert_eq!(grade("img-src data: 'self'"), "A");
    }

    // score 80 (unsafe-eval only, -20) → B
    #[test]
    fn grade_b_unsafe_eval_only() {
        assert_eq!(grade("script-src 'unsafe-eval'"), "B");
    }

    // score 75 (wildcard only, -25) → B
    #[test]
    fn grade_b_wildcard_only() {
        // Use "src *" to ensure the wildcard pattern fires
        assert_eq!(grade("img-src * ; script-src 'self'"), "B");
    }

    // score 70 (unsafe-inline only, -30) → B  (boundary: lowest B)
    #[test]
    fn grade_b_unsafe_inline_only() {
        assert_eq!(grade("script-src 'unsafe-inline'"), "B");
    }

    // score 70 (unsafe-eval -20, data: -10) → B  (another lowest-B combination)
    #[test]
    fn grade_b_eval_plus_data() {
        assert_eq!(grade("script-src 'unsafe-eval'; img-src data:"), "B");
    }

    // score 60 (unsafe-inline -30, data: -10) → C  (boundary: highest C)
    #[test]
    fn grade_c_inline_plus_data() {
        assert_eq!(grade("script-src 'unsafe-inline'; img-src data:"), "C");
    }

    // score 50 (unsafe-inline -30, unsafe-eval -20) → C  (boundary: lowest C)
    #[test]
    fn grade_c_inline_plus_eval() {
        assert_eq!(grade("script-src 'unsafe-inline' 'unsafe-eval'"), "C");
    }

    // score 45 (unsafe-inline -30, wildcard -25) → F
    #[test]
    fn grade_f_inline_plus_wildcard() {
        assert_eq!(grade("default-src * ; script-src 'unsafe-inline'"), "F");
    }

    // score 15 (all four flags: -30 -20 -25 -10) → F
    #[test]
    fn grade_f_all_flags() {
        let csp = "default-src * ; script-src 'unsafe-inline' 'unsafe-eval'; img-src data:";
        let r = parse_csp_strength(csp);
        assert!(r.has_unsafe_inline);
        assert!(r.has_unsafe_eval);
        assert!(r.has_wildcard_source);
        assert!(r.allows_data_uris);
        assert_eq!(r.grade, "F");
    }
}