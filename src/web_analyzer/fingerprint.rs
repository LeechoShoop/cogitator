use reqwest::Client;
use serde::Serialize;

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
pub async fn probe_passive_fingerprint(client: &Client, base_url: &str) -> PassiveTechFingerprint {
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
