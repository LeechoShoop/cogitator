//! Spider: BFS site-crawling engine for Cogitator.
//!
//! Starting from `SpiderConfig::seed_url`, walks the site breadth-first up
//! to `max_depth` levels (or `max_pages` total fetches, whichever comes
//! first), extracting links and forms from each page and streaming one
//! `SpiderResult` per fetched page back through an mpsc channel — the same
//! "stream as you go" shape as `intruder::run`, so the TUI can render rows
//! live rather than waiting for the whole crawl.
//!
//! Crawl boundaries:
//!   * `SpiderConfig::scope` — a discovered link is only enqueued if
//!     `Scope::in_scope` accepts it (see `scope.rs`).
//!   * `robots.txt` — fetched once per origin (scheme+host) and cached for
//!     the lifetime of the run; any URL whose path matches a `Disallow`
//!     rule under a `User-agent: *` block is skipped (not fetched, not
//!     enqueued further).
//!   * `max_depth` / `max_pages` — hard caps on traversal depth and total
//!     fetched pages.
//!
//! Every fetched page is also recorded into `History` so it shows up
//! alongside proxy/interceptor traffic for later review.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use rand::random;
use reqwest::{Client, Url};
use tokio::sync::mpsc::{self, Receiver};

use crate::history::{History, RequestRecord};
use crate::logger;
use crate::scope::Scope;
use crate::scrap_analyze::audit_html;

/// Cap on how much of a response body is buffered into the `History`
/// record — mirrors the 1 MB cap used by the proxy's own
/// `record_exchange` helper, so a handful of huge pages can't blow up
/// memory over a long crawl.
const HISTORY_BODY_CAP: usize = 1_000_000;

// ─── Config ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SpiderConfig {
    pub seed_url: String,
    pub max_depth: u8,
    pub max_pages: usize,
    pub scope: Arc<Scope>,
    /// If `true`, GET-method forms discovered on a page have their
    /// `action` URL treated as an additional link to enqueue (still
    /// subject to scope/robots/depth like any other link). POST forms are
    /// never auto-submitted regardless of this flag — Spider only ever
    /// issues GETs.
    pub follow_forms: bool,
    pub user_agent: String,
    /// ASSUMED ADDITION — disallow paths already known for the seed's
    /// origin, typically `WebAnalysisResult::passive_fingerprint`'s
    /// `robots_disallow_paths` from an earlier `Scan-Site` run against the
    /// same domain. When `Some`, the seed origin's robots cache is seeded
    /// from this instead of issuing a fresh `GET /robots.txt` — this is
    /// the "read from passive_fingerprint" half of "respect robots.txt
    /// disallow rules read from passive_fingerprint or fetched fresh."
    /// Any *other* origin encountered mid-crawl (off-domain link) still
    /// gets a fresh fetch, since this field only carries data for one
    /// origin (the seed's).
    pub cached_robots_disallow: Option<Vec<String>>,
    /// ASSUMED ADDITION — not in the originally specified field list, but
    /// required to satisfy "each request is also pushed to History."
    /// `SpiderConfig` has no other way to reach the shared history store,
    /// and `run`'s signature is fixed to `(SpiderConfig, Arc<Client>)`, so
    /// it has to live here. Wire this to whatever `Arc<History>` the proxy
    /// guard / interceptor already share.
    pub history: Arc<History>,
}

// ─── Forms ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormInfo {
    pub action: String,
    pub method: String,
    pub fields: Vec<String>,
}

// ─── Result ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SpiderResult {
    pub url: String,
    pub depth: u8,
    /// Every absolute link discovered on this page (resolved against
    /// `url`), regardless of whether it was in scope/enqueued — callers
    /// wanting only what was actually queued should re-check against
    /// `scope` themselves.
    pub found_links: Vec<String>,
    pub found_forms: Vec<FormInfo>,
    /// `None` if the request failed outright (timeout, connection error,
    /// non-HTTP response, etc.) rather than completing with a status.
    pub status: Option<u16>,
    pub content_type: Option<String>,
}

// ─── Public entry point ───────────────────────────────────────────────────────

/// Launch a crawl. Returns immediately with a receiver; one `SpiderResult`
/// is pushed per fetched page, in the order pages are actually fetched
/// (BFS order — same depth before the next). The driver task exits
/// (closing the channel) once the queue is drained or `max_pages` is hit.
pub fn run(config: SpiderConfig, client: Arc<Client>) -> Receiver<SpiderResult> {
    let (tx, rx) = mpsc::channel(256);

    tokio::spawn(async move {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, u8)> = VecDeque::new();
        // Cached per-origin (scheme://host) robots.txt disallow rules.
        let mut robots_cache: HashMap<String, Vec<String>> = HashMap::new();
        let mut pages_crawled = 0usize;

        if !config.scope.in_scope(&config.seed_url) {
            logger::warn(&format!(
                "spider: seed URL {} is out of scope, nothing to crawl",
                config.seed_url
            ));
            return;
        }

        // If the caller already has robots.txt disallow rules for the
        // seed's origin (e.g. from a prior Scan-Site's passive
        // fingerprint), seed the cache with them so the crawl doesn't
        // re-fetch robots.txt itself for that origin.
        if let Some(rules) = &config.cached_robots_disallow {
            if let Some(origin) = origin_key(&config.seed_url) {
                robots_cache.insert(origin, rules.clone());
            }
        }

        queue.push_back((config.seed_url.clone(), 0));

        while let Some((url, depth)) = queue.pop_front() {
            if pages_crawled >= config.max_pages {
                logger::debug(&format!(
                    "spider: max_pages ({}) reached, stopping",
                    config.max_pages
                ));
                break;
            }
            if depth > config.max_depth {
                continue;
            }

            let normalized = normalize_url(&url);
            if visited.contains(&normalized) {
                continue;
            }
            visited.insert(normalized);

            // ── robots.txt check ────────────────────────────────────────────
            let Some(origin) = origin_key(&url) else {
                logger::debug(&format!("spider: skipping unparsable URL {url}"));
                continue;
            };

            if !robots_cache.contains_key(&origin) {
                let rules = fetch_robots_disallow(&client, &url, &config.user_agent).await;
                robots_cache.insert(origin.clone(), rules);
            }
            if let Some(rules) = robots_cache.get(&origin) {
                if is_disallowed(&url, rules) {
                    logger::debug(&format!("spider: {url} disallowed by robots.txt, skipping"));
                    continue;
                }
            }

            // ── Fetch ────────────────────────────────────────────────────────
            let started = Instant::now();
            let send_result = client
                .get(&url)
                .header("User-Agent", &config.user_agent)
                .send()
                .await;

            let result = match send_result {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let content_type = resp
                        .headers()
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());
                    let response_headers: Vec<(String, String)> = resp
                        .headers()
                        .iter()
                        .map(|(k, v)| {
                            (k.to_string(), v.to_str().unwrap_or("<non-utf8>").to_string())
                        })
                        .collect();

                    let body = resp.text().await.unwrap_or_default();
                    let elapsed = started.elapsed();

                    record_to_history(&config.history, &url, status, &response_headers, &body, elapsed);

                    let base = Url::parse(&url).ok();
                    let found_links = base
                        .as_ref()
                        .map(|b| extract_links(b, &body))
                        .unwrap_or_default();
                    let found_forms = base
                        .as_ref()
                        .map(|b| extract_forms(b, &body))
                        .unwrap_or_default();

                    // ── Audit hook ───────────────────────────────────────────
                    // `crate::scrap_analyze::audit_html` is synchronous and
                    // takes the raw HTML, returning an `HtmlAuditResult`.
                    // `SpiderResult` has no field to carry the full audit
                    // (it wasn't in the original spec for this type), so it
                    // isn't attached to the streamed result — but a crawl
                    // visits many pages a one-off `Scan-Site` never would,
                    // so leaked secrets / open-redirect patterns found along
                    // the way are surfaced immediately via the logger rather
                    // than silently discarded.
                    let html_audit = audit_html(&body);
                    if !html_audit.potential_tokens.is_empty() {
                        logger::warn(&format!(
                            "spider: possible leaked secret(s) on {url}: {}",
                            html_audit.potential_tokens.join(", ")
                        ));
                    }
                    if !html_audit.js_fingerprint.open_redirect_patterns.is_empty() {
                        logger::warn(&format!(
                            "spider: possible open-redirect pattern(s) on {url}"
                        ));
                    }

                    // Enqueue in-scope links at depth + 1.
                    if depth < config.max_depth {
                        for link in &found_links {
                            enqueue_if_eligible(link, depth + 1, &config.scope, &visited, &mut queue);
                        }
                        if config.follow_forms {
                            for form in &found_forms {
                                if form.method.eq_ignore_ascii_case("get") {
                                    if let Some(resolved) = base
                                        .as_ref()
                                        .and_then(|b| b.join(&form.action).ok())
                                    {
                                        enqueue_if_eligible(
                                            resolved.as_str(),
                                            depth + 1,
                                            &config.scope,
                                            &visited,
                                            &mut queue,
                                        );
                                    }
                                }
                            }
                        }
                    }

                    SpiderResult {
                        url: url.clone(),
                        depth,
                        found_links,
                        found_forms,
                        status: Some(status),
                        content_type,
                    }
                }
                Err(e) => {
                    logger::debug(&format!("spider: request to {url} failed: {e}"));
                    SpiderResult {
                        url: url.clone(),
                        depth,
                        found_links: Vec::new(),
                        found_forms: Vec::new(),
                        status: None,
                        content_type: None,
                    }
                }
            };

            pages_crawled += 1;

            if tx.send(result).await.is_err() {
                // Receiver dropped (TUI navigated away) — stop crawling
                // rather than continuing to do pointless network work.
                break;
            }
        }
    });

    rx
}

/// Push a discovered link onto the BFS queue if it's not already visited,
/// not already queued (best-effort — `visited` is only updated on dequeue,
/// so duplicates within the same frontier are possible but harmless; they
/// get filtered on pop), and in scope.
fn enqueue_if_eligible(
    link: &str,
    next_depth: u8,
    scope: &Scope,
    visited: &HashSet<String>,
    queue: &mut VecDeque<(String, u8)>,
) {
    let normalized = normalize_url(link);
    if visited.contains(&normalized) {
        return;
    }
    if !scope.in_scope(link) {
        return;
    }
    queue.push_back((link.to_string(), next_depth));
}

/// Record one fetched page into `History`, capping the buffered body at
/// `HISTORY_BODY_CAP` bytes.
fn record_to_history(
    history: &History,
    url: &str,
    status: u16,
    response_headers: &[(String, String)],
    body: &str,
    elapsed: std::time::Duration,
) {
    let Ok(parsed) = Url::parse(url) else { return };
    let host = parsed.host_str().unwrap_or("").to_string();
    let path = parsed.path().to_string();

    let mut body_bytes = body.as_bytes().to_vec();
    body_bytes.truncate(HISTORY_BODY_CAP);

    // Spider-issued requests don't come through the proxy's own id
    // counter, so a random id is used. Collisions are vanishingly
    // unlikely (`u64`) and, even if one occurred, would only ever
    // overwrite/shadow another spider-issued record's response fields —
    // never corrupt proxy traffic, which uses its own counter.
    let id: u64 = random();

    history.push(RequestRecord {
        id,
        timestamp: Instant::now(),
        method: "GET".to_string(),
        host,
        path,
        headers: Vec::new(),
        body: Vec::new(),
        response_status: Some(status),
        response_headers: response_headers.to_vec(),
        response_body: Some(body_bytes),
        response_time_ms: Some(elapsed.as_millis()),
        tags: vec!["spider".to_string()],
        stream_id: None,
    });
}

// ─── URL helpers ──────────────────────────────────────────────────────────────

/// Strip the fragment (if any) so `#section` variants of the same page
/// don't get crawled as distinct URLs. Falls back to the raw string if it
/// doesn't parse as a URL at all.
fn normalize_url(url: &str) -> String {
    match Url::parse(url) {
        Ok(mut parsed) => {
            parsed.set_fragment(None);
            parsed.to_string()
        }
        Err(_) => url.to_string(),
    }
}

/// `scheme://host[:port]` — the cache key for robots.txt rules, since
/// robots.txt is scoped per-origin, not per-path.
fn origin_key(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    match parsed.port() {
        Some(port) => Some(format!("{}://{}:{}", parsed.scheme(), host, port)),
        None => Some(format!("{}://{}", parsed.scheme(), host)),
    }
}

// ─── robots.txt ───────────────────────────────────────────────────────────────

/// Fetch `{origin}/robots.txt` and parse its `Disallow` rules. Only the
/// `User-agent: *` block is honoured — Spider doesn't claim a distinct UA
/// identity, so agent-specific blocks aren't applicable. Any failure
/// (network error, non-2xx, unparsable origin) yields an empty rule set,
/// i.e. "nothing disallowed" rather than blocking the whole crawl on a
/// missing/unreachable robots.txt.
async fn fetch_robots_disallow(client: &Client, page_url: &str, user_agent: &str) -> Vec<String> {
    let Some(origin) = origin_key(page_url) else {
        return Vec::new();
    };
    let robots_url = format!("{origin}/robots.txt");

    match client.get(&robots_url).header("User-Agent", user_agent).send().await {
        Ok(resp) if resp.status().is_success() => match resp.text().await {
            Ok(body) => parse_robots(&body),
            Err(e) => {
                logger::debug(&format!("spider: failed to read robots.txt body for {origin}: {e}"));
                Vec::new()
            }
        },
        Ok(resp) => {
            logger::debug(&format!(
                "spider: robots.txt for {origin} returned {} — treating as no rules",
                resp.status()
            ));
            Vec::new()
        }
        Err(e) => {
            logger::debug(&format!("spider: failed to fetch robots.txt for {origin}: {e}"));
            Vec::new()
        }
    }
}

/// Parse `Disallow:` paths out of the `User-agent: *` block(s) of a
/// robots.txt body. Agent-specific blocks (anything not `*`) are skipped
/// entirely. Comments (`#...`) and blank lines are ignored.
fn parse_robots(body: &str) -> Vec<String> {
    let mut rules = Vec::new();
    let mut in_wildcard_block = false;

    for raw_line in body.lines() {
        let line = match raw_line.split('#').next() {
            Some(l) => l.trim(),
            None => continue,
        };
        if line.is_empty() {
            continue;
        }

        let Some((directive, value)) = line.split_once(':') else {
            continue;
        };
        let directive = directive.trim().to_lowercase();
        let value = value.trim();

        match directive.as_str() {
            "user-agent" => {
                in_wildcard_block = value == "*";
            }
            "disallow" if in_wildcard_block => {
                if !value.is_empty() {
                    rules.push(value.to_string());
                }
            }
            _ => {}
        }
    }

    rules
}

/// `true` if `url`'s path starts with any configured disallow prefix.
/// Empty `rules` (or an unparsable `url`) never disallows anything.
fn is_disallowed(url: &str, rules: &[String]) -> bool {
    let Ok(parsed) = Url::parse(url) else { return false };
    let path = parsed.path();
    rules.iter().any(|rule| path.starts_with(rule.as_str()))
}

// ─── HTML extraction ──────────────────────────────────────────────────────────
//
// Lightweight regex-based extraction (no HTML parser dependency pulled in
// just for this) — mirrors the `OnceLock`-compiled-regex convention used in
// web_analyzer.rs. Good enough for well-formed-ish HTML; this intentionally
// doesn't try to handle every malformed-markup edge case a full parser
// would.

fn link_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r#"(?i)<a\s[^>]*\bhref\s*=\s*["']([^"']+)["']"#).unwrap()
    })
}

fn form_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r#"(?is)<form\b([^>]*)>(.*?)</form>"#).unwrap()
    })
}

fn attr_regex(attr: &str) -> regex::Regex {
    regex::Regex::new(&format!(r#"(?i)\b{attr}\s*=\s*["']([^"']*)["']"#)).unwrap()
}

fn form_field_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r#"(?is)<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']+)["']"#)
            .unwrap()
    })
}

/// Resolve every `<a href="...">` on the page against `base`, deduplicated
/// and filtered down to `http`/`https` targets (so `mailto:`, `tel:`,
/// `javascript:`, and bare `#anchor` links never make it into the queue).
fn extract_links(base: &Url, body: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut links = Vec::new();

    for cap in link_regex().captures_iter(body) {
        let href = &cap[1];
        if href.starts_with('#') {
            continue;
        }
        let Ok(resolved) = base.join(href) else { continue };
        if resolved.scheme() != "http" && resolved.scheme() != "https" {
            continue;
        }
        let resolved_str = resolved.to_string();
        if seen.insert(resolved_str.clone()) {
            links.push(resolved_str);
        }
    }

    links
}

/// Extract every `<form>` on the page: resolved absolute `action`
/// (defaulting to the page's own URL if `action` is missing/empty, per
/// HTML spec behaviour), uppercased `method` (defaulting to `"GET"`), and
/// every named `<input>`/`<select>`/`<textarea>` field inside it.
fn extract_forms(base: &Url, body: &str) -> Vec<FormInfo> {
    let action_re = attr_regex("action");
    let method_re = attr_regex("method");

    form_regex()
        .captures_iter(body)
        .map(|cap| {
            let open_tag_attrs = &cap[1];
            let form_body = &cap[2];

            let action_raw = action_re
                .captures(open_tag_attrs)
                .map(|c| c[1].to_string())
                .unwrap_or_default();
            let action = if action_raw.is_empty() {
                base.to_string()
            } else {
                base.join(&action_raw)
                    .map(|u| u.to_string())
                    .unwrap_or(action_raw)
            };

            let method = method_re
                .captures(open_tag_attrs)
                .map(|c| c[1].to_uppercase())
                .filter(|m| !m.is_empty())
                .unwrap_or_else(|| "GET".to_string());

            let fields: Vec<String> = form_field_regex()
                .captures_iter(form_body)
                .map(|c| c[1].to_string())
                .collect();

            FormInfo { action, method, fields }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Url {
        Url::parse("https://example.com/dir/page.html").unwrap()
    }

    // ── link extraction ─────────────────────────────────────────────────

    #[test]
    fn extracts_and_resolves_relative_links() {
        let body = r#"<a href="/about">About</a> <a href="contact.html">Contact</a>"#;
        let links = extract_links(&base(), body);
        assert!(links.contains(&"https://example.com/about".to_string()));
        assert!(links.contains(&"https://example.com/dir/contact.html".to_string()));
    }

    #[test]
    fn dedupes_repeated_links() {
        let body = r#"<a href="/x">1</a><a href="/x">2</a>"#;
        let links = extract_links(&base(), body);
        assert_eq!(links.len(), 1);
    }

    #[test]
    fn resolves_absolute_links_unchanged() {
        let body = r#"<a href="https://other.com/page">x</a>"#;
        let links = extract_links(&base(), body);
        assert_eq!(links, vec!["https://other.com/page".to_string()]);
    }

    // ── form extraction ─────────────────────────────────────────────────

    #[test]
    fn extracts_form_action_method_and_fields() {
        let body = r#"
            <form action="/login" method="post">
                <input name="username" type="text">
                <input name="password" type="password">
                <button type="submit">Go</button>
            </form>
        "#;
        let forms = extract_forms(&base(), body);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].action, "https://example.com/login");
        assert_eq!(forms[0].method, "POST");
        assert_eq!(forms[0].fields, vec!["username".to_string(), "password".to_string()]);
    }

    #[test]
    fn form_without_method_defaults_to_get() {
        let body = r#"<form action="/search"><input name="q"></form>"#;
        let forms = extract_forms(&base(), body);
        assert_eq!(forms[0].method, "GET");
    }

    #[test]
    fn form_without_action_defaults_to_page_url() {
        let body = r#"<form method="post"><input name="q"></form>"#;
        let forms = extract_forms(&base(), body);
        assert_eq!(forms[0].action, base().to_string());
    }

    #[test]
    fn multiple_forms_on_one_page() {
        let body = r#"
            <form action="/a"><input name="x"></form>
            <form action="/b" method="post"><input name="y"></form>
        "#;
        let forms = extract_forms(&base(), body);
        assert_eq!(forms.len(), 2);
        assert_eq!(forms[0].action, "https://example.com/a");
        assert_eq!(forms[1].action, "https://example.com/b");
    }

    // ── robots.txt parsing ──────────────────────────────────────────────

    #[test]
    fn parses_wildcard_disallow_rules() {
        let body = "User-agent: *\nDisallow: /admin\nDisallow: /private\n";
        let rules = parse_robots(body);
        assert_eq!(rules, vec!["/admin".to_string(), "/private".to_string()]);
    }

    #[test]
    fn ignores_agent_specific_blocks() {
        let body = "User-agent: Googlebot\nDisallow: /only-google\n\nUser-agent: *\nDisallow: /everyone\n";
        let rules = parse_robots(body);
        assert_eq!(rules, vec!["/everyone".to_string()]);
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let body = "# comment\nUser-agent: *\n\n# another comment\nDisallow: /x\n";
        let rules = parse_robots(body);
        assert_eq!(rules, vec!["/x".to_string()]);
    }

    #[test]
    fn empty_disallow_value_is_not_a_rule() {
        // "Disallow:" with no value conventionally means "disallow nothing".
        let body = "User-agent: *\nDisallow:\n";
        let rules = parse_robots(body);
        assert!(rules.is_empty());
    }

    #[test]
    fn is_disallowed_matches_prefix() {
        let rules = vec!["/admin".to_string()];
        assert!(is_disallowed("https://example.com/admin/users", &rules));
        assert!(!is_disallowed("https://example.com/public", &rules));
    }

    #[test]
    fn is_disallowed_empty_rules_allows_everything() {
        assert!(!is_disallowed("https://example.com/anything", &[]));
    }

    // ── URL helpers ──────────────────────────────────────────────────────

    #[test]
    fn normalize_strips_fragment() {
        assert_eq!(
            normalize_url("https://example.com/page#section"),
            "https://example.com/page"
        );
    }

    #[test]
    fn origin_key_combines_scheme_and_host() {
        assert_eq!(
            origin_key("https://example.com/a/b"),
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn origin_key_includes_nonstandard_port() {
        assert_eq!(
            origin_key("http://example.com:8080/x"),
            Some("http://example.com:8080".to_string())
        );
    }

    // ── BFS queue helper ──────────────────────────────────────────────────

    #[test]
    fn enqueue_skips_out_of_scope_links() {
        let mut scope = Scope::new();
        scope.add_include(r"example\.com").unwrap();
        let visited = HashSet::new();
        let mut queue = VecDeque::new();

        enqueue_if_eligible("https://other.org/x", 1, &scope, &visited, &mut queue);
        assert!(queue.is_empty());

        enqueue_if_eligible("https://example.com/x", 1, &scope, &visited, &mut queue);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn enqueue_skips_already_visited() {
        let scope = Scope::new();
        let mut visited = HashSet::new();
        visited.insert(normalize_url("https://example.com/x"));
        let mut queue = VecDeque::new();

        enqueue_if_eligible("https://example.com/x", 1, &scope, &visited, &mut queue);
        assert!(queue.is_empty());
    }

    // ── end-to-end run() smoke test ─────────────────────────────────────

    #[tokio::test]
    async fn run_on_unreachable_seed_yields_single_error_result() {
        let config = SpiderConfig {
            seed_url: "https://invalid-host-for-spider-test.invalid/".to_string(),
            max_depth: 2,
            max_pages: 10,
            scope: Arc::new(Scope::new()),
            follow_forms: false,
            user_agent: "Cogitator-Spider-Test".to_string(),
            cached_robots_disallow: None,
            history: Arc::new(History::new()),
        };

        let client = Arc::new(Client::new());
        let mut rx = run(config, client);

        let first = rx.recv().await.expect("expected one result");
        assert!(first.status.is_none());
        assert!(first.found_links.is_empty());

        // Nothing else should follow — the seed failed and had no links.
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn cached_robots_disallow_skips_seed_without_any_fetch() {
        // Seed itself disallowed via the cached rule — should be skipped
        // before any HTTP request is attempted, so the channel closes with
        // zero results. Using an unreachable host doubles as proof no
        // network call was made: if the disallow check were skipped, the
        // earlier `run_on_unreachable_seed_yields_single_error_result` test
        // shows what a real (failed) fetch attempt looks like instead.
        let config = SpiderConfig {
            seed_url: "https://invalid-host-for-spider-test.invalid/".to_string(),
            max_depth: 2,
            max_pages: 10,
            scope: Arc::new(Scope::new()),
            follow_forms: false,
            user_agent: "Cogitator-Spider-Test".to_string(),
            cached_robots_disallow: Some(vec!["/".to_string()]),
            history: Arc::new(History::new()),
        };

        let client = Arc::new(Client::new());
        let mut rx = run(config, client);

        assert!(rx.recv().await.is_none());
    }

    #[test]
    fn audit_html_flags_potential_token_leak_without_panicking() {
        // Smoke-test the real audit_html wiring directly (rather than via a
        // live network round-trip in run()): feed it a page containing
        // something that looks like a leaked API key and confirm the call
        // succeeds and reports it, since that's the signal spider's audit
        // hook logs on.
        let body = r#"<html><body><script>var key = "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567";</script></body></html>"#;
        let audit = audit_html(body);
        assert!(!audit.potential_tokens.is_empty());
    }
}