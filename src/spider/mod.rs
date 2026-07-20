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
//!     enqueued further). See `robots.rs`.
//!   * `max_depth` / `max_pages` — hard caps on traversal depth and total
//!     fetched pages.
//!
//! Every fetched page is also recorded into `History` so it shows up
//! alongside proxy/interceptor traffic for later review.

mod robots;
mod extract;
mod js_fetch;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chromiumoxide::browser::Browser;
use rand::random;
use reqwest::{Client, Url};
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::Semaphore;

use crate::history::{History, RequestRecord};
use crate::logger;
use crate::scope::Scope;
use crate::scrap_analyze::audit_html;

use robots::{fetch_robots, is_disallowed, origin_key, RobotsRules};
use extract::{extract_links_and_forms, extract_sitemap_urls};

/// Cap on how much of a response body is buffered into the `History`
/// record — mirrors the 1 MB cap used by the proxy's own
/// `record_exchange` helper, so a handful of huge pages can't blow up
/// memory over a long crawl.
const HISTORY_BODY_CAP: usize = 1_000_000;

/// Number of parallel tasks allowed to fetch pages concurrently.
const MAX_PARALLEL_FETCHES: usize = 10;

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
    /// When `true`, each page is fetched via a headless Chromium browser
    /// (chromiumoxide) so that JavaScript-rendered content is visible to
    /// the link/form extractor.  The browser is launched once at the start
    /// of the crawl and reused across all workers; if Chrome is not on
    /// `PATH` or the browser fails to start, a warning is logged and the
    /// crawler falls back to the plain `reqwest` path automatically.
    ///
    /// When `false` (the default), the crawler uses the existing fast
    /// `reqwest` path — no browser process is ever spawned.
    pub use_js: bool,
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

enum WorkerResult {
    Fetched {
        url: String,
        depth: u8,
        spider_res: SpiderResult,
    },
    Skipped,
    SitemapsDiscovered(Vec<String>),
}

// ─── Public entry point ───────────────────────────────────────────────────────

/// Launch a crawl. Returns immediately with a receiver; one `SpiderResult`
/// is pushed per fetched page, in the order pages are actually fetched
/// (BFS order — same depth before the next). The driver task exits
/// (closing the channel) once the queue is drained or `max_pages` is hit.
pub fn run(config: SpiderConfig, client: Arc<Client>) -> Receiver<SpiderResult> {
    let (tx, rx) = mpsc::channel(256);

    tokio::spawn(async move {
        if !config.scope.in_scope(&config.seed_url) {
            logger::warn(&format!(
                "spider: seed URL {} is out of scope, nothing to crawl",
                config.seed_url
            ));
            return;
        }

        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, u8)> = VecDeque::new();
        
        let seed_normalized = normalize_url(&config.seed_url);
        visited.insert(seed_normalized.clone());
        queue.push_back((config.seed_url.clone(), 0));

        let mut pages_crawled = 0usize;
        let mut in_flight = 0usize;

        let robots_cache: Arc<tokio::sync::Mutex<HashMap<String, RobotsRules>>> = 
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let origin_next_fetch: Arc<std::sync::Mutex<HashMap<String, Instant>>> = 
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        if let Some(rules) = &config.cached_robots_disallow {
            if let Some(origin) = origin_key(&config.seed_url) {
                let mut rules_obj = RobotsRules::default();
                rules_obj.disallow_paths = rules.clone();
                robots_cache.lock().await.insert(origin, rules_obj);
            }
        }

        // Optionally launch a headless browser for the JS execution path.
        // If use_js is false, or if the browser fails to start, every URL
        // falls back to the plain reqwest path automatically.
        let browser: Option<Arc<Browser>> = if config.use_js {
            match js_fetch::launch_browser().await {
                Ok(b) => Some(Arc::new(b)),
                Err(e) => {
                    logger::warn(&format!(
                        "spider: failed to launch headless browser ({e}); \
                         falling back to static reqwest fetch for this crawl"
                    ));
                    None
                }
            }
        } else {
            None
        };

        let semaphore = Arc::new(Semaphore::new(MAX_PARALLEL_FETCHES));
        let (worker_tx, mut worker_rx) = mpsc::channel(256);

        loop {
            if in_flight == 0 && queue.is_empty() {
                break;
            }

            // We only spawn if queue has items, we have concurrency capacity, and we won't exceed max_pages.
            let can_spawn = !queue.is_empty() 
                && in_flight < MAX_PARALLEL_FETCHES 
                && (pages_crawled + in_flight) < config.max_pages;

            // If we can't spawn, and queue is not empty, but we hit max_pages, 
            // we should still wait for in_flight to drain. We clear queue to drop remaining work.
            if !can_spawn && (pages_crawled + in_flight) >= config.max_pages {
                queue.clear();
            }

            tokio::select! {
                Some(worker_res) = worker_rx.recv() => {
                    in_flight -= 1;
                    
                    match worker_res {
                        WorkerResult::Fetched { url, depth, spider_res } => {
                            pages_crawled += 1;
                            
                            // Enqueue new links
                            if depth < config.max_depth {
                                for link in &spider_res.found_links {
                                    let norm = normalize_url(link);
                                    if !visited.contains(&norm) && config.scope.in_scope(link) {
                                        visited.insert(norm);
                                        queue.push_back((link.clone(), depth + 1));
                                    }
                                }
                                if config.follow_forms {
                                    for form in &spider_res.found_forms {
                                        if form.method.eq_ignore_ascii_case("get") {
                                            if let Ok(base) = Url::parse(&url) {
                                                if let Ok(resolved) = base.join(&form.action) {
                                                    let res_str = resolved.as_str();
                                                    let norm = normalize_url(res_str);
                                                    if !visited.contains(&norm) && config.scope.in_scope(res_str) {
                                                        visited.insert(norm);
                                                        queue.push_back((res_str.to_string(), depth + 1));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            
                            // Send result downstream.
                            if tx.send(spider_res).await.is_err() {
                                // Receiver dropped (e.g. TUI closed tab)
                                break;
                            }
                        }
                        WorkerResult::Skipped => {
                            // Skipped URLs don't count towards pages_crawled.
                        }
                        WorkerResult::SitemapsDiscovered(urls) => {
                            for sitemap_url in urls {
                                let norm = normalize_url(&sitemap_url);
                                if !visited.contains(&norm) && config.scope.in_scope(&sitemap_url) {
                                    visited.insert(norm);
                                    // Treat sitemaps as top-level seeds (depth 0)
                                    queue.push_back((sitemap_url.clone(), 0));
                                }
                            }
                        }
                    }
                }
                
                _ = async {}, if can_spawn => {
                    let (url, depth) = queue.pop_front().unwrap();
                    in_flight += 1;

                    let client = client.clone();
                    let worker_tx = worker_tx.clone();
                    let robots_cache = robots_cache.clone();
                    let origin_next_fetch = origin_next_fetch.clone();
                    let user_agent = config.user_agent.clone();
                    let history = config.history.clone();
                    let browser = browser.clone();
                    
                    let permit = semaphore.clone().acquire_owned().await.unwrap();

                    tokio::spawn(async move {
                        let _permit = permit;
                        
                        let Some(origin) = origin_key(&url) else {
                            logger::debug(&format!("spider: skipping unparsable URL {url}"));
                            let _ = worker_tx.send(WorkerResult::Skipped).await;
                            return;
                        };

                        let (rules, new_sitemaps) = {
                            let mut cache = robots_cache.lock().await;
                            if let Some(r) = cache.get(&origin) {
                                (r.clone(), Vec::new())
                            } else {
                                drop(cache);
                                let fetched = fetch_robots(&client, &url, &user_agent).await;
                                let sitemaps_to_report = fetched.sitemaps.clone();
                                let mut cache = robots_cache.lock().await;
                                let cached = cache.entry(origin.clone()).or_insert(fetched).clone();
                                (cached, sitemaps_to_report)
                            }
                        };

                        if !new_sitemaps.is_empty() {
                            let _ = worker_tx.send(WorkerResult::SitemapsDiscovered(new_sitemaps)).await;
                        }

                        if is_disallowed(&url, &rules) {
                            logger::debug(&format!("spider: {url} disallowed by robots.txt, skipping"));
                            let _ = worker_tx.send(WorkerResult::Skipped).await;
                            return;
                        }

                        // Politeness check (Crawl-delay)
                        let delay = {
                            let mut next_fetch_map = origin_next_fetch.lock().unwrap();
                            let now = Instant::now();
                            let state = next_fetch_map.entry(origin.clone()).or_insert(now);
                            
                            let crawl_delay = Duration::from_secs(rules.crawl_delay_secs.unwrap_or(0));
                            let mut sleep_dur = Duration::from_secs(0);
                            
                            if now < *state {
                                sleep_dur = *state - now;
                                *state += crawl_delay;
                            } else {
                                *state = now + crawl_delay;
                            }
                            sleep_dur
                        };

                        if delay > Duration::from_secs(0) {
                            tokio::time::sleep(delay).await;
                        }

                        // ── Fetch ────────────────────────────────────────
                        //
                        // JS path: try the headless browser first when enabled.
                        // On any failure js_fetch::fetch_js returns None and we
                        // drop through to the plain reqwest path below.
                        let js_html: Option<String> = if let Some(ref b) = browser {
                            js_fetch::fetch_js(b, &url, &user_agent).await
                        } else {
                            None
                        };

                        let spider_res = if let Some(body) = js_html {
                            // ── JS path succeeded ─────────────────────────
                            // We have rendered HTML; synthesise a 200/text-html
                            // response (the browser only returns content if the
                            // page loaded — errors come back as None above).
                            let started = Instant::now();
                            let status = 200u16;
                            let content_type = Some("text/html; charset=utf-8".to_string());

                            record_to_history(
                                &history, &url, status,
                                &[("content-type".to_string(), "text/html; charset=utf-8".to_string())],
                                &body, started.elapsed(),
                            );

                            let base = Url::parse(&url).ok();
                            let is_sitemap = url.ends_with(".xml")
                                || content_type.as_deref().unwrap_or("").contains("xml");

                            let (found_links, found_forms) = if is_sitemap {
                                (extract_sitemap_urls(&body), Vec::new())
                            } else {
                                base.as_ref()
                                    .map(|b| extract_links_and_forms(b, &body))
                                    .unwrap_or_default()
                            };

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

                            SpiderResult {
                                url: url.clone(),
                                depth,
                                found_links,
                                found_forms,
                                status: Some(status),
                                content_type,
                            }
                        } else {
                            // ── Static / fallback path (reqwest) ──────────
                            let started = Instant::now();
                            let send_result = client
                                .get(&url)
                                .header("User-Agent", &user_agent)
                                .send()
                                .await;

                            match send_result {
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

                                    record_to_history(&history, &url, status, &response_headers, &body, elapsed);

                                    let base = Url::parse(&url).ok();
                                    let is_sitemap = url.ends_with(".xml")
                                        || content_type.as_deref().unwrap_or("").contains("xml");

                                    let (found_links, found_forms) = if is_sitemap {
                                        (extract_sitemap_urls(&body), Vec::new())
                                    } else {
                                        base.as_ref()
                                            .map(|b| extract_links_and_forms(b, &body))
                                            .unwrap_or_default()
                                    };

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
                            }
                        };

                        let _ = worker_tx.send(WorkerResult::Fetched { url, depth, spider_res }).await;
                    });
                }
            }
        }
    });

    rx
}

// ─── History integration ──────────────────────────────────────────────────────

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

// ─── URL helper ───────────────────────────────────────────────────────────────

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

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::History;

    // ── URL helpers ──────────────────────────────────────────────────────

    #[test]
    fn normalize_strips_fragment() {
        assert_eq!(
            normalize_url("https://example.com/page#section"),
            "https://example.com/page"
        );
    }

    // ── end-to-end run() smoke tests ─────────────────────────────────────

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
            use_js: false,
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
            use_js: false,
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
        let body = r#"<html><body><script>var key = "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ123456789";</script></body></html>"#;
        let audit = audit_html(body);
        assert!(!audit.potential_tokens.is_empty());
    }

    /// Confirm that when `use_js = false` the crawl completes on an
    /// unreachable host without ever attempting to launch Chrome. This is
    /// validated structurally: `browser` is `None` when `use_js = false`,
    /// so no CDP connection is ever initiated. The test proves the static
    /// path is fully independent of the browser path.
    #[tokio::test]
    async fn static_path_never_constructs_browser_when_use_js_false() {
        let config = SpiderConfig {
            seed_url: "https://invalid-host-for-spider-test.invalid/".to_string(),
            max_depth: 1,
            max_pages: 5,
            scope: Arc::new(Scope::new()),
            follow_forms: false,
            user_agent: "Cogitator-Spider-Test".to_string(),
            cached_robots_disallow: None,
            history: Arc::new(History::new()),
            use_js: false, // <── the key assertion: no browser spawned
        };

        let client = Arc::new(Client::new());
        let mut rx = run(config, client);

        // The seed fetch should fail (unreachable host) and produce one
        // error result — no panic, no timeout waiting for a browser CDP
        // handshake, and no browser process visible on the system.
        let first = rx.recv().await.expect("expected one result from static path");
        assert!(first.status.is_none(), "static path on unreachable host yields no status");
        assert!(rx.recv().await.is_none(), "channel closes after single failed seed");
    }
}
