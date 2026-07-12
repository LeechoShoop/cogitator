//! Spider and Spider-Depth handlers, plus the `build_spider_config` helper
//! that was previously a top-level function in `main.rs`.

use std::sync::Arc;

use crate::{scope, spider as spider_crawler};
use crate::styletui::Screen;
use super::CommandContext;

// ── build_spider_config ───────────────────────────────────────────────────────

/// Build a [`spider_crawler::SpiderConfig`] for the `Spider`/`Spider-Depth`
/// commands, scoped to the given domain/URL so a crawl doesn't wander off-site.
///
/// `domain_or_url` may be a bare domain (`"example.com"`) or a full URL with
/// scheme; bare domains are assumed `https://`.  The crawl's `Scope` is a
/// fresh, single-rule scope (include: the seed's host, regex-escaped) —
/// deliberately independent of the proxy's shared `Scope-Add`/`Scope-Exclude`
/// rules, since those govern proxy traffic logging, not what a one-off crawl
/// is allowed to wander into.
pub(crate) fn build_spider_config(
    domain_or_url: &str,
    max_depth: u8,
    max_pages: usize,
    history: Arc<crate::history::History>,
) -> (String, spider_crawler::SpiderConfig) {
    let trimmed = domain_or_url.trim_end_matches('/');
    let seed_url = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    };

    let host = reqwest::Url::parse(&seed_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| domain_or_url.to_string());

    let mut crawl_scope = scope::Scope::new();
    // Best-effort: an unparsable host would already have failed Url::parse
    // above and fallen back to the raw input, so add_include should only
    // ever fail here on a genuinely pathological domain string — in which
    // case an empty scope ("everything in scope") is a safe fallback.
    let _ = crawl_scope.add_include(&regex::escape(&host));

    let config = spider_crawler::SpiderConfig {
        seed_url: seed_url.clone(),
        max_depth,
        max_pages,
        scope: Arc::new(crawl_scope),
        follow_forms: true,
        // Mirrors the redirect-following client's UA (see
        // web_analyzer::build_clients) so Spider's traffic looks like the
        // rest of Cogitator's passive/active probing rather than
        // self-identifying as a crawler.
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                     (KHTML, like Gecko) Chrome/120.0.0.0 Safari/120.0.0.0"
            .to_string(),
        cached_robots_disallow: None,
        history,
    };

    (seed_url, config)
}

// ── Spider-Depth ──────────────────────────────────────────────────────────────

pub fn spider_depth(ctx: &mut CommandContext<'_>, rest: &str) {
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() != 2 {
        *ctx.output_buffer = "Usage: Spider-Depth <domain> <N>".to_string();
        return;
    }

    match parts[1].parse::<u8>() {
        Ok(depth) => {
            let (seed_url, cfg) =
                build_spider_config(parts[0], depth, 500, ctx.history.clone());

            // `spider::run` spawns its own task; `enter()` provides the
            // runtime context without blocking the TUI loop.
            let _guard = ctx.rt.enter();
            let rx = spider_crawler::run(cfg, ctx.follow.clone());
            drop(_guard);

            ctx.spider_state.reset_for_new_run(
                500,
                format!("crawling {} (depth {})…", seed_url, depth),
            );
            *ctx.spider_rx = Some(rx);
            *ctx.output_buffer = format!(
                "⏳ Crawling {} (depth {}, max 500 pages)…",
                seed_url, depth
            );
            *ctx.current_screen = Screen::Spider;
        }
        Err(_) => {
            *ctx.output_buffer = "Usage: Spider-Depth <domain> <N>".to_string();
        }
    }
}

// ── Spider ────────────────────────────────────────────────────────────────────

pub fn spider(ctx: &mut CommandContext<'_>, rest: &str) {
    if rest.is_empty() {
        *ctx.output_buffer =
            "Usage: Spider <domain>  (or Spider-Depth <domain> <N>)".to_string();
        return;
    }

    let (seed_url, cfg) = build_spider_config(rest, 3, 500, ctx.history.clone());

    let _guard = ctx.rt.enter();
    let rx = spider_crawler::run(cfg, ctx.follow.clone());
    drop(_guard);

    ctx.spider_state.reset_for_new_run(
        500,
        format!("crawling {} (depth 3)…", seed_url),
    );
    *ctx.spider_rx = Some(rx);
    *ctx.output_buffer = format!(
        "⏳ Crawling {} (depth 3, max 500 pages)…",
        seed_url
    );
    *ctx.current_screen = Screen::Spider;
}
