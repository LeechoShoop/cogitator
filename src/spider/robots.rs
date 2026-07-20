//! robots.txt caching helpers for the Spider crawl engine.
//!
//! Responsibility boundary: everything that touches robots.txt lives here.
//! The orchestrator (`super`) calls [`fetch_robots`] and
//! [`is_disallowed`]; it owns the per-origin [`HashMap`] cache itself so
//! that cache lifetime is tied to the BFS loop rather than to any
//! `RobotsCache` struct.

use reqwest::{Client, Url};

use crate::logger;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct RobotsRules {
    pub disallow_paths: Vec<String>,
    pub crawl_delay_secs: Option<u64>,
    pub sitemaps: Vec<String>,
}

// ─── URL origin helper ────────────────────────────────────────────────────────

/// `scheme://host[:port]` — the cache key for robots.txt rules, since
/// robots.txt is scoped per-origin, not per-path.
pub(super) fn origin_key(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    match parsed.port() {
        Some(port) => Some(format!("{}://{}:{}", parsed.scheme(), host, port)),
        None => Some(format!("{}://{}", parsed.scheme(), host)),
    }
}

// ─── robots.txt fetch + parse ─────────────────────────────────────────────────

/// Fetch `{origin}/robots.txt` and parse its rules. Only the
/// `User-agent: *` block is honoured — Spider doesn't claim a distinct UA
/// identity, so agent-specific blocks aren't applicable. Any failure
/// (network error, non-2xx, unparsable origin) yields an empty rule set,
/// i.e. "nothing disallowed and no delay" rather than blocking the whole crawl.
pub(super) async fn fetch_robots(
    client: &Client,
    page_url: &str,
    user_agent: &str,
) -> RobotsRules {
    let Some(origin) = origin_key(page_url) else {
        return RobotsRules::default();
    };
    let robots_url = format!("{origin}/robots.txt");

    match client.get(&robots_url).header("User-Agent", user_agent).send().await {
        Ok(resp) if resp.status().is_success() => match resp.text().await {
            Ok(body) => parse_robots(&body),
            Err(e) => {
                logger::debug(&format!(
                    "spider: failed to read robots.txt body for {origin}: {e}"
                ));
                RobotsRules::default()
            }
        },
        Ok(resp) => {
            logger::debug(&format!(
                "spider: robots.txt for {origin} returned {} — treating as no rules",
                resp.status()
            ));
            RobotsRules::default()
        }
        Err(e) => {
            logger::debug(&format!("spider: failed to fetch robots.txt for {origin}: {e}"));
            RobotsRules::default()
        }
    }
}

/// Parse `Disallow:` paths and `Crawl-delay:` out of the `User-agent: *` block(s) of a
/// robots.txt body. Agent-specific blocks (anything not `*`) are skipped
/// entirely. Comments (`#...`) and blank lines are ignored.
pub(super) fn parse_robots(body: &str) -> RobotsRules {
    let mut rules = RobotsRules::default();
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
                    rules.disallow_paths.push(value.to_string());
                }
            }
            "crawl-delay" if in_wildcard_block => {
                if let Ok(delay) = value.parse::<u64>() {
                    rules.crawl_delay_secs = Some(delay);
                }
            }
            "sitemap" => {
                if !value.is_empty() {
                    rules.sitemaps.push(value.to_string());
                }
            }
            _ => {}
        }
    }

    rules
}

/// `true` if `url`'s path starts with any configured disallow prefix.
/// Empty `rules` (or an unparsable `url`) never disallows anything.
pub(super) fn is_disallowed(url: &str, rules: &RobotsRules) -> bool {
    let Ok(parsed) = Url::parse(url) else { return false };
    let path = parsed.path();
    rules.disallow_paths.iter().any(|rule| path.starts_with(rule.as_str()))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wildcard_disallow_rules() {
        let body = "User-agent: *\nDisallow: /admin\nDisallow: /private\nCrawl-delay: 5\nSitemap: https://example.com/sitemap.xml";
        let rules = parse_robots(body);
        assert_eq!(rules.disallow_paths, vec!["/admin".to_string(), "/private".to_string()]);
        assert_eq!(rules.crawl_delay_secs, Some(5));
        assert_eq!(rules.sitemaps, vec!["https://example.com/sitemap.xml".to_string()]);
    }

    #[test]
    fn ignores_agent_specific_blocks() {
        let body = "User-agent: Googlebot\nDisallow: /only-google\nCrawl-delay: 10\n\nUser-agent: *\nDisallow: /everyone\n";
        let rules = parse_robots(body);
        assert_eq!(rules.disallow_paths, vec!["/everyone".to_string()]);
        assert_eq!(rules.crawl_delay_secs, None);
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let body = "# comment\nUser-agent: *\n\n# another comment\nDisallow: /x\n";
        let rules = parse_robots(body);
        assert_eq!(rules.disallow_paths, vec!["/x".to_string()]);
    }

    #[test]
    fn empty_disallow_value_is_not_a_rule() {
        // "Disallow:" with no value conventionally means "disallow nothing".
        let body = "User-agent: *\nDisallow:\n";
        let rules = parse_robots(body);
        assert!(rules.disallow_paths.is_empty());
    }

    #[test]
    fn is_disallowed_matches_prefix() {
        let rules = RobotsRules {
            disallow_paths: vec!["/admin".to_string()],
            crawl_delay_secs: None,
            sitemaps: Vec::new(),
        };
        assert!(is_disallowed("https://example.com/admin/users", &rules));
        assert!(!is_disallowed("https://example.com/public", &rules));
    }

    #[test]
    fn is_disallowed_empty_rules_allows_everything() {
        assert!(!is_disallowed("https://example.com/anything", &RobotsRules::default()));
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
}
