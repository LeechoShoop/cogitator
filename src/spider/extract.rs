//! HTML link and form extraction for the Spider crawl engine.
//!
//! Uses the `scraper` crate to robustly parse HTML, extracting links and
//! forms. Automatically respects `<base href="...">` if present in the document.

use std::collections::HashSet;

use reqwest::Url;
use scraper::{Html, Selector};

use super::FormInfo;

// ─── Public extraction function ───────────────────────────────────────────────

/// Parses the HTML `body` and extracts all links and forms, taking into account
/// any `<base href="...">` tag present in the document to resolve relative URLs.
pub(super) fn extract_links_and_forms(base: &Url, body: &str) -> (Vec<String>, Vec<FormInfo>) {
    let document = Html::parse_document(body);

    let mut effective_base = base.clone();
    if let Ok(base_sel) = Selector::parse("base[href]") {
        if let Some(base_tag) = document.select(&base_sel).next() {
            if let Some(href) = base_tag.value().attr("href") {
                if let Ok(new_base) = base.join(href) {
                    effective_base = new_base;
                }
            }
        }
    }

    let links = extract_links_impl(&effective_base, &document);
    let forms = extract_forms_impl(&effective_base, &document);

    (links, forms)
}

// ─── Sitemap Extraction ───────────────────────────────────────────────────────

pub(super) fn extract_sitemap_urls(body: &str) -> Vec<String> {
    let document = Html::parse_document(body);
    let mut urls = Vec::new();
    
    if let Ok(loc_sel) = Selector::parse("loc") {
        for element in document.select(&loc_sel) {
            let text = element.text().collect::<String>().trim().to_string();
            if text.starts_with("http") {
                urls.push(text);
            }
        }
    }
    
    urls
}

// ─── Internal implementation ──────────────────────────────────────────────────

fn extract_links_impl(base: &Url, document: &Html) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut links = Vec::new();

    let Ok(a_sel) = Selector::parse("a[href]") else { return links };

    for element in document.select(&a_sel) {
        let Some(href) = element.value().attr("href") else { continue };
        let href = href.trim();
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

fn extract_forms_impl(base: &Url, document: &Html) -> Vec<FormInfo> {
    let mut forms = Vec::new();

    let Ok(form_sel) = Selector::parse("form") else { return forms };
    let Ok(input_sel) = Selector::parse("input[name], select[name], textarea[name]") else { return forms };

    for form_element in document.select(&form_sel) {
        let action_raw = form_element.value().attr("action").unwrap_or("").trim().to_string();
        
        let action = if action_raw.is_empty() {
            base.to_string()
        } else {
            base.join(&action_raw)
                .map(|u| u.to_string())
                .unwrap_or(action_raw)
        };

        let method = form_element
            .value()
            .attr("method")
            .map(|m| m.trim().to_uppercase())
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| "GET".to_string());

        let mut fields = Vec::new();
        for field_element in form_element.select(&input_sel) {
            if let Some(name) = field_element.value().attr("name") {
                fields.push(name.to_string());
            }
        }

        forms.push(FormInfo { action, method, fields });
    }

    forms
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Url {
        Url::parse("https://example.com/dir/page.html").unwrap()
    }

    // ── link extraction ──────────────────────────────────────────────────

    #[test]
    fn extracts_and_resolves_relative_links() {
        let body = r#"<a href="/about">About</a> <a href="contact.html">Contact</a>"#;
        let (links, _) = extract_links_and_forms(&base(), body);
        assert!(links.contains(&"https://example.com/about".to_string()));
        assert!(links.contains(&"https://example.com/dir/contact.html".to_string()));
    }

    #[test]
    fn dedupes_repeated_links() {
        let body = r#"<a href="/x">1</a><a href="/x">2</a>"#;
        let (links, _) = extract_links_and_forms(&base(), body);
        assert_eq!(links.len(), 1);
    }

    #[test]
    fn resolves_absolute_links_unchanged() {
        let body = r#"<a href="https://other.com/page">x</a>"#;
        let (links, _) = extract_links_and_forms(&base(), body);
        assert_eq!(links, vec!["https://other.com/page".to_string()]);
    }

    #[test]
    fn respects_base_href() {
        let body = r#"
            <base href="https://example.com/base/">
            <a href="relative.html">link</a>
        "#;
        let (links, _) = extract_links_and_forms(&base(), body);
        assert_eq!(links, vec!["https://example.com/base/relative.html".to_string()]);
    }

    // ── form extraction ──────────────────────────────────────────────────

    #[test]
    fn extracts_form_action_method_and_fields() {
        let body = r#"
            <form action="/login" method="post">
                <input name="username" type="text">
                <input name="password" type="password">
                <button type="submit">Go</button>
            </form>
        "#;
        let (_, forms) = extract_links_and_forms(&base(), body);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].action, "https://example.com/login");
        assert_eq!(forms[0].method, "POST");
        assert_eq!(forms[0].fields, vec!["username".to_string(), "password".to_string()]);
    }

    #[test]
    fn form_without_method_defaults_to_get() {
        let body = r#"<form action="/search"><input name="q"></form>"#;
        let (_, forms) = extract_links_and_forms(&base(), body);
        assert_eq!(forms[0].method, "GET");
    }

    #[test]
    fn form_without_action_defaults_to_page_url() {
        let body = r#"<form method="post"><input name="q"></form>"#;
        let (_, forms) = extract_links_and_forms(&base(), body);
        assert_eq!(forms[0].action, base().to_string());
    }

    #[test]
    fn multiple_forms_on_one_page() {
        let body = r#"
            <form action="/a"><input name="x"></form>
            <form action="/b" method="post"><input name="y"></form>
        "#;
        let (_, forms) = extract_links_and_forms(&base(), body);
        assert_eq!(forms.len(), 2);
        assert_eq!(forms[0].action, "https://example.com/a");
        assert_eq!(forms[1].action, "https://example.com/b");
    }

    #[test]
    fn extracts_sitemap_loc_tags() {
        let body = r#"
            <?xml version="1.0" encoding="UTF-8"?>
            <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url>
                    <loc>https://example.com/page1.html</loc>
                    <lastmod>2023-01-01</lastmod>
                </url>
                <url>
                    <loc>  http://example.com/page2  </loc>
                </url>
                <sitemap>
                    <loc>https://example.com/sitemap_index2.xml</loc>
                </sitemap>
            </urlset>
        "#;
        let urls = extract_sitemap_urls(body);
        assert_eq!(urls.len(), 3);
        assert_eq!(urls[0], "https://example.com/page1.html");
        assert_eq!(urls[1], "http://example.com/page2");
        assert_eq!(urls[2], "https://example.com/sitemap_index2.xml");
    }
}
