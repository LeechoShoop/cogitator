//! CVE lookup for Cogitator.
//!
//! Takes the free-text technology hints produced by
//! `web_analyzer::probe_passive_fingerprint` (e.g. `"WordPress"`,
//! `"Server: nginx/1.18.0"`, `"Laravel (PHP)"`) and queries the public,
//! key-free circl.lu CVE-Search mirror for known vulnerabilities:
//!
//!   https://cve.circl.lu/api/search/{vendor}/{product}
//!
//! circl.lu only understands CPE-style `(vendor, product)` pairs, not the
//! human-readable strings Cogitator's fingerprinter emits, so the bulk of
//! this module is `tech_to_vendor_product` — a best-effort mapping from
//! hint string to `(vendor, product)`, plus a fallback parser for the
//! `"Server: <name>/<version>"` shape produced from the `Server` response
//! header. Hints that don't map to anything are silently skipped — that's
//! expected and not an error, since most fingerprint hints (stack traces,
//! disallow-path counts, etc.) aren't CVE-lookupable technologies at all.

use crate::logger;
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;
use std::time::Duration;

/// Max number of CVE entries kept per technology, after dedup. circl.lu can
/// return hundreds of historical CVEs for a popular product (e.g. WordPress
/// core); nobody reads past the first page in a terminal report.
const MAX_PER_TECH: usize = 10;

/// Request timeout for a single circl.lu lookup. Generous, since circl.lu's
/// free mirror can be slow under load — a single technology timing out
/// shouldn't be allowed to take down the whole analysis, but it also
/// shouldn't fail prematurely.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

// ─── Result type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct CveMatch {
    pub cve_id: String,
    pub description: String,
    pub cvss: f32,
    pub url: String,
}

// ─── Public entry point ──────────────────────────────────────────────────────

/// Query circl.lu for every technology in `technologies` that maps to a
/// known `(vendor, product)` pair, dedupe the combined results by CVE id,
/// and return them. Technologies with no known mapping, and individual
/// lookups that fail (timeout, non-2xx, malformed JSON), are skipped
/// rather than treated as fatal — partial CVE intel is still useful intel.
pub async fn lookup_cves(technologies: &[String]) -> Vec<CveMatch> {
    let client = match Client::builder().timeout(REQUEST_TIMEOUT).build() {
        Ok(c) => c,
        Err(e) => {
            logger::warn(&format!("cve: failed to build HTTP client: {e}"));
            return Vec::new();
        }
    };

    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut all_matches: Vec<CveMatch> = Vec::new();

    for tech in technologies {
        let Some((vendor, product)) = tech_to_vendor_product(tech) else {
            continue;
        };

        let matches = lookup_one(&client, &vendor, &product).await;
        for m in matches {
            if seen_ids.insert(m.cve_id.clone()) {
                all_matches.push(m);
            }
        }
    }

    all_matches
}

/// Query circl.lu for a single `(vendor, product)` pair and return up to
/// `MAX_PER_TECH` parsed matches. Network/parse failures yield an empty
/// `Vec` so the caller can simply move on to the next technology.
async fn lookup_one(client: &Client, vendor: &str, product: &str) -> Vec<CveMatch> {
    let url = format!(
        "https://cve.circl.lu/api/search/{}/{}",
        urlencode_segment(vendor),
        urlencode_segment(product)
    );

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            logger::debug(&format!("cve: request failed for {vendor}/{product}: {e}"));
            return Vec::new();
        }
    };

    if !resp.status().is_success() {
        logger::debug(&format!(
            "cve: non-success status {} for {vendor}/{product}",
            resp.status()
        ));
        return Vec::new();
    }

    let body: Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            logger::debug(&format!("cve: failed to parse JSON for {vendor}/{product}: {e}"));
            return Vec::new();
        }
    };

    parse_circl_response(&body)
}

// ─── Response parsing ────────────────────────────────────────────────────────

/// Parse a circl.lu `/api/search/{vendor}/{product}` response body into
/// `CveMatch`es, capped at `MAX_PER_TECH`. Pulled out as a pure function
/// (no I/O) so it's directly testable against fixed JSON fixtures.
///
/// circl.lu's response shape has drifted across mirror versions, so this
/// is deliberately defensive:
///   * root may be a bare JSON array, or an object with a `"data"` or
///     `"results"` array
///   * the id field may be `"id"` or `"cveID"` or `"cve_id"`
///   * the summary may be `"summary"` (string) or `"description"`, and
///     `"description"` itself may be a plain string or a CVE5-style array
///     of `{"lang": "en", "value": "..."}` objects
///   * `"cvss"` may be missing or a string instead of a number
fn parse_circl_response(body: &Value) -> Vec<CveMatch> {
    let entries: &[Value] = if let Some(arr) = body.as_array() {
        arr.as_slice()
    } else if let Some(arr) = body.get("data").and_then(|v| v.as_array()) {
        arr.as_slice()
    } else if let Some(arr) = body.get("results").and_then(|v| v.as_array()) {
        arr.as_slice()
    } else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for entry in entries.iter().take(MAX_PER_TECH) {
        let Some(cve_id) = extract_id(entry) else {
            continue;
        };
        let description = extract_description(entry).unwrap_or_else(|| "No description available".to_string());
        let cvss = extract_cvss(entry).unwrap_or(0.0);
        let url = extract_url(entry).unwrap_or_else(|| {
            format!("https://nvd.nist.gov/vuln/detail/{}", cve_id)
        });

        out.push(CveMatch {
            cve_id,
            description,
            cvss,
            url,
        });
    }
    out
}

fn extract_id(entry: &Value) -> Option<String> {
    for key in ["id", "cveID", "cve_id", "cveMetadata"] {
        if let Some(v) = entry.get(key) {
            // cveMetadata is itself an object with an "cveId" field in the
            // CVE5 schema -- handle that one level deeper.
            if key == "cveMetadata" {
                if let Some(id) = v.get("cveId").and_then(|x| x.as_str()) {
                    return Some(id.to_string());
                }
                continue;
            }
            if let Some(s) = v.as_str() {
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

fn extract_description(entry: &Value) -> Option<String> {
    if let Some(s) = entry.get("summary").and_then(|v| v.as_str()) {
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    match entry.get("description") {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(Value::Array(items)) => items
            .iter()
            .find_map(|item| item.get("value").and_then(|v| v.as_str()))
            .map(|s| s.to_string()),
        _ => None,
    }
}

fn extract_cvss(entry: &Value) -> Option<f32> {
    match entry.get("cvss") {
        Some(Value::Number(n)) => n.as_f64().map(|f| f as f32),
        Some(Value::String(s)) => s.parse::<f32>().ok(),
        _ => None,
    }
}

fn extract_url(entry: &Value) -> Option<String> {
    entry
        .get("references")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

// ─── Technology name -> (vendor, product) mapping ────────────────────────────

/// Map a free-text technology hint (as emitted by
/// `probe_passive_fingerprint`) to a `(vendor, product)` CPE-style pair
/// circl.lu can search on. Matching is case-insensitive substring matching
/// against a small static table, checked in order -- first match wins.
///
/// Returns `None` for hints with no sensible CVE-searchable mapping (e.g.
/// `"Blog platform"`, generic framework-hint noise) rather than guessing.
fn tech_to_vendor_product(tech: &str) -> Option<(String, String)> {
    // "Server: nginx/1.18.0" / "Server: Apache/2.4.41" -- pull the product
    // name out of the banner and map *that* instead of the literal string.
    if let Some(banner) = tech.strip_prefix("Server: ") {
        let product_name = banner.split('/').next().unwrap_or(banner).trim();
        return tech_to_vendor_product(product_name).or_else(|| {
            // Unknown server banner -- still worth a guess: most web server
            // CPEs use the lowercased product name as both vendor and
            // product placeholder is wrong for circl.lu, so without a
            // known mapping we give up rather than send a nonsense query.
            None
        });
    }

    const KNOWN: &[(&str, &str, &str)] = &[
        // (substring to match, vendor, product)
        ("wordpress", "wordpress", "wordpress"),
        ("joomla", "joomla", "joomla"),
        ("drupal", "drupal", "drupal"),
        ("magento", "magento", "magento"),
        ("shopify", "shopify", "shopify"),
        ("django", "djangoproject", "django"),
        ("laravel", "laravel", "laravel"),
        ("express.js", "expressjs", "express"),
        ("express", "expressjs", "express"),
        ("asp.net", "microsoft", "asp.net"),
        ("nginx", "nginx", "nginx"),
        ("apache", "apache", "http_server"),
        ("iis", "microsoft", "iis"),
        ("tomcat", "apache", "tomcat"),
        ("rails", "rubyonrails", "rails"),
        ("flask", "palletsprojects", "flask"),
        ("php", "php", "php"),
    ];

    let lower = tech.to_lowercase();
    KNOWN
        .iter()
        .find(|(needle, _, _)| lower.contains(needle))
        .map(|(_, vendor, product)| (vendor.to_string(), product.to_string()))
}

/// Minimal path-segment percent-encoding -- vendor/product names from the
/// static table above are already URL-safe ASCII, but this guards against
/// anything unexpected slipping through (e.g. a future table entry with a
/// space or '+' in it) without pulling in a dedicated encoding crate just
/// for two path segments.
fn urlencode_segment(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_known_technology_names() {
        assert_eq!(
            tech_to_vendor_product("WordPress"),
            Some(("wordpress".to_string(), "wordpress".to_string()))
        );
        assert_eq!(
            tech_to_vendor_product("Laravel (PHP)"),
            Some(("laravel".to_string(), "laravel".to_string()))
        );
        assert_eq!(
            tech_to_vendor_product("Express.js (Node)"),
            Some(("expressjs".to_string(), "express".to_string()))
        );
    }

    #[test]
    fn maps_server_banner_by_product_name() {
        assert_eq!(
            tech_to_vendor_product("Server: nginx/1.18.0"),
            Some(("nginx".to_string(), "nginx".to_string()))
        );
        assert_eq!(
            tech_to_vendor_product("Server: Apache/2.4.41 (Ubuntu)"),
            Some(("apache".to_string(), "http_server".to_string()))
        );
    }

    #[test]
    fn unknown_technology_returns_none() {
        assert_eq!(tech_to_vendor_product("Blog platform"), None);
        assert_eq!(tech_to_vendor_product("Server: WeirdCustomServer/9.9"), None);
    }

    #[test]
    fn parse_bare_array_response() {
        let body = json!([
            {
                "id": "CVE-2021-1234",
                "summary": "A bad bug in the thing.",
                "cvss": 7.5,
                "references": ["https://example.com/advisory"]
            },
            {
                "id": "CVE-2021-5678",
                "summary": "Another bug.",
                "cvss": 9.8,
                "references": []
            }
        ]);
        let matches = parse_circl_response(&body);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].cve_id, "CVE-2021-1234");
        assert_eq!(matches[0].cvss, 7.5);
        assert_eq!(matches[0].url, "https://example.com/advisory");
        // No references -- falls back to NVD URL.
        assert!(matches[1].url.contains("CVE-2021-5678"));
    }

    #[test]
    fn parse_wrapped_in_data_field() {
        let body = json!({
            "data": [
                { "id": "CVE-2020-0001", "summary": "Wrapped entry.", "cvss": 5.0 }
            ]
        });
        let matches = parse_circl_response(&body);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].cve_id, "CVE-2020-0001");
    }

    #[test]
    fn parse_wrapped_in_results_field() {
        let body = json!({
            "results": [
                { "id": "CVE-2020-0002", "summary": "Also wrapped.", "cvss": 3.1 }
            ]
        });
        let matches = parse_circl_response(&body);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].cve_id, "CVE-2020-0002");
    }

    #[test]
    fn parse_cve5_style_description_array() {
        let body = json!([
            {
                "cveMetadata": { "cveId": "CVE-2022-9999" },
                "description": [
                    { "lang": "en", "value": "English summary text." },
                    { "lang": "fr", "value": "Texte francais." }
                ],
                "cvss": "6.5"
            }
        ]);
        let matches = parse_circl_response(&body);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].cve_id, "CVE-2022-9999");
        assert_eq!(matches[0].description, "English summary text.");
        assert_eq!(matches[0].cvss, 6.5);
    }

    #[test]
    fn entries_missing_id_are_skipped() {
        let body = json!([
            { "summary": "No id here.", "cvss": 1.0 },
            { "id": "CVE-2023-0001", "summary": "Has an id.", "cvss": 2.0 }
        ]);
        let matches = parse_circl_response(&body);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].cve_id, "CVE-2023-0001");
    }

    #[test]
    fn caps_at_max_per_tech() {
        let entries: Vec<Value> = (0..25)
            .map(|i| json!({ "id": format!("CVE-2024-{:04}", i), "summary": "x", "cvss": 1.0 }))
            .collect();
        let body = Value::Array(entries);
        let matches = parse_circl_response(&body);
        assert_eq!(matches.len(), MAX_PER_TECH);
    }

    #[test]
    fn malformed_root_returns_empty() {
        let body = json!({ "unexpected": "shape" });
        assert!(parse_circl_response(&body).is_empty());
    }

    #[test]
    fn missing_cvss_defaults_to_zero() {
        let body = json!([{ "id": "CVE-2024-0001", "summary": "x" }]);
        let matches = parse_circl_response(&body);
        assert_eq!(matches[0].cvss, 0.0);
    }

    #[test]
    fn urlencode_leaves_safe_chars_alone() {
        assert_eq!(urlencode_segment("http_server"), "http_server");
        assert_eq!(urlencode_segment("asp.net"), "asp.net");
    }

    #[test]
    fn urlencode_escapes_unsafe_chars() {
        assert_eq!(urlencode_segment("a b"), "a%20b");
    }
}