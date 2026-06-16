use hickory_client::client::{Client, SyncClient};
use hickory_client::rr::{DNSClass, Name, RecordType, RData};
use hickory_client::udp::UdpClientConnection;
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

// ─── Email security surface ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct EmailSecurityRecords {
    pub spf: Option<String>,
    pub dmarc: Option<String>,
    pub dkim_selector_found: bool, // probes common selectors
    pub summary: String,
}

/// Query SPF, DMARC and probe common DKIM selectors for `domain`.
pub fn audit_email_security(domain: &str) -> EmailSecurityRecords {
    let spf = query_txt(domain)
        .into_iter()
        .find(|r| r.starts_with("v=spf1"));

    let dmarc_name = format!("_dmarc.{}", domain);
    let dmarc = query_txt(&dmarc_name)
        .into_iter()
        .find(|r| r.starts_with("v=DMARC1"));

    // Common DKIM selectors used by major ESPs / mail servers
    let common_selectors = ["default", "google", "k1", "mail", "selector1", "selector2", "dkim", "smtp"];
    let dkim_selector_found = common_selectors.iter().any(|sel| {
        let dkim_name = format!("{}._domainkey.{}", sel, domain);
        !query_txt(&dkim_name).is_empty()
    });

    let summary = build_email_summary(spf.as_deref(), dmarc.as_deref(), dkim_selector_found);

    EmailSecurityRecords { spf, dmarc, dkim_selector_found, summary }
}

fn build_email_summary(spf: Option<&str>, dmarc: Option<&str>, dkim: bool) -> String {
    let mut issues = Vec::new();
    if spf.is_none()  { issues.push("No SPF record (email spoofing risk)"); }
    if dmarc.is_none() { issues.push("No DMARC policy (unprotected domain)"); }
    if !dkim { issues.push("No common DKIM selectors found"); }

    if issues.is_empty() {
        "✅ SPF + DMARC + DKIM all present".to_string()
    } else {
        format!("⚠️  {}", issues.join(" | "))
    }
}

// ─── Subdomain takeover surface ──────────────────────────────────────────────

/// One link in a CNAME chain, e.g. `sub.example.com → target.azurewebsites.net`.
#[derive(Debug, Serialize)]
pub struct CnameHop {
    pub from: String,
    pub to: String,
}

/// Result of scanning a single (sub)domain for takeover risk.
#[derive(Debug, Serialize)]
pub struct TakeoverCandidate {
    /// The domain that was queried.
    pub domain: String,
    /// Full CNAME chain up to the final target (or resolution failure).
    pub cname_chain: Vec<CnameHop>,
    /// Final CNAME target, if any.
    pub final_target: Option<String>,
    /// Which known-vulnerable cloud pattern matched, if any.
    pub matched_pattern: Option<String>,
    /// True when the chain ends at an unresolvable name (dangling CNAME).
    pub dangling: bool,
    /// Human-readable risk verdict.
    pub risk: String,
}

/// Aggregate result for an entire domain scan.
#[derive(Debug, Serialize)]
pub struct SubdomainTakeoverAudit {
    pub candidates: Vec<TakeoverCandidate>,
    pub vulnerable_count: usize,
    pub summary: String,
}

// Patterns whose presence in a CNAME target is a meaningful takeover signal.
// Each entry is (pattern_substring, service_name).
const TAKEOVER_PATTERNS: &[(&str, &str)] = &[
    // Azure
    ("azurewebsites.net",      "Azure App Service"),
    ("cloudapp.net",           "Azure Cloud App"),
    ("cloudapp.azure.com",     "Azure Cloud App"),
    ("trafficmanager.net",     "Azure Traffic Manager"),
    ("blob.core.windows.net",  "Azure Blob Storage"),
    ("azure-api.net",          "Azure API Management"),
    // AWS
    ("s3.amazonaws.com",       "AWS S3"),
    ("s3-website",             "AWS S3 Website"),
    ("elasticbeanstalk.com",   "AWS Elastic Beanstalk"),
    ("awsglobalaccelerator.com","AWS Global Accelerator"),
    // GitHub
    ("github.io",              "GitHub Pages"),
    // Heroku
    ("herokudns.com",          "Heroku"),
    ("herokuapp.com",          "Heroku"),
    // Netlify
    ("netlify.app",            "Netlify"),
    ("netlify.com",            "Netlify"),
    // Vercel / Zeit
    ("vercel.app",             "Vercel"),
    ("now.sh",                 "Vercel (legacy)"),
    // Fastly
    ("fastly.net",             "Fastly CDN"),
    // Shopify
    ("myshopify.com",          "Shopify"),
    // Pantheon
    ("pantheonsite.io",        "Pantheon"),
    // Ghost
    ("ghost.io",               "Ghost"),
    // Readme.io
    ("readme.io",              "Readme.io"),
    // Surge
    ("surge.sh",               "Surge.sh"),
    // Zendesk
    ("zendesk.com",            "Zendesk"),
    // Help Scout
    ("helpscoutdocs.com",      "Help Scout Docs"),
    // Cargo
    ("cargocollective.com",    "Cargo Collective"),
    // Tumblr
    ("tumblr.com",             "Tumblr"),
];

/// Walk the CNAME chain for `domain`, following at most `max_hops` links.
///
/// Returns every hop seen so far even if resolution eventually fails, so the
/// caller can detect dangling chains (CNAME exists but final target has no A).
fn walk_cname_chain(domain: &str, max_hops: usize) -> Vec<CnameHop> {
    let mut chain = Vec::new();
    let mut current = domain.to_string();
    let mut visited = std::collections::HashSet::new();

    for _ in 0..max_hops {
        if !visited.insert(current.clone()) {
            // CNAME loop — stop.
            break;
        }

        let targets = query_cname(&current);
        match targets.into_iter().next() {
            Some(next) => {
                chain.push(CnameHop { from: current.clone(), to: next.clone() });
                current = next;
            }
            None => break,
        }
    }

    chain
}

/// Returns true when `name` cannot be resolved to any A / AAAA record.
/// This identifies dangling CNAMEs — the most exploitable scenario.
fn is_unresolvable(name: &str) -> bool {
    query_a(name).is_empty() && query_aaaa(name).is_empty()
}

/// Probe a single domain for subdomain takeover risk.
pub fn probe_takeover(domain: &str) -> TakeoverCandidate {
    let chain = walk_cname_chain(domain, 10);

    let final_target = chain.last().map(|hop| hop.to.clone());

    // Check every node in the chain, not just the tail — a mid-chain cloud
    // service is equally exploitable.
    let matched_pattern = chain.iter()
        .filter_map(|hop| {
            let target_lower = hop.to.to_lowercase();
            TAKEOVER_PATTERNS.iter()
                .find(|(pat, _)| target_lower.contains(pat))
                .map(|(_, service)| service.to_string())
        })
        .next();

    // Dangling: chain is non-empty (CNAME exists) but final target doesn't resolve.
    let dangling = !chain.is_empty()
        && final_target.as_deref().map(is_unresolvable).unwrap_or(false);

    let risk = build_takeover_risk(&matched_pattern, dangling, chain.is_empty());

    TakeoverCandidate {
        domain: domain.to_string(),
        cname_chain: chain,
        final_target,
        matched_pattern,
        dangling,
        risk,
    }
}

/// Audit an entire domain by probing the apex and a set of common subdomains.
pub fn audit_subdomain_takeover(domain: &str) -> SubdomainTakeoverAudit {
    // Start with the apex + a hardcoded list of high-value subdomains.
    // Callers may extend this list; keeping it small avoids hammering DNS.
    let probes: Vec<String> = {
        let prefixes = [
            "", "www", "mail", "blog", "shop", "api", "dev", "staging",
            "beta", "app", "status", "support", "help", "docs", "cdn",
            "static", "assets", "media", "img", "images", "portal",
        ];
        prefixes.iter().map(|p| {
            if p.is_empty() { domain.to_string() }
            else { format!("{}.{}", p, domain) }
        }).collect()
    };

    let candidates: Vec<TakeoverCandidate> = probes.iter()
        .map(|d| probe_takeover(d))
        // Only keep results that have something interesting.
        .filter(|c| !c.cname_chain.is_empty() || c.dangling)
        .collect();

    let vulnerable_count = candidates.iter()
        .filter(|c| c.matched_pattern.is_some() || c.dangling)
        .count();

    let summary = if vulnerable_count == 0 {
        if candidates.is_empty() {
            "✅ No CNAME records found — no takeover surface detected".to_string()
        } else {
            format!("✅ {} CNAME chain(s) found, no known-vulnerable patterns matched", candidates.len())
        }
    } else {
        format!(
            "🚨 {} potential takeover target(s) detected across {} CNAME chain(s)",
            vulnerable_count, candidates.len()
        )
    };

    SubdomainTakeoverAudit { candidates, vulnerable_count, summary }
}

fn build_takeover_risk(
    matched: &Option<String>,
    dangling: bool,
    no_chain: bool,
) -> String {
    if no_chain {
        return "ℹ️  No CNAME — direct A record or no DNS entry".to_string();
    }
    match (matched, dangling) {
        (Some(svc), true)  =>
            format!("🚨 HIGH — dangling CNAME to unclaimed {} resource; takeover likely possible", svc),
        (Some(svc), false) =>
            format!("🟡 MEDIUM — CNAME points to {} (verify resource is claimed)", svc),
        (None, true)       =>
            "🟠 LOW-MEDIUM — dangling CNAME (target unresolvable, no known pattern matched)".to_string(),
        (None, false)      =>
            "✅ CNAME present and resolves; no known-vulnerable pattern matched".to_string(),
    }
}

/// Query TXT records for a given name and return all string values.
fn query_txt(name: &str) -> Vec<String> {
    let name_server: SocketAddr = "8.8.8.8:53".parse().expect("Invalid nameserver");
    let conn = match UdpClientConnection::new(name_server) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let client = SyncClient::new(conn);

    let query_name = match Name::from_str(name) {
        Ok(n) => n,
        Err(_) => return Vec::new(),
    };

    match client.query(&query_name, DNSClass::IN, RecordType::TXT) {
        Ok(response) => response
            .answers()
            .iter()
            .filter_map(|ans| {
                if let Some(RData::TXT(txt)) = ans.data() {
                    let s = txt.txt_data()
                        .iter()
                        .flat_map(|bytes| std::str::from_utf8(bytes).ok())
                        .collect::<String>();
                    Some(s)
                } else {
                    None
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Query CNAME records and return the canonical target names.
fn query_cname(name: &str) -> Vec<String> {
    let name_server: SocketAddr = "8.8.8.8:53".parse().expect("Invalid nameserver");
    let conn = match UdpClientConnection::new(name_server) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let client = SyncClient::new(conn);

    let query_name = match Name::from_str(name) {
        Ok(n) => n,
        Err(_) => return Vec::new(),
    };

    match client.query(&query_name, DNSClass::IN, RecordType::CNAME) {
        Ok(response) => response
            .answers()
            .iter()
            .filter_map(|ans| {
                if let Some(RData::CNAME(cname)) = ans.data() {
                    Some(cname.0.to_utf8())
                } else {
                    None
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Query A records; returns raw IPv4 address strings.
fn query_a(name: &str) -> Vec<String> {
    let name_server: SocketAddr = "8.8.8.8:53".parse().expect("Invalid nameserver");
    let conn = match UdpClientConnection::new(name_server) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let client = SyncClient::new(conn);

    let query_name = match Name::from_str(name) {
        Ok(n) => n,
        Err(_) => return Vec::new(),
    };

    match client.query(&query_name, DNSClass::IN, RecordType::A) {
        Ok(response) => response
            .answers()
            .iter()
            .filter_map(|ans| {
                if let Some(RData::A(addr)) = ans.data() {
                    Some(addr.0.to_string())
                } else {
                    None
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Query AAAA records; returns raw IPv6 address strings.
fn query_aaaa(name: &str) -> Vec<String> {
    let name_server: SocketAddr = "8.8.8.8:53".parse().expect("Invalid nameserver");
    let conn = match UdpClientConnection::new(name_server) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let client = SyncClient::new(conn);

    let query_name = match Name::from_str(name) {
        Ok(n) => n,
        Err(_) => return Vec::new(),
    };

    match client.query(&query_name, DNSClass::IN, RecordType::AAAA) {
        Ok(response) => response
            .answers()
            .iter()
            .filter_map(|ans| {
                if let Some(RData::AAAA(addr)) = ans.data() {
                    Some(addr.0.to_string())
                } else {
                    None
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

// ─── Reverse PTR (unchanged from original) ──────────────────────────────────

pub fn resolve_ip(ip: IpAddr) -> String {
    let name_server = "8.8.8.8:53".parse::<SocketAddr>().expect("Invalid nameserver");
    let conn = match UdpClientConnection::new(name_server) {
        Ok(c) => c,
        Err(_) => return ip.to_string(),
    };
    let client = SyncClient::new(conn);

    let ptr_query = match reverse_ip(ip) {
        Some(reversed) => reversed,
        None => return ip.to_string(),
    };

    let ptr_name = match Name::from_str(&ptr_query) {
        Ok(n) => n,
        Err(_) => return ip.to_string(),
    };

    match client.query(&ptr_name, DNSClass::IN, RecordType::PTR) {
        Ok(answers) => {
            if let Some(answer) = answers.answers().first() {
                if let Some(rdata) = answer.data() {
                    if let RData::PTR(ptr_data) = rdata {
                        return ptr_data.0.to_utf8();
                    }
                }
            }
            ip.to_string()
        }
        Err(_) => ip.to_string(),
    }
}

fn reverse_ip(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(ipv4) => {
            let reversed = ipv4.octets()
                .iter()
                .rev()
                .map(|o| o.to_string())
                .collect::<Vec<_>>()
                .join(".");
            Some(format!("{}.in-addr.arpa.", reversed))
        }
        IpAddr::V6(ipv6) => {
            let nibbles: String = ipv6.octets()
                .iter()
                .flat_map(|b| vec![b & 0x0f, b >> 4])
                .map(|n| format!("{:x}", n))
                .collect::<Vec<_>>()
                .join(".");
            Some(format!("{}.ip6.arpa.", nibbles))
        }
    }
}