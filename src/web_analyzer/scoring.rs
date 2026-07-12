use crate::scrap_analyze::CspStrength;
use crate::crypto_forensic::CryptoAuditResult;
use crate::dns_guard::EmailSecurityRecords;
use super::cors::CorsAudit;
use super::http_methods::HttpMethodAudit;

/// Aggregate security posture score (0-100).
pub fn compute_overall_score(
    has_hsts: bool,
    has_csp: bool,
    has_x_frame: bool,
    has_x_content: bool,
    has_permissions: bool,
    cors: Option<&CorsAudit>,
    csp_strength: Option<&CspStrength>,
    crypto: Option<&CryptoAuditResult>,
    email: Option<&EmailSecurityRecords>,
    http_methods: Option<&HttpMethodAudit>,
) -> (u8, String) {
    let mut score: i32 = 100;

    if !has_hsts       { score -= 15; }
    if !has_csp        { score -= 15; }
    if !has_x_frame    { score -= 10; }
    if !has_x_content  { score -= 5; }
    if !has_permissions { score -= 5; }

    if let Some(cors) = cors {
        if cors.credentials_with_wildcard { score -= 25; }
        else if cors.reflects_origin && cors.acac_header.as_deref() == Some("true") { score -= 15; }
        else if cors.reflects_origin      { score -= 8; }
    }

    if let Some(csp) = csp_strength {
        if csp.has_unsafe_inline  { score -= 10; }
        if csp.has_unsafe_eval    { score -= 8; }
        if csp.has_wildcard_source { score -= 8; }
    }

    if let Some(c) = crypto {
        let issues = c.insecure_cookie_flags.len() as i32;
        score -= issues * 3;
        if !c.hsts_preload { score -= 2; }
    }

    if let Some(e) = email {
        if e.spf.is_none()   { score -= 5; }
        if e.dmarc.is_none() { score -= 5; }
    }

    if let Some(m) = http_methods {
        if m.dangerous_methods.contains(&"TRACE".to_string())  { score -= 20; }
        if m.dangerous_methods.contains(&"PUT".to_string())
            || m.dangerous_methods.contains(&"DELETE".to_string()) { score -= 15; }
        else if !m.dangerous_methods.is_empty()                 { score -= 8; }
    }

    let score = score.clamp(0, 100) as u8;
    let grade = match score {
        90..=100 => "A",
        75..=89  => "B",
        60..=74  => "C",
        45..=59  => "D",
        _        => "F",
    }.to_string();

    (score, grade)
}
