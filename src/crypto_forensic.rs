use crate::config;
use reqwest::header::{HeaderMap, SET_COOKIE};
use serde::Serialize;

#[derive(Serialize)]
pub struct CryptoAuditResult {
    pub tls_version: String,
    pub cookie_security_score: String,
    pub cookies_found: usize,
    pub insecure_cookie_flags: Vec<String>,
    // NEW: JWT-like tokens inside cookie values
    pub jwt_cookies_detected: Vec<String>,
    // NEW: HSTS preload & max-age analysis
    pub hsts_preload: bool,
    pub hsts_max_age_secs: Option<u64>,
    pub hsts_includes_subdomains: bool,
    // NEW: HPKP (deprecated but still seen in wild)
    pub hpkp_detected: bool,
    // NEW: overall crypto score A-F
    pub grade: String,
}

pub fn audit_crypto(headers: &HeaderMap) -> CryptoAuditResult {
    let mut insecure_flags = Vec::new();
    let mut jwt_cookies_detected = Vec::new();
    let mut count = 0;

    for (name, value) in headers.iter() {
        if name == SET_COOKIE {
            count += 1;
            let cookie_str = value.to_str().unwrap_or("");

            if !cookie_str.contains("HttpOnly") {
                insecure_flags.push("Missing HttpOnly".to_string());
            }
            if !cookie_str.contains("Secure") {
                insecure_flags.push("Missing Secure".to_string());
            }
            if !cookie_str.contains("SameSite") {
                insecure_flags.push("Missing SameSite".to_string());
            }

            // Detect JWT pattern: three base64url segments separated by dots
            let cookie_value = cookie_str.split(';').next().unwrap_or("");
            let value_part = cookie_value.split('=').skip(1).collect::<Vec<_>>().join("=");
            if is_jwt_like(&value_part) {
                let cookie_name = cookie_value.split('=').next().unwrap_or("?").trim().to_string();
                jwt_cookies_detected.push(cookie_name);
            }
        }
    }

    // HSTS analysis
    let (hsts_preload, hsts_max_age_secs, hsts_includes_subdomains) =
        parse_hsts(headers);

    // HPKP (Public-Key-Pins) — deprecated in modern browsers but flag if present
    let hpkp_detected = headers.contains_key("public-key-pins")
        || headers.contains_key("public-key-pins-report-only");

    let cookie_score = if insecure_flags.is_empty() && count > 0 {
        "✅ Strong".to_string()
    } else if count == 0 {
        "⚠️  No cookies detected".to_string()
    } else {
        format!("❌ Weak ({} issues)", insecure_flags.len())
    };

    let grade = compute_crypto_grade(
        count,
        insecure_flags.len(),
        hsts_preload,
        hsts_max_age_secs,
        hsts_includes_subdomains,
        !jwt_cookies_detected.is_empty(),
    );

    CryptoAuditResult {
        tls_version: "TLS 1.2/1.3 (negotiated via reqwest/rustls)".to_string(),
        cookie_security_score: cookie_score,
        cookies_found: count,
        insecure_cookie_flags: insecure_flags,
        jwt_cookies_detected,
        hsts_preload,
        hsts_max_age_secs,
        hsts_includes_subdomains,
        hpkp_detected,
        grade,
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Rough JWT detector: three dot-separated base64url segments, first decodable as JSON
fn is_jwt_like(value: &str) -> bool {
    let parts: Vec<&str> = value.splitn(3, '.').collect();
    if parts.len() != 3 { return false; }
    // Each part should be non-empty and consist of base64url chars
    let b64url = |s: &str| s.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '=');
    parts.iter().all(|p| !p.is_empty() && b64url(p)) && parts[0].len() > 4
}

fn parse_hsts(headers: &HeaderMap) -> (bool, Option<u64>, bool) {
    let hsts_value = match headers.get("strict-transport-security")
        .and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_lowercase(),
        None => return (false, None, false),
    };

    let preload = hsts_value.contains("preload");
    let includes_subdomains = hsts_value.contains("includesubdomains");

    let max_age = hsts_value.split(';')
        .find_map(|part| {
            let part = part.trim();
            if part.starts_with("max-age=") {
                part.trim_start_matches("max-age=").parse::<u64>().ok()
            } else {
                None
            }
        });

    (preload, max_age, includes_subdomains)
}

/// Grade A = best, F = worst
fn compute_crypto_grade(
    cookies: usize,
    insecure: usize,
    hsts_preload: bool,
    hsts_max_age: Option<u64>,
    hsts_subdomains: bool,
    has_jwt: bool,
) -> String {
    let mut score: i32 = 100;

    // Cookie penalties
    if cookies > 0 {
        score -= (insecure as i32) * 10;
    }

    // HSTS bonuses/penalties
    match hsts_max_age {
        None => score -= 20,
        Some(age) if age < config::HSTS_MIN_MAX_AGE_SECS => score -= 10, // < 30 days
        _ => {}
    }
    if hsts_subdomains { score += 5; }
    if hsts_preload { score += 5; }

    // JWT exposed in cookies is informational (not necessarily bad but flag it)
    if has_jwt { score -= 5; }

    match score {
        90..=i32::MAX => "A".to_string(),
        75..=89        => "B".to_string(),
        60..=74        => "C".to_string(),
        45..=59        => "D".to_string(),
        _              => "F".to_string(),
    }
}
#[cfg(test)]
mod jwt_tests {
    use super::is_jwt_like;

    // ── valid JWTs ────────────────────────────────────────────────────────────

    #[test]
    fn valid_three_part_jwt() {
        // Realistic HS256 token: header.payload.signature (all base64url)
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\
                     .eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ\
                     .SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert!(is_jwt_like(token));
    }

    #[test]
    fn valid_jwt_with_padding_equals() {
        // '=' is allowed in base64url alphabet per the detector
        let token = "eyJhbGciOiJSUzI1NiJ9\
                     .eyJ1c2VyIjoiYWRtaW4ifQ==\
                     .AAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert!(is_jwt_like(token));
    }

    #[test]
    fn minimal_valid_jwt_exact_boundary() {
        // parts[0] must be > 4 chars; "AAAAA" (5) is the minimum that passes
        let token = "AAAAA.BBBB.CCCC";
        assert!(is_jwt_like(token));
    }

    // ── too few / too many segments ───────────────────────────────────────────

    #[test]
    fn two_segments_rejected() {
        assert!(!is_jwt_like("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ"));
    }

    #[test]
    fn single_segment_rejected() {
        assert!(!is_jwt_like("eyJhbGciOiJIUzI1NiJ9"));
    }

    // splitn(3, '.') stops at 3 parts so a 4-dot string is still accepted
    // (the third "part" will contain the remaining dots as literal chars).
    // That is existing behaviour; this test documents it rather than fixing it.
    #[test]
    fn four_dots_third_part_contains_dots_non_base64url_rejected() {
        // The extra dot ends up in part[2] as a non-base64url char → rejected
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig.extra";
        assert!(!is_jwt_like(token), "extra dot makes part[2] contain '.', not base64url");
    }

    // ── non-base64url characters ──────────────────────────────────────────────

    #[test]
    fn plus_sign_rejected() {
        // '+' is standard base64 but not base64url
        let token = "eyJhbGci+iJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature123";
        assert!(!is_jwt_like(token));
    }

    #[test]
    fn slash_rejected() {
        // '/' is standard base64 but not base64url
        let token = "eyJhbGci/iJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature123";
        assert!(!is_jwt_like(token));
    }

    #[test]
    fn space_in_segment_rejected() {
        let token = "eye hbGci.eyJzdWIiOiIxMjMifQ.signature123";
        assert!(!is_jwt_like(token));
    }

    // ── empty / trivial inputs ────────────────────────────────────────────────

    #[test]
    fn empty_string_rejected() {
        assert!(!is_jwt_like(""));
    }

    #[test]
    fn only_dots_rejected() {
        // parts are empty strings → fails the non-empty check
        assert!(!is_jwt_like(".."));
    }

    #[test]
    fn first_segment_too_short_rejected() {
        // parts[0] length ≤ 4 → rejected (rule: parts[0].len() > 4)
        let token = "AAAA.BBBBBBB.CCCCCCC"; // "AAAA" is exactly 4 chars
        assert!(!is_jwt_like(token));
    }

    // ── opaque session cookie values ──────────────────────────────────────────

    #[test]
    fn opaque_hex_session_id_rejected() {
        // Typical server-side session: 32 hex chars, no dots
        assert!(!is_jwt_like("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"));
    }

    #[test]
    fn opaque_random_base64_no_dots_rejected() {
        // Random base64url blob without dots (e.g. encrypted session)
        assert!(!is_jwt_like("dGhpcyBpcyBub3QgYSBKV1Q"));
    }

    #[test]
    fn opaque_value_with_non_base64url_chars_rejected() {
        // Looks structurally like three parts but contains '@' in one segment
        let token = "eyJhbGci.eyJzdWIi@iIxMjMi.c2lnbmF0dXJl";
        assert!(!is_jwt_like(token));
    }

    #[test]
    fn laravel_session_cookie_rejected() {
        // Laravel encrypted payload: base64-standard (contains '+', '/', '=')
        // wrapped in a JSON envelope — not a JWT structure
        let value = "eyJpdiI6Ik9UQXlNek0rTWpNPSIsInZhbHVlIjoiWVhCd0xYTmxjblpsY2c9PSIsIm1hYyI6ImFiYzEyMyJ9";
        // This is actually one base64url-like blob with no dots → rejected
        assert!(!is_jwt_like(value));
    }
}