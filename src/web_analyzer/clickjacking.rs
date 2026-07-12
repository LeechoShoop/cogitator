use reqwest::header::HeaderMap;
use serde::Serialize;

/// The W3C spec (and all modern browsers) treat `frame-ancestors` in CSP as the
/// authoritative clickjacking defence; `X-Frame-Options` is only a fallback for
/// legacy browsers that pre-date CSP Level 2.  We must cross-reference both
/// before deciding whether the site is actually protected.
#[derive(Serialize)]
pub struct ClickjackingAudit {
    /// Raw value of X-Frame-Options if present.
    pub x_frame_options: Option<String>,
    /// Whether CSP contains a `frame-ancestors` directive.
    pub csp_frame_ancestors: bool,
    /// The extracted `frame-ancestors` value (e.g. `'none'`, `'self'`).
    pub frame_ancestors_value: Option<String>,
    /// True when at least one effective control is in place.
    pub is_protected: bool,
    /// Human-readable verdict.
    pub verdict: String,
}

/// Cross-reference `X-Frame-Options` and `Content-Security-Policy: frame-ancestors`
/// to produce a single, accurate clickjacking verdict.
pub fn audit_clickjacking(headers: &HeaderMap) -> ClickjackingAudit {
    let xfo = headers.get("x-frame-options")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Extract `frame-ancestors` from CSP.  A CSP header may contain multiple
    // semicolon-separated directives; we find the one starting with
    // "frame-ancestors" (case-insensitive) and capture its value.
    let (csp_frame_ancestors, frame_ancestors_value) = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .map(|csp| {
            let directive = csp
                .split(';')
                .map(|d| d.trim())
                .find(|d| d.to_lowercase().starts_with("frame-ancestors"));

            match directive {
                Some(d) => {
                    // Everything after the directive name is the value.
                    let value = d
                        .splitn(2, char::is_whitespace)
                        .nth(1)
                        .map(|s| s.trim().to_string());
                    (true, value)
                }
                None => (false, None),
            }
        })
        .unwrap_or((false, None));

    // Protection logic:
    //   * `frame-ancestors` in CSP  -> protected (supersedes XFO in modern browsers)
    //   * `X-Frame-Options` present -> protected (legacy fallback; still honoured)
    //   * Neither                   -> vulnerable
    let is_protected = csp_frame_ancestors || xfo.is_some();

    let verdict = if csp_frame_ancestors && xfo.is_some() {
        format!(
            "Protected -- CSP frame-ancestors ({}) + X-Frame-Options ({}) both present (belt-and-suspenders)",
            frame_ancestors_value.as_deref().unwrap_or("?"),
            xfo.as_deref().unwrap_or("?"),
        )
    } else if csp_frame_ancestors {
        format!(
            "Protected -- CSP frame-ancestors: {} (X-Frame-Options absent but not required)",
            frame_ancestors_value.as_deref().unwrap_or("?"),
        )
    } else if xfo.is_some() {
        format!(
            "Partial -- X-Frame-Options: {} only (no CSP frame-ancestors; legacy browsers protected, modern browsers rely on XFO fallback)",
            xfo.as_deref().unwrap_or("?"),
        )
    } else {
        "VULNERABLE -- neither X-Frame-Options nor CSP frame-ancestors is set".to_string()
    };

    ClickjackingAudit {
        x_frame_options: xfo,
        csp_frame_ancestors,
        frame_ancestors_value,
        is_protected,
        verdict,
    }
}
