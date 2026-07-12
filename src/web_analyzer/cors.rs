use reqwest::header::HeaderMap;
use serde::Serialize;

#[derive(Serialize)]
pub struct CorsAudit {
    pub acao_header: Option<String>,       // Access-Control-Allow-Origin
    pub acac_header: Option<String>,       // Access-Control-Allow-Credentials
    pub wildcard_origin: bool,
    pub credentials_with_wildcard: bool,   // Worst-case misconfiguration
    pub reflects_origin: bool,             // Server echoes back arbitrary Origin
    pub risk: String,
}

/// Inspect response headers for CORS misconfiguration.
pub fn audit_cors(headers: &HeaderMap, probed_origin: &str) -> CorsAudit {
    let acao = headers.get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let acac = headers.get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let wildcard_origin = acao.as_deref() == Some("*");
    let reflects_origin = acao.as_deref() == Some(probed_origin);
    let credentials_with_wildcard = wildcard_origin && acac.as_deref() == Some("true");

    let risk = if credentials_with_wildcard {
        "CRITICAL -- wildcard + credentials: data theft possible".to_string()
    } else if reflects_origin && acac.as_deref() == Some("true") {
        "HIGH -- origin reflected with credentials: CORS hijacking risk".to_string()
    } else if reflects_origin {
        "MEDIUM -- server reflects arbitrary Origin header".to_string()
    } else if wildcard_origin {
        "LOW-MEDIUM -- wildcard origin (no credentials, read-only risk)".to_string()
    } else {
        "No obvious CORS misconfiguration detected".to_string()
    };

    CorsAudit { acao_header: acao, acac_header: acac, wildcard_origin, credentials_with_wildcard, reflects_origin, risk }
}
