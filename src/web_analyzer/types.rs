use serde::Serialize;
use std::fs::File;
use std::io::Write;

use crate::scrap_analyze::{CspStrength, HtmlAuditResult};
use crate::crypto_forensic::CryptoAuditResult;
use crate::dns_guard::EmailSecurityRecords;

use super::clickjacking::ClickjackingAudit;
use super::redirects::RedirectHop;
use super::cors::CorsAudit;
use super::http_methods::HttpMethodAudit;
use super::fingerprint::PassiveTechFingerprint;

pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Serialize)]
pub struct WebAnalysisResult {
    pub schema_version: String,
    pub target_url: String,
    pub status_code: String,
    pub response_time_ms: u128,
    pub web_server: String,
    pub has_hsts: bool,
    pub has_csp: bool,
    pub clickjacking_audit: ClickjackingAudit,
    pub x_content_type: Option<String>,
    pub referrer_policy: Option<String>,
    pub permissions_policy: bool,
    pub html_audit: Option<HtmlAuditResult>,
    pub crypto_audit: Option<CryptoAuditResult>,
    pub redirect_chain: Vec<RedirectHop>,
    pub cors_audit: Option<CorsAudit>,
    pub csp_strength: Option<CspStrength>,
    pub email_security: Option<EmailSecurityRecords>,
    pub overall_score: u8,
    pub overall_grade: String,
    pub http_method_audit: Option<HttpMethodAudit>,
    pub passive_fingerprint: Option<PassiveTechFingerprint>,
    pub cve_matches: Vec<crate::cve::CveMatch>,
}

pub fn export_to_json(result: &WebAnalysisResult) -> String {
    serde_json::to_string_pretty(result)
        .unwrap_or_else(|_| "{\"error\": \"serialization failed\"}".to_string())
}

pub fn save_to_file(result: &WebAnalysisResult, file_path: &str) -> Result<(), std::io::Error> {
    let json_data = export_to_json(result);
    let mut file = File::create(file_path)?;
    file.write_all(json_data.as_bytes())?;
    Ok(())
}
