use reqwest::Client;
use serde::Serialize;

#[derive(Serialize)]
pub struct HttpMethodAudit {
    pub allowed_methods: Vec<String>,   // everything the Allow header lists
    pub dangerous_methods: Vec<String>, // subset: PUT, DELETE, TRACE, CONNECT, PATCH
    pub options_responded: bool,        // false if server ignored/blocked OPTIONS
    pub risk: String,
}

/// Send an OPTIONS request and classify the methods the server advertises.
///
/// Checks both `Allow` (standard) and `Public` (WebDAV) response headers.
/// The no-follow client is reused so we don't chase redirects on the probe.
pub async fn probe_http_methods(client: &Client, url: &str) -> HttpMethodAudit {
    // Verbs that represent meaningful attack surface when enabled on a web app.
    const DANGEROUS: &[&str] = &["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"];

    let resp = client
        .request(reqwest::Method::OPTIONS, url)
        .send()
        .await;

    let (allowed_methods, options_responded) = match resp {
        Ok(r) => {
            // Some servers put the list in `Public` (WebDAV) instead of `Allow`.
            let allow_value = r.headers()
                .get("allow")
                .or_else(|| r.headers().get("public"))
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            let methods: Vec<String> = allow_value
                .split(',')
                .map(|m| m.trim().to_uppercase())
                .filter(|m| !m.is_empty())
                .collect();

            let responded = !methods.is_empty() || r.status().is_success();
            (methods, responded)
        }
        Err(_) => (Vec::new(), false),
    };

    let dangerous_methods: Vec<String> = DANGEROUS.iter()
        .filter(|&&d| allowed_methods.iter().any(|m| m == d))
        .map(|&d| d.to_string())
        .collect();

    let risk = if !options_responded {
        "Server did not respond to OPTIONS (filtered or disabled)".to_string()
    } else if dangerous_methods.contains(&"TRACE".to_string()) {
        "CRITICAL -- TRACE enabled: cross-site tracing (XST) attack possible".to_string()
    } else if dangerous_methods.contains(&"PUT".to_string())
        || dangerous_methods.contains(&"DELETE".to_string())
    {
        format!(
            "HIGH -- write verbs enabled ({}): potential file upload / resource deletion",
            dangerous_methods.join(", ")
        )
    } else if !dangerous_methods.is_empty() {
        format!(
            "MEDIUM -- non-standard verbs present ({}): review server config",
            dangerous_methods.join(", ")
        )
    } else {
        "No dangerous HTTP methods advertised".to_string()
    };

    HttpMethodAudit { allowed_methods, dangerous_methods, options_responded, risk }
}
