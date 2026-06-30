//! Repeater: manual request resend/edit, à la Burp's Repeater tab.
//!
//! Each `RepeaterTab` holds a raw HTTP/1.1 request as editable text, plus
//! the history of every (request, response) pair sent from that tab. The
//! engine itself is just a mutex-guarded `Vec` of tabs — small tool, no need
//! for an id->tab map; tabs are found by linear scan on `id`.

use crate::history::RequestRecord;
use crate::session::{apply_profile, CookieJar, SessionProfile};
use anyhow::{anyhow, Context, Result};
use reqwest::{Client, Method};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

// ─── Tab ──────────────────────────────────────────────────────────────────────

pub struct RepeaterTab {
    pub id: u8,
    pub name: String,
    pub request_raw: String,
    pub response_raw: String,
    pub history: Vec<(String, String)>,

    /// Origin to send to. Not part of the raw HTTP text (HTTP/1.1 requests
    /// carry only `Host:` + path, not a scheme), so kept alongside it.
    /// Populated from the originating `RequestRecord`/proxy connection and
    /// editable only indirectly (by editing the `Host:` header — see
    /// `send`, which re-derives `host` from the raw text each time).
    pub scheme: String,
}

/// Read-only summary for the TUI tab bar.
#[derive(Debug, Clone)]
pub struct RepeaterTabSummary {
    pub id: u8,
    pub name: String,
    pub request_raw: String,
    pub response_raw: String,
    pub history_len: usize,
}

/// Result of `RepeaterEngine::send`.
#[derive(Debug, Clone)]
pub struct RepeaterResponse {
    pub status: u16,
    pub response_raw: String,
}

// ─── Engine ───────────────────────────────────────────────────────────────────

pub struct RepeaterEngine {
    tabs: Arc<Mutex<Vec<RepeaterTab>>>,
    next_id: Arc<AtomicU8>,
}

impl Clone for RepeaterEngine {
    fn clone(&self) -> Self {
        Self { tabs: self.tabs.clone(), next_id: self.next_id.clone() }
    }
}

impl RepeaterEngine {
    pub fn new() -> Self {
        Self {
            tabs: Arc::new(Mutex::new(Vec::new())),
            next_id: Arc::new(AtomicU8::new(1)),
        }
    }

    /// Build a new tab from a captured `RequestRecord`, reconstructing the
    /// raw HTTP/1.1 request text from its parts. Returns the new tab's id.
    ///
    /// `id` wraps at `u8::MAX` (Repeater realistically never has 255
    /// concurrent tabs open; on wrap a stale id could theoretically collide
    /// with a still-open tab, but that's an acceptable edge for a tool whose
    /// own author is the only user).
    pub fn new_tab(&self, record: &RequestRecord) -> u8 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let scheme = "https".to_string(); // TLS MITM is the only path that feeds Repeater today

        let request_raw = build_raw_request(
            &record.method,
            &record.path,
            &record.host,
            &record.headers,
            &record.body,
        );

        let tab = RepeaterTab {
            id,
            name: format!("{} {}", record.method, record.host),
            request_raw,
            response_raw: String::new(),
            history: Vec::new(),
            scheme,
        };

        self.tabs.lock().unwrap().push(tab);
        id
    }

    /// Overwrite a tab's editable request text (operator edits in the TUI).
    pub fn update_request(&self, tab_id: u8, raw: String) {
        let mut tabs = self.tabs.lock().unwrap();
        if let Some(tab) = tabs.iter_mut().find(|t| t.id == tab_id) {
            tab.request_raw = raw;
        }
    }

    pub fn get_tabs(&self) -> Vec<RepeaterTabSummary> {
        self.tabs
            .lock()
            .unwrap()
            .iter()
            .map(|t| RepeaterTabSummary {
                id: t.id,
                name: t.name.clone(),
                request_raw: t.request_raw.clone(),
                response_raw: t.response_raw.clone(),
                history_len: t.history.len(),
            })
            .collect()
    }

    pub fn close_tab(&self, id: u8) {
        self.tabs.lock().unwrap().retain(|t| t.id != id);
    }

    /// Reconstruct a tab verbatim from a serialised snapshot (e.g. loaded
    /// from a `.cogitator` workspace file). The tab's `id`, `name`, `scheme`,
    /// editable request/response text, and full round-trip history are all
    /// preserved. Caller is responsible for clearing stale tabs first to avoid
    /// id collisions.
    pub fn restore_tab(&self, snap: crate::workspace::RepeaterTabSer) {
        let tab = RepeaterTab {
            id: snap.id,
            name: snap.name,
            request_raw: snap.request_raw,
            response_raw: snap.response_raw,
            history: snap.history,
            scheme: snap.scheme,
        };
        // Advance the id counter so future `new_tab` calls don't collide.
        let next = self.next_id.load(std::sync::atomic::Ordering::SeqCst);
        if snap.id >= next {
            self.next_id.store(snap.id.wrapping_add(1), std::sync::atomic::Ordering::SeqCst);
        }
        self.tabs.lock().unwrap().push(tab);
    }

    /// Clone of the full (request_raw, response_raw) round-trip history for
    /// `tab_id`, oldest first. Returns an empty `Vec` if the tab doesn't
    /// exist (closed, or never sent anything yet) rather than `Option`,
    /// since "no history" and "no such tab" render identically in the TUI.
    pub fn get_history(&self, tab_id: u8) -> Vec<(String, String)> {
        self.tabs
            .lock()
            .unwrap()
            .iter()
            .find(|t| t.id == tab_id)
            .map(|t| t.history.clone())
            .unwrap_or_default()
    }

    /// Parse the tab's `request_raw`, send it via `client`, record the
    /// round-trip in the tab's history, and return the response.
    ///
    /// When `profile` is `Some`, its cookies and custom headers are injected
    /// into the outgoing request *before* it is sent.  Set-Cookie headers
    /// from the response are harvested back into `jar` (if supplied) so the
    /// live session stays up to date across sends.
    pub async fn send(
        &self,
        tab_id: u8,
        client: &Client,
        profile: Option<&SessionProfile>,
        jar: Option<&CookieJar>,
    ) -> Result<RepeaterResponse> {
        let (request_raw, scheme) = {
            let tabs = self.tabs.lock().unwrap();
            let tab = tabs
                .iter()
                .find(|t| t.id == tab_id)
                .ok_or_else(|| anyhow!("no such Repeater tab: {tab_id}"))?;
            (tab.request_raw.clone(), tab.scheme.clone())
        };

        let parsed = parse_raw_request(&request_raw)?;

        let url = format!("{}://{}{}", scheme, parsed.host, parsed.path);
        let method = Method::from_bytes(parsed.method.as_bytes())
            .with_context(|| format!("invalid HTTP method: {}", parsed.method))?;

        let mut builder = client.request(method, &url);
        // Drop a captured `Accept-Encoding` header rather than forward it
        // verbatim: this client may not be built with decompression support
        // for every encoding the origin offers (notably Brotli), and a
        // mismatch there means the *response* arrives compressed and gets
        // rendered as garbage bytes in the read-only response pane. Letting
        // the server choose `identity` (no header = no compression request)
        // keeps the Repeater response pane human-readable; the original
        // captured exchange in `History` still has the real encoded bytes
        // if that's ever needed.
        for (name, value) in filter_headers_for_send(&parsed.headers) {
            builder = builder.header(name, value);
        }
        if !parsed.body.is_empty() {
            builder = builder.body(parsed.body.clone());
        }

        // Inject session cookies + custom headers (e.g. Bearer token) from
        // the active profile, if one was supplied by the caller.
        builder = apply_profile(builder, &parsed.host, profile);

        let resp = builder.send().await.context("Repeater send failed")?;
        let status = resp.status().as_u16();
        let resp_headers = resp.headers().clone();
        let resp_body = resp.bytes().await.context("reading Repeater response body")?;

        // Harvest Set-Cookie headers back into the live jar so subsequent
        // Repeater sends (and Intruder runs) pick them up automatically.
        if let Some(j) = jar {
            j.update_from_response(&parsed.host, &resp_headers);
        }

        let response_raw = build_raw_response(status, &resp_headers, &resp_body);

        let mut tabs = self.tabs.lock().unwrap();
        if let Some(tab) = tabs.iter_mut().find(|t| t.id == tab_id) {
            tab.response_raw = response_raw.clone();
            tab.history.push((request_raw, response_raw.clone()));
        }

        Ok(RepeaterResponse { status, response_raw })
    }
}

impl Default for RepeaterEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Raw HTTP text <-> structured parts ──────────────────────────────────────

struct ParsedRequest {
    method: String,
    path: String,
    host: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Parse a raw HTTP/1.1 request: request-line, headers up to the first blank
/// line, then body. `Host:` is pulled out of the headers since the caller
/// needs it separately to build the target URL.
fn parse_raw_request(raw: &str) -> Result<ParsedRequest> {
    let mut parts = raw.splitn(2, "\r\n\r\n");
    let head = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("").as_bytes().to_vec();

    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or_else(|| anyhow!("empty request"))?;

    let mut rl = request_line.split_whitespace();
    let method = rl.next().ok_or_else(|| anyhow!("missing method"))?.to_string();
    let path = rl.next().ok_or_else(|| anyhow!("missing path"))?.to_string();
    // HTTP version (3rd token) is ignored — reqwest negotiates its own.

    let mut headers = Vec::new();
    let mut host = None;

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("malformed header line: {line}"))?;
        let name = name.trim().to_string();
        let value = value.trim().to_string();

        if name.eq_ignore_ascii_case("host") {
            host = Some(value.clone());
        }
        headers.push((name, value));
    }

    let host = host.ok_or_else(|| anyhow!("request has no Host: header"))?;

    Ok(ParsedRequest { method, path, host, headers, body })
}

/// Headers to send on, with any `Accept-Encoding` entries removed
/// (case-insensitive name match). See the comment at the `send` call site
/// for why: forwarding a captured `Accept-Encoding` can make the origin
/// compress the reply with an encoding this client doesn't decompress.
fn filter_headers_for_send(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("accept-encoding"))
        .cloned()
        .collect()
}

/// Reconstruct a raw HTTP/1.1 request from captured parts, for use as the
/// initial editable text of a new Repeater tab. Inserts `Host:` from `host`
/// if the captured headers didn't already carry one.
fn build_raw_request(
    method: &str,
    path: &str,
    host: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> String {
    let mut out = format!("{method} {path} HTTP/1.1\r\n");

    let has_host = headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("host"));
    if !has_host {
        out.push_str(&format!("Host: {host}\r\n"));
    }
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    out.push_str(&String::from_utf8_lossy(body));
    out
}

/// Render a `reqwest::Response`'s status/headers/body as raw HTTP/1.1 text
/// for display in the tab's response pane.
fn build_raw_response(status: u16, headers: &reqwest::header::HeaderMap, body: &[u8]) -> String {
    let reason = reqwest::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("");

    let mut out = format!("HTTP/1.1 {status} {reason}\r\n");
    for (name, value) in headers.iter() {
        out.push_str(&format!(
            "{}: {}\r\n",
            name,
            value.to_str().unwrap_or("<non-utf8>")
        ));
    }
    out.push_str("\r\n");
    out.push_str(&String::from_utf8_lossy(body));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_get() {
        let raw = "GET /foo?x=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        let parsed = parse_raw_request(raw).unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.path, "/foo?x=1");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.headers.len(), 2);
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn parse_post_with_body() {
        let raw = "POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"u\":\"a\"}";
        let parsed = parse_raw_request(raw).unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.body, b"{\"u\":\"a\"}".to_vec());
    }

    #[test]
    fn parse_missing_host_errors() {
        let raw = "GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n";
        assert!(parse_raw_request(raw).is_err());
    }

    #[test]
    fn parse_malformed_header_errors() {
        let raw = "GET / HTTP/1.1\r\nHost example.com\r\n\r\n";
        assert!(parse_raw_request(raw).is_err());
    }

    #[test]
    fn build_then_parse_roundtrip() {
        let headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Accept".to_string(), "*/*".to_string()),
        ];
        let raw = build_raw_request("GET", "/path", "example.com", &headers, b"");
        let parsed = parse_raw_request(&raw).unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.path, "/path");
        assert_eq!(parsed.host, "example.com");
    }

    #[test]
    fn build_inserts_host_if_absent() {
        let raw = build_raw_request("GET", "/", "example.com", &[], b"");
        assert!(raw.starts_with("GET / HTTP/1.1\r\nHost: example.com\r\n"));
    }

    #[test]
    fn new_tab_assigns_increasing_ids() {
        let engine = RepeaterEngine::new();
        let rec = test_record();
        let id1 = engine.new_tab(&rec);
        let id2 = engine.new_tab(&rec);
        assert_eq!(id2, id1 + 1);
        assert_eq!(engine.get_tabs().len(), 2);
    }

    #[test]
    fn close_tab_removes_it() {
        let engine = RepeaterEngine::new();
        let id = engine.new_tab(&test_record());
        engine.close_tab(id);
        assert!(engine.get_tabs().is_empty());
    }

    #[test]
    fn update_request_overwrites_text() {
        let engine = RepeaterEngine::new();
        let id = engine.new_tab(&test_record());
        engine.update_request(id, "GET /new HTTP/1.1\r\nHost: x.com\r\n\r\n".to_string());
        let tabs = engine.get_tabs();
        assert!(tabs[0].request_raw.contains("/new"));
    }

    #[test]
    fn get_history_empty_for_unsent_tab() {
        let engine = RepeaterEngine::new();
        let id = engine.new_tab(&test_record());
        assert!(engine.get_history(id).is_empty());
    }

    #[test]
    fn get_history_empty_for_missing_tab() {
        let engine = RepeaterEngine::new();
        assert!(engine.get_history(255).is_empty());
    }

    #[test]
    fn send_header_filter_drops_accept_encoding_case_insensitively() {
        let headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Accept-Encoding".to_string(), "br".to_string()),
            ("accept-encoding".to_string(), "gzip".to_string()), // dupe, wrong case
            ("X-Custom".to_string(), "keep-me".to_string()),
        ];
        let filtered = filter_headers_for_send(&headers);
        assert_eq!(
            filtered,
            vec![
                ("Host".to_string(), "example.com".to_string()),
                ("X-Custom".to_string(), "keep-me".to_string()),
            ]
        );
    }

    #[test]
    fn send_header_filter_is_noop_without_accept_encoding() {
        let headers = vec![("Host".to_string(), "example.com".to_string())];
        assert_eq!(filter_headers_for_send(&headers), headers);
    }

    fn test_record() -> RequestRecord {
        RequestRecord {
            id: 1,
            timestamp: std::time::Instant::now(),
            method: "GET".to_string(),
            host: "example.com".to_string(),
            path: "/".to_string(),
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: Vec::new(),
            response_status: None,
            response_headers: Vec::new(),
            response_body: None,
            response_time_ms: None,
            tags: Vec::new(),
            stream_id: None,
        }
    }
}