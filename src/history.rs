//! Request/response history store for Cogitator.
//!
//! Every intercepted exchange that passes through the proxy is recorded here
//! for later review, filtering, and replay. Capped at `MAX_RECORDS` entries —
//! oldest records are evicted first (FIFO) once the cap is hit.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Hard cap on stored records. Oldest entries are evicted on overflow.
pub const MAX_RECORDS: usize = 10_000;

// ─── Record ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RequestRecord {
    pub id: u64,
    pub timestamp: Instant,
    pub method: String,
    pub host: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub response_status: Option<u16>,
    pub response_headers: Vec<(String, String)>,
    pub response_body: Option<Vec<u8>>,
    pub response_time_ms: Option<u128>,
    pub tags: Vec<String>,
    /// h2 stream id for this exchange, when the relevant leg negotiated
    /// HTTP/2 via ALPN (see `tls_mitm::NegotiatedProtocol`). `None` for
    /// plain HTTP/1.1 exchanges and for anything that predates h2 support
    /// (e.g. WebSocket frame records from `ws_interceptor`).
    pub stream_id: Option<u64>,
}

// ─── Filter ───────────────────────────────────────────────────────────────────

/// Filter criteria for `History::list`. All `Some` fields must match
/// (logical AND); `None` fields are ignored.
#[derive(Debug, Clone, Default)]
pub struct HistoryFilter {
    /// Substring match against `host` (case-sensitive).
    pub host_contains: Option<String>,
    /// Exact match against `method` (case-sensitive, e.g. "GET").
    pub method: Option<String>,
    /// Inclusive range matched against `response_status`. Records with no
    /// response yet (`response_status: None`) never match a `Some` range.
    pub status_range: Option<(u16, u16)>,
    /// Record must contain this tag (exact match) among `tags`.
    pub has_tag: Option<String>,
}

impl HistoryFilter {
    fn matches(&self, r: &RequestRecord) -> bool {
        if let Some(ref needle) = self.host_contains {
            if !r.host.contains(needle.as_str()) {
                return false;
            }
        }
        if let Some(ref m) = self.method {
            if &r.method != m {
                return false;
            }
        }
        if let Some((lo, hi)) = self.status_range {
            match r.response_status {
                Some(status) if status >= lo && status <= hi => {}
                _ => return false,
            }
        }
        if let Some(ref tag) = self.has_tag {
            if !r.tags.iter().any(|t| t == tag) {
                return false;
            }
        }
        true
    }
}

// ─── History store ────────────────────────────────────────────────────────────

/// Thread-safe, bounded ring of `RequestRecord`s.
///
/// Cloned `History` handles share the same underlying queue (cheap `Arc`
/// clone) — hand copies to the proxy task, the interceptor, and the TUI
/// alike.
#[derive(Clone)]
pub struct History(Arc<Mutex<VecDeque<RequestRecord>>>);

impl History {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(VecDeque::with_capacity(MAX_RECORDS))))
    }

    /// Append a record, evicting the oldest entry if at capacity.
    pub fn push(&self, record: RequestRecord) {
        let mut q = self.0.lock().unwrap();
        if q.len() >= MAX_RECORDS {
            q.pop_front();
        }
        q.push_back(record);
    }

    /// Fetch a clone of the record with the given `id`, if present.
    ///
    /// Returns an owned `RequestRecord` rather than a reference since the
    /// `MutexGuard` cannot outlive this call.
    pub fn get(&self, id: u64) -> Option<RequestRecord> {
        self.0.lock().unwrap().iter().find(|r| r.id == id).cloned()
    }

    /// Return clones of all records matching `filter`, oldest first.
    pub fn list(&self, filter: HistoryFilter) -> Vec<RequestRecord> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|r| filter.matches(r))
            .cloned()
            .collect()
    }

    /// Drop all stored records.
    pub fn clear(&self) {
        self.0.lock().unwrap().clear();
    }

    /// Fill in the response side of an existing record (found by `id`) once
    /// the origin has replied. No-op if `id` isn't present (e.g. it was
    /// already evicted by the `MAX_RECORDS` cap).
    pub fn record_response(
        &self,
        id: u64,
        status: u16,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
        elapsed: Duration,
    ) {
        let mut q = self.0.lock().unwrap();
        if let Some(r) = q.iter_mut().find(|r| r.id == id) {
            r.response_status = Some(status);
            r.response_headers = headers;
            r.response_body = body;
            r.response_time_ms = Some(elapsed.as_millis());
        }
    }

    /// Append a tag to an existing record, if present. Ignores duplicates.
    pub fn add_tag(&self, id: u64, tag: impl Into<String>) {
        let mut q = self.0.lock().unwrap();
        if let Some(r) = q.iter_mut().find(|r| r.id == id) {
            let tag = tag.into();
            if !r.tags.contains(&tag) {
                r.tags.push(tag);
            }
        }
    }

    /// Current number of stored records.
    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for History {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: u64, host: &str, method: &str, status: Option<u16>) -> RequestRecord {
        RequestRecord {
            id,
            timestamp: Instant::now(),
            method: method.to_string(),
            host: host.to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
            response_status: status,
            response_headers: Vec::new(),
            response_body: None,
            response_time_ms: None,
            tags: Vec::new(),
            stream_id: None,
        }
    }

    #[test]
    fn push_and_get() {
        let h = History::new();
        h.push(rec(1, "example.com", "GET", Some(200)));
        assert_eq!(h.get(1).unwrap().host, "example.com");
        assert!(h.get(2).is_none());
    }

    #[test]
    fn evicts_oldest_past_cap() {
        let h = History::new();
        for i in 0..(MAX_RECORDS as u64 + 5) {
            h.push(rec(i, "x.com", "GET", Some(200)));
        }
        assert_eq!(h.len(), MAX_RECORDS);
        assert!(h.get(0).is_none()); // evicted
        assert!(h.get(4).is_none()); // evicted
        assert!(h.get(5).is_some()); // still present
    }

    #[test]
    fn filter_host_contains() {
        let h = History::new();
        h.push(rec(1, "api.example.com", "GET", Some(200)));
        h.push(rec(2, "other.org", "GET", Some(200)));
        let results = h.list(HistoryFilter {
            host_contains: Some("example".to_string()),
            ..Default::default()
        });
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, 1);
    }

    #[test]
    fn filter_method() {
        let h = History::new();
        h.push(rec(1, "x.com", "GET", Some(200)));
        h.push(rec(2, "x.com", "POST", Some(200)));
        let results = h.list(HistoryFilter {
            method: Some("POST".to_string()),
            ..Default::default()
        });
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, 2);
    }

    #[test]
    fn filter_status_range_excludes_no_response() {
        let h = History::new();
        h.push(rec(1, "x.com", "GET", Some(404)));
        h.push(rec(2, "x.com", "GET", None));
        let results = h.list(HistoryFilter {
            status_range: Some((400, 499)),
            ..Default::default()
        });
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, 1);
    }

    #[test]
    fn filter_has_tag() {
        let h = History::new();
        let mut r = rec(1, "x.com", "GET", Some(200));
        r.tags.push("interesting".to_string());
        h.push(r);
        h.push(rec(2, "x.com", "GET", Some(200)));
        let results = h.list(HistoryFilter {
            has_tag: Some("interesting".to_string()),
            ..Default::default()
        });
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, 1);
    }

    #[test]
    fn record_response_fills_in_fields() {
        let h = History::new();
        h.push(rec(1, "x.com", "GET", None));
        h.record_response(
            1,
            204,
            vec![("Content-Type".to_string(), "text/plain".to_string())],
            Some(b"ok".to_vec()),
            Duration::from_millis(42),
        );
        let r = h.get(1).unwrap();
        assert_eq!(r.response_status, Some(204));
        assert_eq!(r.response_time_ms, Some(42));
        assert_eq!(r.response_body, Some(b"ok".to_vec()));
    }

    #[test]
    fn record_response_on_missing_id_is_noop() {
        let h = History::new();
        h.record_response(999, 200, vec![], None, Duration::from_millis(1));
        assert!(h.get(999).is_none());
    }

    #[test]
    fn add_tag_dedupes() {
        let h = History::new();
        h.push(rec(1, "x.com", "GET", Some(200)));
        h.add_tag(1, "flagged");
        h.add_tag(1, "flagged");
        assert_eq!(h.get(1).unwrap().tags, vec!["flagged".to_string()]);
    }

    #[test]
    fn clear_empties_store() {
        let h = History::new();
        h.push(rec(1, "x.com", "GET", Some(200)));
        h.clear();
        assert!(h.is_empty());
    }
}