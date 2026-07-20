//! Workspace persistence for Cogitator.
//!
//! A workspace captures a consistent snapshot of every piece of in-memory
//! state that a user would care to restore: scope rules, request/response
//! history (capped at the last 1 000 entries), scanner findings, repeater
//! tabs, and named session profiles.
//!
//! Serialised to / from a single pretty-printed JSON file (`.cogitator`).
//!
//! # Quick-start
//!
//! ```rust,ignore
//! // Save
//! let ws = WorkspaceData::capture(&scope, &history, &findings, &repeater, &profiles);
//! ws.save("mywork.cogitator")?;
//!
//! // Load
//! let ws = WorkspaceData::load("mywork.cogitator")?;
//! ws.restore(&scope, &history, &scanner_state, &repeater, &profile_store);
//! ```

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors that can arise when persisting or loading the workspace.
#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    /// Failed to serialise or deserialise the workspace JSON.
    #[error("failed to serialise workspace: {0}")]
    Serialise(#[from] serde_json::Error),

    /// Underlying filesystem I/O error (pass-through).
    #[error(transparent)]
    Io(#[from] io::Error),

    /// Vault encryption/decryption error.
    #[error("vault error: {0}")]
    Vault(String),
}

impl From<WorkspaceError> for io::Error {
    fn from(e: WorkspaceError) -> Self {
        match e {
            WorkspaceError::Io(inner) => inner,
            WorkspaceError::Vault(msg) => io::Error::new(io::ErrorKind::InvalidData, msg),
            other => io::Error::new(io::ErrorKind::InvalidData, other),
        }
    }
}

use crate::history::History;
use crate::repeater::RepeaterEngine;
use crate::scanner::ScanFinding;
use crate::scope::Scope;
use crate::session::{ProfileStore, SessionProfile};

// ─── Serialisable mirrors ─────────────────────────────────────────────────────

/// Serialisable mirror of a single `Scope` rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeRuleSer {
    /// Raw regex pattern string.
    pub pattern: String,
    /// `true` → include rule, `false` → exclude rule.
    pub include: bool,
}

/// Serialisable mirror of `RequestRecord`.
///
/// `Instant` (the runtime timestamp) has no meaningful on-disk form, so we
/// store milliseconds since the Unix epoch instead (best-effort: falls back
/// to 0 if the system clock is before 1970).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestRecordSer {
    pub id: u64,
    /// Unix timestamp in milliseconds (UTC).
    pub timestamp_ms: u64,
    pub method: String,
    pub host: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    /// Request body, base-64 encoded (bodies may be binary).
    pub body_b64: String,
    pub response_status: Option<u16>,
    pub response_headers: Vec<(String, String)>,
    /// Response body, base-64 encoded. `null` when no response yet.
    pub response_body_b64: Option<String>,
    pub response_time_ms: Option<u128>,
    pub tags: Vec<String>,
}

/// Serialisable mirror of `ScanFinding`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFindingSer {
    pub check_name: String,
    pub severity: String, // e.g. "Critical", "High", "Medium", "Low", "Info"
    pub evidence: String,
    pub request_raw: String,
    pub response_snippet: String,
    /// `#[serde(default)]` so workspace files saved before this field
    /// existed still load (empty string / `None`).
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub parameter: Option<String>,
}

/// One scan run, timestamped, so `Scan-Diff` has something to compare.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSnapshot {
    /// Unix timestamp in milliseconds (UTC) when this scan run completed.
    pub timestamp_ms: u64,
    pub findings: Vec<ScanFindingSer>,
}

/// Serialisable mirror of a single `RepeaterTab`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepeaterTabSer {
    pub id: u8,
    pub name: String,
    pub scheme: String,
    pub request_raw: String,
    pub response_raw: String,
    /// Full round-trip history: `(request_raw, response_raw)` pairs.
    pub history: Vec<(String, String)>,
}

/// Serialisable mirror of `SessionProfile`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionProfileSer {
    pub name: String,
    /// domain → cookie string.
    pub cookies: HashMap<String, String>,
    /// Extra request headers (e.g. `Authorization: Bearer …`).
    pub custom_headers: Vec<(String, String)>,
}

// ─── WorkspaceData ────────────────────────────────────────────────────────────

/// On-disk snapshot of the entire Cogitator session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceData {
    /// Semver-style format version for forward-compatibility checks.
    pub version: String,
    /// The proxy `target` string at save time (informational only for now;
    /// the proxy address is controlled by `config::PROXY_ADDR`).
    pub target: String,
    /// Ordered scope rules (include/exclude).
    pub scope_rules: Vec<ScopeRuleSer>,
    /// Last ≤ 1 000 request/response records (oldest-to-newest).
    pub history: Vec<RequestRecordSer>,
    /// Scanner findings from the most recent scan run.
    ///
    /// Deprecated since format 1.1 — kept only so files saved by older
    /// builds still load (and so very old readers of *this* format still
    /// see something). New code should read `scan_snapshots` instead; on
    /// `capture` this always mirrors the most recent snapshot's findings.
    pub scan_findings: Vec<ScanFindingSer>,
    /// All scan runs taken so far, oldest first. Accumulates across saves —
    /// `capture` appends a new snapshot rather than replacing the list.
    #[serde(default)]
    pub scan_snapshots: Vec<ScanSnapshot>,
    /// All open repeater tabs, including their send history.
    pub repeater_tabs: Vec<RepeaterTabSer>,
    /// All named session profiles.
    pub sessions: Vec<SessionProfileSer>,
}

/// Current on-disk format version. Bump the minor number when adding new
/// optional fields; bump the major number for breaking changes.
const FORMAT_VERSION: &str = "1.1";

/// Maximum number of history records written into a workspace file.
pub const WORKSPACE_HISTORY_CAP: usize = 1_000;

/// Cap on accumulated scan snapshots — old runs are evicted FIFO past this
/// so the workspace file doesn't grow unbounded over a long engagement.
pub const MAX_SCAN_SNAPSHOTS: usize = 50;

/// The auto-save file written on every clean exit / `Workspace-Save` without
/// an explicit name.
pub const LAST_WORKSPACE_FILE: &str = "cogitator_last.cogitator";

impl WorkspaceData {
    // ── Construction ──────────────────────────────────────────────────────────

    /// Capture a snapshot of the current runtime state into a `WorkspaceData`.
    ///
    /// `target` is a freeform label stored in the file for informational
    /// purposes (e.g. `config::PROXY_ADDR`).
    pub fn capture(
        target: &str,
        scope: &Arc<Mutex<Scope>>,
        history: &Arc<History>,
        scan_findings: &[ScanFinding],
        previous_snapshots: &[ScanSnapshot],
        repeater: &Arc<RepeaterEngine>,
        profile_store: &ProfileStore,
    ) -> Self {
        // ── Scope rules ───────────────────────────────────────────────────────
        let scope_rules = scope
            .lock()
            .unwrap()
            .list()
            .into_iter()
            .map(|(pattern, include)| ScopeRuleSer { pattern, include })
            .collect();

        // ── History (capped at WORKSPACE_HISTORY_CAP, newest last) ────────────
        let all_records = history.list(crate::history::HistoryFilter::default());
        let start = all_records.len().saturating_sub(WORKSPACE_HISTORY_CAP);
        let history_ser: Vec<RequestRecordSer> = all_records[start..]
            .iter()
            .map(|r| {
                // Approximate wall-clock time: `Instant` is not anchored to
                // the epoch, so we use the current system time minus the
                // record's elapsed age.
                let age = r.timestamp.elapsed();
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let timestamp_ms = now_ms.saturating_sub(age.as_millis() as u64);

                // `all_records` is a `Vec<RequestRecord>` returned by
                // `History::list`, but the slice ref prevents moving fields
                // out — each String/Vec clone here is unavoidable without an
                // additional into_iter() refactor that would not reduce
                // allocations (the records are already owned copies).
                RequestRecordSer {
                    id: r.id,
                    timestamp_ms,
                    method: r.method.clone(),
                    host: r.host.clone(),
                    path: r.path.clone(),
                    headers: r.headers.clone(),
                    body_b64: base64_encode(&r.body),
                    response_status: r.response_status,
                    response_headers: r.response_headers.clone(),
                    response_body_b64: r.response_body.as_ref().map(|b| base64_encode(b)),
                    response_time_ms: r.response_time_ms,
                    tags: r.tags.clone(),
                }
            })
            .collect();

        // ── Scanner findings ──────────────────────────────────────────────────
        // `scan_findings` is `&[ScanFinding]`; moving fields out of a shared
        // slice reference is not possible, so each String/Option<String> must
        // be cloned. The severity is formatted rather than cloned (different type).
        let scan_findings_ser: Vec<ScanFindingSer> = scan_findings
            .iter()
            .map(|f| ScanFindingSer {
                check_name: f.check_name.clone(),
                severity: format!("{:?}", f.severity),
                evidence: f.evidence.clone(),
                request_raw: f.request_raw.clone(),
                response_snippet: f.response_snippet.clone(),
                url: f.url.clone(),
                parameter: f.parameter.clone(),
            })
            .collect();

        // ── Scan snapshots (accumulate across saves) ───────────────────────────
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut scan_snapshots = previous_snapshots.to_vec();
        // Only append a new snapshot if this run actually differs from the
        // last stored one (or there's no prior snapshot at all) — re-saving
        // the workspace without re-scanning shouldn't spam duplicate
        // entries every time `Workspace-Save` runs.
        let is_new_run = match scan_snapshots.last() {
            Some(last) => {
                last.findings.len() != scan_findings_ser.len()
                    || last.findings.iter().zip(&scan_findings_ser).any(|(a, b)| {
                    a.check_name != b.check_name
                        || a.url != b.url
                        || a.parameter != b.parameter
                })
            }
            None => !scan_findings_ser.is_empty(),
        };
        if is_new_run && !scan_findings_ser.is_empty() {
            scan_snapshots.push(ScanSnapshot {
                timestamp_ms: now_ms,
                // Clone here because `scan_findings_ser` is also moved into
                // `WorkspaceData::scan_findings` at the end of this function
                // (back-compat mirror). Cannot move twice.
                findings: scan_findings_ser.clone(),
            });
            if scan_snapshots.len() > MAX_SCAN_SNAPSHOTS {
                let drop_count = scan_snapshots.len() - MAX_SCAN_SNAPSHOTS;
                scan_snapshots.drain(0..drop_count);
            }
        }

        // ── Repeater tabs ─────────────────────────────────────────────────────
        let repeater_tabs: Vec<RepeaterTabSer> = repeater
            .get_tabs()
            .into_iter()
            .map(|summary| {
                let history = repeater.get_history(summary.id);
                RepeaterTabSer {
                    id: summary.id,
                    name: summary.name,
                    scheme: "https".to_string(),
                    request_raw: summary.request_raw,
                    response_raw: summary.response_raw,
                    history,
                }
            })
            .collect();

        // ── Sessions ──────────────────────────────────────────────────────────
        let sessions: Vec<SessionProfileSer> = profile_store
            .list()
            .into_iter()
            .filter_map(|name| profile_store.load(&name))
            .map(|p| SessionProfileSer {
                name: p.name,
                cookies: p.cookies,
                custom_headers: p.custom_headers,
            })
            .collect();

        WorkspaceData {
            version: FORMAT_VERSION.to_string(),
            target: target.to_string(),
            scope_rules,
            history: history_ser,
            scan_findings: scan_findings_ser, // mirror latest, back-compat
            scan_snapshots,
            repeater_tabs,
            sessions,
        }
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    /// Serialise `self` to a pretty-printed JSON file at `path`, creating or
    /// overwriting it.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        self.save_inner(path).map_err(io::Error::from)
    }

    fn save_inner<P: AsRef<Path>>(&self, path: P) -> Result<(), WorkspaceError> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json).map_err(WorkspaceError::Io)
    }

    /// Serialise `self` and encrypt it using `vault.rs`.
    pub fn save_encrypted<P: AsRef<Path>>(&self, path: P, passphrase: &str) -> io::Result<()> {
        crate::vault::encrypt_to_file(self, path, passphrase)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    /// Deserialise a `WorkspaceData` from a `.cogitator` JSON file.
    pub fn load<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Self::load_inner(path).map_err(io::Error::from)
    }

    fn load_inner<P: AsRef<Path>>(path: P) -> Result<Self, WorkspaceError> {
        let contents = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&contents)?)
    }

    /// Decrypt and deserialise a `WorkspaceData` using `vault.rs`.
    pub fn load_encrypted<P: AsRef<Path>>(path: P, passphrase: &str) -> io::Result<Self> {
        crate::vault::decrypt_from_file(path, passphrase)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    // ── Restoration ───────────────────────────────────────────────────────────

    /// Apply this workspace snapshot back into the live runtime state.
    ///
    /// * Scope rules are replaced wholesale.
    /// * History records are appended (existing records are kept; loaded ones
    ///   are pushed in order so they appear at the end of the ring buffer).
    /// * Scanner findings are returned as a `Vec` for the caller to pass
    ///   to `ScannerState::set_findings`.
    /// * Repeater tabs are re-created from scratch; the engine's tabs list is
    ///   cleared first to avoid duplicates.
    /// * Session profiles are merged into the `ProfileStore`.
    pub fn restore(
        &self,
        scope: &Arc<Mutex<Scope>>,
        history: &Arc<History>,
        repeater: &Arc<RepeaterEngine>,
        profile_store: &ProfileStore,
    ) -> (Vec<ScanFindingSer>, Vec<ScanSnapshot>) {
        // ── Scope ──────────────────────────────────────────────────────────────
        {
            let mut s = scope.lock().unwrap();
            s.clear();
            for rule in &self.scope_rules {
                if rule.include {
                    let _ = s.add_include(&rule.pattern);
                } else {
                    let _ = s.add_exclude(&rule.pattern);
                }
            }
        }

        // ── History ────────────────────────────────────────────────────────────
        // Records are pushed in order; the ring buffer will evict the oldest
        // ones if the total exceeds MAX_RECORDS.
        // Iterating `&self.history` gives `&RequestRecordSer`; moving fields
        // out of a reference is not allowed, so String/Vec fields must be
        // cloned. The timestamp is reconstructed as `Instant::now()` (see
        // comment above) and `stream_id` defaults to None (no workspace field).
        for r in &self.history {
            let body = base64_decode(&r.body_b64);
            let response_body = r.response_body_b64.as_deref().map(base64_decode);

            let record = crate::history::RequestRecord {
                id: r.id,
                // We can't reconstruct the original `Instant`; use `now` so
                // the record is valid (elapsed() = ~0). The stored
                // `timestamp_ms` preserves the human-readable time in the file.
                timestamp: std::time::Instant::now(),
                method: r.method.clone(),
                host: r.host.clone(),
                path: r.path.clone(),
                headers: r.headers.clone(),
                body,
                response_status: r.response_status,
                response_headers: r.response_headers.clone(),
                response_body,
                response_time_ms: r.response_time_ms,
                tags: r.tags.clone(),
                stream_id: None,
            };
            history.push(record);
        }

        // ── Repeater ───────────────────────────────────────────────────────────
        // Close every tab that's currently open, then recreate from the snapshot.
        for tab in repeater.get_tabs() {
            repeater.close_tab(tab.id);
        }
        for tab in &self.repeater_tabs {
            // `RepeaterTabSer` derives `Clone`; a single clone is equivalent to
            // cloning all 5 String/Vec fields individually but is less fragile
            // if new fields are added to the struct later.
            repeater.restore_tab(tab.clone());
        }

        // ── Sessions ───────────────────────────────────────────────────────────
        for s in &self.sessions {
            profile_store.save(SessionProfile {
                name: s.name.clone(),
                cookies: s.cookies.clone(),
                custom_headers: s.custom_headers.clone(),
            });
        }

        // Back-compat: if an old file (format < 1.1) has scan_findings but
        // no scan_snapshots, synthesize a single snapshot at load time so
        // Scan-Diff still has something to work with after loading it.
        let scan_snapshots = if self.scan_snapshots.is_empty() && !self.scan_findings.is_empty() {
            vec![ScanSnapshot {
                timestamp_ms: 0,
                findings: self.scan_findings.clone(),
            }]
        } else {
            self.scan_snapshots.clone()
        };

        // Return findings + snapshots for the caller to hand to
        // ScannerState / the Scan-Diff command respectively.
        (self.scan_findings.clone(), scan_snapshots)
    }
}

// ─── Base-64 helpers (no external crate needed — stdlib only) ─────────────────

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };

        out.push(ALPHABET[(b0 >> 2)] as char);
        out.push(ALPHABET[((b0 & 0x3) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((b1 & 0xf) << 2) | (b2 >> 6)] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(s: &str) -> Vec<u8> {
    let decode_char = |c: char| -> Option<u8> {
        match c {
            'A'..='Z' => Some(c as u8 - b'A'),
            'a'..='z' => Some(c as u8 - b'a' + 26),
            '0'..='9' => Some(c as u8 - b'0' + 52),
            '+' => Some(62),
            '/' => Some(63),
            _ => None,
        }
    };

    let bytes: Vec<u8> = s.chars().filter_map(decode_char).collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        out.push((chunk[0] << 2) | (chunk[1] >> 4));
        if chunk.len() > 2 {
            out.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        if chunk.len() > 3 {
            out.push((chunk[2] << 6) | chunk[3]);
        }
    }
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip_empty() {
        let data: &[u8] = b"";
        assert_eq!(base64_decode(&base64_encode(data)), data);
    }

    #[test]
    fn base64_roundtrip_short() {
        let data = b"hello world";
        assert_eq!(base64_decode(&base64_encode(data)), data);
    }

    #[test]
    fn base64_roundtrip_binary() {
        let data: Vec<u8> = (0u8..=255).collect();
        assert_eq!(base64_decode(&base64_encode(&data)), data);
    }

    #[test]
    fn workspace_save_load_roundtrip() {
        let ws = WorkspaceData {
            version: "1.0".to_string(),
            target: "127.0.0.1:8080".to_string(),
            scope_rules: vec![
                ScopeRuleSer { pattern: r"example\.com".to_string(), include: true },
                ScopeRuleSer { pattern: r"ads\.".to_string(), include: false },
            ],
            history: vec![RequestRecordSer {
                id: 1,
                timestamp_ms: 1_700_000_000_000,
                method: "GET".to_string(),
                host: "example.com".to_string(),
                path: "/".to_string(),
                headers: vec![("Host".to_string(), "example.com".to_string())],
                body_b64: base64_encode(b""),
                response_status: Some(200),
                response_headers: vec![],
                response_body_b64: Some(base64_encode(b"ok")),
                response_time_ms: Some(42),
                tags: vec!["interesting".to_string()],
            }],
            scan_findings: vec![ScanFindingSer {
                check_name: "SQLi".to_string(),
                severity: "High".to_string(),
                evidence: "error in SQL syntax".to_string(),
                request_raw: "GET /?id=1' HTTP/1.1".to_string(),
                response_snippet: "You have an error in your SQL syntax".to_string(),
                url: "http://example.com/?id=1".to_string(),
                parameter: Some("id".to_string()),
            }],
            scan_snapshots: vec![ScanSnapshot {
                timestamp_ms: 1_700_000_000_000,
                findings: vec![ScanFindingSer {
                    check_name: "SQLi".to_string(),
                    severity: "High".to_string(),
                    evidence: "error in SQL syntax".to_string(),
                    request_raw: "GET /?id=1' HTTP/1.1".to_string(),
                    response_snippet: "You have an error in your SQL syntax".to_string(),
                    url: "http://example.com/?id=1".to_string(),
                    parameter: Some("id".to_string()),
                }],
            }],
            repeater_tabs: vec![RepeaterTabSer {
                id: 1,
                name: "GET example.com".to_string(),
                scheme: "https".to_string(),
                request_raw: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_string(),
                response_raw: "HTTP/1.1 200 OK\r\n\r\nok".to_string(),
                history: vec![
                    ("GET / HTTP/1.1\r\n\r\n".to_string(), "HTTP/1.1 200 OK\r\n\r\n".to_string()),
                ],
            }],
            sessions: vec![SessionProfileSer {
                name: "admin".to_string(),
                cookies: [("example.com".to_string(), "session=abc".to_string())].into(),
                custom_headers: vec![("Authorization".to_string(), "Bearer tok".to_string())],
            }],
        };

        let tmp = std::env::temp_dir().join(format!(
            "cogitator_ws_test_{}.cogitator",
            std::process::id()
        ));
        ws.save(&tmp).expect("save failed");
        let loaded = WorkspaceData::load(&tmp).expect("load failed");
        let _ = std::fs::remove_file(&tmp);

        assert_eq!(loaded.version, "1.0");
        assert_eq!(loaded.scope_rules.len(), 2);
        assert!(loaded.scope_rules[0].include);
        assert_eq!(loaded.history.len(), 1);
        assert_eq!(loaded.history[0].host, "example.com");
        assert_eq!(loaded.scan_findings.len(), 1);
        assert_eq!(loaded.scan_findings[0].severity, "High");
        assert_eq!(loaded.scan_snapshots.len(), 1);
        assert_eq!(loaded.scan_snapshots[0].findings[0].url, "http://example.com/?id=1");
        assert_eq!(loaded.repeater_tabs.len(), 1);
        assert_eq!(loaded.repeater_tabs[0].history.len(), 1);
        assert_eq!(loaded.sessions.len(), 1);
        assert_eq!(loaded.sessions[0].name, "admin");
    }
}