//! Wire format for `cogitator-worker`'s HTTP API, plus the shared list of
//! check names both the coordinator (`main.rs`'s `Scan-Site-Distributed`
//! command, via `distributed.rs`) and every worker need to agree on.
//!
//! Kept as its own small module rather than folding these types directly
//! into `scanner.rs` — this is transport/protocol shape (what goes over
//! the wire), not scan-engine logic. `ScanTarget`/`ScanFinding` themselves
//! *do* live in `scanner.rs` (see its module docs) and are reused here
//! unchanged; this file only adds the request/response envelopes around
//! them.
//!
//! Exposed to `cogitator-worker` via `lib.rs`'s `#[path]` re-declaration of
//! this exact file; `main.rs` declares it normally as `mod
//! worker_protocol;` for the coordinator side. Same file, two module
//! trees — see `lib.rs`'s module docs for the full rationale.

use serde::{Deserialize, Serialize};

use crate::scanner::{ScanFinding, ScanTarget};

/// Env var holding the shared bearer token every `/scan` and `/health`
/// request must present, and that every `cogitator-worker` process checks
/// incoming requests against. v1's entire auth story: one shared secret,
/// no per-worker tokens, no TLS. Both sides read the *same* constant name
/// so there's no risk of the coordinator and a worker silently agreeing on
/// two different env var names.
pub const WORKER_TOKEN_ENV_VAR: &str = "COGITATOR_WORKER_TOKEN";

/// Every check name a worker can be asked to run, matched against
/// `ScanCheck::name()`. This is the same set (and the same literal
/// strings) as the six checks `main.rs` wires into its own local
/// `scan_checks_vec` and `cogitator-worker` wires into its registry.
///
/// **Keep in sync** if a check is added, removed, or renamed on either
/// side — a name mismatch here doesn't fail to compile, it just means a
/// worker silently has nothing registered under that name (see
/// `ScanRequest::checks` doc comment below), so it's worth an occasional
/// glance whenever `main.rs`'s `scan_checks_vec` changes.
pub const ALL_CHECK_NAMES: &[&str] = &[
    "SQL Injection (error-based)",
    "SQL Injection (time-based blind)",
    "Path Traversal",
    "Cross-Site Scripting (reflected/stored)",
    "Server-Side Request Forgery",
    "XML External Entity (XXE)",
];

/// Request body for `POST /scan` on a `cogitator-worker`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    /// The single target to probe. One request = one target, deliberately —
    /// keeps the worker's handler a straight loop over its registered
    /// checks with no internal fan-out/concurrency to reason about; the
    /// coordinator is what fans work out across *targets* and *workers*.
    pub target: ScanTarget,
    /// Which checks to run against `target`, matched by name against
    /// `ScanCheck::name()`. An empty list means "run every check this
    /// worker has registered" — `distributed.rs` doesn't rely on that
    /// default though, and sends `ALL_CHECK_NAMES` explicitly, so a typo'd
    /// name fails loudly (that check contributes 0 findings, which is
    /// noticeable) rather than silently falling back to "run everything".
    #[serde(default)]
    pub checks: Vec<String>,
}

/// Response body for `POST /scan`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanResponse {
    pub findings: Vec<ScanFinding>,
}

/// Response body for `GET /health` — lets an operator (or a future,
/// smarter coordinator) confirm a worker is up and see what it's able to
/// run before shipping real work to it. `Scan-Site-Distributed` v1 doesn't
/// call this itself (see `distributed.rs` docs), but it costs nothing to
/// expose and is handy for `curl`-ing a worker to sanity-check a
/// deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub available_checks: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_request_defaults_checks_to_empty_when_omitted() {
        let json = r#"{"target":{"url":"http://x","method":"GET","params":[],"headers":[],"body":[]}}"#;
        let req: ScanRequest = serde_json::from_str(json).unwrap();
        assert!(req.checks.is_empty());
    }

    #[test]
    fn scan_response_round_trip() {
        let resp = ScanResponse { findings: Vec::new() };
        let json = serde_json::to_string(&resp).unwrap();
        let back: ScanResponse = serde_json::from_str(&json).unwrap();
        assert!(back.findings.is_empty());
    }

    #[test]
    fn health_response_round_trip() {
        let resp = HealthResponse {
            status: "ok".to_string(),
            available_checks: vec!["Path Traversal".to_string()],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: HealthResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, "ok");
        assert_eq!(back.available_checks, vec!["Path Traversal".to_string()]);
    }

    #[test]
    fn all_check_names_has_no_duplicates() {
        let mut sorted = ALL_CHECK_NAMES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ALL_CHECK_NAMES.len());
    }
}