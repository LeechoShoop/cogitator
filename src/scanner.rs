//! Active scan engine for Cogitator.
//!
//! A `ScanQueue` holds `ScanTarget`s (requests worth probing — usually fed in
//! from history/repeater once something looks interesting). `run_all` fans
//! every `(target, check)` pair out across a bounded pool of concurrent tasks
//! and collects the resulting `ScanFinding`s, worst severity first.

use async_trait::async_trait;
use reqwest::Client;
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;

use crate::logger;

/// Max number of `(target, check)` pairs allowed to run concurrently.
const MAX_PARALLEL_CHECKS: usize = 5;

// ─── Severity ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Lower rank = more severe, so findings can be sorted ascending by rank
    /// to get "most severe first".
    fn rank(&self) -> u8 {
        match self {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        }
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

// ─── Target / Finding ─────────────────────────────────────────────────────────

/// A single request worth actively probing.
#[derive(Debug, Clone)]
pub struct ScanTarget {
    pub url: String,
    pub method: String,
    pub params: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A single piece of evidence produced by a `ScanCheck` against a `ScanTarget`.
#[derive(Debug, Clone)]
pub struct ScanFinding {
    pub check_name: String,
    pub severity: Severity,
    pub evidence: String,
    pub request_raw: String,
    pub response_snippet: String,
    /// Target URL this finding was produced against. Part of the diff
    /// identity key (see `diff_findings`) — populate from
    /// `ScanTarget::url` at construction time.
    pub url: String,
    /// Parameter name the check was probing (query param, form field,
    /// path segment...). `None` for checks that aren't parameter-scoped
    /// (e.g. a host-level TLS finding).
    pub parameter: Option<String>,
}

// ─── Check trait ──────────────────────────────────────────────────────────────

/// A single vulnerability probe. Implementors should be cheap to construct
/// and stateless (or hold only `Arc`-shared config) since `run_all` may run
/// many instances of the same check concurrently against different targets.
#[async_trait]
pub trait ScanCheck: Send + Sync {
    /// Human-readable name used to populate `ScanFinding::check_name` and in
    /// logs (e.g. "Reflected XSS", "SQLi (error-based)").
    fn name(&self) -> &str;

    /// Run this check against `target`, returning zero or more findings.
    /// Implementations own all error handling internally — a failed request
    /// (timeout, connection refused, etc.) should simply yield no findings
    /// rather than propagating an error up through `run_all`.
    async fn check(&self, client: &Client, target: &ScanTarget) -> Vec<ScanFinding>;
}

// ─── Diffing ──────────────────────────────────────────────────────────────────

/// Result of comparing two scan snapshots.
#[derive(Debug, Clone, Default)]
pub struct ScanDiff {
    /// Present in `new` but not in `old` — a new vulnerability appeared.
    pub new_findings: Vec<ScanFinding>,
    /// Present in `old` but not in `new` — looks fixed (regression-verified:
    /// the same check no longer reproduces against the same target).
    pub fixed_findings: Vec<ScanFinding>,
    /// Present in both — still there.
    pub unchanged: Vec<ScanFinding>,
}

/// Compare an `old` scan snapshot against a `new` one.
///
/// Identity key for matching the same finding across two runs is
/// `(check_name, url, parameter)` — deliberately ignoring `evidence` /
/// `response_snippet`, since those text blobs can legitimately shift
/// run-to-run (timing, request IDs in headers, etc.) without the underlying
/// issue having changed.
///
/// O(n+m): keys of `old` are hashed once, then `new` is scanned once.
/// Duplicate keys within the same snapshot (not expected from a single
/// `run_all`, since each `(target, check)` pair runs once) are still
/// handled correctly via multiset semantics — each `old` entry is consumed
/// at most once.
pub fn diff_findings(old: &[ScanFinding], new: &[ScanFinding]) -> ScanDiff {
    use std::collections::HashMap;

    let mut old_remaining: HashMap<(String, String, Option<String>), Vec<&ScanFinding>> =
        HashMap::new();
    for f in old {
        let key = (f.check_name.clone(), f.url.clone(), f.parameter.clone());
        old_remaining.entry(key).or_default().push(f);
    }

    let mut diff = ScanDiff::default();

    for f in new {
        let key = (f.check_name.clone(), f.url.clone(), f.parameter.clone());
        match old_remaining.get_mut(&key).and_then(|v| v.pop()) {
            Some(_) => diff.unchanged.push(f.clone()),
            None => diff.new_findings.push(f.clone()),
        }
    }

    // Whatever's left in old_remaining never got matched against `new`.
    for leftovers in old_remaining.into_values() {
        for f in leftovers {
            diff.fixed_findings.push(f.clone());
        }
    }

    diff
}

// ─── Queue ────────────────────────────────────────────────────────────────────

/// Thread-safe FIFO of pending scan targets.
///
/// Cheap to clone (shares the underlying queue via `Arc`) — hand copies to
/// the TUI and to whatever background task drains it.
#[derive(Clone)]
pub struct ScanQueue(Arc<Mutex<VecDeque<ScanTarget>>>);

impl ScanQueue {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(VecDeque::new())))
    }

    /// Push a target onto the back of the queue.
    pub fn enqueue(&self, target: ScanTarget) {
        self.0.lock().unwrap().push_back(target);
    }

    /// Pop the next pending target, if any.
    pub fn dequeue(&self) -> Option<ScanTarget> {
        self.0.lock().unwrap().pop_front()
    }

    /// Number of targets currently queued.
    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drain every currently-queued target into a `Vec`, leaving the queue
    /// empty. Used by `run_all` to snapshot the work before fanning it out —
    /// targets enqueued *during* a scan run are picked up by the next call,
    /// not silently merged into the in-flight batch.
    pub fn drain(&self) -> Vec<ScanTarget> {
        let mut q = self.0.lock().unwrap();
        q.drain(..).collect()
    }

    /// Run every check against every currently-queued target, draining the
    /// queue in the process.
    ///
    /// Every `(target, check)` pair is its own concurrent task; concurrency
    /// is capped at `MAX_PARALLEL_CHECKS` via a `Semaphore` so a large queue
    /// times many checks doesn't open hundreds of sockets at once. Findings
    /// are collected from all tasks and returned sorted by severity
    /// descending (`Critical` first, `Info` last).
    pub async fn run_all(
        &self,
        checks: Arc<Vec<Arc<dyn ScanCheck>>>,
        client: Client,
    ) -> Vec<ScanFinding> {
        let targets = self.drain();

        if targets.is_empty() || checks.is_empty() {
            return Vec::new();
        }

        let semaphore = Arc::new(Semaphore::new(MAX_PARALLEL_CHECKS));
        let mut handles = Vec::with_capacity(targets.len() * checks.len());

        for target in targets {
            let target = Arc::new(target);
            for check in checks.iter().cloned() {
                let client = client.clone();
                let target = target.clone();
                let semaphore = semaphore.clone();

                let handle = tokio::spawn(async move {
                    // Hold the permit for the lifetime of this single check
                    // run; dropping it on task completion frees a slot for
                    // the next queued pair.
                    let _permit = match semaphore.acquire().await {
                        Ok(p) => p,
                        Err(_) => return Vec::new(), // semaphore closed; bail quietly
                    };

                    check.check(&client, &target).await
                });

                handles.push(handle);
            }
        }

        let mut findings = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(mut f) => findings.append(&mut f),
                Err(e) => logger::warn(&format!("scanner: check task panicked: {e}")),
            }
        }

        findings.sort_by(|a, b| a.severity.cmp(&b.severity));
        findings
    }
}

impl Default for ScanQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(url: &str) -> ScanTarget {
        ScanTarget {
            url: url.to_string(),
            method: "GET".to_string(),
            params: Vec::new(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    struct AlwaysFinds {
        name: String,
        severity: Severity,
    }

    #[async_trait]
    impl ScanCheck for AlwaysFinds {
        fn name(&self) -> &str {
            &self.name
        }

        async fn check(&self, _client: &Client, target: &ScanTarget) -> Vec<ScanFinding> {
            vec![ScanFinding {
                check_name: self.name.clone(),
                severity: self.severity,
                evidence: format!("probed {}", target.url),
                request_raw: String::new(),
                response_snippet: String::new(),
                url: target.url.clone(),
                parameter: None,
            }]
        }
    }

    struct NeverFinds;

    #[async_trait]
    impl ScanCheck for NeverFinds {
        fn name(&self) -> &str {
            "NeverFinds"
        }

        async fn check(&self, _client: &Client, _target: &ScanTarget) -> Vec<ScanFinding> {
            Vec::new()
        }
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Medium < Severity::Low);
        assert!(Severity::Low < Severity::Info);
    }

    #[test]
    fn enqueue_dequeue_and_drain() {
        let q = ScanQueue::new();
        q.enqueue(target("http://a.com"));
        q.enqueue(target("http://b.com"));
        assert_eq!(q.len(), 2);

        let first = q.dequeue().unwrap();
        assert_eq!(first.url, "http://a.com");
        assert_eq!(q.len(), 1);

        let rest = q.drain();
        assert_eq!(rest.len(), 1);
        assert!(q.is_empty());
    }

    #[tokio::test]
    async fn run_all_collects_and_sorts_by_severity() {
        let q = ScanQueue::new();
        q.enqueue(target("http://a.com"));
        q.enqueue(target("http://b.com"));

        let checks: Vec<Arc<dyn ScanCheck>> = vec![
            Arc::new(AlwaysFinds { name: "low-check".into(), severity: Severity::Low }),
            Arc::new(AlwaysFinds { name: "crit-check".into(), severity: Severity::Critical }),
            Arc::new(NeverFinds),
        ];

        let client = Client::new();
        let findings = q.run_all(Arc::new(checks), client).await;

        // 2 targets * 2 producing checks = 4 findings (NeverFinds contributes 0).
        assert_eq!(findings.len(), 4);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].severity, Severity::Critical);
        assert_eq!(findings[2].severity, Severity::Low);
        assert_eq!(findings[3].severity, Severity::Low);

        // Queue should be empty after a run.
        assert!(q.is_empty());
    }

    #[tokio::test]
    async fn run_all_on_empty_queue_returns_empty() {
        let q = ScanQueue::new();
        let checks: Vec<Arc<dyn ScanCheck>> =
            vec![Arc::new(AlwaysFinds { name: "x".into(), severity: Severity::Info })];
        let findings = q.run_all(Arc::new(checks), Client::new()).await;
        assert!(findings.is_empty());
    }
}

#[cfg(test)]
mod diff_tests {
    use super::*;

    fn f(check: &str, url: &str, param: Option<&str>) -> ScanFinding {
        ScanFinding {
            check_name: check.to_string(),
            severity: Severity::High,
            evidence: String::new(),
            request_raw: String::new(),
            response_snippet: String::new(),
            url: url.to_string(),
            parameter: param.map(|s| s.to_string()),
        }
    }

    #[test]
    fn detects_new_fixed_unchanged() {
        let old = vec![
            f("SQLi", "http://a.com/x", Some("id")),
            f("XSS", "http://a.com/y", Some("q")),
        ];
        let new = vec![
            f("SQLi", "http://a.com/x", Some("id")), // unchanged
            f("Traversal", "http://a.com/z", Some("file")), // new
            // XSS on y is gone -> fixed
        ];

        let diff = diff_findings(&old, &new);
        assert_eq!(diff.unchanged.len(), 1);
        assert_eq!(diff.unchanged[0].check_name, "SQLi");
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.new_findings[0].check_name, "Traversal");
        assert_eq!(diff.fixed_findings.len(), 1);
        assert_eq!(diff.fixed_findings[0].check_name, "XSS");
    }

    #[test]
    fn identical_snapshots_are_all_unchanged() {
        let old = vec![f("SQLi", "http://a.com/x", Some("id"))];
        let new = old.clone();
        let diff = diff_findings(&old, &new);
        assert_eq!(diff.unchanged.len(), 1);
        assert!(diff.new_findings.is_empty());
        assert!(diff.fixed_findings.is_empty());
    }

    #[test]
    fn empty_old_means_everything_is_new() {
        let new = vec![f("SQLi", "http://a.com/x", Some("id"))];
        let diff = diff_findings(&[], &new);
        assert_eq!(diff.new_findings.len(), 1);
        assert!(diff.unchanged.is_empty());
        assert!(diff.fixed_findings.is_empty());
    }

    #[test]
    fn empty_new_means_everything_is_fixed() {
        let old = vec![f("SQLi", "http://a.com/x", Some("id"))];
        let diff = diff_findings(&old, &[]);
        assert_eq!(diff.fixed_findings.len(), 1);
        assert!(diff.unchanged.is_empty());
        assert!(diff.new_findings.is_empty());
    }

    #[test]
    fn different_parameter_on_same_url_is_distinct() {
        let old = vec![f("SQLi", "http://a.com/x", Some("id"))];
        let new = vec![f("SQLi", "http://a.com/x", Some("name"))];
        let diff = diff_findings(&old, &new);
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.fixed_findings.len(), 1);
        assert!(diff.unchanged.is_empty());
    }

    #[test]
    fn duplicate_keys_matched_one_to_one() {
        // Two identical findings in `old`, only one in `new` -> one
        // unchanged, one fixed (not two unchanged or other miscounts).
        let old = vec![
            f("SQLi", "http://a.com/x", Some("id")),
            f("SQLi", "http://a.com/x", Some("id")),
        ];
        let new = vec![f("SQLi", "http://a.com/x", Some("id"))];
        let diff = diff_findings(&old, &new);
        assert_eq!(diff.unchanged.len(), 1);
        assert_eq!(diff.fixed_findings.len(), 1);
        assert!(diff.new_findings.is_empty());
    }
}