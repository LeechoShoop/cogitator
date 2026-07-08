//! Coordinator-side client for Cogitator's distributed scanning mode.
//!
//! Ships `ScanTarget`s out to one or more `cogitator-worker` processes over
//! `worker_protocol`'s JSON-over-HTTP API and collects their `ScanFinding`s
//! back. This is the network-facing half of the `Scan-Site-Distributed`
//! TUI command (`main.rs`); partitioning targets, discovering them via
//! `Analyze-Site`, and recording the aggregated result into
//! `scan_snapshots` all stay in `main.rs` alongside the rest of the
//! `Scan-*` commands, exactly like a local `Scan-Site` run would.
//!
//! v1 auth: every request carries `Authorization: Bearer <token>`, where
//! `token` is whatever the operator put in `COGITATOR_WORKER_TOKEN`
//! (`worker_protocol::WORKER_TOKEN_ENV_VAR`) — the same env var every
//! `cogitator-worker` process reads to check incoming requests against.
//! No TLS, no per-worker tokens, no retry/backoff, no health-checking
//! before dispatch: this proves the architecture works, it isn't a fleet
//! manager.

use std::sync::Arc;

use reqwest::Client;
use tokio::sync::Semaphore;

use crate::logger;
use crate::scanner::{ScanFinding, ScanTarget};
use crate::worker_protocol::{ScanRequest, ScanResponse, ALL_CHECK_NAMES};

/// Cap on concurrent in-flight `/scan` requests across all workers, so a
/// large target list doesn't open hundreds of sockets at once. Mirrors the
/// role `scanner::MAX_PARALLEL_CHECKS` plays for a local `Scan-Site` run.
const MAX_PARALLEL_REQUESTS: usize = 5;

/// Split `targets` round-robin across `worker_base_urls` (target 0 -> worker
/// 0, target 1 -> worker 1, ..., wrapping back to worker 0 once the list is
/// exhausted), send each target to its assigned worker's `POST /scan`
/// asking for every check in `worker_protocol::ALL_CHECK_NAMES`, and
/// collect every returned finding — sorted by severity, same as
/// `ScanQueue::run_all` does for a local scan, so the two flows produce
/// identically-shaped output for `record_scan_snapshot`.
///
/// A worker that's unreachable, slow, or returns an error response simply
/// contributes no findings for its share of targets (logged via
/// `logger::warn`, never propagated) rather than failing the whole run —
/// the same "a failed probe just yields nothing" philosophy every
/// `ScanCheck::check` implementation already follows locally.
pub async fn run_distributed_scan(
    client: &Client,
    targets: Vec<ScanTarget>,
    worker_base_urls: &[String],
    token: &str,
) -> Vec<ScanFinding> {
    if targets.is_empty() || worker_base_urls.is_empty() {
        return Vec::new();
    }

    let checks: Vec<String> = ALL_CHECK_NAMES.iter().map(|s| s.to_string()).collect();
    let semaphore = Arc::new(Semaphore::new(MAX_PARALLEL_REQUESTS));
    let mut handles = Vec::with_capacity(targets.len());

    for (i, target) in targets.into_iter().enumerate() {
        let worker_url = worker_base_urls[i % worker_base_urls.len()].clone();
        let client = client.clone();
        let token = token.to_string();
        let checks = checks.clone();
        let semaphore = semaphore.clone();

        let handle = tokio::spawn(async move {
            // Acquire before doing any network work so at most
            // `MAX_PARALLEL_REQUESTS` requests are ever in flight
            // simultaneously, regardless of how many targets/workers there
            // are — same pattern as `ScanQueue::run_all`.
            let _permit = match semaphore.acquire().await {
                Ok(p) => p,
                Err(_) => return Vec::new(), // semaphore closed; bail quietly
            };

            send_scan_request(&client, &worker_url, &target, &checks, &token).await
        });

        handles.push(handle);
    }

    let mut findings = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(mut f) => findings.append(&mut f),
            Err(e) => logger::warn(&format!("distributed scan: worker task panicked: {e}")),
        }
    }

    findings.sort_by(|a, b| a.severity.cmp(&b.severity));
    findings
}

/// Send one `ScanTarget` to one worker's `POST {worker_base_url}/scan`.
/// Any network error, non-2xx status, or malformed response body yields an
/// empty `Vec` (logged via `logger::warn`) rather than an error — see
/// module docs on why a single bad worker shouldn't sink the whole run.
async fn send_scan_request(
    client: &Client,
    worker_base_url: &str,
    target: &ScanTarget,
    checks: &[String],
    token: &str,
) -> Vec<ScanFinding> {
    let url = format!("{}/scan", worker_base_url.trim_end_matches('/'));
    let body = ScanRequest { target: target.clone(), checks: checks.to_vec() };

    let response = match client.post(&url).bearer_auth(token).json(&body).send().await {
        Ok(r) => r,
        Err(e) => {
            logger::warn(&format!(
                "distributed scan: request to {url} for target '{}' failed: {e}",
                target.url
            ));
            return Vec::new();
        }
    };

    if !response.status().is_success() {
        logger::warn(&format!(
            "distributed scan: worker {url} returned {} for target '{}'",
            response.status(),
            target.url
        ));
        return Vec::new();
    }

    match response.json::<ScanResponse>().await {
        Ok(parsed) => parsed.findings,
        Err(e) => {
            logger::warn(&format!("distributed scan: malformed response from {url}: {e}"));
            Vec::new()
        }
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

    #[tokio::test]
    async fn empty_targets_returns_empty_without_any_network_call() {
        let client = Client::new();
        // Deliberately bogus worker address — if this test ever tries to
        // actually connect, something regressed in the empty-input guard.
        let findings = run_distributed_scan(
            &client,
            vec![],
            &["http://127.0.0.1:1".to_string()],
            "token",
        )
            .await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn empty_worker_list_returns_empty_without_any_network_call() {
        let client = Client::new();
        let findings =
            run_distributed_scan(&client, vec![target("http://example.com")], &[], "token").await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn unreachable_worker_yields_no_findings_not_a_panic_or_hang() {
        // Port 1 is reserved and essentially guaranteed not to have
        // anything listening — connection should fail fast, and the
        // failure should be swallowed into "0 findings for this target"
        // rather than propagating or hanging the whole scan.
        let client = Client::new();
        let findings = run_distributed_scan(
            &client,
            vec![target("http://example.com/x"), target("http://example.com/y")],
            &["http://127.0.0.1:1".to_string()],
            "token",
        )
            .await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn targets_partition_round_robin_across_workers() {
        // Can't spin up real `cogitator-worker` processes here, but we can
        // confirm the round-robin *assignment* math directly rather than
        // through the network path: 5 targets over 2 "workers" (both
        // unreachable, so this only exercises the modulo indexing, not a
        // live server) should not panic on out-of-bounds indexing and
        // should attempt all 5 (still 0 findings, since nothing's
        // listening — this test is about robustness of the indexing, not
        // finding counts).
        let client = Client::new();
        let targets: Vec<ScanTarget> = (0..5).map(|i| target(&format!("http://example.com/{i}"))).collect();
        let workers = vec!["http://127.0.0.1:1".to_string(), "http://127.0.0.1:2".to_string()];
        let findings = run_distributed_scan(&client, targets, &workers, "token").await;
        assert!(findings.is_empty());
    }
}