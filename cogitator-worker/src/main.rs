//! `cogitator-worker` — a minimal HTTP scan worker for Cogitator's
//! distributed scanning mode.
//!
//! Exposes exactly two endpoints, both requiring `Authorization: Bearer
//! <COGITATOR_WORKER_TOKEN>` (matching this process's own env var of the
//! same name — see `require_auth`):
//!
//!   POST /scan     { "target": ScanTarget, "checks": ["..."] }
//!                  -> { "findings": [ScanFinding, ...] }
//!   GET  /health   -> { "status": "ok", "available_checks": ["..."] }
//!
//! Every `ScanCheck` implementation it runs (`checks::sqli`,
//! `checks::sqli_blind`, `checks::traversal`, `checks::xss`,
//! `checks::ssrf`, `checks::xxe`) is the exact same code the TUI's
//! `Scan-Site`/`Scan-Request` commands run locally — reused unchanged via
//! the root crate's lib target (see `../src/lib.rs`), not reimplemented or
//! forked here.
//!
//! This is v1: it proves the distributed-scanning architecture works. It
//! is deliberately **not** a fleet-management system — no TLS termination,
//! no per-worker tokens, no discovery/registration protocol, no
//! retry/backoff on the client side (that lives in the coordinator's
//! `distributed.rs`). Auth is one shared bearer token via an env var.
//!
//! ## Running
//! ```text
//! COGITATOR_WORKER_TOKEN=changeme cogitator-worker
//! # optional: COGITATOR_WORKER_BIND=0.0.0.0:9500 (default shown)
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};

use cogitator::checks;
use cogitator::config;
use cogitator::logger;
use cogitator::oob::OobChannel;
use cogitator::scanner::ScanCheck;
use cogitator::worker_protocol::{
    HealthResponse, ScanRequest, ScanResponse, WORKER_TOKEN_ENV_VAR,
};

/// Env var overriding the default bind address.
const BIND_ENV_VAR: &str = "COGITATOR_WORKER_BIND";
const DEFAULT_BIND: &str = "0.0.0.0:9500";

/// Shared state handed to every request handler via axum's `State`
/// extractor. `checks` never changes after startup, and `reqwest::Client`
/// is cheap to clone (internally `Arc`-backed), so this is plain data, not
/// behind an extra lock.
struct AppState {
    token: String,
    checks: Vec<Arc<dyn ScanCheck>>,
    client: reqwest::Client,
}

/// Build the registry of checks this worker can run — the exact same six
/// `ScanCheck` impls, wired up the exact same way (including the OOB
/// channel sharing between SSRF and XXE), as `main.rs`'s `scan_checks_vec`
/// in the TUI. If `cogitator::config::OOB_DOMAIN` is unset, `oob_channel`
/// stays `None` and both checks fall back to their OOB-independent
/// detection paths — same graceful-degradation behavior as the TUI.
async fn build_registry() -> Vec<Arc<dyn ScanCheck>> {
    let oob_channel: Option<OobChannel> = if config::OOB_DOMAIN.is_empty() {
        logger::log_event(
            "cogitator-worker: OOB domain not configured (config::OOB_DOMAIN is empty) — \
             SSRF's OOB phase and XXE's OOB phase are disabled on this worker.",
        );
        None
    } else {
        match config::OOB_BIND_ADDR.parse() {
            Ok(bind_addr) => match OobChannel::new(bind_addr, config::OOB_DOMAIN).await {
                Ok(channel) => Some(channel),
                Err(e) => {
                    logger::error(&format!(
                        "cogitator-worker: failed to start OOB listener on {}: {e}",
                        config::OOB_BIND_ADDR
                    ));
                    None
                }
            },
            Err(e) => {
                logger::error(&format!(
                    "cogitator-worker: config::OOB_BIND_ADDR ('{}') is not a valid socket address: {e}",
                    config::OOB_BIND_ADDR
                ));
                None
            }
        }
    };

    vec![
        Arc::new(checks::sqli::SqliCheck::new()),
        Arc::new(checks::sqli_blind::SqliBlindCheck::new()),
        Arc::new(checks::traversal::TraversalCheck::new()),
        Arc::new(checks::xss::XssCheck::new()),
        Arc::new(checks::ssrf::SsrfCheck::new(oob_channel.clone())),
        Arc::new(checks::xxe::XxeCheck::new(oob_channel)),
    ]
}

/// Check the `Authorization: Bearer <token>` header against this worker's
/// configured token. Returns `Err` with the response to send back
/// (401 — deliberately generic message, no distinction between "missing
/// header" and "wrong token" so a prober can't tell which one it hit).
fn require_auth(headers: &HeaderMap, expected_token: &str) -> Result<(), Response> {
    let provided = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match provided {
        Some(t) if t == expected_token => Ok(()),
        _ => Err((StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response()),
    }
}

async fn health_handler(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_auth(&headers, &state.token) {
        return resp;
    }

    Json(HealthResponse {
        status: "ok".to_string(),
        available_checks: state.checks.iter().map(|c| c.name().to_string()).collect(),
    })
        .into_response()
}

async fn scan_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ScanRequest>,
) -> Response {
    if let Err(resp) = require_auth(&headers, &state.token) {
        return resp;
    }

    // Empty `checks` means "run everything registered" (see
    // `worker_protocol::ScanRequest` doc comment); `distributed.rs` always
    // sends an explicit list, but a hand-rolled `curl` request is free to
    // omit it.
    let run_all = req.checks.is_empty();

    let mut findings = Vec::new();
    for check in &state.checks {
        if run_all || req.checks.iter().any(|name| name == check.name()) {
            findings.extend(check.check(&state.client, &req.target).await);
        }
    }

    logger::log_event(&format!(
        "cogitator-worker: scanned '{}' ({} check(s) requested) -> {} finding(s)",
        req.target.url,
        req.checks.len(),
        findings.len()
    ));

    Json(ScanResponse { findings }).into_response()
}

#[tokio::main]
async fn main() {
    // Reuses the exact same structured JSON logger the TUI uses (see
    // `logger.rs` module docs) — writes its own `cogitator.log` in this
    // process's working directory.
    if let Err(e) = logger::init() {
        eprintln!("cogitator-worker: failed to initialize logger: {e}");
    }

    let token = match std::env::var(WORKER_TOKEN_ENV_VAR) {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!(
                "cogitator-worker: {} is not set — refusing to start unauthenticated. \
                 Set it to a shared secret; the coordinator's Scan-Site-Distributed \
                 command reads the same env var.",
                WORKER_TOKEN_ENV_VAR
            );
            std::process::exit(1);
        }
    };

    let bind_addr: SocketAddr = match std::env::var(BIND_ENV_VAR)
        .unwrap_or_else(|_| DEFAULT_BIND.to_string())
        .parse()
    {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("cogitator-worker: invalid {} value: {e}", BIND_ENV_VAR);
            std::process::exit(1);
        }
    };

    let checks = build_registry().await;
    let check_count = checks.len();

    let state = Arc::new(AppState { token, checks, client: reqwest::Client::new() });

    let app = Router::new()
        .route("/scan", post(scan_handler))
        .route("/health", get(health_handler))
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cogitator-worker: failed to bind {bind_addr}: {e}");
            std::process::exit(1);
        }
    };

    logger::log_event(&format!(
        "cogitator-worker: listening on {bind_addr} ({check_count} check(s) registered)"
    ));
    println!("cogitator-worker listening on {bind_addr} ({check_count} check(s) registered)");

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("cogitator-worker: server error: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn require_auth_rejects_missing_header() {
        let headers = HeaderMap::new();
        assert!(require_auth(&headers, "secret").is_err());
    }

    #[test]
    fn require_auth_rejects_wrong_token() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer wrong"));
        assert!(require_auth(&headers, "secret").is_err());
    }

    #[test]
    fn require_auth_rejects_missing_bearer_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("secret"));
        assert!(require_auth(&headers, "secret").is_err());
    }

    #[test]
    fn require_auth_accepts_matching_token() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer secret"));
        assert!(require_auth(&headers, "secret").is_ok());
    }

    #[tokio::test]
    async fn build_registry_registers_all_six_checks() {
        let checks = build_registry().await;
        assert_eq!(checks.len(), 6);
        let names: Vec<&str> = checks.iter().map(|c| c.name()).collect();
        assert!(names.contains(&"SQL Injection (error-based)"));
        assert!(names.contains(&"XML External Entity (XXE)"));
    }

    #[tokio::test]
    async fn registry_names_match_worker_protocol_all_check_names() {
        // Guards the "keep in sync" warning in worker_protocol.rs's doc
        // comment: if a check is added/renamed here without updating
        // `ALL_CHECK_NAMES`, this test catches it instead of the mismatch
        // silently manifesting as "that check never runs distributed".
        use cogitator::worker_protocol::ALL_CHECK_NAMES;

        let checks = build_registry().await;
        let mut registered: Vec<&str> = checks.iter().map(|c| c.name()).collect();
        registered.sort_unstable();

        let mut expected: Vec<&str> = ALL_CHECK_NAMES.to_vec();
        expected.sort_unstable();

        assert_eq!(registered, expected);
    }
}