use hyper::body::Incoming;
use hyper::Request;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use crate::config;
use crate::history::{History, RequestRecord};
use crate::logger;

// ─── Intercept action ────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum InterceptAction {
    Forward,
    Drop,
    /// Operator-edited replacement for the request.
    ///
    /// Deliberately *not* `Request<Incoming>`: `Incoming` is hyper's
    /// connection-bound streaming body — it can only be produced by hyper
    /// itself while reading off a live socket, so there is no way to build
    /// one by hand from text typed into the TUI editor. Carrying the edited
    /// parts instead lets whatever eventually consumes this action (the
    /// forwarding path in `proxy_guard`/`tls_mitm`) rebuild a request using
    /// whatever body type it forwards with (e.g. `Full<Bytes>`).
    Modify {
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
}

// ─── WebSocket frame action (mirrors InterceptAction, one level simpler) ────
//
// WS frames don't carry the request/response duality HTTP does, so this is
// deliberately smaller than `InterceptAction`: just the payload can be
// edited (opcode/fin are preserved from the original frame by whichever
// caller resolves this — see `ws_interceptor::pump_direction`).
#[derive(Debug)]
pub enum WsFrameAction {
    Forward,
    Drop,
    /// Operator-edited replacement payload.
    Replace(Vec<u8>),
}

/// A WS frame parked for manual review, analogous to [`FrozenRequest`].
pub struct FrozenWsFrame {
    pub id: u64,
    /// "client→server" / "server→client".
    pub direction: &'static str,
    /// Opcode name ("Text", "Binary", "Ping", "Pong", "Close", …).
    pub opcode: String,
    /// Payload preview (already capped at `config::WS_PAYLOAD_PREVIEW_BYTES`
    /// by the caller) — enough to review/edit from the TUI without holding
    /// arbitrarily large frames in the queue.
    pub payload: Vec<u8>,
    pub tx: oneshot::Sender<WsFrameAction>,
}

/// Read-only snapshot of a [`FrozenWsFrame`], safe to clone out from behind
/// the queue's mutex for rendering in the TUI. Mirrors [`FrozenSummary`].
#[derive(Debug, Clone)]
pub struct FrozenWsSummary {
    pub id: u64,
    pub direction: &'static str,
    pub opcode: String,
    pub payload: Vec<u8>,
}



pub struct FrozenRequest {
    pub id: u64,
    pub method: String,
    pub uri: String,
    pub host: String,
    /// Snapshot of the original request headers, captured at freeze time —
    /// kept alongside `req` so the TUI can render/edit them without needing
    /// to touch the live `Incoming` body.
    pub headers: Vec<(String, String)>,
    pub req: Option<Request<Incoming>>,
    pub tx: oneshot::Sender<InterceptAction>,
}

// ─── Rate limiting ────────────────────────────────────────────────────────────

/// Outcome of a single rate-limit check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitVerdict {
    /// Request is within the allowed window; `count` is the updated tally.
    Allowed { count: u64 },
    /// IP has exceeded the threshold; `count` is the current tally.
    Throttled { count: u64, limit: u64 },
}

/// Per-IP sliding-window state.
struct WindowState {
    /// Number of requests seen in the current window.
    count: u64,
    /// When the current window started.
    window_start: Instant,
}

/// Thread-safe, per-IP request counter.
///
/// Uses a fixed-duration tumbling window: the counter resets the first time a
/// request arrives after `config::RATE_LIMIT_WINDOW_SECS` have elapsed since
/// the window opened.  This is intentionally simple — it is a DoS early-warning
/// system, not a precision token-bucket limiter.
struct RateLimiter {
    window: Duration,
    max_requests: u64,
    /// Keyed by remote IP address.
    table: Mutex<HashMap<IpAddr, WindowState>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            window: Duration::from_secs(config::RATE_LIMIT_WINDOW_SECS),
            max_requests: config::RATE_LIMIT_MAX_REQUESTS,
            table: Mutex::new(HashMap::new()),
        }
    }

    /// Record one request for `ip` and return the verdict.
    ///
    /// Stale entries for other IPs are evicted opportunistically on every call
    /// to bound memory growth without needing a separate housekeeping task.
    fn check(&self, ip: IpAddr) -> RateLimitVerdict {
        let now = Instant::now();
        let mut table = self.table.lock().unwrap();

        // Opportunistic eviction: remove windows that expired more than one
        // full window ago so the map does not grow unboundedly in long sessions.
        let evict_cutoff = self.window * 2;
        table.retain(|_, s| now.duration_since(s.window_start) < evict_cutoff);

        let state = table.entry(ip).or_insert_with(|| WindowState {
            count: 0,
            window_start: now,
        });

        // Reset the window if it has expired.
        if now.duration_since(state.window_start) >= self.window {
            state.count = 0;
            state.window_start = now;
        }

        state.count += 1;
        let count = state.count;

        if count > self.max_requests {
            RateLimitVerdict::Throttled { count, limit: self.max_requests }
        } else {
            RateLimitVerdict::Allowed { count }
        }
    }
}

// ─── Interceptor engine ───────────────────────────────────────────────────────

pub struct InterceptorEngine {
    pub queue: Arc<Mutex<VecDeque<FrozenRequest>>>,
    pub request_counter: Arc<std::sync::atomic::AtomicU64>,
    rate_limiter: Arc<RateLimiter>,
    /// Every request that makes it past the rate limiter is recorded here,
    /// keyed by the same `id` used for the intercept queue, so the TUI can
    /// browse history independently of whether a request was ever frozen
    /// for manual review.
    pub history: History,
    /// Separate frozen-frame queue for WebSocket traffic (see
    /// `ws_interceptor.rs`). Kept apart from `queue` above since a WS frame
    /// isn't a `FrozenRequest` (no method/URI, payload-only edits) — same
    /// oneshot-channel pattern, different id space and item shape.
    ws_queue: Arc<Mutex<VecDeque<FrozenWsFrame>>>,
    ws_id_counter: Arc<std::sync::atomic::AtomicU64>,
    /// Off by default. Freezing *every* WS frame unconditionally would stall
    /// a chatty connection (frequent app-level pings/keepalives are common)
    /// the moment the InterceptorView's Frozen sub-view isn't being watched
    /// — so unlike HTTP requests (always queued, subject only to rate
    /// limiting), WS interception is opt-in, toggled from the TUI.
    ws_intercept_enabled: Arc<std::sync::atomic::AtomicBool>,
}

impl Clone for InterceptorEngine {
    fn clone(&self) -> Self {
        Self {
            queue: self.queue.clone(),
            request_counter: self.request_counter.clone(),
            rate_limiter: self.rate_limiter.clone(),
            history: self.history.clone(),
            ws_queue: self.ws_queue.clone(),
            ws_id_counter: self.ws_id_counter.clone(),
            ws_intercept_enabled: self.ws_intercept_enabled.clone(),
        }
    }
}

impl InterceptorEngine {
    pub fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
            request_counter: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            rate_limiter: Arc::new(RateLimiter::new()),
            history: History::new(),
            ws_queue: Arc::new(Mutex::new(VecDeque::new())),
            ws_id_counter: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            ws_intercept_enabled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Check the rate limit for `ip` without recording a request.
    ///
    /// Useful for the TUI status panel — lets the UI display per-IP tallies
    /// without side-effects.
    pub fn rate_limit_verdict(&self, ip: IpAddr) -> RateLimitVerdict {
        self.rate_limiter.check(ip)
    }

    /// Freeze a request for manual review, subject to rate limiting.
    ///
    /// If the source IP has exceeded `config::RATE_LIMIT_MAX_REQUESTS` within
    /// the current window the request is **not** queued: the returned receiver
    /// will immediately yield `InterceptAction::Drop` and a warning is logged.
    ///
    /// Otherwise the request is enqueued normally and the caller awaits the
    /// receiver for the operator's decision.
    pub fn freeze_request(
        &self,
        req: Request<Incoming>,
        host: String,
        peer_ip: IpAddr,
    ) -> oneshot::Receiver<InterceptAction> {
        let (tx, rx) = oneshot::channel();

        match self.rate_limiter.check(peer_ip) {
            RateLimitVerdict::Throttled { count, limit } => {
                logger::warn(&format!(
                    "Rate limit exceeded for {}: {} requests in {}s window (limit {}). Dropping.",
                    peer_ip,
                    count,
                    config::RATE_LIMIT_WINDOW_SECS,
                    limit,
                ));
                // Send Drop immediately; if the receiver is gone we just discard.
                let _ = tx.send(InterceptAction::Drop);
            }
            RateLimitVerdict::Allowed { count } => {
                let id = self.request_counter
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let method = req.method().to_string();
                let uri = req.uri().to_string();

                if count == 1 {
                    // First request in a new window — good moment to log the
                    // window opening without spamming on every request.
                    logger::debug(&format!(
                        "Rate limiter: new window opened for {} (limit {}/{}s)",
                        peer_ip,
                        config::RATE_LIMIT_MAX_REQUESTS,
                        config::RATE_LIMIT_WINDOW_SECS,
                    ));
                }

                // Record the request in history immediately, before we know
                // anything about the response. `response_*` fields stay
                // `None`/empty until `record_response` is called once the
                // origin replies (or the operator drops/modifies it).
                let headers: Vec<(String, String)> = req
                    .headers()
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.to_string(),
                            value.to_str().unwrap_or("<non-utf8>").to_string(),
                        )
                    })
                    .collect();
                let path = req.uri().path().to_string();

                self.history.push(RequestRecord {
                    id,
                    timestamp: Instant::now(),
                    method: method.clone(),
                    host: host.clone(),
                    path,
                    headers: headers.clone(),
                    // The request body lives in `Incoming` and is consumed
                    // by whatever forwards/displays this request later —
                    // capturing it here would require buffering the whole
                    // body up front. Left empty for now; revisit if/when the
                    // proxy path buffers bodies for replay.
                    body: Vec::new(),
                    response_status: None,
                    response_headers: Vec::new(),
                    response_body: None,
                    response_time_ms: None,
                    tags: Vec::new(),
                    stream_id: None,
                });

                let frozen = FrozenRequest {
                    id,
                    method,
                    uri,
                    host,
                    headers,
                    req: Some(req),
                    tx,
                };
                if let Ok(mut q) = self.queue.lock() {
                    q.push_back(frozen);
                }
            }
        }

        rx
    }

    /// Fill in the response side of the history record for `id` once the
    /// origin has replied (or the operator decided to drop/modify it).
    /// No-op if the record was already evicted under history's `MAX_RECORDS`
    /// cap.
    pub fn record_response(
        &self,
        id: u64,
        status: u16,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
        elapsed: Duration,
    ) {
        self.history.record_response(id, status, headers, body, elapsed);
    }

    pub fn get_next_pending(&self) -> Option<FrozenRequest> {
        self.queue.lock().unwrap().pop_front()
    }

    /// Read-only summary of every request currently parked in the intercept
    /// queue, for the TUI's "Frozen" list. Does not consume anything — safe
    /// to call every render tick.
    pub fn frozen_snapshot(&self) -> Vec<FrozenSummary> {
        self.queue
            .lock()
            .unwrap()
            .iter()
            .map(|f| FrozenSummary {
                id: f.id,
                method: f.method.clone(),
                uri: f.uri.clone(),
                host: f.host.clone(),
                headers: f.headers.clone(),
            })
            .collect()
    }

    /// Remove the frozen request with the given `id` from the queue, if
    /// still present, so the caller can decide its `InterceptAction` (it
    /// owns the `tx` once removed). Returns `None` if it was already
    /// resolved or evicted by the time this is called.
    pub fn take_frozen(&self, id: u64) -> Option<FrozenRequest> {
        let mut q = self.queue.lock().unwrap();
        let idx = q.iter().position(|f| f.id == id)?;
        // `VecDeque::remove` preserves the relative order of the remaining
        // elements, which keeps the TUI list stable across removals.
        q.remove(idx)
    }

    // ── WebSocket frame interception ────────────────────────────────────

    /// `true` if WS frames should be parked for operator review instead of
    /// auto-forwarded. Toggled from the TUI (the 'w' freeze toggle in
    /// `InterceptorView`'s Frozen sub-view — distinct from the 'w' *filter*
    /// toggle in History mode, which only narrows what's displayed).
    pub fn ws_intercept_enabled(&self) -> bool {
        self.ws_intercept_enabled.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn set_ws_intercept_enabled(&self, enabled: bool) {
        self.ws_intercept_enabled.store(enabled, std::sync::atomic::Ordering::SeqCst);
    }

    /// Park a WS frame for manual review and return the receiver the caller
    /// (`ws_interceptor::pump_direction`) awaits for the operator's
    /// decision. Mirrors `freeze_request`'s oneshot pattern, minus rate
    /// limiting — WS frames aren't subject to the HTTP rate limiter.
    pub fn freeze_ws_frame(
        &self,
        direction: &'static str,
        opcode: String,
        payload: Vec<u8>,
    ) -> oneshot::Receiver<WsFrameAction> {
        let (tx, rx) = oneshot::channel();
        let id = self.ws_id_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let frozen = FrozenWsFrame { id, direction, opcode, payload, tx };
        if let Ok(mut q) = self.ws_queue.lock() {
            q.push_back(frozen);
        }
        rx
    }

    /// Read-only summary of every WS frame currently parked for review, for
    /// the TUI's Frozen sub-view. Safe to call every render tick.
    pub fn frozen_ws_snapshot(&self) -> Vec<FrozenWsSummary> {
        self.ws_queue
            .lock()
            .unwrap()
            .iter()
            .map(|f| FrozenWsSummary {
                id: f.id,
                direction: f.direction,
                opcode: f.opcode.clone(),
                payload: f.payload.clone(),
            })
            .collect()
    }

    /// Remove the frozen WS frame with `id` from the queue so the caller can
    /// resolve its `tx`. Mirrors `take_frozen`.
    pub fn take_frozen_ws(&self, id: u64) -> Option<FrozenWsFrame> {
        let mut q = self.ws_queue.lock().unwrap();
        let idx = q.iter().position(|f| f.id == id)?;
        q.remove(idx)
    }
}

/// Read-only view of a [`FrozenRequest`], safe to clone out from behind the
/// queue's mutex for rendering in the TUI.
#[derive(Debug, Clone)]
pub struct FrozenSummary {
    pub id: u64,
    pub method: String,
    pub uri: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
}
#[cfg(test)]
mod ws_tests {
    use super::*;

    #[test]
    fn ws_intercept_toggle_defaults_off() {
        let engine = InterceptorEngine::new();
        assert!(!engine.ws_intercept_enabled());
        engine.set_ws_intercept_enabled(true);
        assert!(engine.ws_intercept_enabled());
    }

    #[tokio::test]
    async fn freeze_ws_frame_parks_and_resolves() {
        let engine = InterceptorEngine::new();
        let rx = engine.freeze_ws_frame("client→server", "Text".to_string(), b"hi".to_vec());

        let snapshot = engine.frozen_ws_snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].opcode, "Text");

        let id = snapshot[0].id;
        let frozen = engine.take_frozen_ws(id).expect("frame should still be queued");
        assert!(engine.frozen_ws_snapshot().is_empty());

        let _ = frozen.tx.send(WsFrameAction::Replace(b"bye".to_vec()));
        match rx.await {
            Ok(WsFrameAction::Replace(payload)) => assert_eq!(payload, b"bye"),
            other => panic!("expected Replace, got {other:?}"),
        }
    }

    #[test]
    fn take_frozen_ws_missing_id_is_none() {
        let engine = InterceptorEngine::new();
        assert!(engine.take_frozen_ws(999).is_none());
    }
}