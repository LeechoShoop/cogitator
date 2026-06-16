use hyper::body::Incoming;
use hyper::Request;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use crate::config;
use crate::logger;

// ─── Intercept action ────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum InterceptAction {
    Forward,
    Drop,
    Modify(Request<Incoming>),
}

// ─── Frozen request (queue entry) ────────────────────────────────────────────

pub struct FrozenRequest {
    pub id: u64,
    pub method: String,
    pub uri: String,
    pub host: String,
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
}

impl Clone for InterceptorEngine {
    fn clone(&self) -> Self {
        Self {
            queue: self.queue.clone(),
            request_counter: self.request_counter.clone(),
            rate_limiter: self.rate_limiter.clone(),
        }
    }
}

impl InterceptorEngine {
    pub fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
            request_counter: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            rate_limiter: Arc::new(RateLimiter::new()),
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

                let frozen = FrozenRequest {
                    id,
                    method,
                    uri,
                    host,
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

    pub fn get_next_pending(&self) -> Option<FrozenRequest> {
        self.queue.lock().unwrap().pop_front()
    }
}