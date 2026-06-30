/// Central configuration for Cogitator.
///
/// All magic numbers live here. Import the relevant constant where needed
/// rather than scattering literals throughout the codebase.

// ── Proxy ────────────────────────────────────────────────────────────────────

/// Address the proxy guard listens on.
pub const PROXY_ADDR: &str = "127.0.0.1:8080";

/// How long (ms) to wait after cancelling the proxy token before tearing
/// down the terminal, giving the accept loop time to log its shutdown line.
pub const PROXY_SHUTDOWN_GRACE_MS: u64 = 100;

// ── Health monitoring ────────────────────────────────────────────────────────

/// CPU usage % above which a process is flagged as **critical** (health check
/// alert that replaces the main output buffer).
pub const CPU_CRITICAL_THRESHOLD: f32 = 80.0;

/// CPU usage % above which a process appears in `Find-Suspicious` results.
pub const CPU_SUSPICIOUS_THRESHOLD: f32 = 5.0;

/// How often the background health check runs.
pub const HEALTH_CHECK_INTERVAL_SECS: u64 = 5;

// ── Proxy rate limiting ───────────────────────────────────────────────────────

/// Maximum number of requests a single IP may make within one window before
/// the interceptor flags it as throttled.
pub const RATE_LIMIT_MAX_REQUESTS: u64 = 100;

/// Duration of the sliding rate-limit window in seconds.
/// The counter for an IP resets when this many seconds have elapsed since the
/// first request in the current window.
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;


/// Minimum acceptable HSTS `max-age` in seconds (30 days).
/// Values below this incur a score penalty in `crypto_forensic`.
pub const HSTS_MIN_MAX_AGE_SECS: u64 = 2_592_000;

// ── WebSocket interception ───────────────────────────────────────────────────

/// How much of a WS frame's payload is copied into the `History` preview
/// (`RequestRecord::body`). Mirrors `proxy_guard::MAX_HISTORY_BODY_BYTES` in
/// spirit but deliberately much smaller — WS rows in History are for
/// spotting patterns frame-by-frame, not full replay of a chatty stream.
pub const WS_PAYLOAD_PREVIEW_BYTES: usize = 256;