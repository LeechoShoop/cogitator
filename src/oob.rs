//! Out-of-band (OOB) interaction listener for Cogitator.
//!
//! Some vulnerability classes (blind SSRF, XXE with external entity
//! resolution, blind command injection via DNS exfil, etc.) never reflect
//! anything into the HTTP response — the only observable signal is that the
//! *target* made a network callback somewhere else, on its own schedule.
//! This module gives Cogitator's active checks a way to notice that: hand
//! out a unique token, embed it in a payload as `{token}.<your-oob-domain>`,
//! send the payload, then ask whether that token's subdomain was ever
//! looked up.
//!
//! The implementation is a minimal authoritative DNS server: any lookup
//! for `<anything>.<domain>` is logged against the leftmost label (the
//! token) and answered with `NXDOMAIN`. We don't need a real answer — the
//! *lookup itself* is the signal, and libc/most HTTP clients issuing an
//! SSRF/XXE callback only need to attempt resolution to prove the
//! vulnerability, regardless of what comes back.
//!
//! # ⚠️ Operators must own the OOB domain
//!
//! This module deliberately does **not** ship a default domain or fall
//! back to any third-party "collaborator"-style service (e.g. Burp
//! Collaborator, interactsh, etc.). Pointing Cogitator at infrastructure
//! you don't control means:
//!
//!   - every token you ever mint — and therefore every target you test —
//!     is visible to whoever runs that service, and
//!   - you have no guarantee the DNS responses you get back (or the timing
//!     of when a "hit" is reported) haven't been tampered with.
//!
//! To use this module you need:
//!
//!   1. A domain (or subdomain) you control, e.g. `oob.yourcompany.tld`.
//!   2. An `NS` record for that domain (or a glue `A`/`AAAA` record, per
//!      your registrar's requirements) pointing at the public IP of the
//!      host where [`OobChannel::new`] binds its UDP socket.
//!   3. Port 53/UDP reachable from the public internet on that host (or a
//!      firewall/NAT rule forwarding it there) — `bind_addr` here is just
//!      the local socket Cogitator listens on, and DNS resolution for the
//!      domain has to actually route queries to it.
//!
//! Pass that domain into [`OobChannel::new`] as `domain`. Nothing in this
//! module will ever contact an external service on your behalf.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_server::authority::MessageResponseBuilder;
use hickory_server::proto::op::{Header, ResponseCode};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo, ServerFuture};
use rand::RngCore;
use tokio::net::UdpSocket;

use crate::logger;

/// Random bytes per token before hex-encoding (32 hex chars — enough that
/// guessing a live token by brute-force DNS scanning is infeasible within
/// any check's timeout window).
const TOKEN_BYTES: usize = 16;

/// How often `was_triggered` re-checks the state while waiting.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// How long a token is kept in `pending` (issued, never triggered) or
/// `triggered` (issued, resolved) before opportunistic GC drops it. Chosen
/// generously relative to any realistic check timeout so a slow-to-fire
/// OOB callback (e.g. a queued async job on the target) still counts.
const RECORD_RETENTION: Duration = Duration::from_secs(3600);

/// Internal bookkeeping shared between `OobChannel` handles and the DNS
/// request handler running inside `ServerFuture`.
struct OobState {
    /// token -> time issued, for tokens with no hit yet.
    pending: HashMap<String, Instant>,
    /// token -> time of the *first* DNS lookup observed for it.
    triggered: HashMap<String, Instant>,
}

impl OobState {
    fn new() -> Self {
        Self { pending: HashMap::new(), triggered: HashMap::new() }
    }

    /// Drop anything older than `RECORD_RETENTION` from both maps.
    /// Called opportunistically on every `new_token` / hit rather than on
    /// a timer, which is enough to keep memory bounded across a long scan
    /// session without needing a background task of its own.
    fn gc(&mut self) {
        let cutoff = Instant::now();
        self.pending.retain(|_, issued_at| cutoff.duration_since(*issued_at) < RECORD_RETENTION);
        self.triggered.retain(|_, hit_at| cutoff.duration_since(*hit_at) < RECORD_RETENTION);
    }
}

/// Handle to the OOB listener. Cheaply `Clone`-able (wraps `Arc`s) so every
/// check that wants to mint a probe token can hold its own copy.
#[derive(Clone)]
pub struct OobChannel {
    /// The operator-controlled domain, without a leading dot
    /// (e.g. `oob.yourcompany.tld`). See module docs for what "controlled"
    /// requires.
    domain: Arc<str>,
    state: Arc<Mutex<OobState>>,
}

impl OobChannel {
    /// Bind a minimal authoritative DNS server on `bind_addr` (UDP) and
    /// start answering queries in the background. Returns immediately once
    /// the socket is bound; the accept loop runs as a spawned task for the
    /// lifetime of the returned `OobChannel` (dropping every clone of it
    /// does *not* currently stop the task — this is a long-lived,
    /// once-per-process listener by design).
    ///
    /// `domain` must be a domain (or subdomain) you control — see the
    /// module-level docs. This function does not validate DNS delegation;
    /// it only binds the local socket and starts answering. If the `NS`
    /// records for `domain` don't actually point here, no real-world
    /// lookups will ever arrive and every `was_triggered` call will time
    /// out.
    pub async fn new(bind_addr: SocketAddr, domain: impl Into<String>) -> io::Result<Self> {
        let domain: Arc<str> = Arc::from(domain.into());
        let state = Arc::new(Mutex::new(OobState::new()));

        let socket = UdpSocket::bind(bind_addr).await?;
        logger::log_event(&format!(
            "OOB listener bound on {bind_addr}, authoritative for *.{domain}"
        ));

        let handler = OobHandler { domain: domain.clone(), state: state.clone() };
        let mut server = ServerFuture::new(handler);
        server.register_socket(socket);

        // Long-lived background task: drives the DNS accept loop for as
        // long as the process runs. Errors here (e.g. the OS yanking the
        // socket) are logged, not propagated — by the time this fires, the
        // caller has long since gotten its `Ok(OobChannel)` back.
        tokio::spawn(async move {
            if let Err(e) = server.block_until_done().await {
                logger::error(&format!("OOB listener stopped unexpectedly: {e}"));
            }
        });

        Ok(Self { domain, state })
    }

    /// Mint a fresh, unpredictable token and register it as pending. Embed
    /// the result in a payload via [`OobChannel::full_domain`] (or just
    /// `format!("{token}.{domain}")` yourself) and send it to the target.
    pub fn new_token(&self) -> String {
        let mut bytes = [0u8; TOKEN_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let token = bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();

        let mut state = self.state.lock().unwrap();
        state.gc();
        state.pending.insert(token.clone(), Instant::now());
        token
    }

    /// The fully-qualified hostname a check should embed in its payload
    /// for `token` (e.g. as an SSRF target URL's host, or an XXE external
    /// entity's `SYSTEM` URI).
    pub fn full_domain(&self, token: &str) -> String {
        format!("{token}.{}", self.domain)
    }

    /// Block (asynchronously) until either `token` has received a DNS
    /// lookup, or `timeout` elapses — whichever comes first. Returns
    /// `true` for the former, `false` for the latter.
    ///
    /// Safe to call even if `token` was never returned by `new_token` on
    /// this channel (e.g. a check built its own string) — it just won't
    /// ever be found, so this degrades to sleeping out `timeout` and
    /// returning `false`.
    pub async fn was_triggered(&self, token: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;

        loop {
            if self.state.lock().unwrap().triggered.contains_key(token) {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let remaining = deadline.saturating_duration_since(now);
            tokio::time::sleep(remaining.min(POLL_INTERVAL)).await;
        }
    }

    /// Record that a lookup for `token` arrived. Called by [`OobHandler`]
    /// on every query that resolves to a syntactically valid token under
    /// `domain`; exposed at `pub(crate)` visibility (rather than folded
    /// directly into the handler) so this bookkeeping can be unit-tested
    /// without spinning up a real DNS server.
    pub(crate) fn record_hit(&self, token: &str) {
        let mut state = self.state.lock().unwrap();
        state.gc();
        state.pending.remove(token);
        state.triggered.entry(token.to_string()).or_insert_with(Instant::now);
    }
}

/// `true` if `s` has the shape `new_token` produces (`TOKEN_BYTES * 2` hex
/// characters). Anything else arriving as a query's leftmost label is
/// background internet noise (mass DNS scanners routinely probe every
/// public resolver/authoritative server they find) and is deliberately
/// *not* recorded, so it can't pad out `triggered`/`pending` or be mistaken
/// for a real hit.
fn is_valid_token_format(s: &str) -> bool {
    s.len() == TOKEN_BYTES * 2 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Extract the candidate token from a queried name, given the
/// operator-configured `domain`. Returns `Some(leftmost_label)` iff
/// `query_name` is exactly `<label>.<domain>` (trailing-dot and case
/// insensitive); `None` for anything else (wrong domain, no label, or
/// multiple extra labels between the token and the domain — Cogitator's
/// own payloads never generate those, so a query shaped that way isn't one
/// of ours).
fn extract_token(query_name: &str, domain: &str) -> Option<String> {
    let q = query_name.trim_end_matches('.').to_lowercase();
    let d = domain.trim_end_matches('.').to_lowercase();

    let suffix = format!(".{d}");
    let prefix = q.strip_suffix(&suffix)?;

    if prefix.is_empty() || prefix.contains('.') {
        return None;
    }
    Some(prefix.to_string())
}

// ─── DNS request handler ──────────────────────────────────────────────────────
//
// The only job of this handler is: pull the queried name out of the
// request, see if it's `<token>.<domain>`, record a hit if so, and answer
// NXDOMAIN either way (we're not standing up real infrastructure behind
// these names — the query itself is the entire signal).

struct OobHandler {
    domain: Arc<str>,
    state: Arc<Mutex<OobState>>,
}

#[async_trait::async_trait]
impl RequestHandler for OobHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let query_name = request.query().name().to_string();

        if let Some(token) = extract_token(&query_name, &self.domain) {
            if is_valid_token_format(&token) {
                logger::log_event(&format!("OOB hit: token {token} resolved"));
                // Reconstruct a channel handle purely to reuse
                // `record_hit`'s locking/GC logic rather than duplicating
                // it here — cheap, since `OobChannel` is just two `Arc`s.
                OobChannel { domain: self.domain.clone(), state: self.state.clone() }
                    .record_hit(&token);
            }
        }

        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_response_code(ResponseCode::NXDomain);
        let response = builder.build_no_records(header);

        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                logger::error(&format!("OOB listener: failed to send DNS response: {e}"));
                // Independent fallback header (rather than reusing `header`,
                // which `build_no_records` above already consumed) — a
                // minimal ServFail is all a caller of this trait method
                // needs when the send itself failed.
                let mut fallback = Header::new();
                fallback.set_response_code(ResponseCode::ServFail);
                fallback.into()
            }
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────
//
// These exercise the pure bookkeeping (`extract_token`, `is_valid_token_format`,
// GC, `was_triggered` timing) directly, without binding a socket or sending
// real DNS traffic. `OobHandler::handle_request` is exactly the DNS-protocol
// glue around `extract_token` + `OobChannel::record_hit`, both of which are
// covered here already.

#[cfg(test)]
mod tests {
    use super::*;

    fn channel() -> OobChannel {
        OobChannel {
            domain: Arc::from("oob.example.com"),
            state: Arc::new(Mutex::new(OobState::new())),
        }
    }

    #[test]
    fn extracts_token_from_single_label_subdomain() {
        let token = extract_token("abc123.oob.example.com", "oob.example.com");
        assert_eq!(token, Some("abc123".to_string()));
    }

    #[test]
    fn extracts_token_case_and_trailing_dot_insensitive() {
        let token = extract_token("ABC123.OOB.EXAMPLE.COM.", "oob.example.com");
        assert_eq!(token, Some("abc123".to_string()));
    }

    #[test]
    fn rejects_wrong_domain() {
        assert_eq!(extract_token("abc123.evil.com", "oob.example.com"), None);
    }

    #[test]
    fn rejects_bare_domain_with_no_label() {
        assert_eq!(extract_token("oob.example.com", "oob.example.com"), None);
    }

    #[test]
    fn rejects_multiple_labels_before_domain() {
        // Cogitator only ever emits `{token}.<domain>`; anything with an
        // extra label in between isn't a query we minted.
        assert_eq!(extract_token("extra.abc123.oob.example.com", "oob.example.com"), None);
    }

    #[test]
    fn token_format_matches_new_token_output() {
        let c = channel();
        let token = c.new_token();
        assert!(is_valid_token_format(&token));
        assert_eq!(token.len(), TOKEN_BYTES * 2);
    }

    #[test]
    fn rejects_non_hex_and_wrong_length_as_token_format() {
        assert!(!is_valid_token_format("not-hex-but-32-characters-long!"));
        assert!(!is_valid_token_format("abc123")); // too short
    }

    #[test]
    fn new_tokens_are_unique() {
        let c = channel();
        let a = c.new_token();
        let b = c.new_token();
        assert_ne!(a, b);
    }

    #[test]
    fn full_domain_embeds_token_under_configured_domain() {
        let c = channel();
        let token = c.new_token();
        assert_eq!(c.full_domain(&token), format!("{token}.oob.example.com"));
    }

    #[tokio::test]
    async fn was_triggered_true_when_hit_recorded_before_call() {
        let c = channel();
        let token = c.new_token();
        c.record_hit(&token);
        assert!(c.was_triggered(&token, Duration::from_millis(50)).await);
    }

    #[tokio::test]
    async fn was_triggered_false_on_timeout_with_no_hit() {
        let c = channel();
        let token = c.new_token();
        assert!(!c.was_triggered(&token, Duration::from_millis(300)).await);
    }

    #[tokio::test]
    async fn was_triggered_false_for_unknown_token() {
        let c = channel();
        assert!(!c.was_triggered("deadbeefdeadbeefdeadbeefdeadbeef", Duration::from_millis(100)).await);
    }

    #[tokio::test]
    async fn was_triggered_detects_hit_that_arrives_mid_wait() {
        let c = channel();
        let token = c.new_token();

        let c2 = c.clone();
        let token2 = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            c2.record_hit(&token2);
        });

        assert!(c.was_triggered(&token, Duration::from_secs(2)).await);
    }

    #[test]
    fn record_hit_moves_token_from_pending_to_triggered() {
        let c = channel();
        let token = c.new_token();
        {
            let state = c.state.lock().unwrap();
            assert!(state.pending.contains_key(&token));
            assert!(!state.triggered.contains_key(&token));
        }

        c.record_hit(&token);

        let state = c.state.lock().unwrap();
        assert!(!state.pending.contains_key(&token));
        assert!(state.triggered.contains_key(&token));
    }

    #[test]
    fn record_hit_keeps_first_hit_timestamp_on_repeat_lookups() {
        // A resolver may retry/re-query the same name multiple times (e.g.
        // A then AAAA); the recorded time should be the *first* sighting.
        let c = channel();
        let token = c.new_token();

        c.record_hit(&token);
        let first_seen = {
            let state = c.state.lock().unwrap();
            *state.triggered.get(&token).unwrap()
        };

        c.record_hit(&token);
        let second_seen = {
            let state = c.state.lock().unwrap();
            *state.triggered.get(&token).unwrap()
        };

        assert_eq!(first_seen, second_seen);
    }

    #[test]
    fn gc_drops_stale_pending_and_triggered_entries() {
        let mut state = OobState::new();
        // Simulate an old entry by backdating its Instant.
        let old = Instant::now() - RECORD_RETENTION - Duration::from_secs(1);
        state.pending.insert("stale_pending_token".to_string(), old);
        state.triggered.insert("stale_triggered_token".to_string(), old);
        state.pending.insert("fresh_token".to_string(), Instant::now());

        state.gc();

        assert!(!state.pending.contains_key("stale_pending_token"));
        assert!(!state.triggered.contains_key("stale_triggered_token"));
        assert!(state.pending.contains_key("fresh_token"));
    }
}