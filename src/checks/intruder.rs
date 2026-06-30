//! Intruder: payload fuzzing engine for Cogitator.
//!
//! Takes a raw HTTP request template containing one or more `§PAYLOAD§`
//! markers and a set of payload lists, substitutes payloads according to
//! the selected `IntruderMode`, fires the resulting requests concurrently
//! (bounded by `threads`), and streams results back through an mpsc
//! channel as each request completes — mirroring `scanner.rs`'s
//! `Semaphore`-capped fan-out, but request-by-request rather than
//! check-by-check so the TUI can render results live instead of waiting
//! for the whole run.
//!
//! ## Marker semantics
//!
//! Every literal occurrence of `§PAYLOAD§` in `template` is a distinct,
//! position-ordered marker slot. How many payload *lists* are consulted,
//! and how they're zipped against those slots, depends on `mode`:
//!
//!   * `Sniper`        — exactly one marker; every entry in `payloads` is
//!                        tried in that slot, one request per payload.
//!   * `BatteringRam`   — one or more markers; every entry in `payloads` is
//!                        inserted into *all* slots simultaneously (same
//!                        payload, every marker), one request per payload.
//!   * `Pitchfork`      — N markers, N payload sets (`payload_sets`); slot
//!                        `k` always draws from `payload_sets[k]`, stepping
//!                        all sets in lockstep. Stops at the shortest set.
//!   * `ClusterBomb`    — N markers, N payload sets; every combination
//!                        (cartesian product) across all sets is tried.
//!
//! `payloads` is the single flat list used by `Sniper`/`BatteringRam`.
//! `payload_sets` is the per-marker list used by `Pitchfork`/`ClusterBomb`.
//! Only one of the two is consulted, based on `mode` — see `run`.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::{Client, Method};
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::Semaphore;

use crate::logger;
use crate::session::{apply_profile, SessionProfile};

/// Literal marker Intruder looks for inside `IntruderConfig::template`.
pub const MARKER: &str = "§PAYLOAD§";

/// Default number of concurrent in-flight requests if the caller doesn't
/// override `IntruderConfig::threads`.
pub const DEFAULT_THREADS: usize = 10;

// ─── Attack mode ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntruderMode {
    /// One marker, iterate `payloads` through it.
    Sniper,
    /// All markers, same payload in every slot, iterate `payloads`.
    BatteringRam,
    /// N markers, N payload sets, stepped in lockstep, stop at shortest.
    Pitchfork,
    /// N markers, N payload sets, full cartesian product.
    ClusterBomb,
}

// ─── Config ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IntruderConfig {
    /// Raw HTTP/1.1 request text (request line + headers + optional body),
    /// containing one or more `§PAYLOAD§` markers to be substituted.
    pub template: String,
    /// Flat payload list — consulted by `Sniper` and `BatteringRam`.
    pub payloads: Vec<String>,
    /// Per-marker payload lists — consulted by `Pitchfork` and
    /// `ClusterBomb`. `payload_sets[k]` feeds the k-th `§PAYLOAD§`
    /// occurrence in `template` (in order of appearance). Ignored by
    /// `Sniper`/`BatteringRam`.
    pub payload_sets: Vec<Vec<String>>,
    pub mode: IntruderMode,
    /// Max concurrent in-flight requests.
    pub threads: usize,
    /// Delay before dispatching each request, in milliseconds (0 = none).
    /// Useful for dodging naive rate limiters during a scan.
    pub delay_ms: u64,
}

impl Default for IntruderConfig {
    fn default() -> Self {
        Self {
            template: String::new(),
            payloads: Vec::new(),
            payload_sets: Vec::new(),
            mode: IntruderMode::Sniper,
            threads: DEFAULT_THREADS,
            delay_ms: 0,
        }
    }
}

// ─── Result ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IntruderResult {
    /// Human-readable rendering of whatever payload(s) produced this
    /// request — for `Sniper`/`BatteringRam` this is just the payload
    /// string; for `Pitchfork`/`ClusterBomb` it's the per-marker values
    /// joined with " | " so multi-marker attacks remain attributable.
    pub payload: String,
    /// `None` if the request failed outright (timeout, connection error,
    /// etc.) rather than completing with an HTTP response.
    pub status: Option<u16>,
    pub length: usize,
    pub response_time_ms: u128,
    pub response_raw: String,
}

// ─── Wordlist sources ─────────────────────────────────────────────────────────

/// Where to pull payload strings from for an Intruder run.
///
/// `load_wordlist` turns any of these into a single lazy `Iterator<Item =
/// String>` — nothing is materialised into a `Vec` up front except
/// `Inline`, which is already a `Vec` the caller built themselves.
#[derive(Debug, Clone)]
pub enum WordlistSource {
    /// Payloads already in memory (e.g. typed directly into the TUI).
    Inline(Vec<String>),
    /// One payload per non-empty line of a file on disk. Lines are read
    /// lazily — a multi-gigabyte wordlist is never pulled fully into
    /// memory, only buffered a chunk at a time by `BufReader`.
    File(PathBuf),
    /// Decimal integers `start..=end` (inclusive), stepping by `step`.
    /// Useful for numeric IDs, ports, PINs, etc. `step == 0` yields an
    /// empty iterator rather than looping forever.
    Range { start: u64, end: u64, step: u64 },
    /// Every string over `charset` with length in `min_len..=max_len`,
    /// shortest first, generated in lexicographic (odometer) order.
    /// Classic brute-force charset attack — e.g. `charset: "abc"`,
    /// `min_len: 1`, `max_len: 3` yields `a, b, c, aa, ab, ..., ccc`.
    Alpha {
        charset: String,
        min_len: usize,
        max_len: usize,
    },
}

/// Build a single lazy iterator over every payload string described by
/// `source`. None of the variants pre-generate their full output — `File`
/// streams lines off disk, `Range` computes each value on demand, and
/// `Alpha` runs an odometer-style brute-force generator that holds only
/// the current combination's indices in memory, no matter how large
/// `charset.len().pow(max_len)` is.
pub fn load_wordlist(source: &WordlistSource) -> Box<dyn Iterator<Item = String> + Send> {
    match source {
        WordlistSource::Inline(words) => Box::new(words.clone().into_iter()),

        WordlistSource::File(path) => match File::open(path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                Box::new(
                    reader
                        .lines()
                        .filter_map(|line| line.ok())
                        .map(|line| line.trim().to_string())
                        .filter(|line| !line.is_empty()),
                )
            }
            Err(e) => {
                logger::warn(&format!(
                    "intruder: failed to open wordlist file {}: {e}",
                    path.display()
                ));
                Box::new(std::iter::empty())
            }
        },

        WordlistSource::Range { start, end, step } => {
            let (start, end, step) = (*start, *end, *step);
            if step == 0 || start > end {
                Box::new(std::iter::empty())
            } else {
                Box::new(
                    (0..)
                        .map(move |i: u64| start.saturating_add(i.saturating_mul(step)))
                        .take_while(move |v| *v <= end)
                        .map(|v| v.to_string()),
                )
            }
        }

        WordlistSource::Alpha { charset, min_len, max_len } => {
            Box::new(AlphaBruteForce::new(charset.clone(), *min_len, *max_len))
        }
    }
}

/// Lazy odometer-style brute-force generator over a fixed charset.
///
/// Holds only the current combination as a `Vec<usize>` of charset
/// indices (length = current word length) — memory use is `O(max_len)`,
/// never `O(charset.len() ^ max_len)`. Each `next()` call either advances
/// the odometer by one (carrying into higher digits as needed) or, once
/// every combination of the current length is exhausted, bumps the word
/// length and resets the odometer for that new length.
struct AlphaBruteForce {
    chars: Vec<char>,
    min_len: usize,
    max_len: usize,
    /// Current word length being generated. `None` once `max_len` has
    /// been fully exhausted (iterator is done).
    current_len: Option<usize>,
    /// Current combination, as indices into `chars`. Empty only
    /// momentarily before the first word of a given length is emitted.
    indices: Vec<usize>,
    /// Whether `indices` still needs to be (re)initialised for
    /// `current_len` before the next word can be read off it.
    needs_init: bool,
}

impl AlphaBruteForce {
    fn new(charset: String, min_len: usize, max_len: usize) -> Self {
        let chars: Vec<char> = charset.chars().collect();
        // Degenerate cases (empty charset, or min_len > max_len, or
        // min_len == 0 with nothing useful to emit) all collapse to "done"
        // by leaving current_len as None.
        let current_len = if chars.is_empty() || min_len > max_len {
            None
        } else {
            Some(min_len)
        };

        Self {
            chars,
            min_len,
            max_len,
            current_len,
            indices: Vec::new(),
            needs_init: true,
        }
    }

    /// Advance `indices` to the next combination at the current length,
    /// odometer-style (rightmost digit increments fastest, carrying left).
    /// Returns `false` if every combination at this length is exhausted.
    fn advance(&mut self) -> bool {
        for digit in self.indices.iter_mut().rev() {
            *digit += 1;
            if *digit < self.chars.len() {
                return true;
            }
            *digit = 0;
            // carry into the next digit to the left
        }
        // Every digit carried past the end — this length is exhausted.
        false
    }
}

impl Iterator for AlphaBruteForce {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        loop {
            let len = self.current_len?;

            if self.needs_init {
                self.indices = vec![0; len];
                self.needs_init = false;
            } else if !self.advance() {
                // Move on to the next word length, or finish entirely.
                if len >= self.max_len {
                    self.current_len = None;
                    return None;
                }
                self.current_len = Some(len + 1);
                self.needs_init = true;
                continue;
            }

            let word: String = self.indices.iter().map(|&i| self.chars[i]).collect();
            return Some(word);
        }
    }
}



/// Launch an intruder run. Returns immediately with a receiver; results are
/// pushed onto the channel as each request completes (not in any guaranteed
/// order — callers wanting a stable ordering should sort downstream).
///
/// When `profile` is `Some`, its cookies and custom headers are injected into
/// every outgoing request.  Pass `None` to use no session credentials.
///
/// The spawned driver task owns the channel sender and the request
/// generation; it exits (closing the channel) once every combination has
/// been dispatched and awaited.
pub fn run(
    config: IntruderConfig,
    client: Arc<Client>,
    profile: Option<Arc<SessionProfile>>,
) -> Receiver<IntruderResult> {
    let (tx, rx) = mpsc::channel(256);

    tokio::spawn(async move {
        let combos = match build_combinations(&config) {
            Ok(c) => c,
            Err(e) => {
                logger::warn(&format!("intruder: bad config, aborting run: {e}"));
                return;
            }
        };

        if combos.is_empty() {
            logger::warn("intruder: no payload combinations produced, nothing to send");
            return;
        }

        let threads = config.threads.max(1);
        let semaphore = Arc::new(Semaphore::new(threads));
        let delay = Duration::from_millis(config.delay_ms);
        let template = Arc::new(config.template.clone());

        let mut handles = Vec::with_capacity(combos.len());

        for combo in combos {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }

            let semaphore = semaphore.clone();
            let client = client.clone();
            let template = template.clone();
            let tx = tx.clone();
            let profile = profile.clone();

            let handle = tokio::spawn(async move {
                let _permit = match semaphore.acquire().await {
                    Ok(p) => p,
                    Err(_) => return, // semaphore closed; bail quietly
                };

                let label = combo.join(" | ");
                let rendered = substitute_markers(&template, &combo);

                let result = match build_request(&client, &rendered) {
                    Ok((method, url, headers, body)) => {
                        // Extract the host from the resolved URL for
                        // per-domain cookie lookup in apply_profile.
                        let domain = reqwest::Url::parse(&url)
                            .ok()
                            .and_then(|u| u.host_str().map(|h| h.to_string()))
                            .unwrap_or_default();

                        let started = Instant::now();
                        let req = apply_profile(
                            client.request(method, &url).headers(headers).body(body),
                            &domain,
                            profile.as_deref(),
                        );

                        match req.send().await {
                            Ok(resp) => {
                                let status = resp.status().as_u16();
                                let elapsed = started.elapsed().as_millis();
                                let text = resp.text().await.unwrap_or_default();
                                IntruderResult {
                                    payload: label,
                                    status: Some(status),
                                    length: text.len(),
                                    response_time_ms: elapsed,
                                    response_raw: text,
                                }
                            }
                            Err(e) => IntruderResult {
                                payload: label,
                                status: None,
                                length: 0,
                                response_time_ms: started.elapsed().as_millis(),
                                response_raw: format!("<request error: {e}>"),
                            },
                        }
                    }
                    Err(e) => IntruderResult {
                        payload: label,
                        status: None,
                        length: 0,
                        response_time_ms: 0,
                        response_raw: format!("<template parse error: {e}>"),
                    },
                };

                // Receiver may have been dropped (TUI navigated away) —
                // discard rather than panic.
                let _ = tx.send(result).await;
            });

            handles.push(handle);
        }

        for handle in handles {
            if let Err(e) = handle.await {
                logger::warn(&format!("intruder: request task panicked: {e}"));
            }
        }
        // tx (and every clone) drops here as handles complete, closing the
        // channel and letting the receiver's loop terminate.
    });

    rx
}

// ─── Combination generation ───────────────────────────────────────────────────

/// Build the full list of marker-value combinations to send, one `Vec<String>`
/// per request (one entry per marker slot, in template order).
fn build_combinations(config: &IntruderConfig) -> Result<Vec<Vec<String>>, String> {
    let marker_count = config.template.matches(MARKER).count();

    if marker_count == 0 {
        return Err(format!("template contains no {MARKER} markers"));
    }

    match config.mode {
        IntruderMode::Sniper => {
            if marker_count != 1 {
                return Err(format!(
                    "Sniper mode expects exactly 1 marker, found {marker_count}"
                ));
            }
            Ok(config.payloads.iter().map(|p| vec![p.clone()]).collect())
        }

        IntruderMode::BatteringRam => {
            if config.payloads.is_empty() {
                return Err("BatteringRam mode requires a non-empty payloads list".to_string());
            }
            Ok(config
                .payloads
                .iter()
                .map(|p| std::iter::repeat(p.clone()).take(marker_count).collect())
                .collect())
        }

        IntruderMode::Pitchfork => {
            if config.payload_sets.len() != marker_count {
                return Err(format!(
                    "Pitchfork mode requires {marker_count} payload sets (one per marker), found {}",
                    config.payload_sets.len()
                ));
            }
            let shortest = config
                .payload_sets
                .iter()
                .map(|s| s.len())
                .min()
                .unwrap_or(0);

            if shortest == 0 {
                return Err("Pitchfork mode requires every payload set to be non-empty".to_string());
            }

            Ok((0..shortest)
                .map(|i| {
                    config
                        .payload_sets
                        .iter()
                        .map(|set| set[i].clone())
                        .collect()
                })
                .collect())
        }

        IntruderMode::ClusterBomb => {
            if config.payload_sets.len() != marker_count {
                return Err(format!(
                    "ClusterBomb mode requires {marker_count} payload sets (one per marker), found {}",
                    config.payload_sets.len()
                ));
            }
            if config.payload_sets.iter().any(|s| s.is_empty()) {
                return Err("ClusterBomb mode requires every payload set to be non-empty".to_string());
            }

            // Cartesian product, built up one marker slot at a time.
            let mut combos: Vec<Vec<String>> = vec![Vec::new()];
            for set in &config.payload_sets {
                let mut next = Vec::with_capacity(combos.len() * set.len());
                for combo in &combos {
                    for value in set {
                        let mut extended = combo.clone();
                        extended.push(value.clone());
                        next.push(extended);
                    }
                }
                combos = next;
            }
            Ok(combos)
        }
    }
}

/// Replace each `§PAYLOAD§` occurrence in `template`, in order, with the
/// corresponding entry from `values` (one value per marker slot).
fn substitute_markers(template: &str, values: &[String]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    let mut values = values.iter();

    while let Some(idx) = rest.find(MARKER) {
        out.push_str(&rest[..idx]);
        if let Some(v) = values.next() {
            out.push_str(v);
        }
        rest = &rest[idx + MARKER.len()..];
    }
    out.push_str(rest);
    out
}

// ─── Raw HTTP/1.1 parsing ─────────────────────────────────────────────────────

/// Parse a rendered raw HTTP/1.1 request (request line + headers + blank
/// line + optional body) into the pieces needed to build a `reqwest`
/// request. Mirrors `repeater.rs`'s parse-and-resend approach.
///
/// Expects the request line's path to be either an absolute URL
/// (`GET https://host/path HTTP/1.1`) or an origin-form path paired with a
/// `Host:` header (`GET /path HTTP/1.1` + `Host: example.com`) — the
/// latter is resolved against an assumed `https://` scheme unless the
/// request line already specifies one.
fn build_request(
    _client: &Client,
    raw: &str,
) -> Result<(Method, String, reqwest::header::HeaderMap, Vec<u8>), String> {
    // Tolerate templates authored with plain "\n" line endings too.
    let crlf_split: Vec<&str> = raw.split("\r\n").collect();
    let parts: Vec<&str> = if crlf_split.len() > 1 {
        crlf_split
    } else {
        raw.split('\n').collect()
    };

    let mut iter = parts.into_iter();

    let request_line = iter
        .next()
        .ok_or_else(|| "empty request template".to_string())?;
    let mut rl_parts = request_line.split_whitespace();
    let method_str = rl_parts.next().ok_or("missing HTTP method")?;
    let target = rl_parts.next().ok_or("missing request target")?;

    let method = Method::from_bytes(method_str.as_bytes())
        .map_err(|_| format!("invalid HTTP method: {method_str}"))?;

    let mut headers = reqwest::header::HeaderMap::new();
    let mut host_header: Option<String> = None;
    let mut body_lines: Vec<&str> = Vec::new();
    let mut in_body = false;

    for line in iter {
        if !in_body {
            if line.is_empty() {
                in_body = true;
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim();
                let value = value.trim();
                if name.eq_ignore_ascii_case("host") {
                    host_header = Some(value.to_string());
                }
                if let (Ok(hn), Ok(hv)) = (
                    reqwest::header::HeaderName::from_bytes(name.as_bytes()),
                    reqwest::header::HeaderValue::from_str(value),
                ) {
                    headers.insert(hn, hv);
                }
            }
        } else {
            body_lines.push(line);
        }
    }

    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        let host = host_header
            .ok_or_else(|| "relative request target with no Host header".to_string())?;
        format!("https://{host}{target}")
    };

    let body = body_lines.join("\n").into_bytes();

    Ok((method, url, headers, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(template: &str, mode: IntruderMode) -> IntruderConfig {
        IntruderConfig {
            template: template.to_string(),
            mode,
            ..Default::default()
        }
    }

    #[test]
    fn substitute_single_marker() {
        let out = substitute_markers("GET /x?id=§PAYLOAD§ HTTP/1.1", &["1".to_string()]);
        assert_eq!(out, "GET /x?id=1 HTTP/1.1");
    }

    #[test]
    fn substitute_multiple_markers_in_order() {
        let out = substitute_markers(
            "§PAYLOAD§:§PAYLOAD§",
            &["a".to_string(), "b".to_string()],
        );
        assert_eq!(out, "a:b");
    }

    #[test]
    fn sniper_requires_exactly_one_marker() {
        let mut c = cfg("§PAYLOAD§ and §PAYLOAD§", IntruderMode::Sniper);
        c.payloads = vec!["x".to_string()];
        assert!(build_combinations(&c).is_err());
    }

    #[test]
    fn sniper_one_request_per_payload() {
        let mut c = cfg("id=§PAYLOAD§", IntruderMode::Sniper);
        c.payloads = vec!["1".to_string(), "2".to_string(), "3".to_string()];
        let combos = build_combinations(&c).unwrap();
        assert_eq!(combos, vec![vec!["1".to_string()], vec!["2".to_string()], vec!["3".to_string()]]);
    }

    #[test]
    fn battering_ram_fills_all_markers_with_same_payload() {
        let mut c = cfg("a=§PAYLOAD§&b=§PAYLOAD§", IntruderMode::BatteringRam);
        c.payloads = vec!["x".to_string(), "y".to_string()];
        let combos = build_combinations(&c).unwrap();
        assert_eq!(
            combos,
            vec![
                vec!["x".to_string(), "x".to_string()],
                vec!["y".to_string(), "y".to_string()],
            ]
        );
    }

    #[test]
    fn pitchfork_steps_in_lockstep_and_stops_at_shortest() {
        let mut c = cfg("a=§PAYLOAD§&b=§PAYLOAD§", IntruderMode::Pitchfork);
        c.payload_sets = vec![
            vec!["a1".to_string(), "a2".to_string(), "a3".to_string()],
            vec!["b1".to_string(), "b2".to_string()],
        ];
        let combos = build_combinations(&c).unwrap();
        assert_eq!(
            combos,
            vec![
                vec!["a1".to_string(), "b1".to_string()],
                vec!["a2".to_string(), "b2".to_string()],
            ]
        );
    }

    #[test]
    fn pitchfork_requires_one_set_per_marker() {
        let mut c = cfg("a=§PAYLOAD§&b=§PAYLOAD§", IntruderMode::Pitchfork);
        c.payload_sets = vec![vec!["only-one-set".to_string()]];
        assert!(build_combinations(&c).is_err());
    }

    #[test]
    fn cluster_bomb_full_cartesian_product() {
        let mut c = cfg("a=§PAYLOAD§&b=§PAYLOAD§", IntruderMode::ClusterBomb);
        c.payload_sets = vec![
            vec!["a1".to_string(), "a2".to_string()],
            vec!["b1".to_string(), "b2".to_string()],
        ];
        let combos = build_combinations(&c).unwrap();
        assert_eq!(combos.len(), 4);
        assert!(combos.contains(&vec!["a1".to_string(), "b1".to_string()]));
        assert!(combos.contains(&vec!["a1".to_string(), "b2".to_string()]));
        assert!(combos.contains(&vec!["a2".to_string(), "b1".to_string()]));
        assert!(combos.contains(&vec!["a2".to_string(), "b2".to_string()]));
    }

    #[test]
    fn no_marker_in_template_is_an_error() {
        let mut c = cfg("GET / HTTP/1.1", IntruderMode::Sniper);
        c.payloads = vec!["x".to_string()];
        assert!(build_combinations(&c).is_err());
    }

    #[test]
    fn build_request_parses_absolute_url_request_line() {
        let raw = "GET https://example.com/x?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let client = Client::new();
        let (method, url, _headers, body) = build_request(&client, raw).unwrap();
        assert_eq!(method, Method::GET);
        assert_eq!(url, "https://example.com/x?id=1");
        assert!(body.is_empty());
    }

    #[test]
    fn build_request_resolves_relative_target_via_host_header() {
        let raw = "POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=1";
        let client = Client::new();
        let (method, url, headers, body) = build_request(&client, raw).unwrap();
        assert_eq!(method, Method::POST);
        assert_eq!(url, "https://example.com/login");
        assert_eq!(headers.get("Content-Type").unwrap(), "application/x-www-form-urlencoded");
        assert_eq!(body, b"user=admin&pass=1");
    }

    #[test]
    fn build_request_without_host_or_absolute_url_errors() {
        let raw = "GET /no-host HTTP/1.1\r\n\r\n";
        let client = Client::new();
        assert!(build_request(&client, raw).is_err());
    }

    // ── WordlistSource / load_wordlist ──────────────────────────────────

    #[test]
    fn inline_wordlist_yields_in_order() {
        let src = WordlistSource::Inline(vec!["a".to_string(), "b".to_string()]);
        let out: Vec<String> = load_wordlist(&src).collect();
        assert_eq!(out, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn file_wordlist_skips_blank_lines_and_trims() {
        let tmp = std::env::temp_dir().join(format!(
            "cogitator_wordlist_test_{}_{}.txt",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::write(&tmp, "  admin\n\nroot \n\nguest\n").unwrap();

        let src = WordlistSource::File(tmp.clone());
        let out: Vec<String> = load_wordlist(&src).collect();
        let _ = std::fs::remove_file(&tmp);

        assert_eq!(out, vec!["admin".to_string(), "root".to_string(), "guest".to_string()]);
    }

    #[test]
    fn missing_file_wordlist_yields_empty_not_panic() {
        let src = WordlistSource::File(PathBuf::from("/nonexistent/path/wordlist.txt"));
        let out: Vec<String> = load_wordlist(&src).collect();
        assert!(out.is_empty());
    }

    #[test]
    fn range_wordlist_yields_decimal_strings() {
        let src = WordlistSource::Range { start: 1, end: 5, step: 2 };
        let out: Vec<String> = load_wordlist(&src).collect();
        assert_eq!(out, vec!["1".to_string(), "3".to_string(), "5".to_string()]);
    }

    #[test]
    fn range_wordlist_zero_step_is_empty() {
        let src = WordlistSource::Range { start: 1, end: 5, step: 0 };
        let out: Vec<String> = load_wordlist(&src).collect();
        assert!(out.is_empty());
    }

    #[test]
    fn range_wordlist_start_after_end_is_empty() {
        let src = WordlistSource::Range { start: 10, end: 5, step: 1 };
        let out: Vec<String> = load_wordlist(&src).collect();
        assert!(out.is_empty());
    }

    #[test]
    fn alpha_wordlist_generates_in_length_order() {
        let src = WordlistSource::Alpha {
            charset: "ab".to_string(),
            min_len: 1,
            max_len: 2,
        };
        let out: Vec<String> = load_wordlist(&src).collect();
        assert_eq!(
            out,
            vec!["a", "b", "aa", "ab", "ba", "bb"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn alpha_wordlist_single_length() {
        let src = WordlistSource::Alpha {
            charset: "xyz".to_string(),
            min_len: 1,
            max_len: 1,
        };
        let out: Vec<String> = load_wordlist(&src).collect();
        assert_eq!(out, vec!["x".to_string(), "y".to_string(), "z".to_string()]);
    }

    #[test]
    fn alpha_wordlist_empty_charset_is_empty() {
        let src = WordlistSource::Alpha {
            charset: String::new(),
            min_len: 1,
            max_len: 3,
        };
        let out: Vec<String> = load_wordlist(&src).collect();
        assert!(out.is_empty());
    }

    #[test]
    fn alpha_wordlist_min_greater_than_max_is_empty() {
        let src = WordlistSource::Alpha {
            charset: "ab".to_string(),
            min_len: 3,
            max_len: 1,
        };
        let out: Vec<String> = load_wordlist(&src).collect();
        assert!(out.is_empty());
    }

    #[test]
    fn alpha_wordlist_is_lazy_does_not_blow_up_for_large_max_len() {
        // charset.len()^max_len here is 26^8 — far too large to materialise.
        // Just pull the first few items and confirm it doesn't hang or OOM.
        let src = WordlistSource::Alpha {
            charset: "abcdefghijklmnopqrstuvwxyz".to_string(),
            min_len: 1,
            max_len: 8,
        };
        let first_five: Vec<String> = load_wordlist(&src).take(5).collect();
        assert_eq!(
            first_five,
            vec!["a", "b", "c", "d", "e"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }
}

