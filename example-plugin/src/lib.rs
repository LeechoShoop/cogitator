//! `secrets-detector-plugin` — an example Cogitator plugin that flags
//! secret-shaped strings (API keys, private key blocks, JWTs, ...) showing
//! up in proxied requests and responses.
//!
//! This crate exists as a **complete, working template** — see
//! `PLUGINS.md` (at the workspace root) for the full walkthrough of how
//! to copy this crate and turn it into your own plugin, plus exact build
//! commands. The short version:
//!
//!   1. Every plugin implements [`cogitator_plugin_api::CogitatorPlugin`] —
//!      `name()`, `description()`, and (optionally) `on_request()`/
//!      `on_response()`, each returning a `Vec<ScanFinding>`.
//!   2. The crate is built as a `cdylib` (see `Cargo.toml`'s `[lib]`
//!      section) and exports two C symbols via the bottom-of-file
//!      `export_plugin!` macro call — that's the entire ABI surface
//!      Cogitator's `dlopen`-based loader depends on.
//!   3. Cogitator checks `cogitator_plugin_abi_version()` *before* ever
//!      calling `cogitator_plugin_create()` — a mismatched
//!      `cogitator-plugin-api` version gets the plugin refused and
//!      logged, not loaded and crashed.
//!
//! ## Nuances worth knowing before you write your own (see PLUGINS.md at
//! ## the long-form explanation of each)
//!
//! - **`#[async_trait]` on the `impl` block, not just the trait.** The
//!   trait's `async fn`s are a macro-generated `fn(...) -> Pin<Box<dyn
//!   Future + Send>>` under the hood — your `impl` must go through the
//!   exact same macro expansion (same `async-trait` *major* version) or
//!   the generated function signatures won't line up with what the trait
//!   object's vtable expects. See `Cargo.toml`'s comment on this.
//! - **`Send + Sync` is a hard requirement, not a suggestion.** Cogitator
//!   spawns every plugin's hook call onto its own `tokio` task
//!   (`tokio::task::JoinSet`, see `plugin.rs`) so plugins run concurrently.
//!   Any type you put inside your plugin struct's fields must itself be
//!   `Send + Sync` for your plugin to satisfy the trait bound at all —
//!   `Arc<Mutex<T>>` is the usual escape hatch for shared mutable state,
//!   never a bare `Rc<RefCell<T>>` or raw pointer.
//! - **Don't panic inside your hooks if you can help it, and never panic
//!   inside `name()`/`description()`.** A panic inside `on_request`/
//!   `on_response` is caught by `JoinSet` (it becomes a logged
//!   `JoinError`, other plugins keep running) — annoying but safe.
//!   A panic inside `name()`/`description()`, or inside whatever
//!   constructor `export_plugin!`'s `$ctor` expression runs, happens
//!   *outside* any `catch_unwind` boundary, directly across the FFI call
//!   from Cogitator's loader into your `.so` — unwinding across an FFI
//!   boundary is undefined behavior. Keep these infallible.
//! - **The same Rust compiler version must build both sides.** The ABI
//!   version check (below) only catches *intentional, logged* changes to
//!   `cogitator-plugin-api`'s types. Rust's default `repr(Rust)` struct
//!   layout is *not* guaranteed stable across different `rustc` versions
//!   or even different optimization levels — it's unspecified by design.
//!   Two `.so`s built from byte-identical source with two different
//!   `rustc` versions are not guaranteed to agree on `RequestRecord`'s
//!   memory layout even though `PLUGIN_ABI_VERSION` matches. Build your
//!   plugin with the exact same `rustc`/`cargo` version Cogitator itself
//!   was built with — `rustc --version` on both sides, compared by hand.
//! - **Don't set a custom `#[global_allocator]`** unless Cogitator does
//!   too. `cogitator_plugin_create` allocates your plugin with
//!   `Box::into_raw`; Cogitator later deallocates it with
//!   `Box::from_raw` inside its own process — both allocation and
//!   deallocation must go through the *same* allocator implementation, or
//!   freeing memory allocated by a different allocator is undefined
//!   behavior. Just don't touch the global allocator and this is a
//!   non-issue.
//! - **`crate-type = ["cdylib"]` doesn't break `cargo test`.** `cargo
//!   test` always compiles the lib target as a self-contained test
//!   binary (effectively `rustc --test`), which overrides the declared
//!   crate type — so the `#[cfg(test)] mod tests` at the bottom of this
//!   file runs completely normally with plain `cargo test`, no dlopen or
//!   loader involved at all. It only exercises your plugin's *logic*, not
//!   the ABI-loading path itself (only a real Cogitator run with
//!   `--features external_plugins` tests that part).

use std::sync::OnceLock;

use async_trait::async_trait;
use cogitator_plugin_api::{CogitatorPlugin, RequestRecord, ScanFinding, Severity};
use regex::Regex;

// ─── Detection patterns ───────────────────────────────────────────────────────
//
// Each pattern is a (human-readable label, severity, regex) triple. Adding
// a new secret shape to detect is just adding a new entry here — nothing
// else in this file needs to change.
//
// Severity follows the guidance table in PLUGINS.md (workspace root):
//   Critical — a private key is a direct path to full compromise (SSH/TLS).
//   High     — API keys/tokens are direct account/service access.
//   Medium   — the generic "key=value"-shaped match is a looser heuristic,
//              more prone to false positives (e.g. matching a client-side
//              placeholder or a non-secret config value), so it's ranked
//              a notch below the named, high-confidence formats above it.
//   Info     — a JWT's *presence* isn't itself a vulnerability (session
//              tokens are supposed to be there); it's flagged so a human
//              can judge whether this occurrence is expected, matching how
//              `crypto_forensic::audit_crypto` treats JWT-shaped cookie
//              values in the main Cogitator binary.

struct Pattern {
    label: &'static str,
    severity: Severity,
    regex: Regex,
}

/// Compiled once, reused for every hook call. `OnceLock` (rather than a
/// `lazy_static!`/`once_cell` dependency) mirrors the pattern already used
/// throughout Cogitator's own codebase (see e.g. `logger.rs`'s redaction
/// regexes) for exactly this "compile a static regex once" need.
fn patterns() -> &'static [Pattern] {
    static PATTERNS: OnceLock<Vec<Pattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            Pattern {
                label: "AWS Access Key ID",
                severity: Severity::High,
                regex: Regex::new(r"AKIA[0-9A-Z]{16}").expect("static regex must compile"),
            },
            Pattern {
                label: "Private Key Block",
                severity: Severity::Critical,
                regex: Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
                    .expect("static regex must compile"),
            },
            Pattern {
                label: "GitHub Personal Access Token",
                severity: Severity::High,
                // gh[pousr]_ covers the "pat"/"oauth"/"user-to-server"/
                // "server-to-server"/"refresh" token prefixes GitHub uses.
                regex: Regex::new(r"gh[pousr]_[A-Za-z0-9]{36}")
                    .expect("static regex must compile"),
            },
            Pattern {
                label: "Slack Token",
                severity: Severity::High,
                regex: Regex::new(r"xox[baprs]-[0-9A-Za-z-]{10,48}")
                    .expect("static regex must compile"),
            },
            Pattern {
                label: "Generic API Key/Secret Assignment",
                severity: Severity::Medium,
                // Matches things shaped like `api_key: "abc123..."`,
                // `"secret"="xyz..."`, `token = 'q1w2e3...'` — a fairly
                // loose heuristic on purpose (see severity note above).
                regex: Regex::new(
                    r#"(?i)(?:api[_-]?key|secret|token)["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']"#,
                )
                    .expect("static regex must compile"),
            },
            Pattern {
                label: "JSON Web Token (JWT)",
                severity: Severity::Info,
                // Three dot-separated base64url segments; JWT headers are
                // always `{"alg":...}`-shaped JSON, which base64url-encodes
                // to a leading "eyJ" in every real-world JWT.
                regex: Regex::new(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")
                    .expect("static regex must compile"),
            },
        ]
    })
}

/// Scan `text` against every configured pattern. Returns at most one hit
/// per pattern (the first match) — mirrors the "one confirmed hit is
/// enough signal" convention Cogitator's own `checks/sqli.rs` etc. follow,
/// so a response with the same key repeated ten times doesn't produce ten
/// near-identical findings.
fn scan_text(text: &str) -> Vec<(&'static str, Severity, String)> {
    patterns()
        .iter()
        .filter_map(|p| {
            p.regex
                .find(text)
                .map(|m| (p.label, p.severity, mask_secret(m.as_str())))
        })
        .collect()
}

/// Partially redact a matched secret before it goes into a `ScanFinding`'s
/// `evidence` field. `ScanFinding`s end up in Cogitator's on-disk
/// `cogitator.log`, HTML/PDF reports, and the Findings screen — all places
/// a *full* live credential has no business being copy-pasted into.
/// Keeping the first/last few characters is enough for a human to
/// recognise which secret was found (and to go rotate it) without the
/// finding itself becoming a second copy of the credential.
fn mask_secret(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 10 {
        // Too short to partially reveal without giving away most of it —
        // just report that *something* matched, fully masked.
        return "*".repeat(chars.len());
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}...{tail} ({} chars)", chars.len())
}

/// Which side of the exchange a hit was found on — only used to word the
/// finding's `check_name`/`request_raw` appropriately; the detection logic
/// itself (`scan_text`) doesn't care which side it's scanning.
#[derive(Clone, Copy)]
enum Direction {
    Request,
    Response,
}

impl Direction {
    fn label(self) -> &'static str {
        match self {
            Direction::Request => "request",
            Direction::Response => "response",
        }
    }
}

/// Build `ScanFinding`s for every secret-shaped hit in `record`'s headers
/// and body on the given `direction`. Shared by both hooks — see
/// `SecretsDetectorPlugin::on_request`/`on_response` below — since the
/// scanning logic is identical either way, just applied to a different
/// pair of (headers, body) fields on the same `RequestRecord`.
fn findings_for(record: &RequestRecord, direction: Direction) -> Vec<ScanFinding> {
    let (headers, body): (&[(String, String)], &[u8]) = match direction {
        Direction::Request => (&record.headers, &record.body),
        // `response_body` is optional (proxy_guard caps it and may not
        // have captured it at all for some exchanges) and
        // `response_headers` defaults to empty until a response arrives —
        // both are handled gracefully by simply having nothing to scan.
        Direction::Response => (
            &record.response_headers,
            record.response_body.as_deref().unwrap_or(&[]),
        ),
    };

    let mut hits: Vec<(&'static str, Severity, String)> = Vec::new();

    // Header values first — a leaked key in a custom debug/auth header is
    // just as real a finding as one in the body, and cheaper to scan.
    for (_, value) in headers {
        hits.extend(scan_text(value));
    }

    // Body — `body`/`response_body` are raw bytes (could be anything: a
    // binary asset, compressed data that wasn't decoded, etc.), so this is
    // a lossy best-effort text view rather than an assumption that it's
    // always valid UTF-8.
    let body_text = String::from_utf8_lossy(body);
    hits.extend(scan_text(&body_text));

    let request_raw = format!("{} {}{}", record.method, record.host, record.path);
    let url = format!("{}{}", record.host, record.path);

    hits.into_iter()
        .map(|(label, severity, masked)| ScanFinding {
            check_name: format!("Secrets Exposure: {label}"),
            severity,
            evidence: format!("{label} found in {}: {masked}", direction.label()),
            request_raw: request_raw.clone(),
            response_snippet: String::new(),
            url: url.clone(),
            parameter: None,
        })
        .collect()
}

// ─── The plugin itself ────────────────────────────────────────────────────────

/// Flags secret-shaped strings — API keys, private key blocks, JWTs, and a
/// generic `key: "value"` heuristic — appearing in proxied requests or
/// responses.
///
/// A unit struct (no fields) because this plugin has no state to carry
/// between calls — every hook call is independent. If your own plugin
/// needs state (a counter, a cache, a client handle for an outbound
/// call...), add fields here, but remember the `Send + Sync` requirement
/// from the module docs above: e.g. `client: reqwest::Client` is fine
/// (already `Send + Sync + Clone` internally), a raw `Cell<T>` or `Rc<T>`
/// is not and won't compile against the trait bound.
pub struct SecretsDetectorPlugin;
impl SecretsDetectorPlugin {
    pub fn new() -> Self {
        Self
    }
}
// `#[async_trait]` here (on the `impl`, not just on the trait definition in
// cogitator-plugin-api) is what makes `on_request`/`on_response` compile as
// real `async fn`s below. Under the hood the macro rewrites each into a
// `fn(&self, ...) -> Pin<Box<dyn Future<Output = Vec<ScanFinding>> + Send +
// '_>>` — mechanically identical to what the macro generated for the trait
// declaration itself. Skip this attribute and the compiler will tell you
// `on_request`/`on_response`'s signatures don't match the trait; add a
// *different major version* of `async-trait` than cogitator-plugin-api
// uses and you risk a subtler problem (two incompatible desugarings that
// happen to both compile against the same trait) — hence Cargo.toml pins
// `async-trait = "0.1.89"` to match cogitator-plugin-api's own pin exactly,
// not just "some 0.1.x".
#[async_trait]
impl CogitatorPlugin for SecretsDetectorPlugin {
    fn name(&self) -> &str {
        "secrets-in-response-detector"
    }

    fn description(&self) -> &str {
        "Flags API keys, private key blocks, and other secret-shaped \
         strings found in proxied requests and responses"
    }

    /// Checking the request side too (not just responses) catches things
    /// like a client accidentally echoing a previously-issued token back
    /// in a header, or a misconfigured frontend embedding a server-side
    /// secret into a request body.
    ///
    /// Note what you *don't* have here: any response data. `on_request`
    /// fires the moment Cogitator receives the request from the client,
    /// before it's even forwarded to the origin — `record.response_*`
    /// fields are still `None`/empty at this point (the struct is shared
    /// shape between both hooks, not two different types), so there's
    /// nothing to gain from checking them here.
    async fn on_request(&self, record: &RequestRecord) -> Vec<ScanFinding> {
        findings_for(record, Direction::Request)
    }

    /// The main event: a server accidentally including a credential in a
    /// response body (a stack trace, a debug endpoint, a misconfigured
    /// `.env` served as static content, ...) or a header.
    ///
    /// This is `&self`, not `&mut self` — like every `CogitatorPlugin`
    /// method. Your plugin is stored as `Arc<dyn CogitatorPlugin>` and
    /// shared across every concurrently-running hook call, so there is no
    /// exclusive access to mutate through even if the trait allowed it;
    /// any real mutable state needs interior mutability (`Mutex`/`RwLock`/
    /// atomics) behind a `&self` field, guarded by the `Send + Sync`
    /// requirement already noted above.
    async fn on_response(&self, record: &RequestRecord) -> Vec<ScanFinding> {
        findings_for(record, Direction::Response)
    }
}

// REQUIRED: exports the two `#[no_mangle] extern "C"` symbols Cogitator's
// dlopen loader looks for (`cogitator_plugin_abi_version` and
// `cogitator_plugin_create`). Without this line the `.so`/`.dll`/`.dylib`
// builds fine but Cogitator refuses to load it — see PLUGINS.md (workspace
// troubleshooting section for exactly what that failure looks like.
//
// A few things happening here that are worth understanding rather than
// treating as magic:
//
// - `$ctor` (here, `SecretsDetectorPlugin`, a bare unit-struct value — the
//   macro doesn't require `::new()`, any expression producing a value that
//   implements `CogitatorPlugin` works) is evaluated exactly once, the
//   moment Cogitator's loader calls `cogitator_plugin_create()` — i.e.
//   once per Cogitator process startup, not once per request. Construction
//   cost here is a one-time thing, not a hot path.
// - The macro's `cogitator_plugin_create` does `Box::into_raw(Box::new($ctor))`
//   and hands the *raw pointer* back across the FFI boundary — this leaks
//   the `Box` on our side deliberately. Ownership transfers to Cogitator,
//   which reconstructs it with `Box::from_raw` (see `plugin.rs`'s
//   `load_external_plugins`) and holds it for the rest of the process's
//   lifetime. This is exactly why the global-allocator note in the module
//   docs above matters: the `Box::new` here and the `Box::from_raw`
//   (eventual drop) over there must agree on how memory was allocated.
// - Cogitator's loader also does `std::mem::forget(lib)` on the loaded
//   `libloading::Library` right after a successful load — it deliberately
//   never unloads your `.so` for the rest of the process's lifetime.
//   Reason: your plugin's vtable (the function pointers backing the `dyn
//   CogitatorPlugin` trait object) point into code living inside your
//   `.so`'s mapped memory. If that library were ever unloaded while
//   Cogitator still held the trait object, every subsequent call through
//   it would jump into unmapped memory. So: once loaded, a plugin lives
//   for the whole process — there's no hot-unload/reload story here in v1.
// - `edition = "2024"` in this crate's `Cargo.toml` matters specifically
//   for the `#[unsafe(no_mangle)]` syntax the macro expands to — recent
//   Rust editions require `unsafe` to be spelled out on `#[no_mangle]`
//   `extern "C" fn`s (they're inherently unsafe: you're promising the
//   symbol name won't clash and the calling convention matches). Building
//   this crate on an edition that predates that lint will still work, but
//   matching `cogitator-plugin-api`'s own edition is the simplest way to
//   avoid ever having to think about it.
cogitator_plugin_api::export_plugin!(SecretsDetectorPlugin::new());

// ─── Tests ────────────────────────────────────────────────────────────────────
//
// Run with `cargo test` from inside this directory (or `cargo test -p
// secrets-detector-plugin` from the workspace root) — plain unit tests, no
// running Cogitator instance or `.so` loading involved.

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Build a minimal `RequestRecord` for a test, with everything not
    /// relevant to the case at hand left at an empty/default value.
    fn sample(response_body: Option<&[u8]>) -> RequestRecord {
        RequestRecord {
            id: 1,
            timestamp: Instant::now(),
            method: "GET".to_string(),
            host: "example.com".to_string(),
            path: "/api/debug".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
            response_status: Some(200),
            response_headers: Vec::new(),
            response_body: response_body.map(|b| b.to_vec()),
            response_time_ms: Some(12),
            tags: Vec::new(),
            stream_id: None,
        }
    }

    #[test]
    fn mask_secret_keeps_first_and_last_four_chars() {
        let masked = mask_secret("AKIAABCDEFGHIJKLMNOP");
        assert!(masked.starts_with("AKIA"));
        assert!(masked.ends_with("MNOP"));
        assert!(masked.contains("..."));
        // The full secret must never appear in the masked output.
        assert!(!masked.contains("ABCDEFGHIJKLMNOP"));
    }

    #[test]
    fn mask_secret_fully_masks_short_strings() {
        let masked = mask_secret("short1");
        assert_eq!(masked, "*".repeat(6));
    }

    #[test]
    fn detects_aws_access_key_id() {
        let hits = scan_text("config: AKIAABCDEFGHIJKLMNOP is the key");
        assert!(hits.iter().any(|(label, sev, _)| *label == "AWS Access Key ID" && *sev == Severity::High));
    }

    #[test]
    fn detects_private_key_block() {
        let hits = scan_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...");
        assert!(hits.iter().any(|(label, sev, _)| *label == "Private Key Block" && *sev == Severity::Critical));
    }

    #[test]
    fn detects_github_token() {
        let token = format!("ghp_{}", "a".repeat(36));
        let hits = scan_text(&format!("GITHUB_TOKEN={token}"));
        assert!(hits.iter().any(|(label, _, _)| *label == "GitHub Personal Access Token"));
    }

    #[test]
    fn detects_slack_token() {
        let hits = scan_text("slack webhook uses xoxb-1234567890-abcdefghijklmnop");
        assert!(hits.iter().any(|(label, _, _)| *label == "Slack Token"));
    }

    #[test]
    fn detects_generic_key_value_assignment() {
        let hits = scan_text(r#"{"api_key": "sk_live_abcdefghijklmnopqrstuvwx"}"#);
        assert!(hits
            .iter()
            .any(|(label, sev, _)| *label == "Generic API Key/Secret Assignment" && *sev == Severity::Medium));
    }

    #[test]
    fn detects_jwt_as_informational() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGhpc2lzbm90YXJlYWxzaWc";
        let hits = scan_text(jwt);
        assert!(hits.iter().any(|(label, sev, _)| *label == "JSON Web Token (JWT)" && *sev == Severity::Info));
    }

    #[test]
    fn clean_text_produces_no_hits() {
        let hits = scan_text("Hello, world! Nothing suspicious here.");
        assert!(hits.is_empty());
    }

    #[test]
    fn only_first_match_per_pattern_is_reported() {
        let text = "AKIAABCDEFGHIJKLMNOP and also AKIAZZZZZZZZZZZZZZZZ";
        let hits: Vec<_> = scan_text(text)
            .into_iter()
            .filter(|(label, _, _)| *label == "AWS Access Key ID")
            .collect();
        assert_eq!(hits.len(), 1);
    }

    #[tokio::test]
    async fn on_response_flags_secret_in_body() {
        let plugin = SecretsDetectorPlugin;
        let record = sample(Some(b"leaked: AKIAABCDEFGHIJKLMNOP"));
        let findings = plugin.on_response(&record).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, "Secrets Exposure: AWS Access Key ID");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(!findings[0].evidence.contains("ABCDEFGHIJKLMNOP"));
    }

    #[tokio::test]
    async fn on_response_with_no_body_produces_no_findings() {
        let plugin = SecretsDetectorPlugin;
        let record = sample(None);
        assert!(plugin.on_response(&record).await.is_empty());
    }

    #[tokio::test]
    async fn on_request_scans_headers_too() {
        let plugin = SecretsDetectorPlugin;
        let mut record = sample(None);
        record.headers.push((
            "X-Debug-Token".to_string(),
            "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ));
        let findings = plugin.on_request(&record).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, "Secrets Exposure: GitHub Personal Access Token");
    }

    #[test]
    fn plugin_metadata_is_present() {
        let plugin = SecretsDetectorPlugin;
        assert_eq!(plugin.name(), "secrets-in-response-detector");
        assert!(!plugin.description().is_empty());
    }
}