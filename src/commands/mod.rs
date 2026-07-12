/// Command dispatch module.
///
/// Splits the monolithic if/else command chain from `main.rs` into a
/// table-driven registry.  Each logical command group lives in its own
/// submodule; `dispatch` routes a trimmed input string to the appropriate
/// handler by walking the ordered registry.
pub mod analyze;
pub mod intruder;
pub mod pipeline;
pub mod repeater;
pub mod scan;
pub mod scope;
pub mod session;
pub mod spider;
pub mod system;
pub mod workspace;

use std::sync::{Arc, Mutex};

use crate::styletui::{IntruderState, ScannerState, Screen, SpiderState};

// ── CommandContext ────────────────────────────────────────────────────────────

/// All mutable event-loop state and shared Arc handles needed by command
/// handlers.
///
/// Constructed once per `KeyCode::Enter` event inside `main`, then passed
/// by `&mut` reference into `dispatch`.  Handlers never outlive the
/// event-loop iteration that created the context.
pub struct CommandContext<'a> {
    // ── TUI output ────────────────────────────────────────────────────────────
    pub output_buffer:   &'a mut String,
    pub popup_text:      &'a mut String,
    pub show_popup:      &'a mut bool,
    pub popup_scroll:    &'a mut u16,
    pub scroll_offset:   &'a mut u16,
    pub current_screen:  &'a mut Screen,

    // ── Per-tool mutable state ────────────────────────────────────────────────
    pub scan_snapshots:  &'a mut Vec<crate::workspace::ScanSnapshot>,
    pub scanner_state:   &'a mut ScannerState,
    pub intruder_rx:     &'a mut Option<tokio::sync::mpsc::Receiver<crate::checks::intruder::IntruderResult>>,
    pub intruder_state:  &'a mut IntruderState,
    pub loaded_template: &'a mut Option<String>,
    pub spider_rx:       &'a mut Option<tokio::sync::mpsc::Receiver<crate::spider::SpiderResult>>,
    pub spider_state:    &'a mut SpiderState,

    // ── Read-only system snapshot ─────────────────────────────────────────────
    pub sys: &'a sysinfo::System,

    // ── Tokio runtime (for block_on calls) ────────────────────────────────────
    pub rt: &'a tokio::runtime::Runtime,

    // ── HTTP client pool ──────────────────────────────────────────────────────
    pub no_follow: &'a Arc<reqwest::Client>,
    pub follow:    &'a Arc<reqwest::Client>,

    // ── Shared Arc state ──────────────────────────────────────────────────────
    pub scope:         &'a Arc<Mutex<crate::scope::Scope>>,
    pub history:       &'a Arc<crate::history::History>,
    pub repeater:      &'a Arc<crate::repeater::RepeaterEngine>,
    pub scan_checks:   &'a Arc<Vec<Arc<dyn crate::scanner::ScanCheck>>>,
    pub scan_queue:    &'a crate::scanner::ScanQueue,
    pub cookie_jar:    &'a crate::session::CookieJar,
    pub profile_store: &'a crate::session::ProfileStore,
    pub cert_cache:    &'a Arc<crate::tls_mitm::CertCache>,
}

// ── Dispatch helpers ──────────────────────────────────────────────────────────

/// Returns `true` if `input` equals `kw` exactly, or starts with `kw`
/// followed by at least one ASCII whitespace character (space or tab).
///
/// This preserves the original behaviour: commands that take no arguments
/// (e.g. `"Scope-Clear"`) must be an exact match, while commands that
/// accept arguments also match when the argument is present.
#[inline]
fn matches(input: &str, kw: &str) -> bool {
    input == kw
        || (input.len() > kw.len()
            && input.starts_with(kw)
            && input.as_bytes()[kw.len()].is_ascii_whitespace())
}

/// Strips the keyword `kw` from `input` and trims any leading whitespace,
/// returning the argument portion of the command.
#[inline]
fn rest<'i>(input: &'i str, kw: &str) -> &'i str {
    input[kw.len()..].trim_start()
}

// ── dispatch ──────────────────────────────────────────────────────────────────

/// Route a command string to the appropriate handler.
///
/// The registry below is an ordered table of `(keyword, handler)` pairs.
/// More-specific keywords precede any shared prefix (e.g. `"Analyze-Site-Json"`
/// before `"Analyze-Site"`, `"Spider-Depth"` before `"Spider"`).
///
/// `exit` and `Esc` are handled in the event loop *before* this function is
/// called and are not listed here.  Unrecognised input falls through to the
/// pipeline processor (`GP`, `CG`, `GC`, `GPP`, …).
pub fn dispatch(ctx: &mut CommandContext<'_>, input: &str) {
    let t = input.trim();

    // ── Web analysis / TLS export ─────────────────────────────────────────────
    if      matches(t, "Analyze-Site-Json") { analyze::analyze_site_json(ctx, rest(t, "Analyze-Site-Json")); }
    else if matches(t, "Analyze-Email")     { analyze::analyze_email    (ctx, rest(t, "Analyze-Email")); }
    else if matches(t, "Analyze-Site")      { analyze::analyze_site     (ctx, rest(t, "Analyze-Site")); }
    else if matches(t, "Export-CA")         { analyze::export_ca        (ctx); }

    // ── Proxy scope ───────────────────────────────────────────────────────────
    else if matches(t, "Scope-Add")         { scope::scope_add    (ctx, rest(t, "Scope-Add")); }
    else if matches(t, "Scope-Exclude")     { scope::scope_exclude(ctx, rest(t, "Scope-Exclude")); }
    else if matches(t, "Scope-List")        { scope::scope_list   (ctx); }
    else if matches(t, "Scope-Clear")       { scope::scope_clear  (ctx); }

    // ── Repeater ──────────────────────────────────────────────────────────────
    else if matches(t, "Send-To-Repeater")  { repeater::send_to_repeater(ctx, rest(t, "Send-To-Repeater")); }

    // ── Scanner (Scan-Diff before Scan-S*/Scan-R* to avoid prefix shadowing) ─
    else if matches(t, "Scan-Diff")         { scan::scan_diff   (ctx); }
    else if matches(t, "Scan-Site")         { scan::scan_site   (ctx, rest(t, "Scan-Site")); }
    else if matches(t, "Scan-Request")      { scan::scan_request(ctx, rest(t, "Scan-Request")); }

    // ── Intruder ──────────────────────────────────────────────────────────────
    else if matches(t, "Fuzz")              { intruder::fuzz         (ctx, rest(t, "Fuzz")); }
    else if matches(t, "Intruder-Load")     { intruder::intruder_load(ctx, rest(t, "Intruder-Load")); }

    // ── Spider (Spider-Depth before Spider) ───────────────────────────────────
    else if matches(t, "Spider-Depth")      { spider::spider_depth(ctx, rest(t, "Spider-Depth")); }
    else if matches(t, "Spider")            { spider::spider      (ctx, rest(t, "Spider")); }

    // ── Sessions ──────────────────────────────────────────────────────────────
    else if matches(t, "Session-Save")      { session::session_save(ctx, rest(t, "Session-Save")); }
    else if matches(t, "Session-Load")      { session::session_load(ctx, rest(t, "Session-Load")); }
    else if matches(t, "Session-List")      { session::session_list(ctx); }

    // ── Workspace ─────────────────────────────────────────────────────────────
    else if matches(t, "Workspace-Save")    { workspace::workspace_save(ctx, rest(t, "Workspace-Save")); }
    else if matches(t, "Workspace-Load")    { workspace::workspace_load(ctx, rest(t, "Workspace-Load")); }
    else if matches(t, "Workspace-New")     { workspace::workspace_new(ctx); }

    // ── Built-ins ─────────────────────────────────────────────────────────────
    else if matches(t, "help")              { system::help(ctx); }

    // ── Pipeline fallback (GP, CG, GC, GPP, Get-NIF, …) ─────────────────────
    else if !t.is_empty() {
        *ctx.output_buffer = pipeline::process_pipeline(t, ctx.sys);
        *ctx.scroll_offset = 0;
    }
}
