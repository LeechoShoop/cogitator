use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use sysinfo::{Pid, System};
use tokio_util::sync::CancellationToken;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

mod config;
mod styletui;
mod logger;
mod notifier;
mod network_guard;
pub mod dns_guard;
pub mod web_analyzer;
mod scrap_analyze;
mod crypto_forensic;
mod cve;
mod proxy_guard;
mod interceptor;
mod tls_mitm;
mod ws_interceptor;
mod history;
mod scope;
mod repeater;
mod scanner;
mod checks;
mod spider;
mod session;
mod workspace;
mod plugin;

use styletui::{InterceptorState, IntruderState, RepeaterState, ScannerState, Screen, SpiderState};

#[derive(Debug, Clone)]
enum Value {
    Text(String),
    Int(i32),
    Object(HashMap<String, Value>),
}

type PipelineData = Vec<Value>;

fn format_pretty(data: &PipelineData) -> String {
    if data.is_empty() {
        return "No data found.".to_string();
    }
    data.iter().map(|item| {
        match item {
            Value::Object(map) => {
                let mut parts = Vec::new();
                for (key, val) in map {
                    let val_str = match val {
                        Value::Text(s) => s.clone(),
                        Value::Int(i) => i.to_string(),
                        Value::Object(_) => "Nested Object".to_string(),
                    };
                    parts.push(format!("{}: {}", key, val_str));
                }
                parts.join(" | ")
            }
            _ => format!("{:?}", item),
        }
    }).collect::<Vec<_>>().join("\n")
}

fn check_system_health(sys: &System) -> Option<String> {
    for (pid, process) in sys.processes() {
        if process.cpu_usage() > config::CPU_CRITICAL_THRESHOLD {
            return Some(format!(
                "⚠️  CRITICAL: Process '{}' (PID: {}) consuming {}% CPU!",
                process.name().to_string_lossy(),
                pid.as_u32(),
                process.cpu_usage() as i32
            ));
        }
    }
    None
}

fn get_help_text() -> String {
    "╔═══════════════════════════════════════════════════════╗\n\
     ║       COGITATOR — SACRED COMMANDMENTS v0.7            ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  WEB FORENSICS                                         ║\n\
     ║    Analyze-Site <dom>       Full audit (human)         ║\n\
     ║    Analyze-Site-Json <dom>  Full audit (JSON export)   ║\n\
     ║    Analyze-Email <dom>      SPF / DMARC / DKIM check   ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  TLS MITM                                              ║\n\
     ║    Export-CA            Copy CA cert + install guide   ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  PROXY SCOPE                                           ║\n\
     ║    Scope-Add <regex>     Restrict logging to matches   ║\n\
     ║    Scope-Exclude <regex> Never log/analyze matches     ║\n\
     ║    Scope-List            Show configured scope rules   ║\n\
     ║    Scope-Clear           Remove all scope rules         ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  SESSIONS                                              ║\n\
     ║    Session-Save <name>   Snapshot cookie jar as profile║\n\
     ║    Session-Load <name>   Restore cookies from profile  ║\n\
     ║    Session-List          List saved session profiles   ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  REPEATER                                              ║\n\
     ║    Send-To-Repeater <id>  Open history record in tab    ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  SCANNER                                               ║\n\
     ║    Scan-Site <domain>    Active-scan discovered forms  ║\n\
     ║    Scan-Request <id>     Active-scan a history record  ║\n\
     ║    Scan-Diff             Compare latest vs prior scan  ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  INTRUDER                                              ║\n\
     ║    Fuzz <url> <wordlist>  Sniper-fuzz a §PAYLOAD§ URL  ║\n\
     ║    Intruder-Load <file>  Load raw HTTP template (file) ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  SPIDER                                                ║\n\
     ║    Spider <domain>        Crawl (depth 3, 500 pages)   ║\n\
     ║    Spider-Depth <dom> <N> Crawl with explicit depth    ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  PROCESS RITES                                         ║\n\
     ║    GP                   List all processes             ║\n\
     ║    Find-Suspicious      Detect high CPU usage          ║\n\
     ║    Exterminate <PID>    Purge a process                ║\n\
     ║    GPP <PID>            Reveal process path            ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  NETWORK LITANIES                                      ║\n\
     ║    Get-NIF              List network interfaces        ║\n\
     ║    GC                   List active sockets + DNS      ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  WORKSPACE                                             ║\n\
     ║    Workspace-Save [file]  Save state (.cogitator)      ║\n\
     ║    Workspace-Load <file>  Restore state from file      ║\n\
     ║    Workspace-New          Reset all in-memory state    ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  SYSTEM                                                ║\n\
     ║    CG                   Clear log records              ║\n\
     ║    help                 Display this holy mandate      ║\n\
     ║    exit                 Appease the Machine Spirit     ║\n\
     ╚═══════════════════════════════════════════════════════╝".to_string()
}

fn main() -> Result<(), io::Error> {
    logger::init().expect("Failed to initialise logger");

    // ── Optional workspace file from CLI argument ─────────────────────────────
    // Usage: cogitator [workspace.cogitator]
    let cli_workspace: Option<std::path::PathBuf> = std::env::args().nth(1).map(Into::into);

    // Инициализируем асинхронную среду выполнения Tokio
    let rt = tokio::runtime::Runtime::new()?;

    // ── Shared HTTP client pool ───────────────────────────────────────────────
    // Build both clients once here so every analyze_site call (TUI + proxy)
    // reuses the same connection pool instead of tearing it down on each scan.

    fn parse_severity_str(s: &str) -> scanner::Severity {
        match s {
            "Critical" => scanner::Severity::Critical,
            "High" => scanner::Severity::High,
            "Medium" => scanner::Severity::Medium,
            "Low" => scanner::Severity::Low,
            _ => scanner::Severity::Info,
        }
    }

    /// Reconstitute a runtime `ScanFinding` from its serialised mirror —
    /// shared by the CLI-arg workspace load, `Workspace-Load`, and
    /// `Scan-Diff` (which rebuilds both sides of the diff from stored
    /// snapshots).
    fn finding_from_ser(f: &workspace::ScanFindingSer) -> scanner::ScanFinding {
        scanner::ScanFinding {
            check_name: f.check_name.clone(),
            severity: parse_severity_str(&f.severity),
            evidence: f.evidence.clone(),
            request_raw: f.request_raw.clone(),
            response_snippet: f.response_snippet.clone(),
            url: f.url.clone(),
            parameter: f.parameter.clone(),
        }
    }

    /// Convert a freshly-produced `ScanFinding` (from a `Scan-Site` /
    /// `Scan-Request` run) into its serialised mirror, for appending to
    /// `scan_snapshots`.
    fn finding_to_ser(f: &scanner::ScanFinding) -> workspace::ScanFindingSer {
        workspace::ScanFindingSer {
            check_name: f.check_name.clone(),
            severity: format!("{:?}", f.severity),
            evidence: f.evidence.clone(),
            request_raw: f.request_raw.clone(),
            response_snippet: f.response_snippet.clone(),
            url: f.url.clone(),
            parameter: f.parameter.clone(),
        }
    }

    /// Push a new entry onto `scan_snapshots` for a just-completed scan run,
    /// evicting the oldest entry past `workspace::MAX_SCAN_SNAPSHOTS`.
    fn record_scan_snapshot(
        scan_snapshots: &mut Vec<workspace::ScanSnapshot>,
        findings: &[scanner::ScanFinding],
    ) {
        if findings.is_empty() {
            return;
        }
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        scan_snapshots.push(workspace::ScanSnapshot {
            timestamp_ms,
            findings: findings.iter().map(finding_to_ser).collect(),
        });
        if scan_snapshots.len() > workspace::MAX_SCAN_SNAPSHOTS {
            let drop_count = scan_snapshots.len() - workspace::MAX_SCAN_SNAPSHOTS;
            scan_snapshots.drain(0..drop_count);
        }
    }

    // reuses the same connection pool instead of tearing it down on each scan.
    let (no_follow, follow) = web_analyzer::build_clients()
        .expect("Failed to build HTTP clients");
    let no_follow = Arc::new(no_follow);
    let follow    = Arc::new(follow);

    // Атомарный флаг для отслеживания состояния прокси-сервера
    let proxy_running = Arc::new(AtomicBool::new(false));
    let proxy_flag_clone = proxy_running.clone();

    // Token shared between the TUI loop and start_proxy.
    // Cancelling it from either side stops the accept loop cleanly.
    let proxy_shutdown = CancellationToken::new();
    let proxy_shutdown_clone = proxy_shutdown.clone();

    // Wrap the two clients in a DefaultSiteAnalyzer so proxy_guard depends only
    // on the trait, not on reqwest internals.  The TUI path keeps calling
    // analyze_site directly with its own Arc<Client> references (unchanged).
    let proxy_analyzer: Arc<dyn web_analyzer::SiteAnalyzer> =
        Arc::new(web_analyzer::DefaultSiteAnalyzer::new(
            no_follow.clone(),
            follow.clone(),
        ));

    // Local CA (generated once / loaded from cogitator_ca.pem + .key) used to
    // mint per-domain leaf certificates for TLS MITM on CONNECT requests.
    let cert_cache = Arc::new(
        tls_mitm::CertCache::new().expect("Failed to initialise TLS MITM certificate authority"),
    );
    if cert_cache.ca_was_freshly_generated() {
        logger::log_event(&format!(
            "Startup: no existing {} found — generated a new local MITM CA.",
            cert_cache.ca_cert_path()
        ));
    } else {
        logger::log_event(&format!(
            "Startup: loaded existing local MITM CA from {}.",
            cert_cache.ca_cert_path()
        ));
    }

    // The TUI loop needs its own handle for the `Export-CA` command, so clone
    // before the original Arc is moved into the spawned proxy task below.
    let cert_cache_for_tui = cert_cache.clone();

    // Shared request/response history. The proxy task records every
    // completed exchange into it; clone before moving the original into the
    // spawned task if the TUI ever needs its own handle (e.g. a future
    // `History` browsing command).
    let history = Arc::new(history::History::new());
    let history_for_tui = history.clone();

    // Repeater engine: holds the editable request/response tabs shown in
    // the RepeaterView screen. Populated either manually (Ctrl+N) or via
    // the `Send-To-Repeater <history_id>` command below.
    let repeater_engine = Arc::new(repeater::RepeaterEngine::new());
    let repeater_engine_for_tui = repeater_engine.clone();

    // InterceptorEngine backs the Interceptor screen's "Frozen" sub-view
    // (requests parked for manual Forward/Drop/Edit) and, since
    // ws_interceptor was wired in, also WebSocket frame interception —
    // the proxy task gets its own clone below so both it and the TUI share
    // the same queues.
    let interceptor_engine_for_tui = Arc::new(interceptor::InterceptorEngine::new());
    let interceptor_engine_for_proxy = interceptor_engine_for_tui.clone();

    // Shared proxy scope. Empty by default ("all in scope"). The TUI's
    // Scope-* commands mutate this through the Mutex; the proxy task only
    // ever reads it (via Scope::in_scope) to decide whether to log/analyze
    // a request or auto-forward it untouched.
    let scope = Arc::new(std::sync::Mutex::new(scope::Scope::new()));
    let scope_for_tui = scope.clone();

    // Запускаем прокси-сервер в фоновом асинхронном потоке
    rt.spawn(async move {
        if let Err(e) = proxy_guard::start_proxy(
            config::PROXY_ADDR,
            proxy_flag_clone,
            proxy_shutdown_clone,
            proxy_analyzer,
            cert_cache,
            history,
            scope,
            interceptor_engine_for_proxy,
        ).await {
            logger::log_event(&format!("Proxy Guard Critical Error: {}", e));
        }
    });

    // Настраиваем терминал для работы TUI (сырой режим + альтернативный экран)
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut sys = System::new_all();
    let mut input_buffer = String::new();
    let mut output_buffer = String::from("System Initialized. Awaiting sacred input... Type 'help' for commandments.");
    let mut scroll_offset: u16 = 0;

    let mut show_popup = false;
    let mut popup_text = String::new();
    let mut popup_scroll_offset: u16 = 0;

    let mut last_health_check = Instant::now();
    let health_check_interval = Duration::from_secs(config::HEALTH_CHECK_INTERVAL_SECS);

    let mut current_screen = Screen::Main;
    let mut repeater_state = RepeaterState::new(repeater_engine_for_tui.clone());
    let mut interceptor_state = InterceptorState::new(history_for_tui.clone(), interceptor_engine_for_tui.clone());
    let mut scanner_state = ScannerState::new();
    // Accumulated scan runs (oldest first) — fed by every completed
    // Scan-Site/Scan-Request, persisted via WorkspaceData, and consumed by
    // the Scan-Diff command (compares the last two entries).
    let mut scan_snapshots: Vec<workspace::ScanSnapshot> = Vec::new();
    let mut intruder_state = IntruderState::new();
    let mut spider_state = SpiderState::new();

    // Live result streams for the two background engines. `None` when no
    // run is in flight. Each is drained (non-blocking) once per loop tick,
    // right before drawing — see the "Drain background engine channels"
    // block below.
    let mut intruder_rx: Option<tokio::sync::mpsc::Receiver<checks::intruder::IntruderResult>> = None;
    let mut spider_rx: Option<tokio::sync::mpsc::Receiver<spider::SpiderResult>> = None;

    // `Intruder-Load <file>` stages a raw HTTP template here. Nothing
    // currently consumes it — there's no specified command that pairs a
    // loaded template with a payload source and launches it — so for now
    // this just confirms the file was read. Wire a future
    // `Intruder-Run`-style command (or extend `Fuzz`) to pull from this
    // once that's specified.
    let mut loaded_intruder_template: Option<String> = None;

    // Active scan checks run by `Scan-Site` / `Scan-Request`. Built once and
    // shared via `Arc` so `ScanQueue::run_all` can hand out clones to every
    // spawned `(target, check)` task without re-allocating the check list
    // on every scan.
    let scan_checks: std::sync::Arc<Vec<std::sync::Arc<dyn scanner::ScanCheck>>> =
        std::sync::Arc::new(vec![
            std::sync::Arc::new(checks::sqli::SqliCheck::new()),
            std::sync::Arc::new(checks::traversal::TraversalCheck::new()),
        ]);
    let scan_queue = scanner::ScanQueue::new();

    // Session management: shared cookie jar and named profile store.
    // The jar is updated automatically whenever Repeater receives a response
    // that carries Set-Cookie headers. Profiles can be saved/loaded via the
    // Session-Save / Session-Load / Session-List TUI commands below.
    let cookie_jar = session::CookieJar::new();
    let profile_store = session::ProfileStore::new();

    // ── Workspace: auto-restore prompt ────────────────────────────────────────
    // If a CLI argument was given, load it immediately and silently.
    // Otherwise, if `cogitator_last.cogitator` exists in the working directory,
    // ask the user whether to restore it via the startup output_buffer.
    let last_ws_path = std::path::Path::new(workspace::LAST_WORKSPACE_FILE);
    let mut startup_ws_to_offer: Option<workspace::WorkspaceData> = None;

    if let Some(ref path) = cli_workspace {
        match workspace::WorkspaceData::load(path) {
            Ok(ws) => {
                let (findings_ser, snaps) = ws.restore(
                    &scope_for_tui,
                    &history_for_tui,
                    &repeater_engine_for_tui,
                    &profile_store,
                );
                scan_snapshots = snaps;
                // Reconstitute ScanFinding objects from the serialised mirrors
                // so scanner_state shows the restored findings immediately.
                let restored_findings: Vec<scanner::ScanFinding> =
                    findings_ser.iter().map(finding_from_ser).collect();
                let count = restored_findings.len();
                scanner_state.set_findings(
                    restored_findings,
                    format!("restored from {}", path.display()),
                );
                output_buffer = format!(
                    "✅ Workspace loaded from {} ({} finding(s) restored)",
                    path.display(),
                    count
                );
                logger::log_event(&format!("Workspace loaded from {}", path.display()));
            }
            Err(e) => {
                output_buffer = format!(
                    "❌ Failed to load workspace '{}': {}",
                    path.display(),
                    e
                );
            }
        }
    } else if last_ws_path.exists() {
        // Offer to restore; the user can press Enter on the pre-filled command
        // or delete it and type something else.
        match workspace::WorkspaceData::load(last_ws_path) {
            Ok(ws) => {
                startup_ws_to_offer = Some(ws);
                output_buffer = format!(
                    "💾 Found auto-save '{}'. Run  Workspace-Load {}  to restore it, or type any other command to continue fresh.",
                    workspace::LAST_WORKSPACE_FILE,
                    workspace::LAST_WORKSPACE_FILE,
                );
            }
            Err(_) => {} // corrupt / unreadable — ignore silently
        }
    }

    loop {
        sys.refresh_all();

        // Периодическая проверка нагрузки на систему
        if last_health_check.elapsed() >= health_check_interval {
            if let Some(warning) = check_system_health(&sys) {
                output_buffer = warning.clone();
                logger::log_event(&warning);
            }
            last_health_check = Instant::now();
        }

        // ── Drain background engine channels ────────────────────────────────────
        //
        // Both `checks::intruder::run` and `spider::run` spawn their own
        // background task and hand back a `Receiver` immediately — they
        // don't block. Draining here, once per tick, is what makes
        // IntruderView/SpiderView feel "live": every redraw picks up
        // whatever arrived since the last one, with no separate
        // "run finished, now show results" step.
        if let Some(rx) = intruder_rx.as_mut() {
            let mut disconnected = false;
            loop {
                match rx.try_recv() {
                    Ok(item) => intruder_state.push_result(item),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
            if disconnected {
                intruder_rx = None;
            }
        }
        if let Some(rx) = spider_rx.as_mut() {
            let mut disconnected = false;
            loop {
                match rx.try_recv() {
                    Ok(item) => spider_state.push_result(item),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
            if disconnected {
                spider_rx = None;
            }
        }

        // Отрисовка интерфейса
        if current_screen == Screen::Repeater {
            repeater_state.sync_from_selected();
        }
        terminal.draw(|f| {
            match current_screen {
                Screen::Repeater => styletui::draw_repeater_view(f, &repeater_state),
                Screen::Interceptor => styletui::draw_interceptor_view(f, &interceptor_state),
                Screen::Scanner => styletui::draw_scanner_view(f, &scanner_state),
                Screen::Intruder => styletui::draw_intruder_view(f, &intruder_state),
                Screen::Spider => styletui::draw_spider_view(f, &spider_state),
                _ => styletui::draw_ui(
                    f,
                    &input_buffer,
                    &output_buffer,
                    scroll_offset,
                    show_popup,
                    &popup_text,
                    popup_scroll_offset,
                    proxy_running.load(Ordering::SeqCst), // Передаем статус прокси
                ),
            }
        })?;

        // Обработка пользовательского ввода
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                // Если открыт Popup, любое нажатие (кроме стрелочек) закрывает его
                if show_popup && key.code != KeyCode::Up && key.code != KeyCode::Down {
                    show_popup = false;
                    popup_scroll_offset = 0;
                    continue;
                }

                match key.code {
                    KeyCode::Tab if !show_popup => {
                        current_screen = current_screen.next();
                        continue;
                    }
                    _ if current_screen == Screen::Interceptor && !show_popup => {
                        interceptor_state.handle_key(key);
                        continue;
                    }
                    _ if current_screen == Screen::Scanner && !show_popup => {
                        scanner_state.handle_key(key);
                        continue;
                    }
                    _ if current_screen == Screen::Intruder && !show_popup => {
                        intruder_state.handle_key(key);
                        continue;
                    }
                    _ if current_screen == Screen::Spider && !show_popup => {
                        spider_state.handle_key(key);
                        continue;
                    }
                    _ if current_screen == Screen::Repeater && !show_popup => {
                        repeater_state.handle_key(key);
                        if let Some(tab_id) = repeater_state.pending_history_view.take() {
                            let rounds = repeater_engine_for_tui.get_history(tab_id);
                            if rounds.is_empty() {
                                popup_text = format!(
                                    "┌─[ REPEATER TAB #{} HISTORY ]──────────────\n│  (nothing sent yet)\n└────────────────────────────────────────────\n",
                                    tab_id
                                );
                            } else {
                                let mut text = format!(
                                    "┌─[ REPEATER TAB #{} HISTORY ({} round-trips) ]──\n",
                                    tab_id, rounds.len()
                                );
                                for (i, (req, resp)) in rounds.iter().enumerate() {
                                    text.push_str(&format!("│\n│ ── Round {} ──\n│ » Request:\n", i + 1));
                                    for line in req.lines() {
                                        text.push_str(&format!("│   {}\n", line));
                                    }
                                    text.push_str("│ « Response:\n");
                                    for line in resp.lines() {
                                        text.push_str(&format!("│   {}\n", line));
                                    }
                                }
                                text.push_str("└────────────────────────────────────────────\n");
                                popup_text = text;
                            }
                            popup_scroll_offset = 0;
                            show_popup = true;
                        }
                        if let Some(tab_id) = repeater_state.pending_send.take() {
                            // Reuse the TUI's `follow` client pool so Repeater
                            // sends share the same connection pool as the
                            // rest of the app instead of spinning up new
                            // reqwest::Client instances per send.
                            match rt.block_on(repeater_engine_for_tui.send(
                                tab_id,
                                &follow,
                                None,          // no active profile — set via Session-Load
                                Some(&cookie_jar), // harvest Set-Cookie back into jar
                            )) {
                                Ok(_) => {}
                                Err(e) => {
                                    logger::log_event(&format!(
                                        "Repeater send failed for tab #{}: {}",
                                        tab_id, e
                                    ));
                                }
                            }
                        }
                        continue;
                    }
                    _ => {}
                }

                match key.code {
                    KeyCode::Up => {
                        if show_popup { popup_scroll_offset = popup_scroll_offset.saturating_sub(1); }
                        else { scroll_offset = scroll_offset.saturating_sub(1); }
                    }
                    KeyCode::Down => {
                        if show_popup { popup_scroll_offset = popup_scroll_offset.saturating_add(1); }
                        else { scroll_offset = scroll_offset.saturating_add(1); }
                    }
                    KeyCode::Enter => {
                        let trimmed_input = input_buffer.trim().to_string();

                        if trimmed_input == "exit" {
                            break;
                        } else if trimmed_input == "help" {
                            output_buffer = get_help_text();
                            scroll_offset = 0;
                        } else if trimmed_input == "Export-CA" {
                            let cwd = std::env::current_dir()
                                .unwrap_or_else(|_| std::path::PathBuf::from("."));
                            match cert_cache_for_tui.export_ca_to(&cwd) {
                                Ok(dest_path) => {
                                    let mut text = String::from(
                                        "┌─[ EXPORT CA: cogitator_ca.pem ]──────────────\n"
                                    );
                                    text.push_str(&format!("│  Copied to: {}\n", dest_path.display()));
                                    text.push_str("│\n");
                                    text.push_str("│  CHROME / EDGE (chromium-based):\n");
                                    text.push_str("│    Settings → Privacy and security → Security →\n");
                                    text.push_str("│    Manage certificates → Authorities tab → Import.\n");
                                    text.push_str("│    Select the file above, check \"Trust this\n");
                                    text.push_str("│    certificate for identifying websites\", confirm.\n");
                                    text.push_str("│\n");
                                    text.push_str("│  FIREFOX:\n");
                                    text.push_str("│    Settings → Privacy & Security → Certificates →\n");
                                    text.push_str("│    View Certificates → Authorities tab → Import.\n");
                                    text.push_str("│    Select the file above, check \"Trust this CA to\n");
                                    text.push_str("│    identify websites\", confirm.\n");
                                    text.push_str("│\n");
                                    text.push_str("│  OS TRUST STORE:\n");
                                    text.push_str("│    Windows: double-click the .pem → Install\n");
                                    text.push_str("│      Certificate → Local Machine → place in\n");
                                    text.push_str("│      \"Trusted Root Certification Authorities\".\n");
                                    text.push_str("│    macOS: open in Keychain Access → System keychain\n");
                                    text.push_str("│      → set \"Always Trust\" for this certificate.\n");
                                    text.push_str("│    Linux (Debian/Ubuntu): copy to\n");
                                    text.push_str("│      /usr/local/share/ca-certificates/ as a .crt\n");
                                    text.push_str("│      file, then run `sudo update-ca-certificates`.\n");
                                    text.push_str("│\n");
                                    text.push_str("│  ⚠ This CA can decrypt any TLS traffic from a\n");
                                    text.push_str("│    client that trusts it. Only install it on\n");
                                    text.push_str("│    machines/browsers you control and intend to\n");
                                    text.push_str("│    MITM-inspect with Cogitator.\n");
                                    text.push_str("└────────────────────────────────────────────\n");
                                    popup_text = text;
                                    popup_scroll_offset = 0;
                                    show_popup = true;
                                    output_buffer = format!("✅ CA exported to {}", dest_path.display());
                                }
                                Err(e) => {
                                    output_buffer = format!(
                                        "❌ Export-CA failed: {} (has the proxy generated {} yet?)",
                                        e,
                                        cert_cache_for_tui.ca_cert_path()
                                    );
                                }
                            }
                        } else if trimmed_input.starts_with("Analyze-Site-Json") {
                            let parts: Vec<&str> = trimmed_input.split_whitespace().collect();
                            if parts.len() == 2 {
                                let result = rt.block_on(web_analyzer::analyze_site(parts[1], &no_follow, &follow));
                                popup_text = web_analyzer::export_to_json(&result);

                                let filename = format!("{}_report.json", parts[1].replace(':', "_"));
                                match web_analyzer::save_to_file(&result, &filename) {
                                    Ok(_) => output_buffer = format!("✅ JSON saved to {}", filename),
                                    Err(e) => output_buffer = format!("❌ Save failed: {}", e),
                                }
                                popup_scroll_offset = 0;
                                show_popup = true;
                            } else {
                                output_buffer = "Usage: Analyze-Site-Json <domain>".to_string();
                            }
                        } else if trimmed_input.starts_with("Analyze-Email") {
                            let parts: Vec<&str> = trimmed_input.split_whitespace().collect();
                            if parts.len() == 2 {
                                let domain = parts[1];
                                let records = dns_guard::audit_email_security(domain);
                                let mut text = format!("┌─[ EMAIL SECURITY: {} ]─────────────────────\n", domain);
                                text.push_str(&format!("│  SPF:   {}\n", records.spf.as_deref().unwrap_or("❌ Not found")));
                                text.push_str(&format!("│  DMARC: {}\n", records.dmarc.as_deref().unwrap_or("❌ Not found")));
                                text.push_str(&format!("│  DKIM:  {}\n", if records.dkim_selector_found { "✅ Found (common selector)" } else { "⚠️  Not detected" }));
                                text.push_str(&format!("│  {}\n", records.summary));
                                text.push_str("└────────────────────────────────────────────\n");
                                popup_text = text;
                                popup_scroll_offset = 0;
                                show_popup = true;
                                output_buffer = format!("✅ Email security checked: {}", domain);
                            } else {
                                output_buffer = "Usage: Analyze-Email <domain>".to_string();
                            }
                        } else if trimmed_input.starts_with("Analyze-Site") {
                            let parts: Vec<&str> = trimmed_input.split_whitespace().collect();
                            if parts.len() == 2 {
                                let result = rt.block_on(web_analyzer::analyze_site(parts[1], &no_follow, &follow));
                                popup_text = web_analyzer::format_analysis(&result);
                                popup_scroll_offset = 0;
                                show_popup = true;
                                output_buffer = format!("✅ Scan complete: {}", parts[1]);
                            } else {
                                output_buffer = "Usage: Analyze-Site <domain>".to_string();
                            }
                        } else if trimmed_input.starts_with("Scope-Add") {
                            let rest = trimmed_input["Scope-Add".len()..].trim();
                            if rest.is_empty() {
                                output_buffer = "Usage: Scope-Add <regex>".to_string();
                            } else {
                                match scope_for_tui.lock().unwrap().add_include(rest) {
                                    Ok(_) => output_buffer = format!("✅ Scope include added: {}", rest),
                                    Err(e) => output_buffer = format!("❌ Invalid regex: {}", e),
                                }
                            }
                        } else if trimmed_input.starts_with("Scope-Exclude") {
                            let rest = trimmed_input["Scope-Exclude".len()..].trim();
                            if rest.is_empty() {
                                output_buffer = "Usage: Scope-Exclude <regex>".to_string();
                            } else {
                                match scope_for_tui.lock().unwrap().add_exclude(rest) {
                                    Ok(_) => output_buffer = format!("✅ Scope exclude added: {}", rest),
                                    Err(e) => output_buffer = format!("❌ Invalid regex: {}", e),
                                }
                            }
                        } else if trimmed_input == "Scope-List" {
                            let rules = scope_for_tui.lock().unwrap().list();
                            if rules.is_empty() {
                                output_buffer = "Scope is empty — all traffic is in scope.".to_string();
                            } else {
                                let mut text = String::from("┌─[ PROXY SCOPE ]───────────────────────────\n");
                                for (pattern, include) in &rules {
                                    text.push_str(&format!(
                                        "│  {} {}\n",
                                        if *include { "+ INCLUDE" } else { "- EXCLUDE" },
                                        pattern
                                    ));
                                }
                                text.push_str("└────────────────────────────────────────────\n");
                                output_buffer = text;
                            }
                            scroll_offset = 0;
                        } else if trimmed_input == "Scope-Clear" {
                            scope_for_tui.lock().unwrap().clear();
                            output_buffer = "✅ Scope cleared — all traffic is now in scope.".to_string();
                        } else if trimmed_input.starts_with("Send-To-Repeater") {
                            let rest = trimmed_input["Send-To-Repeater".len()..].trim();
                            match rest.parse::<u64>() {
                                Ok(id) => match history_for_tui.get(id) {
                                    Some(record) => {
                                        let tab_id = repeater_engine_for_tui.new_tab(&record);
                                        output_buffer = format!(
                                            "✅ History record #{} opened in Repeater tab #{}",
                                            id, tab_id
                                        );
                                        current_screen = Screen::Repeater;
                                    }
                                    None => {
                                        output_buffer = format!(
                                            "❌ No history record with id {} (evicted or never existed)",
                                            id
                                        );
                                    }
                                },
                                Err(_) => {
                                    output_buffer = "Usage: Send-To-Repeater <history_id>".to_string();
                                }
                            }
                        } else if trimmed_input.starts_with("Scan-Site") {
                            let rest = trimmed_input["Scan-Site".len()..].trim();
                            if rest.is_empty() {
                                output_buffer = "Usage: Scan-Site <domain>".to_string();
                            } else {
                                let domain = rest.to_string();
                                output_buffer = format!("⏳ Scanning {} (Analyze-Site + active checks)…", domain);

                                let result = rt.block_on(web_analyzer::analyze_site(&domain, &no_follow, &follow));
                                let base_url = result.target_url.clone();

                                let vectors = result
                                    .html_audit
                                    .as_ref()
                                    .map(|h| h.attack_vectors.clone())
                                    .unwrap_or_default();

                                if vectors.is_empty() {
                                    scanner_state.set_findings(
                                        Vec::new(),
                                        format!("{} — no attack vectors found (no forms?)", domain),
                                    );
                                    output_buffer = format!(
                                        "⚠️  Analyze-Site found no form-based attack vectors on {}",
                                        domain
                                    );
                                } else {
                                    // Build one ScanTarget per discovered attack vector.
                                    // `form_action` may be relative ("[No Action Defined]"
                                    // or a path) — resolve it against the scanned page's
                                    // URL so checks hit a real, absolute endpoint.
                                    for vector in &vectors {
                                        let action = &vector.form_action;
                                        let url = if action.starts_with("http://") || action.starts_with("https://") {
                                            action.clone()
                                        } else if action == "[No Action Defined]" {
                                            // No explicit action — the form submits to
                                            // the page it lives on.
                                            base_url.clone()
                                        } else {
                                            match reqwest::Url::parse(&base_url).and_then(|b| b.join(action)) {
                                                Ok(joined) => joined.to_string(),
                                                Err(_) => base_url.clone(),
                                            }
                                        };

                                        // Hidden/text/etc. inputs all become probeable
                                        // params; checkbox/radio/submit/file/button are
                                        // skipped — they aren't free-text injection points.
                                        let skip_types = ["checkbox", "radio", "submit", "button", "file", "image", "reset"];
                                        if skip_types.contains(&vector.input_type.as_str()) {
                                            continue;
                                        }

                                        scan_queue.enqueue(scanner::ScanTarget {
                                            url,
                                            method: "GET".to_string(),
                                            params: vec![(vector.name.clone(), "test".to_string())],
                                            headers: Vec::new(),
                                            body: Vec::new(),
                                        });
                                    }

                                    let findings = rt.block_on(
                                        scan_queue.run_all(scan_checks.clone(), (*follow).clone()),
                                    );
                                    let count = findings.len();
                                    record_scan_snapshot(&mut scan_snapshots, &findings);
                                    scanner_state.set_findings(
                                        findings,
                                        format!("{} — {} finding(s) from {} vector(s)", domain, count, vectors.len()),
                                    );
                                    output_buffer = format!(
                                        "✅ Scan complete: {} — {} finding(s) across {} attack vector(s)",
                                        domain, count, vectors.len()
                                    );
                                    current_screen = Screen::Scanner;
                                }
                            }
                        } else if trimmed_input.starts_with("Scan-Request") {
                            let rest = trimmed_input["Scan-Request".len()..].trim();
                            match rest.parse::<u64>() {
                                Ok(id) => match history_for_tui.get(id) {
                                    Some(record) => {
                                        // Turn the recorded request's query string (if
                                        // any) into probeable params. Bodies/headers
                                        // are carried over as-is; if there were no query
                                        // params, the checks simply find nothing to
                                        // substitute and report no findings for this id.
                                        let url = format!("https://{}{}", record.host, record.path);
                                        let params: Vec<(String, String)> = reqwest::Url::parse(&url)
                                            .map(|u| {
                                                u.query_pairs()
                                                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                                                    .collect()
                                            })
                                            .unwrap_or_default();

                                        scan_queue.enqueue(scanner::ScanTarget {
                                            url,
                                            method: record.method.clone(),
                                            params,
                                            headers: record.headers.clone(),
                                            body: record.body.clone(),
                                        });

                                        let findings = rt.block_on(
                                            scan_queue.run_all(scan_checks.clone(), (*follow).clone()),
                                        );
                                        let count = findings.len();
                                        record_scan_snapshot(&mut scan_snapshots, &findings);
                                        scanner_state.set_findings(
                                            findings,
                                            format!("history #{} — {} finding(s)", id, count),
                                        );
                                        output_buffer = format!(
                                            "✅ Scan complete: history #{} — {} finding(s)",
                                            id, count
                                        );
                                        current_screen = Screen::Scanner;
                                    }
                                    None => {
                                        output_buffer = format!(
                                            "❌ No history record with id {} (evicted or never existed)",
                                            id
                                        );
                                    }
                                },
                                Err(_) => {
                                    output_buffer = "Usage: Scan-Request <history_id>".to_string();
                                }
                            }
                        } else if trimmed_input == "Scan-Diff" {
                            if scan_snapshots.len() < 2 {
                                output_buffer = "Need at least 2 scan snapshots to diff — run Scan-Site/Scan-Request twice.".to_string();
                            } else {
                                let n = scan_snapshots.len();
                                let old: Vec<scanner::ScanFinding> = scan_snapshots[n - 2]
                                    .findings
                                    .iter()
                                    .map(finding_from_ser)
                                    .collect();
                                let new: Vec<scanner::ScanFinding> = scan_snapshots[n - 1]
                                    .findings
                                    .iter()
                                    .map(finding_from_ser)
                                    .collect();
                                let diff = scanner::diff_findings(&old, &new);

                                let mut text = format!(
                                    "┌─[ SCAN-DIFF: snapshot #{} vs #{} ]──────────────\n",
                                    n - 1, n
                                );
                                text.push_str(&format!("│  New findings ({}):\n", diff.new_findings.len()));
                                for f in &diff.new_findings {
                                    text.push_str(&format!(
                                        "│    + [{:?}] {} — {} ({})\n",
                                        f.severity, f.check_name, f.url,
                                        f.parameter.as_deref().unwrap_or("—")
                                    ));
                                }
                                text.push_str(&format!("│  Fixed ({}):\n", diff.fixed_findings.len()));
                                for f in &diff.fixed_findings {
                                    text.push_str(&format!(
                                        "│    - [{:?}] {} — {} ({})\n",
                                        f.severity, f.check_name, f.url,
                                        f.parameter.as_deref().unwrap_or("—")
                                    ));
                                }
                                text.push_str(&format!("│  Unchanged ({}):\n", diff.unchanged.len()));
                                for f in &diff.unchanged {
                                    text.push_str(&format!(
                                        "│    = [{:?}] {} — {} ({})\n",
                                        f.severity, f.check_name, f.url,
                                        f.parameter.as_deref().unwrap_or("—")
                                    ));
                                }
                                text.push_str("└────────────────────────────────────────────\n");
                                output_buffer = format!(
                                    "✅ Scan-Diff: {} new, {} fixed, {} unchanged",
                                    diff.new_findings.len(), diff.fixed_findings.len(), diff.unchanged.len()
                                );
                                popup_text = text;
                                popup_scroll_offset = 0;
                                show_popup = true;
                            }
                        } else if trimmed_input.starts_with("Fuzz") {
                            let rest = trimmed_input["Fuzz".len()..].trim();
                            let parts: Vec<&str> = rest.split_whitespace().collect();
                            if parts.len() != 2 {
                                output_buffer = format!(
                                    "Usage: Fuzz <url containing {}> <wordlist_file>",
                                    checks::intruder::MARKER
                                );
                            } else {
                                let url = parts[0];
                                let wordlist_path = parts[1];

                                if !url.contains(checks::intruder::MARKER) {
                                    output_buffer = format!(
                                        "❌ URL must contain a {} marker to fuzz",
                                        checks::intruder::MARKER
                                    );
                                } else {
                                    let payloads: Vec<String> = checks::intruder::load_wordlist(
                                        &checks::intruder::WordlistSource::File(PathBuf::from(wordlist_path)),
                                    )
                                        .collect();

                                    if payloads.is_empty() {
                                        output_buffer = format!(
                                            "❌ Wordlist {} was empty or unreadable",
                                            wordlist_path
                                        );
                                    } else {
                                        // Absolute-form request line — `build_request`
                                        // in intruder.rs treats the target as a ready
                                        // URL when it starts with http(s)://, so no
                                        // Host header (and no premature URL-parsing
                                        // of the §PAYLOAD§-laden string) is needed.
                                        let template = format!("GET {} HTTP/1.1\r\n\r\n", url);
                                        let payload_count = payloads.len();

                                        let cfg = checks::intruder::IntruderConfig {
                                            template,
                                            payloads,
                                            payload_sets: Vec::new(),
                                            mode: checks::intruder::IntruderMode::Sniper,
                                            threads: checks::intruder::DEFAULT_THREADS,
                                            delay_ms: 0,
                                        };

                                        // `intruder::run` spawns its own task via
                                        // `tokio::spawn`, which needs an active
                                        // runtime context to schedule onto — `enter()`
                                        // sets that context without blocking (unlike
                                        // `block_on`), so the TUI loop keeps going
                                        // while the fuzz run streams results in.
                                        let _guard = rt.enter();
                                        let rx = checks::intruder::run(cfg, follow.clone(), None);
                                        drop(_guard);

                                        intruder_state.reset_for_new_run(format!(
                                            "fuzzing {} ({} payload(s))",
                                            url, payload_count
                                        ));
                                        intruder_rx = Some(rx);
                                        output_buffer = format!(
                                            "⏳ Fuzzing {} — streaming results into Intruder view…",
                                            url
                                        );
                                        current_screen = Screen::Intruder;
                                    }
                                }
                            }
                        } else if trimmed_input.starts_with("Intruder-Load") {
                            let rest = trimmed_input["Intruder-Load".len()..].trim();
                            if rest.is_empty() {
                                output_buffer = "Usage: Intruder-Load <file>".to_string();
                            } else {
                                match std::fs::read_to_string(rest) {
                                    Ok(contents) => {
                                        let marker_count = contents.matches(checks::intruder::MARKER).count();
                                        let byte_len = contents.len();
                                        loaded_intruder_template = Some(contents);
                                        output_buffer = format!(
                                            "✅ Loaded template from {} ({} bytes, {} {} marker(s))",
                                            rest, byte_len, marker_count, checks::intruder::MARKER
                                        );
                                    }
                                    Err(e) => {
                                        output_buffer = format!("❌ Failed to read {}: {}", rest, e);
                                    }
                                }
                            }
                        } else if trimmed_input.starts_with("Spider-Depth") {
                            // Checked before the plain "Spider" branch below,
                            // since "Spider-Depth ..." also starts_with "Spider".
                            let rest = trimmed_input["Spider-Depth".len()..].trim();
                            let parts: Vec<&str> = rest.split_whitespace().collect();
                            if parts.len() != 2 {
                                output_buffer = "Usage: Spider-Depth <domain> <N>".to_string();
                            } else {
                                match parts[1].parse::<u8>() {
                                    Ok(depth) => {
                                        let (seed_url, cfg) = build_spider_config(
                                            parts[0],
                                            depth,
                                            500,
                                            history_for_tui.clone(),
                                        );
                                        let _guard = rt.enter();
                                        let rx = spider::run(cfg, follow.clone());
                                        drop(_guard);

                                        spider_state.reset_for_new_run(
                                            500,
                                            format!("crawling {} (depth {})…", seed_url, depth),
                                        );
                                        spider_rx = Some(rx);
                                        output_buffer = format!(
                                            "⏳ Crawling {} (depth {}, max 500 pages)…",
                                            seed_url, depth
                                        );
                                        current_screen = Screen::Spider;
                                    }
                                    Err(_) => {
                                        output_buffer = "Usage: Spider-Depth <domain> <N>".to_string();
                                    }
                                }
                            }
                        } else if trimmed_input.starts_with("Spider") {
                            let rest = trimmed_input["Spider".len()..].trim();
                            if rest.is_empty() {
                                output_buffer =
                                    "Usage: Spider <domain>  (or Spider-Depth <domain> <N>)".to_string();
                            } else {
                                let (seed_url, cfg) =
                                    build_spider_config(rest, 3, 500, history_for_tui.clone());
                                let _guard = rt.enter();
                                let rx = spider::run(cfg, follow.clone());
                                drop(_guard);

                                spider_state.reset_for_new_run(
                                    500,
                                    format!("crawling {} (depth 3)…", seed_url),
                                );
                                spider_rx = Some(rx);
                                output_buffer = format!(
                                    "⏳ Crawling {} (depth 3, max 500 pages)…",
                                    seed_url
                                );
                                current_screen = Screen::Spider;
                            }
                        } else if trimmed_input.starts_with("Session-Save") {
                            let name = trimmed_input["Session-Save".len()..].trim();
                            if name.is_empty() {
                                output_buffer = "Usage: Session-Save <name>".to_string();
                            } else {
                                let mut profile = cookie_jar.snapshot();
                                profile.name = name.to_string();
                                profile_store.save(profile);
                                output_buffer = format!("✅ Session saved as '{}'", name);
                            }
                        } else if trimmed_input.starts_with("Session-Load") {
                            let name = trimmed_input["Session-Load".len()..].trim();
                            if name.is_empty() {
                                output_buffer = "Usage: Session-Load <name>".to_string();
                            } else {
                                match profile_store.load(name) {
                                    Some(profile) => {
                                        cookie_jar.restore_from_profile(&profile);
                                        output_buffer = format!(
                                            "✅ Session '{}' loaded ({} domain(s) restored)",
                                            name,
                                            profile.cookies.len()
                                        );
                                    }
                                    None => {
                                        output_buffer = format!(
                                            "❌ No saved session named '{}' (try Session-List)",
                                            name
                                        );
                                    }
                                }
                            }
                        } else if trimmed_input == "Session-List" {
                            let names = profile_store.list();
                            if names.is_empty() {
                                output_buffer =
                                    "No saved sessions yet. Use Session-Save <name>.".to_string();
                            } else {
                                let mut text =
                                    String::from("┌─[ SAVED SESSIONS ]────────────────────────\n");
                                for n in &names {
                                    if let Some(p) = profile_store.load(n) {
                                        text.push_str(&format!(
                                            "│  {}  ({} domain(s), {} custom header(s))\n",
                                            n,
                                            p.cookies.len(),
                                            p.custom_headers.len()
                                        ));
                                    }
                                }
                                text.push_str("└────────────────────────────────────────────\n");
                                output_buffer = text;
                            }
                            scroll_offset = 0;
                        } else if trimmed_input.starts_with("Workspace-Save") {
                            let rest = trimmed_input["Workspace-Save".len()..].trim();
                            let path = if rest.is_empty() {
                                workspace::LAST_WORKSPACE_FILE.to_string()
                            } else {
                                rest.to_string()
                            };
                            let ws = workspace::WorkspaceData::capture(
                                config::PROXY_ADDR,
                                &scope_for_tui,
                                &history_for_tui,
                                &scanner_state.findings,
                                &scan_snapshots,
                                &repeater_engine_for_tui,
                                &profile_store,
                            );
                            match ws.save(&path) {
                                Ok(_) => {
                                    output_buffer = format!("✅ Workspace saved to '{}'", path);
                                    logger::log_event(&format!("Workspace saved to {}", path));
                                }
                                Err(e) => {
                                    output_buffer = format!("❌ Workspace-Save failed: {}", e);
                                }
                            }
                        } else if trimmed_input.starts_with("Workspace-Load") {
                            let rest = trimmed_input["Workspace-Load".len()..].trim();
                            if rest.is_empty() {
                                output_buffer = "Usage: Workspace-Load <file.cogitator>".to_string();
                            } else {
                                match workspace::WorkspaceData::load(rest) {
                                    Ok(ws) => {
                                        let (findings_ser, snaps) = ws.restore(
                                            &scope_for_tui,
                                            &history_for_tui,
                                            &repeater_engine_for_tui,
                                            &profile_store,
                                        );
                                        scan_snapshots = snaps;
                                        let restored_findings: Vec<scanner::ScanFinding> =
                                            findings_ser.iter().map(finding_from_ser).collect();
                                        let count = restored_findings.len();
                                        scanner_state.set_findings(
                                            restored_findings,
                                            format!("restored from {}", rest),
                                        );
                                        output_buffer = format!(
                                            "✅ Workspace loaded from '{}' ({} finding(s) restored)",
                                            rest, count
                                        );
                                        logger::log_event(&format!("Workspace loaded from {}", rest));
                                        scroll_offset = 0;
                                    }
                                    Err(e) => {
                                        output_buffer = format!(
                                            "❌ Workspace-Load '{}' failed: {}",
                                            rest, e
                                        );
                                    }
                                }
                            }
                        } else if trimmed_input == "Workspace-New" {
                            // Reset all in-memory state back to blank.
                            scope_for_tui.lock().unwrap().clear();
                            history_for_tui.clear();
                            for tab in repeater_engine_for_tui.get_tabs() {
                                repeater_engine_for_tui.close_tab(tab.id);
                            }
                            scanner_state.set_findings(Vec::new(), "workspace reset");
                            scan_snapshots.clear();
                            output_buffer = "✅ Workspace-New: all state cleared.".to_string();
                            scroll_offset = 0;
                        } else if !trimmed_input.is_empty() {
                            output_buffer = process_pipeline(&trimmed_input, &sys);
                            scroll_offset = 0;
                        }

                        input_buffer.clear();
                    }
                    KeyCode::Char(c) => input_buffer.push(c),
                    KeyCode::Backspace => { input_buffer.pop(); }
                    KeyCode::Esc => break,
                    _ => {}
                }
            }
        }
    }

    // ── Auto-save workspace on clean exit ────────────────────────────────────
    let exit_ws = workspace::WorkspaceData::capture(
        config::PROXY_ADDR,
        &scope_for_tui,
        &history_for_tui,
        &scanner_state.findings,
        &scan_snapshots,
        &repeater_engine_for_tui,
        &profile_store,
    );
    if let Err(e) = exit_ws.save(workspace::LAST_WORKSPACE_FILE) {
        logger::log_event(&format!("Auto-save workspace failed: {}", e));
    } else {
        logger::log_event(&format!("Workspace auto-saved to {}", workspace::LAST_WORKSPACE_FILE));
    }

    // Возвращаем терминал в исходное состояние при выходе
    // Signal the proxy to stop and give it a moment to log its shutdown.
    proxy_shutdown.cancel();
    std::thread::sleep(std::time::Duration::from_millis(config::PROXY_SHUTDOWN_GRACE_MS));

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

/// Build a `SpiderConfig` for `Spider`/`Spider-Depth`, scoped to the given
/// domain/URL so a crawl doesn't wander off-site by default.
///
/// `domain_or_url` may be a bare domain ("example.com") or a full URL with
/// scheme; bare domains are assumed `https://`. The crawl's `Scope` is a
/// fresh, single-rule scope (include: the seed's host, regex-escaped) —
/// deliberately independent of the proxy's shared `Scope-Add`/`Scope-Exclude`
/// rules, since those govern proxy traffic logging, not what a one-off
/// crawl is allowed to wander into.
fn build_spider_config(
    domain_or_url: &str,
    max_depth: u8,
    max_pages: usize,
    history: Arc<history::History>,
) -> (String, spider::SpiderConfig) {
    let trimmed = domain_or_url.trim_end_matches('/');
    let seed_url = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    };

    let host = reqwest::Url::parse(&seed_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| domain_or_url.to_string());

    let mut crawl_scope = scope::Scope::new();
    // Best-effort: an unparsable host would already have failed Url::parse
    // above and fallen back to the raw input, so add_include should only
    // ever fail here on a genuinely pathological domain string — in which
    // case an empty scope ("everything in scope") is a safe fallback.
    let _ = crawl_scope.add_include(&regex::escape(&host));

    let config = spider::SpiderConfig {
        seed_url: seed_url.clone(),
        max_depth,
        max_pages,
        scope: Arc::new(crawl_scope),
        follow_forms: true,
        // Mirrors the redirect-following client's UA (see
        // web_analyzer::build_clients) so Spider's traffic looks like the
        // rest of Cogitator's passive/active probing rather than
        // self-identifying as a crawler.
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/120.0.0.0".to_string(),
        cached_robots_disallow: None,
        history,
    };

    (seed_url, config)
}

fn process_pipeline(input: &str, sys: &System) -> String {
    let stages: Vec<&str> = input.split('|').map(|s| s.trim()).collect();
    let mut current_data: PipelineData = Vec::new();

    for stage in stages {
        let mut parts = stage.split_whitespace();
        let cmd = parts.next().unwrap_or("");
        let args: Vec<&str> = parts.collect();

        match cmd {
            "GP" => {
                current_data = sys.processes().iter().map(|(pid, proc)| {
                    let mut map = HashMap::new();
                    map.insert("Name".to_string(), Value::Text(proc.name().to_string_lossy().into_owned()));
                    map.insert("Id".to_string(), Value::Int(pid.as_u32() as i32));
                    map.insert("CPU".to_string(), Value::Int(proc.cpu_usage() as i32));
                    Value::Object(map)
                }).collect();
            }
            "CG" => {
                return match logger::clear_log() {
                    Ok(_) => "✅ Log cleared. All records purged.".to_string(),
                    Err(_) => "❌ Error: Failed to clear logs.".to_string(),
                };
            }
            "GC" => {
                return network_guard::get_active_connections(sys);
            }
            "GPP" => {
                if args.len() == 1 {
                    let pid_val: usize = args[0].parse().unwrap_or(0);
                    let pid = sysinfo::Pid::from(pid_val);
                    return match sys.process(pid) {
                        Some(proc) => {
                            let path = proc.exe()
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_else(|| "Access Denied / Path Unknown".to_string());
                            format!("🗂️  Process {} → {}", pid_val, path)
                        }
                        None => format!("❌ Process {} not found.", pid_val),
                    };
                }
                return "Usage: GPP <PID>".to_string();
            }
            "Get-NIF" => {
                current_data.clear();
                let networks = sysinfo::Networks::new_with_refreshed_list();
                for (interface_name, data) in &networks {
                    let mut net_map = HashMap::new();
                    net_map.insert("Interface".to_string(), Value::Text(interface_name.clone()));
                    let ips = data.ip_networks().iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(", ");
                    net_map.insert("IPs".to_string(), Value::Text(if ips.is_empty() { "—".to_string() } else { ips }));
                    net_map.insert("MAC".to_string(), Value::Text(format!("{}", data.mac_address())));
                    current_data.push(Value::Object(net_map));
                }
            }
            "Find-Suspicious" => {
                current_data = sys.processes().iter()
                    .filter(|(_, p)| p.cpu_usage() > config::CPU_SUSPICIOUS_THRESHOLD)
                    .map(|(pid, proc)| {
                        let mut map = HashMap::new();
                        map.insert("Name".to_string(), Value::Text(proc.name().to_string_lossy().into_owned()));
                        map.insert("CPU%".to_string(), Value::Int(proc.cpu_usage() as i32));
                        map.insert("Status".to_string(), Value::Text("⚠️  SUSPICIOUS".to_string()));
                        map.insert("PID".to_string(), Value::Int(pid.as_u32() as i32));
                        Value::Object(map)
                    }).collect();

                if current_data.is_empty() {
                    return "✅ No suspicious processes found. The Machine Spirit is calm.".to_string();
                }
            }
            "Select-Object" => {
                if !args.is_empty() {
                    let prop = args[0];
                    current_data = current_data.into_iter().filter_map(|val| {
                        if let Value::Object(mut map) = val {
                            if let Some(v) = map.remove(prop) {
                                let mut new_map = HashMap::new();
                                new_map.insert(prop.to_string(), v);
                                return Some(Value::Object(new_map));
                            }
                        }
                        None
                    }).collect();
                }
            }
            "Exterminate" => {
                if let Some(pid_str) = args.first() {
                    if let Ok(pid_val) = pid_str.parse::<u32>() {
                        let target_pid = Pid::from(pid_val as usize);
                        if let Some(p) = sys.process(target_pid) {
                            let name = p.name().to_string_lossy().into_owned();
                            p.kill();
                            let msg = format!("💀 Purged: {} (PID: {})", name, pid_val);
                            logger::log_event(&msg);
                            return msg;
                        }
                    }
                }
                return "❌ Error: Invalid or not found PID".to_string();
            }
            _ => return format!("❓ Unknown command: '{}'\n   Type 'help' for Sacred Commandments.", cmd),
        }
    }

    format_pretty(&current_data)
}