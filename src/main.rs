use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use sysinfo::System;
use tokio_util::sync::CancellationToken;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

mod commands;
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

// ── Health check ──────────────────────────────────────────────────────────────

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

// ── main ──────────────────────────────────────────────────────────────────────

fn main() -> Result<(), io::Error> {
    logger::init().expect("Failed to initialise logger");

    // ── Optional workspace file from CLI argument ──────────────────────────────
    // Usage: cogitator [workspace.cogitator]
    let cli_workspace: Option<std::path::PathBuf> =
        std::env::args().nth(1).map(Into::into);

    // ── Async runtime ─────────────────────────────────────────────────────────
    let rt = tokio::runtime::Runtime::new()?;

    // ── Shared HTTP client pool ───────────────────────────────────────────────
    // Build both clients once so every analyze_site call (TUI + proxy)
    // reuses the same connection pool instead of tearing it down on each scan.
    let (no_follow, follow) = web_analyzer::build_clients()
        .expect("Failed to build HTTP clients");
    let no_follow = Arc::new(no_follow);
    let follow    = Arc::new(follow);

    // ── Proxy lifecycle handles ───────────────────────────────────────────────
    let proxy_running = Arc::new(AtomicBool::new(false));
    let proxy_flag_clone = proxy_running.clone();

    let proxy_shutdown       = CancellationToken::new();
    let proxy_shutdown_clone = proxy_shutdown.clone();

    // Wrap the two clients in a DefaultSiteAnalyzer so proxy_guard depends only
    // on the trait, not on reqwest internals.
    let proxy_analyzer: Arc<dyn web_analyzer::SiteAnalyzer> =
        Arc::new(web_analyzer::DefaultSiteAnalyzer::new(
            no_follow.clone(),
            follow.clone(),
        ));

    // ── TLS MITM certificate authority ────────────────────────────────────────
    let cert_cache = Arc::new(
        tls_mitm::CertCache::new()
            .expect("Failed to initialise TLS MITM certificate authority"),
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
    let cert_cache_for_tui = cert_cache.clone();

    // ── Shared history / repeater / interceptor ───────────────────────────────
    let history = Arc::new(history::History::new());
    let history_for_tui = history.clone();

    let repeater_engine = Arc::new(repeater::RepeaterEngine::new());
    let repeater_engine_for_tui = repeater_engine.clone();

    let interceptor_engine_for_tui   = Arc::new(interceptor::InterceptorEngine::new());
    let interceptor_engine_for_proxy = interceptor_engine_for_tui.clone();

    // ── Proxy scope ───────────────────────────────────────────────────────────
    let scope = Arc::new(std::sync::Mutex::new(scope::Scope::new()));
    let scope_for_tui = scope.clone();

    // ── Spawn proxy ───────────────────────────────────────────────────────────
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
        )
        .await
        {
            logger::log_event(&format!("Proxy Guard Critical Error: {}", e));
        }
    });

    // ── Terminal setup ────────────────────────────────────────────────────────
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // ── TUI event-loop state ──────────────────────────────────────────────────
    let mut sys = System::new_all();
    let mut input_buffer  = String::new();
    let mut output_buffer = String::from(
        "System Initialized. Awaiting sacred input... Type 'help' for commandments.",
    );
    let mut scroll_offset: u16 = 0;

    let mut show_popup           = false;
    let mut popup_text           = String::new();
    let mut popup_scroll_offset: u16 = 0;

    let mut last_health_check    = Instant::now();
    let health_check_interval    = Duration::from_secs(config::HEALTH_CHECK_INTERVAL_SECS);

    let mut current_screen  = Screen::Main;
    let mut repeater_state  = RepeaterState::new(repeater_engine_for_tui.clone());
    let mut interceptor_state = InterceptorState::new(
        history_for_tui.clone(),
        interceptor_engine_for_tui.clone(),
    );
    let mut scanner_state   = ScannerState::new();

    // Accumulated scan runs (oldest first) — fed by every completed
    // Scan-Site/Scan-Request, persisted via WorkspaceData, and consumed by
    // the Scan-Diff command (compares the last two entries).
    let mut scan_snapshots: Vec<workspace::ScanSnapshot> = Vec::new();

    let mut intruder_state  = IntruderState::new();
    let mut spider_state    = SpiderState::new();

    // Live result streams for the two background engines.  `None` when no
    // run is in flight.  Drained (non-blocking) once per loop tick, right
    // before drawing.
    let mut intruder_rx: Option<tokio::sync::mpsc::Receiver<checks::intruder::IntruderResult>> =
        None;
    let mut spider_rx: Option<tokio::sync::mpsc::Receiver<spider::SpiderResult>> = None;

    // `Intruder-Load <file>` stages a raw HTTP template here.
    let mut loaded_intruder_template: Option<String> = None;

    // Active scan checks — built once and shared via Arc so ScanQueue::run_all
    // can hand out clones to every spawned (target, check) task.
    let scan_checks: Arc<Vec<Arc<dyn scanner::ScanCheck>>> = Arc::new(vec![
        Arc::new(checks::sqli::SqliCheck::new()),
        Arc::new(checks::traversal::TraversalCheck::new()),
    ]);
    let scan_queue = scanner::ScanQueue::new();

    // Session management: shared cookie jar and named profile store.
    let cookie_jar    = session::CookieJar::new();
    let profile_store = session::ProfileStore::new();

    // ── Workspace: auto-restore prompt ────────────────────────────────────────
    let last_ws_path = std::path::Path::new(workspace::LAST_WORKSPACE_FILE);
    let mut startup_ws_to_offer: Option<workspace::WorkspaceData> = None;

    if let Some(ref path) = cli_workspace {
        // CLI argument given — load immediately and silently.
        match workspace::WorkspaceData::load(path) {
            Ok(ws) => {
                let (findings_ser, snaps) = ws.restore(
                    &scope_for_tui,
                    &history_for_tui,
                    &repeater_engine_for_tui,
                    &profile_store,
                );
                scan_snapshots = snaps;
                let restored_findings: Vec<scanner::ScanFinding> =
                    findings_ser.iter().map(commands::scan::finding_from_ser).collect();
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
        // Offer to restore; user can press Enter on the pre-filled command
        // or delete it and type something else.
        match workspace::WorkspaceData::load(last_ws_path) {
            Ok(ws) => {
                startup_ws_to_offer = Some(ws);
                output_buffer = format!(
                    "💾 Found auto-save '{}'. Run  Workspace-Load {}  to restore it, \
                     or type any other command to continue fresh.",
                    workspace::LAST_WORKSPACE_FILE,
                    workspace::LAST_WORKSPACE_FILE,
                );
            }
            Err(_) => {} // corrupt / unreadable — ignore silently
        }
    }

    // ── Event loop ────────────────────────────────────────────────────────────
    loop {
        sys.refresh_all();

        // Periodic system health check.
        if last_health_check.elapsed() >= health_check_interval {
            if let Some(warning) = check_system_health(&sys) {
                output_buffer = warning.clone();
                logger::log_event(&warning);
            }
            last_health_check = Instant::now();
        }

        // ── Drain background engine channels ──────────────────────────────────
        // Both `checks::intruder::run` and `spider::run` spawn their own
        // background task and hand back a `Receiver` immediately — they don't
        // block.  Draining here, once per tick, is what makes
        // IntruderView/SpiderView feel "live".
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

        // ── Draw ──────────────────────────────────────────────────────────────
        if current_screen == Screen::Repeater {
            repeater_state.sync_from_selected();
        }
        terminal.draw(|f| {
            match current_screen {
                Screen::Repeater    => styletui::draw_repeater_view(f, &repeater_state),
                Screen::Interceptor => styletui::draw_interceptor_view(f, &interceptor_state),
                Screen::Scanner     => styletui::draw_scanner_view(f, &scanner_state),
                Screen::Intruder    => styletui::draw_intruder_view(f, &intruder_state),
                Screen::Spider      => styletui::draw_spider_view(f, &spider_state),
                _ => styletui::draw_ui(
                    f,
                    &input_buffer,
                    &output_buffer,
                    scroll_offset,
                    show_popup,
                    &popup_text,
                    popup_scroll_offset,
                    proxy_running.load(Ordering::SeqCst),
                ),
            }
        })?;

        // ── Input handling ────────────────────────────────────────────────────
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                // Any key (except arrows) dismisses an open popup.
                if show_popup && key.code != KeyCode::Up && key.code != KeyCode::Down {
                    show_popup = false;
                    popup_scroll_offset = 0;
                    continue;
                }

                // ── Screen-specific key handling ──────────────────────────────
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

                        // Show history popup for the selected tab.
                        if let Some(tab_id) = repeater_state.pending_history_view.take() {
                            let rounds = repeater_engine_for_tui.get_history(tab_id);
                            if rounds.is_empty() {
                                popup_text = format!(
                                    "┌─[ REPEATER TAB #{} HISTORY ]──────────────\n\
                                     │  (nothing sent yet)\n\
                                     └────────────────────────────────────────────\n",
                                    tab_id
                                );
                            } else {
                                let mut text = format!(
                                    "┌─[ REPEATER TAB #{} HISTORY ({} round-trips) ]──\n",
                                    tab_id,
                                    rounds.len()
                                );
                                for (i, (req, resp)) in rounds.iter().enumerate() {
                                    text.push_str(&format!(
                                        "│\n│ ── Round {} ──\n│ » Request:\n",
                                        i + 1
                                    ));
                                    for line in req.lines() {
                                        text.push_str(&format!("│   {}\n", line));
                                    }
                                    text.push_str("│ « Response:\n");
                                    for line in resp.lines() {
                                        text.push_str(&format!("│   {}\n", line));
                                    }
                                }
                                text.push_str(
                                    "└────────────────────────────────────────────\n",
                                );
                                popup_text = text;
                            }
                            popup_scroll_offset = 0;
                            show_popup = true;
                        }

                        // Fire off a Repeater send on the selected tab.
                        if let Some(tab_id) = repeater_state.pending_send.take() {
                            // Reuse the TUI's `follow` client pool so Repeater
                            // sends share the same connection pool as the rest
                            // of the app instead of spinning up new instances.
                            match rt.block_on(repeater_engine_for_tui.send(
                                tab_id,
                                &follow,
                                None,            // no active profile — set via Session-Load
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

                // ── Global key handling ───────────────────────────────────────
                match key.code {
                    KeyCode::Up => {
                        if show_popup {
                            popup_scroll_offset = popup_scroll_offset.saturating_sub(1);
                        } else {
                            scroll_offset = scroll_offset.saturating_sub(1);
                        }
                    }
                    KeyCode::Down => {
                        if show_popup {
                            popup_scroll_offset = popup_scroll_offset.saturating_add(1);
                        } else {
                            scroll_offset = scroll_offset.saturating_add(1);
                        }
                    }

                    KeyCode::Enter => {
                        let trimmed_input = input_buffer.trim().to_string();

                        // `exit` must break the loop; it cannot be a regular handler.
                        if trimmed_input == "exit" {
                            break;
                        }

                        if !trimmed_input.is_empty() {
                            // Assemble the context from all event-loop locals,
                            // then let the command registry route the input.
                            let mut ctx = commands::CommandContext {
                                output_buffer:   &mut output_buffer,
                                popup_text:      &mut popup_text,
                                show_popup:      &mut show_popup,
                                popup_scroll:    &mut popup_scroll_offset,
                                scroll_offset:   &mut scroll_offset,
                                current_screen:  &mut current_screen,
                                scan_snapshots:  &mut scan_snapshots,
                                scanner_state:   &mut scanner_state,
                                intruder_rx:     &mut intruder_rx,
                                intruder_state:  &mut intruder_state,
                                loaded_template: &mut loaded_intruder_template,
                                spider_rx:       &mut spider_rx,
                                spider_state:    &mut spider_state,
                                sys:             &sys,
                                rt:              &rt,
                                no_follow:       &no_follow,
                                follow:          &follow,
                                scope:           &scope_for_tui,
                                history:         &history_for_tui,
                                repeater:        &repeater_engine_for_tui,
                                scan_checks:     &scan_checks,
                                scan_queue:      &scan_queue,
                                cookie_jar:      &cookie_jar,
                                profile_store:   &profile_store,
                                cert_cache:      &cert_cache_for_tui,
                            };
                            commands::dispatch(&mut ctx, &trimmed_input);
                        }

                        input_buffer.clear();
                    }

                    KeyCode::Char(c) => input_buffer.push(c),
                    KeyCode::Backspace => {
                        input_buffer.pop();
                    }
                    // `Esc` must break the loop; cannot be a regular handler.
                    KeyCode::Esc => break,
                    _ => {}
                }
            }
        }
    }

    // ── Auto-save workspace on clean exit ─────────────────────────────────────
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
        logger::log_event(&format!(
            "Workspace auto-saved to {}",
            workspace::LAST_WORKSPACE_FILE
        ));
    }

    // Signal the proxy to stop and give it a moment to log its shutdown.
    proxy_shutdown.cancel();
    std::thread::sleep(std::time::Duration::from_millis(
        config::PROXY_SHUTDOWN_GRACE_MS,
    ));

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}