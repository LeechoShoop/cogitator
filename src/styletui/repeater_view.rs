use ratatui::{layout::{Alignment, Constraint, Direction, Layout, Rect}, style::{Color, Modifier, Style}, widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph, Wrap}, Frame};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::sync::Arc;
use crate::history::{History, HistoryFilter, RequestRecord};
use crate::interceptor::{FrozenSummary, FrozenWsSummary, InterceptAction, InterceptorEngine, WsFrameAction};
use crate::checks::intruder::IntruderResult;
use crate::spider::{FormInfo, SpiderResult};
use crate::repeater::{RepeaterEngine, RepeaterTabSummary};
use crate::scanner::{ScanFinding, Severity};
use super::*;

// ─── InterceptorView ──────────────────────────────────────────────────────────
//


/// Drives the RepeaterView screen. Sending is async (`RepeaterEngine::send`),
/// so `handle_key` only flags intent via `pending_send`; the caller (main's
/// event loop, which owns the tokio runtime) is responsible for noticing the
/// flag, calling `rt.block_on(engine.send(..))`, and clearing it.
pub struct RepeaterState {
    pub engine: Arc<RepeaterEngine>,
    /// Index into `engine.get_tabs()`, the currently focused tab.
    pub selected: usize,
    pub request_scroll: u16,
    pub response_scroll: u16,
    /// Set by Ctrl+Enter; cleared once the caller has dispatched the send.
    pub pending_send: Option<u8>,
    /// Set by Ctrl+H; cleared once the caller has rendered the history
    /// popup for this tab id (via `RepeaterEngine::get_history`).
    pub pending_history_view: Option<u8>,
    /// `Some` while editing the request textarea has a trailing cursor —
    /// kept simple: the textarea is always "in edit mode" while this screen
    /// is focused, mirroring the Repeater tab's `request_raw` directly.
    pub editing_buffer: String,
}

impl RepeaterState {
    pub fn new(engine: Arc<RepeaterEngine>) -> Self {
        Self {
            engine,
            selected: 0,
            request_scroll: 0,
            response_scroll: 0,
            pending_send: None,
            pending_history_view: None,
            editing_buffer: String::new(),
        }
    }

    fn tabs(&self) -> Vec<RepeaterTabSummary> {
        self.engine.get_tabs()
    }

    fn selected_tab(&self) -> Option<RepeaterTabSummary> {
        self.tabs().into_iter().nth(self.selected)
    }

    /// Call once per frame before drawing, so edits to `editing_buffer` made
    /// while this tab was focused get pushed into the engine and so a freshly
    /// selected tab's text is loaded into the buffer.
    pub fn sync_from_selected(&mut self) {
        if let Some(t) = self.selected_tab() {
            self.editing_buffer = t.request_raw;
        } else {
            self.editing_buffer.clear();
        }
    }

    /// Route a key press to this screen. Call only while `Screen::Repeater`
    /// is active and no popup is open.
    pub fn handle_key(&mut self, key: KeyEvent) {
        let code = key.code;
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

        if ctrl {
            match code {
                KeyCode::Enter => {
                    if let Some(t) = self.selected_tab() {
                        self.engine.update_request(t.id, self.editing_buffer.clone());
                        self.pending_send = Some(t.id);
                    }
                    return;
                }
                KeyCode::Char('n') => {
                    let blank = RequestRecord {
                        id: 0,
                        timestamp: std::time::Instant::now(),
                        method: "GET".to_string(),
                        host: "example.com".to_string(),
                        path: "/".to_string(),
                        headers: vec![("Host".to_string(), "example.com".to_string())],
                        body: Vec::new(),
                        response_status: None,
                        response_headers: Vec::new(),
                        response_body: None,
                        response_time_ms: None,
                        tags: Vec::new(),
                        stream_id: None,
                    };
                    self.engine.new_tab(&blank);
                    self.selected = self.tabs().len().saturating_sub(1);
                    self.sync_from_selected();
                    return;
                }
                KeyCode::Char('w') => {
                    if let Some(t) = self.selected_tab() {
                        self.engine.close_tab(t.id);
                        if self.selected > 0 {
                            self.selected -= 1;
                        }
                        self.sync_from_selected();
                    }
                    return;
                }
                KeyCode::Char('h') => {
                    // Caller (the main event loop) owns the popup widget —
                    // RepeaterState has no popup state of its own. It reads
                    // `pending_history_view`, calls
                    // `engine.get_history(id)`, renders it into the existing
                    // popup, then clears the flag.
                    if let Some(t) = self.selected_tab() {
                        self.pending_history_view = Some(t.id);
                    }
                    return;
                }
                _ => {}
            }
        }

        match code {
            KeyCode::Left => {
                self.selected = self.selected.saturating_sub(1);
                self.sync_from_selected();
                self.request_scroll = 0;
                self.response_scroll = 0;
            }
            KeyCode::Right => {
                let len = self.tabs().len();
                if len > 0 && self.selected + 1 < len {
                    self.selected += 1;
                }
                self.sync_from_selected();
                self.request_scroll = 0;
                self.response_scroll = 0;
            }
            KeyCode::Enter => self.editing_buffer.push('\n'),
            KeyCode::Backspace => { self.editing_buffer.pop(); }
            KeyCode::Tab => self.editing_buffer.push('\t'),
            KeyCode::Char(c) => self.editing_buffer.push(c),
            KeyCode::PageUp => self.request_scroll = self.request_scroll.saturating_sub(10),
            KeyCode::PageDown => self.request_scroll = self.request_scroll.saturating_add(10),
            _ => {}
        }

        // Keep the engine's copy live as the operator types, so a Ctrl+H /
        // tab switch elsewhere always sees current text even without an
        // explicit save action.
        if let Some(t) = self.selected_tab() {
            self.engine.update_request(t.id, self.editing_buffer.clone());
        }
    }
}

/// Renders the RepeaterView screen.
pub fn draw_repeater_view(f: &mut Frame, state: &RepeaterState) {
    let screen_size = f.size();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Min(5), Constraint::Length(3)])
        .split(screen_size);

    let main_area = outer[0];
    let footer_area = outer[1];

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(18), Constraint::Percentage(82)])
        .split(main_area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(cols[1]);

    let tabs = state.tabs();

    // ── Left strip: tab list ────────────────────────────────────────────────
    let mut tab_text = String::new();
    if tabs.is_empty() {
        tab_text.push_str("  (no tabs — Ctrl+N for one,\n   or Send-To-Repeater <id>)\n");
    }
    for (i, t) in tabs.iter().enumerate() {
        let marker = if i == state.selected { ">" } else { " " };
        tab_text.push_str(&format!("{} #{} {}\n", marker, t.id, t.name));
    }

    let tab_block = Block::default()
        .title(" ┼ [ ⚙ REPEATER ⚙ ] ┼ ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(GEAR_GRAY))
        .padding(Padding::horizontal(1));
    let tab_widget = Paragraph::new(tab_text)
        .style(Style::default().fg(Color::White))
        .block(tab_block)
        .wrap(Wrap { trim: false });
    f.render_widget(tab_widget, cols[0]);

    // ── Top right: editable request textarea ───────────────────────────────
    let mut request_text = state.editing_buffer.clone();
    request_text.push('▌'); // cursor glyph, mirrors the editor popup convention

    let request_title = match state.selected_tab() {
        Some(t) => format!(" ✎ [ REQUEST #{} ] (Ctrl+Enter send) ", t.id),
        None => " ✎ [ REQUEST ] (Ctrl+N for a tab) ".to_string(),
    };
    let request_block = Block::default()
        .title(request_title)
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(MECHANICUS_RED))
        .padding(Padding::horizontal(1));
    let request_widget = Paragraph::new(request_text)
        .style(Style::default().fg(Color::Rgb(220, 220, 220)))
        .block(request_block)
        .wrap(Wrap { trim: false })
        .scroll((state.request_scroll, 0));
    f.render_widget(request_widget, rows[0]);

    // ── Bottom right: read-only response display ───────────────────────────
    let response_text = match state.selected_tab() {
        Some(t) if !t.response_raw.is_empty() => t.response_raw,
        Some(_) => "  (not sent yet — Ctrl+Enter to send)\n".to_string(),
        None => String::new(),
    };
    let response_block = Block::default()
        .title(" [ RESPONSE ] (read-only) ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan))
        .padding(Padding::horizontal(1));
    let response_widget = Paragraph::new(response_text)
        .style(Style::default().fg(Color::White))
        .block(response_block)
        .wrap(Wrap { trim: false })
        .scroll((state.response_scroll, 0));
    f.render_widget(response_widget, rows[1]);

    // ── Footer ───────────────────────────────────────────────────────────────
    let footer_block = Block::default()
        .title(" [ CONTROLS ] ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(MECHANICUS_RED))
        .padding(Padding::horizontal(1));
    let footer_widget = Paragraph::new(
        " ←/→ switch tab   Ctrl+N new   Ctrl+W close   Ctrl+Enter send   Ctrl+H history   Tab switch screen ",
    )
        .style(Style::default().fg(RUST_ORANGE).add_modifier(Modifier::BOLD))
        .block(footer_block);
    f.render_widget(footer_widget, footer_area);
}
