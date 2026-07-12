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
// Third TUI screen (cycled to with Tab). Two panels:
//   Left  (30%) — scrollable list of history records: "#id METHOD host/path STATUS"
//   Right (70%) — details of the selected record: headers then body, toggling
//                 between UTF-8 and hex view with 'x'.
//
// Navigation: Up/Down move through the list, Enter expands/collapses the
// detail panel's body view, 'f' opens an inline host-filter input, 'c'
// clears history.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailViewMode {
    Utf8,
    Hex,
}

/// Which sub-view of the InterceptorView is active. Toggled with 'i'.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptorMode {
    /// Browse completed/in-flight exchanges from `History` (the original view).
    History,
    /// Browse requests currently parked in `InterceptorEngine::queue` awaiting
    /// an operator decision (Forward/Drop/Modify).
    Frozen,
}

/// Within `InterceptorMode::Frozen`, which queue is currently displayed.
/// Toggled with 'w' — mirrors the 'i' top-level toggle but one level down,
/// since HTTP requests and WS frames are parked in separate queues with
/// different item shapes (see `interceptor::FrozenRequest` vs
/// `interceptor::FrozenWsFrame`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrozenTarget {
    Http,
    Ws,
}

/// Inline editor state for the 'e' (Edit) action on a frozen WS frame.
///
/// Simpler than `EditorState`: a WS frame has no headers, just a payload, so
/// the textarea holds nothing but the (best-effort UTF-8) payload text.
/// `commit()` hands back raw bytes for `WsFrameAction::Replace`.
pub struct WsEditorState {
    pub id: u64,
    pub text: String,
}

impl WsEditorState {
    fn from_summary(s: &FrozenWsSummary) -> Self {
        Self { id: s.id, text: String::from_utf8_lossy(&s.payload).into_owned() }
    }

    fn commit(&self) -> Vec<u8> {
        self.text.clone().into_bytes()
    }
}

/// Inline editor state for the 'e' (Edit) action on a frozen request.
///
/// The textarea holds headers and body together as plain text, separated by
/// a blank line — mirrors how a raw HTTP message reads. `commit()` parses it
/// back apart.
pub struct EditorState {
    /// id of the `FrozenRequest` being edited (already removed from the
    /// queue via `take_frozen` once editing starts).
    pub id: u64,
    pub text: String,
    pub scroll: u16,
}

impl EditorState {
    fn from_summary(s: &FrozenSummary) -> Self {
        let mut text = String::new();
        for (k, v) in &s.headers {
            text.push_str(k);
            text.push_str(": ");
            text.push_str(v);
            text.push('\n');
        }
        text.push('\n'); // blank line separates headers from body
        // Body is intentionally left blank: the original request body lives
        // in the live `Incoming` stream and isn't buffered anywhere ahead of
        // time (see the comment in `interceptor::freeze_request`), so there
        // is nothing to pre-fill — the operator types the replacement body
        // here from scratch.
        Self { id: s.id, text, scroll: 0 }
    }

    /// Split the textarea back into `(headers, body)` on the first blank
    /// line. Lines before it are parsed as `Key: Value`; everything after
    /// (including further blank lines) is the literal body.
    fn commit(&self) -> (Vec<(String, String)>, Vec<u8>) {
        let mut headers = Vec::new();
        let mut lines = self.text.split('\n');
        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        let body = lines.collect::<Vec<_>>().join("\n").into_bytes();
        (headers, body)
    }
}

pub struct InterceptorState {
    pub history: Arc<History>,
    pub engine: Arc<InterceptorEngine>,
    pub mode: InterceptorMode,
    /// Index into the (newest-first) filtered record list.
    pub selected: usize,
    pub list_scroll: u16,
    pub detail_scroll: u16,
    /// Whether the detail panel's body section is expanded (Enter toggles).
    pub expanded: bool,
    pub detail_view: DetailViewMode,
    pub filter_active: bool,
    pub filter_input: String,
    pub filter_host: Option<String>,
    /// Index into `engine.frozen_snapshot()`, used only in `Frozen` mode.
    pub frozen_selected: usize,
    /// `Some` while the inline header/body editor popup is open.
    pub editor: Option<EditorState>,
    /// History-mode filter: when `true`, only `"websocket"`-tagged records
    /// are shown (toggled with 'w'). Independent of `filter_host` — both
    /// apply together (logical AND) since `records()` runs the host filter
    /// through `HistoryFilter` and this one as a post-filter.
    pub ws_only: bool,
    /// Which queue `Frozen` mode is currently browsing. Toggled with 'w'
    /// while in Frozen mode (distinct from the History-mode 'w' above —
    /// the key is reused because the two modes' filter bars never overlap).
    pub frozen_target: FrozenTarget,
    /// Index into `engine.frozen_ws_snapshot()`, used only when
    /// `frozen_target == FrozenTarget::Ws`.
    pub frozen_ws_selected: usize,
    /// `Some` while the inline WS payload editor popup is open.
    pub ws_editor: Option<WsEditorState>,
}

impl InterceptorState {
    pub fn new(history: Arc<History>, engine: Arc<InterceptorEngine>) -> Self {
        Self {
            history,
            engine,
            mode: InterceptorMode::History,
            selected: 0,
            list_scroll: 0,
            detail_scroll: 0,
            expanded: false,
            detail_view: DetailViewMode::Utf8,
            filter_active: false,
            filter_input: String::new(),
            filter_host: None,
            frozen_selected: 0,
            editor: None,
            ws_only: false,
            frozen_target: FrozenTarget::Http,
            frozen_ws_selected: 0,
            ws_editor: None,
        }
    }

    /// Records matching the current host filter (and, if `ws_only` is set,
    /// the `"websocket"` tag), newest first.
    fn records(&self) -> Vec<RequestRecord> {
        let filter = HistoryFilter {
            host_contains: self.filter_host.clone(),
            ..Default::default()
        };
        let mut list = self.history.list(filter);
        if self.ws_only {
            list.retain(|r| r.tags.iter().any(|t| t == "websocket"));
        }
        list.reverse(); // History::list returns oldest-first; show newest first
        list
    }

    fn selected_record(&self) -> Option<RequestRecord> {
        self.records().into_iter().nth(self.selected)
    }

    /// Route a key press to this screen's state. Call only while
    /// `Screen::Interceptor` is active and no popup is open.
    ///
    /// Takes the full `KeyEvent` (not just `KeyCode`) because the editor's
    /// commit action is bound to Ctrl+S, which needs the modifier bits.
    pub fn handle_key(&mut self, key: KeyEvent) {
        let code = key.code;

        // ── Inline editor popup takes priority over everything else ────────
        if let Some(editor) = self.editor.as_mut() {
            match code {
                KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    let (headers, body) = editor.commit();
                    let id = editor.id;
                    if let Some(frozen) = self.engine.take_frozen(id) {
                        let _ = frozen.tx.send(InterceptAction::Modify { headers, body });
                    }
                    self.editor = None;
                    if self.frozen_selected > 0 {
                        self.frozen_selected -= 1;
                    }
                }
                KeyCode::Esc => {
                    // The FrozenRequest is only pulled out of the queue on
                    // commit (Ctrl+S) — see `handle_frozen_key`'s 'e' case —
                    // so cancelling here is a plain no-op; it's still sitting
                    // in the queue untouched.
                    self.editor = None;
                }
                KeyCode::Enter => editor.text.push('\n'),
                KeyCode::Backspace => { editor.text.pop(); }
                KeyCode::Char(c) => editor.text.push(c),
                KeyCode::PageUp => editor.scroll = editor.scroll.saturating_sub(10),
                KeyCode::PageDown => editor.scroll = editor.scroll.saturating_add(10),
                _ => {}
            }
            return;
        }

        // ── WS payload editor popup, same priority as the HTTP one ─────────
        if let Some(editor) = self.ws_editor.as_mut() {
            match code {
                KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    let payload = editor.commit();
                    let id = editor.id;
                    if let Some(frozen) = self.engine.take_frozen_ws(id) {
                        let _ = frozen.tx.send(WsFrameAction::Replace(payload));
                    }
                    self.ws_editor = None;
                    if self.frozen_ws_selected > 0 {
                        self.frozen_ws_selected -= 1;
                    }
                }
                KeyCode::Esc => {
                    // Frame is still sitting in the queue (only pulled out
                    // on commit) — cancelling is a plain no-op.
                    self.ws_editor = None;
                }
                KeyCode::Enter => editor.text.push('\n'),
                KeyCode::Backspace => { editor.text.pop(); }
                KeyCode::Char(c) => editor.text.push(c),
                _ => {}
            }
            return;
        }

        if self.filter_active {
            match code {
                KeyCode::Enter => {
                    let val = self.filter_input.trim().to_string();
                    self.filter_host = if val.is_empty() { None } else { Some(val) };
                    self.filter_active = false;
                    self.selected = 0;
                    self.detail_scroll = 0;
                }
                KeyCode::Esc => {
                    self.filter_active = false;
                    self.filter_input.clear();
                }
                KeyCode::Backspace => {
                    self.filter_input.pop();
                }
                KeyCode::Char(c) => self.filter_input.push(c),
                _ => {}
            }
            return;
        }

        // ── 'W' (shift) toggles whether WS frames get frozen for review at
        // all — independent of which mode/queue is currently displayed,
        // since it's a proxy-side switch (`InterceptorEngine::ws_intercept_enabled`)
        // rather than a view concern.
        if code == KeyCode::Char('W') {
            self.engine.set_ws_intercept_enabled(!self.engine.ws_intercept_enabled());
            return;
        }

        // ── Mode toggle: 'i' flips between History and Frozen views ────────
        if code == KeyCode::Char('i') {
            self.mode = match self.mode {
                InterceptorMode::History => InterceptorMode::Frozen,
                InterceptorMode::Frozen => InterceptorMode::History,
            };
            self.frozen_selected = 0;
            return;
        }

        if self.mode == InterceptorMode::Frozen {
            self.handle_frozen_key(code);
            return;
        }

        match code {
            KeyCode::Up => {
                self.selected = self.selected.saturating_sub(1);
                self.detail_scroll = 0;
            }
            KeyCode::Down => {
                let len = self.records().len();
                if len > 0 && self.selected + 1 < len {
                    self.selected += 1;
                }
                self.detail_scroll = 0;
            }
            KeyCode::Enter => self.expanded = !self.expanded,
            KeyCode::Char('x') => {
                self.detail_view = match self.detail_view {
                    DetailViewMode::Utf8 => DetailViewMode::Hex,
                    DetailViewMode::Hex => DetailViewMode::Utf8,
                };
            }
            KeyCode::Char('f') => {
                self.filter_active = true;
                self.filter_input.clear();
            }
            KeyCode::Char('w') => {
                self.ws_only = !self.ws_only;
                self.selected = 0;
                self.detail_scroll = 0;
            }
            KeyCode::Char('c') => {
                self.history.clear();
                self.selected = 0;
                self.detail_scroll = 0;
                self.list_scroll = 0;
            }
            KeyCode::PageUp => self.detail_scroll = self.detail_scroll.saturating_sub(10),
            KeyCode::PageDown => self.detail_scroll = self.detail_scroll.saturating_add(10),
            _ => {}
        }
    }

    /// Keybindings active only while `mode == InterceptorMode::Frozen`:
    ///   Up/Down — select an item in the currently displayed queue
    ///   w       — switch between the HTTP queue and the WS frame queue
    ///   f       — Forward it
    ///   d       — Drop it
    ///   e       — open the inline editor (Modify/Replace)
    fn handle_frozen_key(&mut self, code: KeyCode) {
        if code == KeyCode::Char('w') {
            self.frozen_target = match self.frozen_target {
                FrozenTarget::Http => FrozenTarget::Ws,
                FrozenTarget::Ws => FrozenTarget::Http,
            };
            self.frozen_ws_selected = 0;
            self.frozen_selected = 0;
            return;
        }

        match self.frozen_target {
            FrozenTarget::Http => self.handle_frozen_http_key(code),
            FrozenTarget::Ws => self.handle_frozen_ws_key(code),
        }
    }

    fn handle_frozen_http_key(&mut self, code: KeyCode) {
        let frozen = self.engine.frozen_snapshot();

        match code {
            KeyCode::Up => self.frozen_selected = self.frozen_selected.saturating_sub(1),
            KeyCode::Down => {
                if !frozen.is_empty() && self.frozen_selected + 1 < frozen.len() {
                    self.frozen_selected += 1;
                }
            }
            KeyCode::Char('f') => {
                if let Some(s) = frozen.get(self.frozen_selected) {
                    if let Some(f) = self.engine.take_frozen(s.id) {
                        let _ = f.tx.send(InterceptAction::Forward);
                        if self.frozen_selected > 0 {
                            self.frozen_selected -= 1;
                        }
                    }
                }
            }
            KeyCode::Char('d') => {
                if let Some(s) = frozen.get(self.frozen_selected) {
                    if let Some(f) = self.engine.take_frozen(s.id) {
                        let _ = f.tx.send(InterceptAction::Drop);
                        if self.frozen_selected > 0 {
                            self.frozen_selected -= 1;
                        }
                    }
                }
            }
            KeyCode::Char('e') => {
                if let Some(s) = frozen.get(self.frozen_selected) {
                    self.editor = Some(EditorState::from_summary(s));
                    // Note: the FrozenRequest is *not* removed from the
                    // queue yet — only on commit (Ctrl+S) — so cancelling
                    // (Esc) leaves it exactly where it was, still pending.
                }
            }
            _ => {}
        }
    }

    /// Same shape as `handle_frozen_http_key`, but against
    /// `InterceptorEngine`'s separate WS frame queue. 'd' drops the frame
    /// silently (neither side ever sees it); 'e' opens `ws_editor` for a
    /// payload-only `Replace`.
    fn handle_frozen_ws_key(&mut self, code: KeyCode) {
        let frozen = self.engine.frozen_ws_snapshot();

        match code {
            KeyCode::Up => self.frozen_ws_selected = self.frozen_ws_selected.saturating_sub(1),
            KeyCode::Down => {
                if !frozen.is_empty() && self.frozen_ws_selected + 1 < frozen.len() {
                    self.frozen_ws_selected += 1;
                }
            }
            KeyCode::Char('f') => {
                if let Some(s) = frozen.get(self.frozen_ws_selected) {
                    if let Some(f) = self.engine.take_frozen_ws(s.id) {
                        let _ = f.tx.send(WsFrameAction::Forward);
                        if self.frozen_ws_selected > 0 {
                            self.frozen_ws_selected -= 1;
                        }
                    }
                }
            }
            KeyCode::Char('d') => {
                if let Some(s) = frozen.get(self.frozen_ws_selected) {
                    if let Some(f) = self.engine.take_frozen_ws(s.id) {
                        let _ = f.tx.send(WsFrameAction::Drop);
                        if self.frozen_ws_selected > 0 {
                            self.frozen_ws_selected -= 1;
                        }
                    }
                }
            }
            KeyCode::Char('e') => {
                if let Some(s) = frozen.get(self.frozen_ws_selected) {
                    self.ws_editor = Some(WsEditorState::from_summary(s));
                }
            }
            _ => {}
        }
    }
}

/// Render bytes as a `hexdump -C`-style canonical hex view.
fn hex_dump(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "<empty>".to_string();
    }
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        out.push_str(&format!("{:08x}  ", i * 16));
        for (j, b) in chunk.iter().enumerate() {
            out.push_str(&format!("{:02x} ", b));
            if j == 7 {
                out.push(' ');
            }
        }
        // pad if last chunk is short, so the ASCII column stays aligned
        for j in chunk.len()..16 {
            out.push_str("   ");
            if j == 7 {
                out.push(' ');
            }
        }
        out.push_str(" |");
        for b in chunk {
            let c = *b as char;
            out.push(if c.is_ascii_graphic() || c == ' ' { c } else { '.' });
        }
        out.push_str("|\n");
    }
    out
}

fn format_status(record: &RequestRecord) -> String {
    match record.response_status {
        Some(s) => s.to_string(),
        None => "—".to_string(),
    }
}

fn format_headers(headers: &[(String, String)]) -> String {
    if headers.is_empty() {
        return "  (none)\n".to_string();
    }
    headers.iter().map(|(k, v)| format!("  {}: {}\n", k, v)).collect()
}

/// Renders the InterceptorView screen.
pub fn draw_interceptor_view(f: &mut Frame, state: &InterceptorState) {
    match state.mode {
        InterceptorMode::History => draw_history_mode(f, state),
        InterceptorMode::Frozen => draw_frozen_mode(f, state),
    }

    if let Some(editor) = &state.editor {
        draw_editor_popup(f, editor);
    }
    if let Some(editor) = &state.ws_editor {
        draw_ws_editor_popup(f, editor);
    }
}

fn draw_history_mode(f: &mut Frame, state: &InterceptorState) {
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
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(main_area);

    let records = state.records();

    // ── Left panel: record list ───────────────────────────────────────────
    let mut list_text = String::new();
    if records.is_empty() {
        list_text.push_str("  (no requests captured yet)\n");
    }
    for (i, r) in records.iter().enumerate() {
        let marker = if i == state.selected { ">" } else { " " };
        let line = format!(
            "{} #{:<4} {:<6} {}{} [{}]\n",
            marker,
            r.id,
            r.method,
            r.host,
            r.path,
            format_status(r),
        );
        list_text.push_str(&line);
    }

    let list_title = match &state.filter_host {
        Some(h) => format!(" ┼ [ ⚙ HISTORY ⚙ ] (filter: {}) ┼ ", h),
        None => " ┼ [ ⚙ HISTORY ⚙ ] ┼ ".to_string(),
    };
    let list_block = Block::default()
        .title(list_title)
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(GEAR_GRAY))
        .padding(Padding::horizontal(1));
    let list_widget = Paragraph::new(list_text)
        .style(Style::default().fg(Color::White))
        .block(list_block)
        .wrap(Wrap { trim: false })
        .scroll((state.list_scroll, 0));
    f.render_widget(list_widget, cols[0]);

    // ── Right panel: detail view ──────────────────────────────────────────
    let detail_text = match state.selected_record() {
        None => "No record selected.".to_string(),
        Some(r) => {
            let mut s = String::new();
            s.push_str(&format!("#{} {} {}{}\n", r.id, r.method, r.host, r.path));
            s.push_str(&format!(
                "Status: {}   Time: {}\n\n",
                format_status(&r),
                r.response_time_ms.map(|ms| format!("{}ms", ms)).unwrap_or_else(|| "—".to_string()),
            ));

            s.push_str("── Request Headers ──\n");
            s.push_str(&format_headers(&r.headers));

            s.push_str("\n── Request Body ");
            s.push_str(match state.detail_view {
                DetailViewMode::Utf8 => "(UTF-8, press 'x' for hex) ──\n",
                DetailViewMode::Hex => "(HEX, press 'x' for UTF-8) ──\n",
            });
            if state.expanded {
                match state.detail_view {
                    DetailViewMode::Utf8 => {
                        if r.body.is_empty() {
                            s.push_str("  <empty>\n");
                        } else {
                            s.push_str(&String::from_utf8_lossy(&r.body));
                            s.push('\n');
                        }
                    }
                    DetailViewMode::Hex => s.push_str(&hex_dump(&r.body)),
                }
            } else {
                s.push_str("  (press Enter to expand)\n");
            }

            if let Some(ref body) = r.response_body {
                s.push_str("\n── Response Headers ──\n");
                s.push_str(&format_headers(&r.response_headers));
                s.push_str("\n── Response Body ");
                s.push_str(match state.detail_view {
                    DetailViewMode::Utf8 => "(UTF-8, press 'x' for hex) ──\n",
                    DetailViewMode::Hex => "(HEX, press 'x' for UTF-8) ──\n",
                });
                if state.expanded {
                    match state.detail_view {
                        DetailViewMode::Utf8 => {
                            if body.is_empty() {
                                s.push_str("  <empty>\n");
                            } else {
                                s.push_str(&String::from_utf8_lossy(body));
                                s.push('\n');
                            }
                        }
                        DetailViewMode::Hex => s.push_str(&hex_dump(body)),
                    }
                } else {
                    s.push_str("  (press Enter to expand)\n");
                }
            }

            s
        }
    };

    let detail_block = Block::default()
        .title(" ┼ [ ⚙ DETAILS ⚙ ] ┼ ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(MECHANICUS_RED))
        .padding(Padding::horizontal(2));
    let detail_widget = Paragraph::new(detail_text)
        .style(Style::default().fg(Color::White))
        .block(detail_block)
        .wrap(Wrap { trim: false })
        .scroll((state.detail_scroll, 0));
    f.render_widget(detail_widget, cols[1]);

    // ── Footer: filter input or key hints ─────────────────────────────────
    let footer_text = if state.filter_active {
        format!(" Filter by host (Enter to apply, Esc to cancel) > {}", state.filter_input)
    } else {
        format!(
            " ↑/↓ select   Enter expand body   x hex/utf8   f filter   w {} websocket-only   c clear history   i frozen requests   W WS-freeze {}   Tab switch screen ",
            if state.ws_only { "[on]" } else { "[off]" },
            if state.engine.ws_intercept_enabled() { "[armed]" } else { "[off]" },
        )
    };
    let footer_block = Block::default()
        .title(" [ CONTROLS ] ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(if state.filter_active { Color::Cyan } else { MECHANICUS_RED }))
        .padding(Padding::horizontal(1));
    let footer_widget = Paragraph::new(footer_text)
        .style(Style::default().fg(RUST_ORANGE).add_modifier(Modifier::BOLD))
        .block(footer_block);
    f.render_widget(footer_widget, footer_area);
}

// ─── Frozen mode ──────────────────────────────────────────────────────────────
//
// Single-panel list of requests currently parked in `InterceptorEngine::queue`
// awaiting a decision. No detail pane — the headers preview lives inline in
// each row's expandable-on-select block, since frozen requests are typically
// reviewed one at a time via the editor rather than browsed at length.

fn draw_frozen_mode(f: &mut Frame, state: &InterceptorState) {
    match state.frozen_target {
        FrozenTarget::Http => draw_frozen_http(f, state),
        FrozenTarget::Ws => draw_frozen_ws(f, state),
    }
}

fn draw_frozen_http(f: &mut Frame, state: &InterceptorState) {
    let screen_size = f.size();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Min(5), Constraint::Length(3)])
        .split(screen_size);

    let frozen = state.engine.frozen_snapshot();

    let mut body = String::new();
    if frozen.is_empty() {
        body.push_str("  (no requests are currently frozen)\n");
    }
    for (i, f_req) in frozen.iter().enumerate() {
        let marker = if i == state.frozen_selected { ">" } else { " " };
        body.push_str(&format!(
            "{} #{:<4} {:<6} {}{}\n",
            marker, f_req.id, f_req.method, f_req.host, f_req.uri,
        ));
        if i == state.frozen_selected {
            // Show this entry's headers indented underneath it.
            for (k, v) in &f_req.headers {
                body.push_str(&format!("      {}: {}\n", k, v));
            }
            if f_req.headers.is_empty() {
                body.push_str("      (no headers)\n");
            }
        }
    }

    let list_block = Block::default()
        .title(" ┼ [ ⚙ FROZEN REQUESTS ⚙ ] ┼ ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan))
        .padding(Padding::horizontal(1));
    let list_widget = Paragraph::new(body)
        .style(Style::default().fg(Color::White))
        .block(list_block)
        .wrap(Wrap { trim: false });
    f.render_widget(list_widget, outer[0]);

    let footer_block = Block::default()
        .title(" [ CONTROLS ] ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan))
        .padding(Padding::horizontal(1));
    let footer_widget = Paragraph::new(
        " ↑/↓ select   f forward   d drop   e edit & forward   w WS frames   i back to history   Tab switch screen ",
    )
        .style(Style::default().fg(RUST_ORANGE).add_modifier(Modifier::BOLD))
        .block(footer_block);
    f.render_widget(footer_widget, outer[1]);
}

/// WS-frame counterpart of `draw_frozen_http`. Same layout; rows show
/// direction + opcode + a short payload preview instead of method/URI.
fn draw_frozen_ws(f: &mut Frame, state: &InterceptorState) {
    let screen_size = f.size();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Min(5), Constraint::Length(3)])
        .split(screen_size);

    let frozen = state.engine.frozen_ws_snapshot();

    let mut body = String::new();
    if !state.engine.ws_intercept_enabled() {
        body.push_str("  (WS freeze is OFF — press 'W' to arm it; frames are auto-forwarded meanwhile)\n");
    }
    if frozen.is_empty() {
        body.push_str("  (no WS frames are currently frozen)\n");
    }
    for (i, frame) in frozen.iter().enumerate() {
        let marker = if i == state.frozen_ws_selected { ">" } else { " " };
        let preview = String::from_utf8_lossy(&frame.payload);
        let preview = preview.chars().take(80).collect::<String>();
        body.push_str(&format!(
            "{} #{:<4} {:<6} {:<14} {}\n",
            marker, frame.id, frame.opcode, frame.direction, preview,
        ));
    }

    let list_block = Block::default()
        .title(" ┼ [ ⚙ FROZEN WS FRAMES ⚙ ] ┼ ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan))
        .padding(Padding::horizontal(1));
    let list_widget = Paragraph::new(body)
        .style(Style::default().fg(Color::White))
        .block(list_block)
        .wrap(Wrap { trim: false });
    f.render_widget(list_widget, outer[0]);

    let footer_block = Block::default()
        .title(" [ CONTROLS ] ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan))
        .padding(Padding::horizontal(1));
    let footer_widget = Paragraph::new(
        " ↑/↓ select   f forward   d drop   e edit payload & forward   w HTTP requests   W arm/disarm freeze   i back to history ",
    )
        .style(Style::default().fg(RUST_ORANGE).add_modifier(Modifier::BOLD))
        .block(footer_block);
    f.render_widget(footer_widget, outer[1]);
}

/// Inline header/body editor popup, opened with 'e' on a frozen request.
fn draw_editor_popup(f: &mut Frame, editor: &EditorState) {
    let screen_size = f.size();
    let popup_area = centered_rect(75, 65, screen_size);

    let block = Block::default()
        .title(format!(" ✎ [ EDIT REQUEST #{} ] (Ctrl+S commit, Esc cancel) ", editor.id))
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(Color::Cyan))
        .padding(Padding::uniform(1));

    // A trailing cursor glyph makes it visually obvious this is an editable
    // textarea and not just another readonly popup.
    let mut text = editor.text.clone();
    text.push('▌');

    let paragraph = Paragraph::new(text)
        .style(Style::default().fg(Color::Rgb(220, 220, 220)))
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((editor.scroll, 0));

    f.render_widget(Clear, popup_area);
    f.render_widget(paragraph, popup_area);
}

/// WS counterpart of `draw_editor_popup` — same popup shape, but editing a
/// raw payload (best-effort UTF-8) rather than headers+body.
fn draw_ws_editor_popup(f: &mut Frame, editor: &WsEditorState) {
    let screen_size = f.size();
    let popup_area = centered_rect(75, 65, screen_size);

    let block = Block::default()
        .title(format!(" ✎ [ EDIT WS FRAME #{} ] (Ctrl+S commit, Esc cancel) ", editor.id))
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(Color::Cyan))
        .padding(Padding::uniform(1));

    let mut text = editor.text.clone();
    text.push('▌');

    let paragraph = Paragraph::new(text)
        .style(Style::default().fg(Color::Rgb(220, 220, 220)))
        .block(block)
        .wrap(Wrap { trim: false });

    f.render_widget(Clear, popup_area);
    f.render_widget(paragraph, popup_area);
}
//
// Fourth TUI screen (cycled to with Tab). Layout:
//   Left strip   (18%) — tab list, one row per RepeaterTab (name + id)
//   Top right    (50% of remaining) — editable request textarea (raw HTTP)
//   Bottom right (50% of remaining) — read-only response display
//
// Keybindings:
//   Ctrl+Enter — send the current request
//   Ctrl+N     — open a new empty tab
//   Ctrl+W     — close the current tab
//   ←/→        — switch between tabs
//   Ctrl+H     — show this tab's history in the existing popup
