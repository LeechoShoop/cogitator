use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph, Wrap},
    Frame,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::sync::Arc;
use crate::history::{History, HistoryFilter, RequestRecord};
use crate::interceptor::{FrozenSummary, FrozenWsSummary, InterceptAction, InterceptorEngine, WsFrameAction};
use crate::checks::intruder::IntruderResult;
use crate::spider::{FormInfo, SpiderResult};
use crate::repeater::{RepeaterEngine, RepeaterTabSummary};
use crate::scanner::{ScanFinding, Severity};

// Sacred colors of the Adeptus Mechanicus
pub const MECHANICUS_RED: Color = Color::Rgb(138, 24, 24);
pub const GEAR_GRAY: Color = Color::Rgb(80, 80, 80);
pub const RUST_ORANGE: Color = Color::Rgb(210, 105, 30);

/// Which top-level screen is currently visible. Cycled with Tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Main,
    Interceptor,
    Repeater,
    Scanner,
    Intruder,
    Spider,
}

impl Screen {
    pub fn next(self) -> Self {
        match self {
            Screen::Main => Screen::Interceptor,
            Screen::Interceptor => Screen::Repeater,
            Screen::Repeater => Screen::Scanner,
            Screen::Scanner => Screen::Intruder,
            Screen::Intruder => Screen::Spider,
            Screen::Spider => Screen::Main,
        }
    }
}

/// Вспомогательная функция для генерации центрированного прямоугольника под Popup
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Renders the grand machine interface
pub fn draw_ui(
    f: &mut Frame,
    input_text: &str,
    output_text: &str,
    scroll: u16,
    show_popup: bool,
    popup_text: &str,
    popup_scroll: u16,
    is_proxy_active: bool, // Новый аргумент состояния
) {
    let screen_size = f.size();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(10), // Header
                Constraint::Min(5),     // Main log output
                Constraint::Length(3),  // Input field
            ]
        )
        .split(screen_size);

    // 1. Header с индикатором статуса прокси
    let status_text = if is_proxy_active { "[ONLINE]" } else { "[OFFLINE]" };
    let status_color = if is_proxy_active { Color::Green } else { Color::Red };

    let header_art = format!(
        "    _     _                                       _     _    \n\
         _ /_|   |_\\ _                                 _ /_|   |_\\ _ \n\
         \\/  |___|  \\/        COGITATOR OS v0.7        \\/  |___|  \\/ \n\
         =======|=======  PROXY: {}  =======|=======\n\
                |          THE OMNISSIAH PROTECTS            |       ",
        status_text
    );

    let header = Paragraph::new(header_art)
        .style(Style::default().fg(MECHANICUS_RED).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center);

    f.render_widget(header, chunks[0]);

    // Рисуем индикатор статуса поверх заголовка (опционально, можно просто красить текст)
    // В данном случае мы просто добавили его в текст header_art

    // 2. Main Console Output
    let main_block = Block::default()
        .title(" ┼ [ ⚙ SACRED DATABANKS ⚙ ] [ LOGS ] ┼ ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(GEAR_GRAY))
        .padding(Padding::horizontal(2));

    let output = Paragraph::new(output_text)
        .style(Style::default().fg(Color::White))
        .block(main_block)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    f.render_widget(output, chunks[1]);

    // 3. Command Input Bar
    let input_block = Block::default()
        .title(" [ ENTER BINARY CANTICLE ] ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(MECHANICUS_RED))
        .padding(Padding::horizontal(1));

    let input_prompt = format!(" cogitator-ps ⚙ > {}", input_text);
    let input = Paragraph::new(input_prompt)
        .style(Style::default().fg(RUST_ORANGE).add_modifier(Modifier::BOLD))
        .block(input_block);
    f.render_widget(input, chunks[2]);

    // --- ОТРИСОВКА POPUP ---
    if show_popup {
        let popup_area = centered_rect(75, 65, screen_size);
        let popup_block = Block::default()
            .title(" 🌐 [ ⚙ SACRED WEB SCANNER ⚙ ] ")
            .title_alignment(Alignment::Center)
            .borders(Borders::ALL)
            .border_type(BorderType::Double)
            .border_style(Style::default().fg(Color::Cyan))
            .padding(Padding::uniform(1));

        let popup_paragraph = Paragraph::new(popup_text)
            .style(Style::default().fg(Color::Rgb(220, 220, 220)))
            .block(popup_block)
            .wrap(Wrap { trim: false })
            .scroll((popup_scroll, 0));

        f.render_widget(Clear, popup_area);
        f.render_widget(popup_paragraph, popup_area);
    }
}
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
// ─── ScannerView ──────────────────────────────────────────────────────────────
//
// Fifth TUI screen (cycled to with Tab). Three panels:
//   Left       (30%) — findings list, grouped by severity (Critical first),
//                       colour-coded per severity.
//   Top right  (35%) — request_raw of the selected finding.
//   Bottom right (35%) — response_snippet of the selected finding.
//
// Findings are populated by the `Scan-Site <domain>` / `Scan-Request <id>`
// TUI commands (handled in `main.rs`), which run the active checks and hand
// the resulting `Vec<ScanFinding>` to `ScannerState::set_findings`.
//
// Navigation: Up/Down move through the flattened (grouped) finding list;
// PageUp/PageDown scroll the request panel, Ctrl+R scrolls the response panel.

/// Colour used to render a given severity in the findings list.
fn severity_color(sev: Severity) -> Color {
    match sev {
        Severity::Critical => Color::Rgb(255, 0, 0),   // bright red
        Severity::High => Color::Rgb(255, 140, 0),     // orange
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Rgb(120, 120, 120),     // dim
        Severity::Info => Color::Rgb(160, 160, 160),    // grey
    }
}

fn severity_label(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

/// One row in the flattened, grouped findings list: either a group header
/// (severity label, not selectable) or a finding (selectable, indexes back
/// into `ScannerState::findings`).
enum ScannerRow {
    Header(Severity),
    Finding(usize),
}

pub struct ScannerState {
    /// Raw findings as returned by the most recent scan run. Re-grouped by
    /// severity explicitly on every render rather than relying on incoming
    /// order, so the grouping/colour-coding holds even if that upstream
    /// sort invariant ever changes.
    pub findings: Vec<ScanFinding>,
    /// Index into the *findings-only* ordering (i.e. ignoring header rows)
    /// of the currently selected finding.
    pub selected: usize,
    pub list_scroll: u16,
    pub request_scroll: u16,
    pub response_scroll: u16,
    /// Short status line shown in the list panel's title — e.g. "Scanning
    /// example.com…" or "12 findings from history #42".
    pub status: String,
}

impl ScannerState {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            selected: 0,
            list_scroll: 0,
            request_scroll: 0,
            response_scroll: 0,
            status: "no scan run yet — Scan-Site <domain> or Scan-Request <id>".to_string(),
        }
    }

    /// Replace the current findings set (e.g. after `Scan-Site` /
    /// `Scan-Request` completes) and reset selection/scroll.
    pub fn set_findings(&mut self, findings: Vec<ScanFinding>, status: impl Into<String>) {
        self.findings = findings;
        self.selected = 0;
        self.list_scroll = 0;
        self.request_scroll = 0;
        self.response_scroll = 0;
        self.status = status.into();
    }

    /// Build the flattened, grouped row list: a `Header` row for every
    /// severity that has at least one finding, immediately followed by
    /// `Finding` rows for that severity (worst severity first).
    fn rows(&self) -> Vec<ScannerRow> {
        const ORDER: [Severity; 5] = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ];

        let mut rows = Vec::new();
        for &sev in &ORDER {
            let indices: Vec<usize> = self
                .findings
                .iter()
                .enumerate()
                .filter(|(_, f)| f.severity == sev)
                .map(|(i, _)| i)
                .collect();
            if indices.is_empty() {
                continue;
            }
            rows.push(ScannerRow::Header(sev));
            for i in indices {
                rows.push(ScannerRow::Finding(i));
            }
        }
        rows
    }

    /// The `ScanFinding` currently selected, if any (skips header rows when
    /// counting against `self.selected`).
    fn selected_finding(&self) -> Option<&ScanFinding> {
        let finding_indices: Vec<usize> = self
            .rows()
            .into_iter()
            .filter_map(|r| match r {
                ScannerRow::Finding(i) => Some(i),
                ScannerRow::Header(_) => None,
            })
            .collect();
        finding_indices
            .get(self.selected)
            .and_then(|&i| self.findings.get(i))
    }

    fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// Route a key press to this screen. Call only while `Screen::Scanner`
    /// is active and no popup is open.
    pub fn handle_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up => {
                self.selected = self.selected.saturating_sub(1);
                self.request_scroll = 0;
                self.response_scroll = 0;
            }
            KeyCode::Down => {
                let len = self.finding_count();
                if len > 0 && self.selected + 1 < len {
                    self.selected += 1;
                }
                self.request_scroll = 0;
                self.response_scroll = 0;
            }
            KeyCode::PageUp => self.request_scroll = self.request_scroll.saturating_sub(10),
            KeyCode::PageDown => self.request_scroll = self.request_scroll.saturating_add(10),
            KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.response_scroll = self.response_scroll.saturating_add(10);
            }
            _ => {}
        }
    }
}

impl Default for ScannerState {
    fn default() -> Self {
        Self::new()
    }
}

/// Renders the ScannerView screen.
pub fn draw_scanner_view(f: &mut Frame, state: &ScannerState) {
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

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(cols[1]);

    // ── Left: findings list grouped by severity, colour-coded ──────────────
    let rows_data = state.rows();

    let mut finding_counter = 0usize;
    let mut selected_row_idx: Option<usize> = None;

    let mut list_lines: Vec<ratatui::text::Line> = Vec::new();
    if rows_data.is_empty() {
        list_lines.push(ratatui::text::Line::from("  (no findings yet)"));
    }
    for (row_idx, row) in rows_data.iter().enumerate() {
        match row {
            ScannerRow::Header(sev) => {
                list_lines.push(ratatui::text::Line::from(
                    ratatui::text::Span::styled(
                        format!(" ── {} ──", severity_label(*sev)),
                        Style::default()
                            .fg(severity_color(*sev))
                            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                    ),
                ));
            }
            ScannerRow::Finding(i) => {
                let f = &state.findings[*i];
                let is_selected = finding_counter == state.selected;
                if is_selected {
                    selected_row_idx = Some(row_idx);
                }
                let marker = if is_selected { ">" } else { " " };
                let text = format!(" {} {}", marker, f.check_name);
                let mut style = Style::default().fg(severity_color(f.severity));
                if is_selected {
                    style = style.add_modifier(Modifier::BOLD | Modifier::REVERSED);
                }
                list_lines.push(ratatui::text::Line::from(
                    ratatui::text::Span::styled(text, style),
                ));
                finding_counter += 1;
            }
        }
    }

    let list_title = format!(" ┼ [ ⚙ SCANNER ⚙ ] [ {} ] ┼ ", state.status);
    let list_block = Block::default()
        .title(list_title)
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(GEAR_GRAY))
        .padding(Padding::horizontal(1));

    // Auto-scroll so the selected row stays roughly in view.
    let visible_height = cols[0].height.saturating_sub(2); // minus borders
    let mut scroll = state.list_scroll;
    if let Some(idx) = selected_row_idx {
        let idx = idx as u16;
        if idx < scroll {
            scroll = idx;
        } else if visible_height > 0 && idx >= scroll + visible_height {
            scroll = idx + 1 - visible_height;
        }
    }

    let list_widget = Paragraph::new(list_lines)
        .block(list_block)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    f.render_widget(list_widget, cols[0]);

    // ── Top right: request_raw of the selected finding ─────────────────────
    let selected = state.selected_finding();

    let request_text = selected
        .map(|f| f.request_raw.clone())
        .unwrap_or_else(|| "  (no finding selected)".to_string());
    let request_title = match selected {
        Some(f) => format!(" » [ REQUEST — {} ] ", f.check_name),
        None => " » [ REQUEST ] ".to_string(),
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

    // ── Bottom right: response_snippet of the selected finding ─────────────
    let response_text = selected
        .map(|f| {
            if f.response_snippet.is_empty() {
                "  (empty response snippet)".to_string()
            } else {
                f.response_snippet.clone()
            }
        })
        .unwrap_or_else(|| "  (no finding selected)".to_string());
    let response_title = match selected {
        Some(f) => format!(" « [ RESPONSE — {} ] ", severity_label(f.severity)),
        None => " « [ RESPONSE ] ".to_string(),
    };
    let response_border = selected
        .map(|f| severity_color(f.severity))
        .unwrap_or(Color::Cyan);
    let response_block = Block::default()
        .title(response_title)
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(response_border))
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
        " ↑/↓ select finding   PgUp/PgDn scroll request   Ctrl+R scroll response   Scan-Site <domain>   Scan-Request <id>   Tab switch screen ",
    )
        .style(Style::default().fg(RUST_ORANGE).add_modifier(Modifier::BOLD))
        .block(footer_block);
    f.render_widget(footer_widget, footer_area);
}

// ─── IntruderView ─────────────────────────────────────────────────────────────
//
// Sixth TUI screen (cycled to with Tab). Single-panel results table:
//
//   #   Payload   Status   Length   Time(ms)
//
// Populated live: `Fuzz <url> <wordlist_file>` and `Intruder-Load <file>`
// (handled in `main.rs`) kick off an `intruder::run` and hand its
// `Receiver<IntruderResult>` to the caller, which polls it every tick and
// calls `IntruderState::push_result` for each item that arrives — rows
// appear in the table as the engine produces them, no separate "run
// finished" step required.
//
// The first result to ever arrive becomes the baseline: every later row is
// compared against that baseline's `(status, length)` pair. Rows that
// differ on either field are anomalies — rendered in gold — while rows that
// match stay dim, since an unchanged status/length pair usually means the
// payload didn't do anything interesting.
//
// Keybindings:
//   ↑/↓    — move selection
//   a      — toggle "anomalies only" (hides baseline-matching rows)
//   1-4    — sort by Payload / Status / Length / Time respectively;
//            pressing the same key again reverses the current direction
//   Enter  — open the selected row's full response in a popup
//   Esc    — (while popup open) close it
//   PageUp/PageDown — scroll the open response popup

/// Gold used to flag a row whose status or length diverges from baseline.
const ANOMALY_GOLD: Color = Color::Rgb(212, 175, 55);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntruderSortColumn {
    Payload,
    Status,
    Length,
    Time,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortDirection {
    Ascending,
    Descending,
}

/// One streamed-in result, tagged with its arrival order so the `#` column
/// stays stable regardless of how the table is currently sorted.
struct IntruderRow {
    seq: usize,
    result: IntruderResult,
}

/// Read-only popup state for "Enter — view full response", mirroring
/// `EditorState`'s textarea-popup shape but with no edit/commit behaviour.
pub struct ResponsePopupState {
    pub title: String,
    pub text: String,
    pub scroll: u16,
}

pub struct IntruderState {
    rows: Vec<IntruderRow>,
    /// `(status, length)` of the first result ever pushed. `None` until
    /// at least one result has arrived.
    baseline: Option<(Option<u16>, usize)>,
    pub anomalies_only: bool,
    sort: Option<(IntruderSortColumn, SortDirection)>,
    pub selected: usize,
    pub list_scroll: u16,
    pub response_popup: Option<ResponsePopupState>,
    /// Short status line shown in the panel title — e.g. "Fuzzing
    /// example.com/login (id param)…" or "Loaded template from disk".
    pub status: String,
}

impl IntruderState {
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            baseline: None,
            anomalies_only: false,
            sort: None,
            selected: 0,
            list_scroll: 0,
            response_popup: None,
            status: "no run yet — Fuzz <url> <wordlist_file>".to_string(),
        }
    }

    /// Clear all rows/baseline/sort/filter state, e.g. right before kicking
    /// off a fresh `Fuzz`/`Intruder-Load`-driven run so stale rows from a
    /// previous run don't linger mixed in with the new ones.
    pub fn reset_for_new_run(&mut self, status: impl Into<String>) {
        self.rows.clear();
        self.baseline = None;
        self.anomalies_only = false;
        self.sort = None;
        self.selected = 0;
        self.list_scroll = 0;
        self.response_popup = None;
        self.status = status.into();
    }

    /// Feed one freshly-arrived `IntruderResult` into the table. The very
    /// first call after a reset establishes the baseline; every row
    /// (including this first one) is compared against whatever baseline is
    /// current at push time.
    pub fn push_result(&mut self, result: IntruderResult) {
        if self.baseline.is_none() {
            self.baseline = Some((result.status, result.length));
        }
        let seq = self.rows.len();
        self.rows.push(IntruderRow { seq, result });
    }

    fn is_anomaly(&self, row: &IntruderRow) -> bool {
        match self.baseline {
            Some((b_status, b_len)) => {
                row.result.status != b_status || row.result.length != b_len
            }
            None => false,
        }
    }

    /// Rows to actually display: filtered by `anomalies_only` (if set),
    /// then sorted by `sort` (if set) — insertion order otherwise.
    fn visible_rows(&self) -> Vec<&IntruderRow> {
        let mut rows: Vec<&IntruderRow> = if self.anomalies_only {
            self.rows.iter().filter(|r| self.is_anomaly(r)).collect()
        } else {
            self.rows.iter().collect()
        };

        if let Some((col, dir)) = self.sort {
            rows.sort_by(|a, b| {
                let ord = match col {
                    IntruderSortColumn::Payload => a.result.payload.cmp(&b.result.payload),
                    IntruderSortColumn::Status => a.result.status.cmp(&b.result.status),
                    IntruderSortColumn::Length => a.result.length.cmp(&b.result.length),
                    IntruderSortColumn::Time => a.result.response_time_ms.cmp(&b.result.response_time_ms),
                };
                match dir {
                    SortDirection::Ascending => ord,
                    SortDirection::Descending => ord.reverse(),
                }
            });
        }

        rows
    }

    fn selected_row(&self) -> Option<&IntruderRow> {
        self.visible_rows().into_iter().nth(self.selected)
    }

    /// Set (or flip the direction of) the active sort column. Pressing the
    /// same column's key twice in a row reverses it instead of being a
    /// no-op, mirroring how most spreadsheet/table UIs handle repeat clicks
    /// on a column header.
    fn set_sort(&mut self, col: IntruderSortColumn) {
        self.sort = match self.sort {
            Some((current, SortDirection::Ascending)) if current == col => {
                Some((col, SortDirection::Descending))
            }
            _ => Some((col, SortDirection::Ascending)),
        };
        self.selected = 0;
        self.list_scroll = 0;
    }

    /// Route a key press to this screen. Call only while `Screen::Intruder`
    /// is active and no other popup is open.
    pub fn handle_key(&mut self, key: KeyEvent) {
        // ── Response popup takes priority over everything else ─────────────
        if let Some(popup) = self.response_popup.as_mut() {
            match key.code {
                KeyCode::Esc => self.response_popup = None,
                KeyCode::PageUp => popup.scroll = popup.scroll.saturating_sub(10),
                KeyCode::PageDown => popup.scroll = popup.scroll.saturating_add(10),
                KeyCode::Up => popup.scroll = popup.scroll.saturating_sub(1),
                KeyCode::Down => popup.scroll = popup.scroll.saturating_add(1),
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Up => {
                self.selected = self.selected.saturating_sub(1);
            }
            KeyCode::Down => {
                let len = self.visible_rows().len();
                if len > 0 && self.selected + 1 < len {
                    self.selected += 1;
                }
            }
            KeyCode::Char('a') => {
                self.anomalies_only = !self.anomalies_only;
                self.selected = 0;
                self.list_scroll = 0;
            }
            KeyCode::Char('1') => self.set_sort(IntruderSortColumn::Payload),
            KeyCode::Char('2') => self.set_sort(IntruderSortColumn::Status),
            KeyCode::Char('3') => self.set_sort(IntruderSortColumn::Length),
            KeyCode::Char('4') => self.set_sort(IntruderSortColumn::Time),
            KeyCode::Enter => {
                if let Some(row) = self.selected_row() {
                    self.response_popup = Some(ResponsePopupState {
                        title: format!(
                            " 📡 [ RESPONSE #{} — {} ] ",
                            row.seq + 1,
                            row.result.payload,
                        ),
                        text: row.result.response_raw.clone(),
                        scroll: 0,
                    });
                }
            }
            KeyCode::PageUp => self.list_scroll = self.list_scroll.saturating_sub(10),
            KeyCode::PageDown => self.list_scroll = self.list_scroll.saturating_add(10),
            _ => {}
        }
    }
}

impl Default for IntruderState {
    fn default() -> Self {
        Self::new()
    }
}

fn format_intruder_status(status: Option<u16>) -> String {
    match status {
        Some(s) => s.to_string(),
        None => "ERR".to_string(),
    }
}

fn sort_indicator(state: &IntruderState, col: IntruderSortColumn) -> &'static str {
    match state.sort {
        Some((c, SortDirection::Ascending)) if c == col => " ▲",
        Some((c, SortDirection::Descending)) if c == col => " ▼",
        _ => "",
    }
}

/// Renders the IntruderView screen.
pub fn draw_intruder_view(f: &mut Frame, state: &IntruderState) {
    let screen_size = f.size();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Length(2), Constraint::Min(5), Constraint::Length(3)])
        .split(screen_size);

    let header_area = outer[0];
    let main_area = outer[1];
    let footer_area = outer[2];

    // ── Column header row ───────────────────────────────────────────────────
    let header_line = format!(
        "  {:<5} {:<28}{:<10}{:<10}{:<10}",
        "#",
        format!("Payload{}", sort_indicator(state, IntruderSortColumn::Payload)),
        format!("Status{}", sort_indicator(state, IntruderSortColumn::Status)),
        format!("Length{}", sort_indicator(state, IntruderSortColumn::Length)),
        format!("Time(ms){}", sort_indicator(state, IntruderSortColumn::Time)),
    );
    let header_widget = Paragraph::new(header_line)
        .style(Style::default().fg(RUST_ORANGE).add_modifier(Modifier::BOLD | Modifier::UNDERLINED));
    f.render_widget(header_widget, header_area);

    // ── Results table ───────────────────────────────────────────────────────
    let visible = state.visible_rows();

    let mut lines: Vec<ratatui::text::Line> = Vec::new();
    if visible.is_empty() {
        let msg = if state.rows.is_empty() {
            "  (no results yet — Fuzz <url> <wordlist_file> or Intruder-Load <file>)"
        } else {
            "  (no anomalies — press 'a' to show all rows)"
        };
        lines.push(ratatui::text::Line::from(msg));
    }

    for (i, row) in visible.iter().enumerate() {
        let is_selected = i == state.selected;
        let is_anomaly = state.is_anomaly(row);

        let marker = if is_selected { ">" } else { " " };
        // Truncate long payloads so the table stays aligned rather than
        // wrapping mid-row.
        let payload_display: String = row.result.payload.chars().take(26).collect();
        let text = format!(
            "{} {:<5} {:<28}{:<10}{:<10}{:<10}",
            marker,
            row.seq + 1,
            payload_display,
            format_intruder_status(row.result.status),
            row.result.length,
            row.result.response_time_ms,
        );

        let mut style = if is_anomaly {
            Style::default().fg(ANOMALY_GOLD).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Rgb(120, 120, 120))
        };
        if is_selected {
            style = style.add_modifier(Modifier::REVERSED);
        }

        lines.push(ratatui::text::Line::from(ratatui::text::Span::styled(text, style)));
    }

    let baseline_summary = match state.baseline {
        Some((status, len)) => format!(
            "baseline: {} / {}b",
            format_intruder_status(status),
            len
        ),
        None => "no baseline yet".to_string(),
    };
    let filter_summary = if state.anomalies_only { " | anomalies only" } else { "" };
    let list_title = format!(
        " ┼ [ ⚙ INTRUDER ⚙ ] [ {} ] [ {}{} ] ┼ ",
        state.status, baseline_summary, filter_summary,
    );
    let list_block = Block::default()
        .title(list_title)
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(GEAR_GRAY))
        .padding(Padding::horizontal(1));
    let list_widget = Paragraph::new(lines)
        .block(list_block)
        .wrap(Wrap { trim: false })
        .scroll((state.list_scroll, 0));
    f.render_widget(list_widget, main_area);

    // ── Footer ───────────────────────────────────────────────────────────────
    let footer_block = Block::default()
        .title(" [ CONTROLS ] ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(MECHANICUS_RED))
        .padding(Padding::horizontal(1));
    let footer_widget = Paragraph::new(
        " ↑/↓ select   a anomalies only   1-4 sort col   Enter view response   Fuzz <url> <wordlist>   Intruder-Load <file>   Tab switch screen ",
    )
        .style(Style::default().fg(RUST_ORANGE).add_modifier(Modifier::BOLD))
        .block(footer_block);
    f.render_widget(footer_widget, footer_area);

    // ── Response popup, if open ─────────────────────────────────────────────
    if let Some(popup) = &state.response_popup {
        draw_response_popup(f, popup);
    }
}

/// Read-only response popup opened with Enter on a selected row. Mirrors
/// `draw_editor_popup`'s shape but adds no cursor glyph / commit affordance
/// since there's nothing to edit here.
fn draw_response_popup(f: &mut Frame, popup: &ResponsePopupState) {
    let screen_size = f.size();
    let popup_area = centered_rect(75, 65, screen_size);

    let block = Block::default()
        .title(format!("{}(Esc close, PgUp/PgDn scroll) ", popup.title))
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(ANOMALY_GOLD))
        .padding(Padding::uniform(1));

    let text = if popup.text.is_empty() {
        "  <empty response>".to_string()
    } else {
        popup.text.clone()
    };

    let paragraph = Paragraph::new(text)
        .style(Style::default().fg(Color::Rgb(220, 220, 220)))
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((popup.scroll, 0));

    f.render_widget(Clear, popup_area);
    f.render_widget(paragraph, popup_area);
}
// ─── SpiderView ───────────────────────────────────────────────────────────────
//
// Seventh TUI screen (cycled to with Tab, after Intruder). Renders the
// crawl as an indented URL tree — indentation comes straight from
// `SpiderResult::depth`, so this is *not* a true parent/child tree (Spider
// doesn't track which link led to which page), just depth-as-indentation
// against arrival (BFS) order, which is enough to read the crawl's shape
// at a glance.
//
// Populated live: `Spider <domain>` / `Spider-Depth <domain> <N>` (handled
// in `main.rs`) kick off a `spider::run` and hand its
// `Receiver<SpiderResult>` to the caller, which polls it every tick and
// calls `SpiderState::push_result` for each item that arrives — rows
// appear as pages are actually fetched, same live-streaming shape as
// IntruderView.
//
// Progress line: "X / max_pages crawled — Y forms found", where X is
// simply the number of results received so far and Y is the running total
// of every `FormInfo` across every page seen.
//
// Keybindings:
//   ↑/↓             — move selection
//   PageUp/PageDown — scroll the tree

#[derive(Debug, Clone)]
struct SpiderRow {
    result: SpiderResult,
}

pub struct SpiderState {
    rows: Vec<SpiderRow>,
    /// Target page cap for the in-progress (or most recently finished)
    /// crawl — purely for the "X / max_pages" progress line; doesn't
    /// affect anything else rendered here.
    pub max_pages: usize,
    /// Running total of `found_forms.len()` across every row received so
    /// far — recomputing this from `rows` on every frame would be
    /// `O(n)` per redraw for no benefit, so it's tracked incrementally.
    pub forms_found: usize,
    pub selected: usize,
    pub list_scroll: u16,
    /// Short status line — e.g. "crawling example.com (depth 3)…" or
    /// "idle — Spider <domain>".
    pub status: String,
}

impl SpiderState {
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            max_pages: 0,
            forms_found: 0,
            selected: 0,
            list_scroll: 0,
            status: "idle — Spider <domain> or Spider-Depth <domain> <N>".to_string(),
        }
    }

    /// Clear all rows/counters, e.g. right before kicking off a fresh
    /// `Spider`/`Spider-Depth`-driven run so stale rows from a previous
    /// crawl don't linger mixed in with the new one.
    pub fn reset_for_new_run(&mut self, max_pages: usize, status: impl Into<String>) {
        self.rows.clear();
        self.max_pages = max_pages;
        self.forms_found = 0;
        self.selected = 0;
        self.list_scroll = 0;
        self.status = status.into();
    }

    /// Feed one freshly-arrived `SpiderResult` into the tree.
    pub fn push_result(&mut self, result: SpiderResult) {
        self.forms_found += result.found_forms.len();
        self.rows.push(SpiderRow { result });
    }

    pub fn pages_crawled(&self) -> usize {
        self.rows.len()
    }

    /// Route a key press to this screen. Call only while `Screen::Spider`
    /// is active and no popup is open.
    pub fn handle_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up => {
                self.selected = self.selected.saturating_sub(1);
            }
            KeyCode::Down => {
                if !self.rows.is_empty() && self.selected + 1 < self.rows.len() {
                    self.selected += 1;
                }
            }
            KeyCode::PageUp => self.list_scroll = self.list_scroll.saturating_sub(10),
            KeyCode::PageDown => self.list_scroll = self.list_scroll.saturating_add(10),
            _ => {}
        }
    }
}

impl Default for SpiderState {
    fn default() -> Self {
        Self::new()
    }
}

fn format_spider_status(status: Option<u16>) -> String {
    match status {
        Some(s) => s.to_string(),
        None => "ERR".to_string(),
    }
}

/// Green for 2xx/3xx, yellow for 4xx, red for 5xx/failed requests.
fn spider_status_color(status: Option<u16>) -> Color {
    match status {
        Some(s) if s < 400 => Color::Green,
        Some(s) if s < 500 => Color::Yellow,
        Some(_) => Color::Red,
        None => Color::Red,
    }
}

/// Trim a `Content-Type` header value down to just the MIME type (drops
/// `; charset=...` and similar parameters) so the column stays narrow.
fn short_content_type(content_type: &Option<String>) -> String {
    match content_type {
        Some(ct) => ct.split(';').next().unwrap_or(ct).trim().to_string(),
        None => "—".to_string(),
    }
}

/// Renders the SpiderView screen.
pub fn draw_spider_view(f: &mut Frame, state: &SpiderState) {
    let screen_size = f.size();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Length(2), Constraint::Min(5), Constraint::Length(3)])
        .split(screen_size);

    let progress_area = outer[0];
    let main_area = outer[1];
    let footer_area = outer[2];

    // ── Progress indicator ──────────────────────────────────────────────────
    let progress_line = if state.max_pages > 0 {
        format!(
            "  {} / {} crawled — {} forms found",
            state.pages_crawled(),
            state.max_pages,
            state.forms_found,
        )
    } else {
        format!("  {} crawled — {} forms found", state.pages_crawled(), state.forms_found)
    };
    let progress_widget = Paragraph::new(progress_line)
        .style(Style::default().fg(RUST_ORANGE).add_modifier(Modifier::BOLD));
    f.render_widget(progress_widget, progress_area);

    // ── URL tree ─────────────────────────────────────────────────────────────
    let mut lines: Vec<ratatui::text::Line> = Vec::new();

    if state.rows.is_empty() {
        lines.push(ratatui::text::Line::from(
            "  (no pages yet — Spider <domain> or Spider-Depth <domain> <N>)",
        ));
    }

    for (i, row) in state.rows.iter().enumerate() {
        let is_selected = i == state.selected;
        let depth = row.result.depth as usize;

        // Depth-as-indentation, with a small branch glyph so the tree
        // shape is readable even though it's not a real parent/child
        // structure (see module doc comment above).
        let indent = if depth == 0 {
            String::new()
        } else {
            format!("{}└─ ", "   ".repeat(depth - 1))
        };

        let marker = if is_selected { ">" } else { " " };
        let status_str = format_spider_status(row.result.status);
        let content_type_str = short_content_type(&row.result.content_type);

        // URL column width is whatever's left of the row after borders,
        // padding, the marker+space, the indent, and the trailing
        // " · STATUS · content/type" columns. Previously this was a fixed
        // 55 chars regardless of terminal width, which truncated URLs even
        // when there was plenty of horizontal room — now it stretches to
        // fill wide terminals and only falls back to a sane minimum on
        // narrow ones.
        //
        // Fixed budget: 1 (border) + 1 (padding) + 2 (marker + space)
        // + 3 (" · " before status) + 5 (status_str width) + 3 (" · "
        // before content-type) + content_type_str.len() + 1 (border).
        const STATUS_COL_WIDTH: usize = 5;
        const MIN_URL_COL_WIDTH: usize = 20;
        let fixed_budget = 1 + 1 + 2 + 3 + STATUS_COL_WIDTH + 3 + content_type_str.chars().count() + 1;
        let row_width = main_area.width as usize;
        let url_col_width = row_width
            .saturating_sub(fixed_budget)
            .saturating_sub(indent.len())
            .max(MIN_URL_COL_WIDTH);

        let text = format!(
            "{} {}{:<width$} · {:<5} · {}",
            marker,
            indent,
            truncate_middle(&row.result.url, url_col_width),
            status_str,
            content_type_str,
            width = url_col_width,
        );

        let mut style = Style::default().fg(spider_status_color(row.result.status));
        if is_selected {
            style = style.add_modifier(Modifier::REVERSED);
        }

        lines.push(ratatui::text::Line::from(ratatui::text::Span::styled(text, style)));
    }

    let list_title = format!(" ┼ [ 🕸 SPIDER 🕸 ] [ {} ] ┼ ", state.status);
    let list_block = Block::default()
        .title(list_title)
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(GEAR_GRAY))
        .padding(Padding::horizontal(1));

    // Auto-scroll so the selected row stays in view when navigating with Up/Down.
    // Mirrors the same pattern used in draw_scanner_view.
    let visible_height = main_area.height.saturating_sub(2); // minus top/bottom borders
    let mut scroll = state.list_scroll;
    if !state.rows.is_empty() {
        let idx = state.selected as u16;
        if idx < scroll {
            scroll = idx;
        } else if visible_height > 0 && idx >= scroll + visible_height {
            scroll = idx + 1 - visible_height;
        }
    }

    let list_widget = Paragraph::new(lines)
        .block(list_block)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    f.render_widget(list_widget, main_area);

    // ── Footer ───────────────────────────────────────────────────────────────
    let footer_block = Block::default()
        .title(" [ CONTROLS ] ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(MECHANICUS_RED))
        .padding(Padding::horizontal(1));
    let footer_widget = Paragraph::new(
        " ↑/↓ select   PgUp/PgDn scroll   Spider <domain>   Spider-Depth <domain> <N>   Tab switch screen ",
    )
        .style(Style::default().fg(RUST_ORANGE).add_modifier(Modifier::BOLD))
        .block(footer_block);
    f.render_widget(footer_widget, footer_area);
}

/// Shorten `s` to at most `max_len` chars, replacing a middle chunk with
/// `…` so both the scheme/host (start) and the most specific path segment
/// (end) stay visible — more useful for URLs than truncating from the end,
/// since the host is what disambiguates rows at a glance.
fn truncate_middle(s: &str, max_len: usize) -> String {
    if max_len == 0 {
        return String::new();
    }
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max_len {
        return s.to_string();
    }
    if max_len <= 3 {
        return chars[..max_len].iter().collect();
    }
    let keep = max_len - 1; // reserve 1 for the ellipsis
    let head = keep / 2 + keep % 2;
    let tail = keep - head;
    let head_str: String = chars[..head].iter().collect();
    let tail_str: String = chars[chars.len() - tail..].iter().collect();
    format!("{head_str}…{tail_str}")
}

#[cfg(test)]
mod spider_view_tests {
    use super::*;

    fn result(url: &str, depth: u8, status: Option<u16>) -> SpiderResult {
        SpiderResult {
            url: url.to_string(),
            depth,
            found_links: Vec::new(),
            found_forms: Vec::new(),
            status,
            content_type: Some("text/html; charset=utf-8".to_string()),
        }
    }

    #[test]
    fn push_result_tracks_forms_found() {
        let mut state = SpiderState::new();
        let mut r = result("https://example.com/", 0, Some(200));
        r.found_forms.push(FormInfo {
            action: "https://example.com/login".to_string(),
            method: "POST".to_string(),
            fields: vec!["user".to_string()],
        });
        state.push_result(r);
        assert_eq!(state.forms_found, 1);
        assert_eq!(state.pages_crawled(), 1);
    }

    #[test]
    fn reset_clears_rows_and_counters() {
        let mut state = SpiderState::new();
        state.push_result(result("https://example.com/", 0, Some(200)));
        state.reset_for_new_run(500, "crawling example.com (depth 3)…");
        assert_eq!(state.pages_crawled(), 0);
        assert_eq!(state.forms_found, 0);
        assert_eq!(state.max_pages, 500);
    }

    #[test]
    fn format_status_none_is_err() {
        assert_eq!(format_spider_status(None), "ERR");
        assert_eq!(format_spider_status(Some(404)), "404");
    }

    #[test]
    fn short_content_type_strips_charset() {
        assert_eq!(
            short_content_type(&Some("text/html; charset=utf-8".to_string())),
            "text/html"
        );
        assert_eq!(short_content_type(&None), "—");
    }

    #[test]
    fn truncate_middle_keeps_head_and_tail() {
        let long = "https://example.com/a/very/long/path/that/goes/on/and/on/forever";
        let out = truncate_middle(long, 20);
        assert_eq!(out.chars().count(), 20);
        assert!(out.starts_with("https://"));
        assert!(out.contains('…'));
    }

    #[test]
    fn truncate_middle_noop_when_short_enough() {
        assert_eq!(truncate_middle("https://x.com/", 50), "https://x.com/");
    }
}