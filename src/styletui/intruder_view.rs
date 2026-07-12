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
