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

