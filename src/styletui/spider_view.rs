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