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

pub mod interceptor_view;
pub mod repeater_view;
pub mod scanner_view;
pub mod intruder_view;
pub mod spider_view;

pub use interceptor_view::*;
pub use repeater_view::*;
pub use scanner_view::*;
pub use intruder_view::*;
pub use spider_view::*;
