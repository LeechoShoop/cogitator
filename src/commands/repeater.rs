//! Send-To-Repeater handler.

use crate::styletui::Screen;
use super::CommandContext;

// ── Send-To-Repeater ──────────────────────────────────────────────────────────

pub fn send_to_repeater(ctx: &mut CommandContext<'_>, rest: &str) {
    match rest.parse::<u64>() {
        Ok(id) => match ctx.history.get(id) {
            Some(record) => {
                let tab_id = ctx.repeater.new_tab(&record);
                *ctx.output_buffer = format!(
                    "✅ History record #{} opened in Repeater tab #{}",
                    id, tab_id
                );
                *ctx.current_screen = Screen::Repeater;
            }
            None => {
                *ctx.output_buffer = format!(
                    "❌ No history record with id {} (evicted or never existed)",
                    id
                );
            }
        },
        Err(_) => {
            *ctx.output_buffer = "Usage: Send-To-Repeater <history_id>".to_string();
        }
    }
}
