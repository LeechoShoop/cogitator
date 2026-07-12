//! Session-Save, Session-Load, Session-List handlers.

use super::CommandContext;

// ── Session-Save ──────────────────────────────────────────────────────────────

pub fn session_save(ctx: &mut CommandContext<'_>, rest: &str) {
    if rest.is_empty() {
        *ctx.output_buffer = "Usage: Session-Save <name>".to_string();
        return;
    }
    let mut profile = ctx.cookie_jar.snapshot();
    profile.name = rest.to_string();
    ctx.profile_store.save(profile);
    *ctx.output_buffer = format!("✅ Session saved as '{}'", rest);
}

// ── Session-Load ──────────────────────────────────────────────────────────────

pub fn session_load(ctx: &mut CommandContext<'_>, rest: &str) {
    if rest.is_empty() {
        *ctx.output_buffer = "Usage: Session-Load <name>".to_string();
        return;
    }
    match ctx.profile_store.load(rest) {
        Some(profile) => {
            ctx.cookie_jar.restore_from_profile(&profile);
            *ctx.output_buffer = format!(
                "✅ Session '{}' loaded ({} domain(s) restored)",
                rest,
                profile.cookies.len()
            );
        }
        None => {
            *ctx.output_buffer = format!(
                "❌ No saved session named '{}' (try Session-List)",
                rest
            );
        }
    }
}

// ── Session-List ──────────────────────────────────────────────────────────────

pub fn session_list(ctx: &mut CommandContext<'_>) {
    let names = ctx.profile_store.list();
    if names.is_empty() {
        *ctx.output_buffer = "No saved sessions yet. Use Session-Save <name>.".to_string();
    } else {
        let mut text = String::from("┌─[ SAVED SESSIONS ]────────────────────────\n");
        for n in &names {
            if let Some(p) = ctx.profile_store.load(n) {
                text.push_str(&format!(
                    "│  {}  ({} domain(s), {} custom header(s))\n",
                    n,
                    p.cookies.len(),
                    p.custom_headers.len()
                ));
            }
        }
        text.push_str("└────────────────────────────────────────────\n");
        *ctx.output_buffer = text;
    }
    *ctx.scroll_offset = 0;
}
