//! Scope-Add, Scope-Exclude, Scope-List, Scope-Clear handlers.

use super::CommandContext;

// ── Scope-Add ─────────────────────────────────────────────────────────────────

pub fn scope_add(ctx: &mut CommandContext<'_>, rest: &str) {
    if rest.is_empty() {
        *ctx.output_buffer = "Usage: Scope-Add <regex>".to_string();
    } else {
        match ctx.scope.lock().unwrap().add_include(rest) {
            Ok(_) => *ctx.output_buffer = format!("✅ Scope include added: {}", rest),
            Err(e) => *ctx.output_buffer = format!("❌ Invalid regex: {}", e),
        }
    }
}

// ── Scope-Exclude ─────────────────────────────────────────────────────────────

pub fn scope_exclude(ctx: &mut CommandContext<'_>, rest: &str) {
    if rest.is_empty() {
        *ctx.output_buffer = "Usage: Scope-Exclude <regex>".to_string();
    } else {
        match ctx.scope.lock().unwrap().add_exclude(rest) {
            Ok(_) => *ctx.output_buffer = format!("✅ Scope exclude added: {}", rest),
            Err(e) => *ctx.output_buffer = format!("❌ Invalid regex: {}", e),
        }
    }
}

// ── Scope-List ────────────────────────────────────────────────────────────────

pub fn scope_list(ctx: &mut CommandContext<'_>) {
    let rules = ctx.scope.lock().unwrap().list();
    if rules.is_empty() {
        *ctx.output_buffer = "Scope is empty — all traffic is in scope.".to_string();
    } else {
        let mut text = String::from("┌─[ PROXY SCOPE ]───────────────────────────\n");
        for (pattern, include) in &rules {
            text.push_str(&format!(
                "│  {} {}\n",
                if *include { "+ INCLUDE" } else { "- EXCLUDE" },
                pattern
            ));
        }
        text.push_str("└────────────────────────────────────────────\n");
        *ctx.output_buffer = text;
    }
    *ctx.scroll_offset = 0;
}

// ── Scope-Clear ───────────────────────────────────────────────────────────────

pub fn scope_clear(ctx: &mut CommandContext<'_>) {
    ctx.scope.lock().unwrap().clear();
    *ctx.output_buffer = "✅ Scope cleared — all traffic is now in scope.".to_string();
}
