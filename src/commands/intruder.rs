//! Fuzz and Intruder-Load handlers.

use std::path::PathBuf;

use crate::checks;
use crate::styletui::Screen;
use super::CommandContext;

// ── Fuzz ──────────────────────────────────────────────────────────────────────

pub fn fuzz(ctx: &mut CommandContext<'_>, rest: &str) {
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() != 2 {
        *ctx.output_buffer = format!(
            "Usage: Fuzz <url containing {}> <wordlist_file>",
            checks::intruder::MARKER
        );
        return;
    }

    let url = parts[0];
    let wordlist_path = parts[1];

    if !url.contains(checks::intruder::MARKER) {
        *ctx.output_buffer = format!(
            "❌ URL must contain a {} marker to fuzz",
            checks::intruder::MARKER
        );
        return;
    }

    let payloads: Vec<String> = checks::intruder::load_wordlist(
        &checks::intruder::WordlistSource::File(PathBuf::from(wordlist_path)),
    )
    .collect();

    if payloads.is_empty() {
        *ctx.output_buffer = format!(
            "❌ Wordlist {} was empty or unreadable",
            wordlist_path
        );
        return;
    }

    // Absolute-form request line — `build_request` in intruder.rs treats the
    // target as a ready URL when it starts with http(s)://, so no Host header
    // (and no premature URL-parsing of the §PAYLOAD§-laden string) is needed.
    let template = format!("GET {} HTTP/1.1\r\n\r\n", url);
    let payload_count = payloads.len();

    let cfg = checks::intruder::IntruderConfig {
        template,
        payloads,
        payload_sets: Vec::new(),
        mode: checks::intruder::IntruderMode::Sniper,
        threads: checks::intruder::DEFAULT_THREADS,
        delay_ms: 0,
    };

    // `intruder::run` spawns its own task via `tokio::spawn`, which needs an
    // active runtime context — `enter()` sets that context without blocking
    // (unlike `block_on`), so the TUI loop keeps going while results stream in.
    let _guard = ctx.rt.enter();
    let rx = checks::intruder::run(cfg, ctx.follow.clone(), None);
    drop(_guard);

    ctx.intruder_state.reset_for_new_run(format!(
        "fuzzing {} ({} payload(s))",
        url, payload_count
    ));
    *ctx.intruder_rx = Some(rx);
    *ctx.output_buffer = format!(
        "⏳ Fuzzing {} — streaming results into Intruder view…",
        url
    );
    *ctx.current_screen = Screen::Intruder;
}

// ── Intruder-Load ─────────────────────────────────────────────────────────────

pub fn intruder_load(ctx: &mut CommandContext<'_>, rest: &str) {
    if rest.is_empty() {
        *ctx.output_buffer = "Usage: Intruder-Load <file>".to_string();
        return;
    }

    match std::fs::read_to_string(rest) {
        Ok(contents) => {
            let marker_count = contents.matches(checks::intruder::MARKER).count();
            let byte_len = contents.len();
            *ctx.loaded_template = Some(contents);
            *ctx.output_buffer = format!(
                "✅ Loaded template from {} ({} bytes, {} {} marker(s))",
                rest, byte_len, marker_count, checks::intruder::MARKER
            );
        }
        Err(e) => {
            *ctx.output_buffer = format!("❌ Failed to read {}: {}", rest, e);
        }
    }
}
