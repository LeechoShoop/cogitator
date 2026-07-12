//! Workspace-Save, Workspace-Load, Workspace-New handlers.

use crate::{config, logger, workspace};
use super::CommandContext;
use super::scan::finding_from_ser;

// ── Workspace-Save ────────────────────────────────────────────────────────────

pub fn workspace_save(ctx: &mut CommandContext<'_>, rest: &str) {
    let path = if rest.is_empty() {
        workspace::LAST_WORKSPACE_FILE.to_string()
    } else {
        rest.to_string()
    };
    let ws = workspace::WorkspaceData::capture(
        config::PROXY_ADDR,
        ctx.scope,
        ctx.history,
        &ctx.scanner_state.findings,
        ctx.scan_snapshots,
        ctx.repeater,
        ctx.profile_store,
    );
    match ws.save(&path) {
        Ok(_) => {
            *ctx.output_buffer = format!("✅ Workspace saved to '{}'", path);
            logger::log_event(&format!("Workspace saved to {}", path));
        }
        Err(e) => {
            *ctx.output_buffer = format!("❌ Workspace-Save failed: {}", e);
        }
    }
}

// ── Workspace-Load ────────────────────────────────────────────────────────────

pub fn workspace_load(ctx: &mut CommandContext<'_>, rest: &str) {
    if rest.is_empty() {
        *ctx.output_buffer = "Usage: Workspace-Load <file.cogitator>".to_string();
        return;
    }
    match workspace::WorkspaceData::load(rest) {
        Ok(ws) => {
            let (findings_ser, snaps) = ws.restore(
                ctx.scope,
                ctx.history,
                ctx.repeater,
                ctx.profile_store,
            );
            *ctx.scan_snapshots = snaps;
            let restored_findings: Vec<crate::scanner::ScanFinding> =
                findings_ser.iter().map(finding_from_ser).collect();
            let count = restored_findings.len();
            ctx.scanner_state.set_findings(
                restored_findings,
                format!("restored from {}", rest),
            );
            *ctx.output_buffer = format!(
                "✅ Workspace loaded from '{}' ({} finding(s) restored)",
                rest, count
            );
            logger::log_event(&format!("Workspace loaded from {}", rest));
            *ctx.scroll_offset = 0;
        }
        Err(e) => {
            *ctx.output_buffer = format!(
                "❌ Workspace-Load '{}' failed: {}",
                rest, e
            );
        }
    }
}

// ── Workspace-New ─────────────────────────────────────────────────────────────

pub fn workspace_new(ctx: &mut CommandContext<'_>) {
    // Reset all in-memory state back to blank.
    ctx.scope.lock().unwrap().clear();
    ctx.history.clear();
    for tab in ctx.repeater.get_tabs() {
        ctx.repeater.close_tab(tab.id);
    }
    ctx.scanner_state.set_findings(Vec::new(), "workspace reset");
    ctx.scan_snapshots.clear();
    *ctx.output_buffer = "✅ Workspace-New: all state cleared.".to_string();
    *ctx.scroll_offset = 0;
}
