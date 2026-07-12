//! Scan-Site, Scan-Request, Scan-Diff handlers, plus the serialisation
//! helpers that were previously inner functions inside `main`.

use crate::{scanner, workspace};
use crate::styletui::Screen;
use super::CommandContext;

// ── Serialisation helpers (previously inner fns in main) ──────────────────────

/// Parse a severity string as stored in [`workspace::ScanFindingSer`] back
/// into a [`scanner::Severity`] variant.
pub(crate) fn parse_severity_str(s: &str) -> scanner::Severity {
    match s {
        "Critical" => scanner::Severity::Critical,
        "High"     => scanner::Severity::High,
        "Medium"   => scanner::Severity::Medium,
        "Low"      => scanner::Severity::Low,
        _          => scanner::Severity::Info,
    }
}

/// Reconstitute a runtime [`scanner::ScanFinding`] from its serialised mirror.
///
/// Shared by the CLI-arg workspace load in `main`, `Workspace-Load`, and
/// `Scan-Diff` (which rebuilds both sides of the diff from stored snapshots).
pub(crate) fn finding_from_ser(f: &workspace::ScanFindingSer) -> scanner::ScanFinding {
    scanner::ScanFinding {
        check_name:       f.check_name.clone(),
        severity:         parse_severity_str(&f.severity),
        evidence:         f.evidence.clone(),
        request_raw:      f.request_raw.clone(),
        response_snippet: f.response_snippet.clone(),
        url:              f.url.clone(),
        parameter:        f.parameter.clone(),
    }
}

/// Convert a freshly-produced [`scanner::ScanFinding`] into its serialised
/// mirror, for appending to `scan_snapshots`.
pub(crate) fn finding_to_ser(f: &scanner::ScanFinding) -> workspace::ScanFindingSer {
    workspace::ScanFindingSer {
        check_name:       f.check_name.clone(),
        severity:         format!("{:?}", f.severity),
        evidence:         f.evidence.clone(),
        request_raw:      f.request_raw.clone(),
        response_snippet: f.response_snippet.clone(),
        url:              f.url.clone(),
        parameter:        f.parameter.clone(),
    }
}

/// Push a new entry onto `scan_snapshots` for a just-completed scan run,
/// evicting the oldest entry when the list exceeds `workspace::MAX_SCAN_SNAPSHOTS`.
pub(crate) fn record_scan_snapshot(
    scan_snapshots: &mut Vec<workspace::ScanSnapshot>,
    findings: &[scanner::ScanFinding],
) {
    if findings.is_empty() {
        return;
    }
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    scan_snapshots.push(workspace::ScanSnapshot {
        timestamp_ms,
        findings: findings.iter().map(finding_to_ser).collect(),
    });
    if scan_snapshots.len() > workspace::MAX_SCAN_SNAPSHOTS {
        let drop_count = scan_snapshots.len() - workspace::MAX_SCAN_SNAPSHOTS;
        scan_snapshots.drain(0..drop_count);
    }
}

// ── Scan-Site ─────────────────────────────────────────────────────────────────

pub fn scan_site(ctx: &mut CommandContext<'_>, rest: &str) {
    if rest.is_empty() {
        *ctx.output_buffer = "Usage: Scan-Site <domain>".to_string();
        return;
    }

    let domain = rest.to_string();
    *ctx.output_buffer = format!("⏳ Scanning {} (Analyze-Site + active checks)…", domain);

    let result = ctx.rt.block_on(crate::web_analyzer::analyze_site(
        &domain,
        ctx.no_follow,
        ctx.follow,
    ));
    let base_url = result.target_url.clone();

    let vectors = result
        .html_audit
        .as_ref()
        .map(|h| h.attack_vectors.clone())
        .unwrap_or_default();

    if vectors.is_empty() {
        ctx.scanner_state.set_findings(
            Vec::new(),
            format!("{} — no attack vectors found (no forms?)", domain),
        );
        *ctx.output_buffer = format!(
            "⚠️  Analyze-Site found no form-based attack vectors on {}",
            domain
        );
        return;
    }

    // Build one ScanTarget per discovered attack vector.
    // `form_action` may be relative — resolve against the scanned page's URL.
    let skip_types = ["checkbox", "radio", "submit", "button", "file", "image", "reset"];
    for vector in &vectors {
        // Hidden/text/etc. inputs are probeable; others are skipped.
        if skip_types.contains(&vector.input_type.as_str()) {
            continue;
        }
        let action = &vector.form_action;
        let url = if action.starts_with("http://") || action.starts_with("https://") {
            action.clone()
        } else if action == "[No Action Defined]" {
            // No explicit action — the form submits to the page it lives on.
            base_url.clone()
        } else {
            match reqwest::Url::parse(&base_url).and_then(|b| b.join(action)) {
                Ok(joined) => joined.to_string(),
                Err(_)     => base_url.clone(),
            }
        };

        ctx.scan_queue.enqueue(scanner::ScanTarget {
            url,
            method: "GET".to_string(),
            params: vec![(vector.name.clone(), "test".to_string())],
            headers: Vec::new(),
            body: Vec::new(),
        });
    }

    let findings = ctx.rt.block_on(
        ctx.scan_queue.run_all(ctx.scan_checks.clone(), (**ctx.follow).clone()),
    );
    let count = findings.len();
    record_scan_snapshot(ctx.scan_snapshots, &findings);
    ctx.scanner_state.set_findings(
        findings,
        format!("{} — {} finding(s) from {} vector(s)", domain, count, vectors.len()),
    );
    *ctx.output_buffer = format!(
        "✅ Scan complete: {} — {} finding(s) across {} attack vector(s)",
        domain, count, vectors.len()
    );
    *ctx.current_screen = Screen::Scanner;
}

// ── Scan-Request ──────────────────────────────────────────────────────────────

pub fn scan_request(ctx: &mut CommandContext<'_>, rest: &str) {
    match rest.parse::<u64>() {
        Ok(id) => match ctx.history.get(id) {
            Some(record) => {
                // Turn the recorded request's query string (if any) into
                // probeable params.  Bodies/headers are carried over as-is.
                let url = format!("https://{}{}", record.host, record.path);
                let params: Vec<(String, String)> = reqwest::Url::parse(&url)
                    .map(|u| {
                        u.query_pairs()
                            .map(|(k, v)| (k.into_owned(), v.into_owned()))
                            .collect()
                    })
                    .unwrap_or_default();

                ctx.scan_queue.enqueue(scanner::ScanTarget {
                    url,
                    method:  record.method.clone(),
                    params,
                    headers: record.headers.clone(),
                    body:    record.body.clone(),
                });

                let findings = ctx.rt.block_on(
                    ctx.scan_queue.run_all(ctx.scan_checks.clone(), (**ctx.follow).clone()),
                );
                let count = findings.len();
                record_scan_snapshot(ctx.scan_snapshots, &findings);
                ctx.scanner_state.set_findings(
                    findings,
                    format!("history #{} — {} finding(s)", id, count),
                );
                *ctx.output_buffer = format!(
                    "✅ Scan complete: history #{} — {} finding(s)",
                    id, count
                );
                *ctx.current_screen = Screen::Scanner;
            }
            None => {
                *ctx.output_buffer = format!(
                    "❌ No history record with id {} (evicted or never existed)",
                    id
                );
            }
        },
        Err(_) => {
            *ctx.output_buffer = "Usage: Scan-Request <history_id>".to_string();
        }
    }
}

// ── Scan-Diff ─────────────────────────────────────────────────────────────────

pub fn scan_diff(ctx: &mut CommandContext<'_>) {
    if ctx.scan_snapshots.len() < 2 {
        *ctx.output_buffer =
            "Need at least 2 scan snapshots to diff — run Scan-Site/Scan-Request twice.".to_string();
        return;
    }

    let n = ctx.scan_snapshots.len();
    let old: Vec<scanner::ScanFinding> = ctx.scan_snapshots[n - 2]
        .findings
        .iter()
        .map(finding_from_ser)
        .collect();
    let new: Vec<scanner::ScanFinding> = ctx.scan_snapshots[n - 1]
        .findings
        .iter()
        .map(finding_from_ser)
        .collect();
    let diff = scanner::diff_findings(&old, &new);

    let mut text = format!(
        "┌─[ SCAN-DIFF: snapshot #{} vs #{} ]──────────────\n",
        n - 1, n
    );
    text.push_str(&format!("│  New findings ({}):\n", diff.new_findings.len()));
    for f in &diff.new_findings {
        text.push_str(&format!(
            "│    + [{:?}] {} — {} ({})\n",
            f.severity, f.check_name, f.url,
            f.parameter.as_deref().unwrap_or("—")
        ));
    }
    text.push_str(&format!("│  Fixed ({}):\n", diff.fixed_findings.len()));
    for f in &diff.fixed_findings {
        text.push_str(&format!(
            "│    - [{:?}] {} — {} ({})\n",
            f.severity, f.check_name, f.url,
            f.parameter.as_deref().unwrap_or("—")
        ));
    }
    text.push_str(&format!("│  Unchanged ({}):\n", diff.unchanged.len()));
    for f in &diff.unchanged {
        text.push_str(&format!(
            "│    = [{:?}] {} — {} ({})\n",
            f.severity, f.check_name, f.url,
            f.parameter.as_deref().unwrap_or("—")
        ));
    }
    text.push_str("└────────────────────────────────────────────\n");
    *ctx.output_buffer = format!(
        "✅ Scan-Diff: {} new, {} fixed, {} unchanged",
        diff.new_findings.len(), diff.fixed_findings.len(), diff.unchanged.len()
    );
    *ctx.popup_text = text;
    *ctx.popup_scroll = 0;
    *ctx.show_popup = true;
}
