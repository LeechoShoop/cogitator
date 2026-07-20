//! PDF scan report generator, using `printpdf` (pure Rust — no
//! headless-browser/wkhtmltopdf dependency).
//!
//! This is deliberately a *simpler*, hand-laid-out sibling to
//! `report::generate_html`, not a literal HTML-to-PDF conversion:
//! `printpdf`'s classic layer/text API has no built-in word-wrap or
//! automatic reflow, so getting pixel parity with the HTML report would
//! mean re-implementing a layout engine. Instead this module focuses on
//! the thing that actually matters for a document meant to be handed to
//! someone — **correct pagination**: a cover page with target/date/summary
//! counts, then one section per finding, text wrapped to the page width,
//! and a fresh page started automatically whenever content would run off
//! the bottom margin.
//!
//! # Why plain ASCII
//!
//! Findings are rendered with the standard 14 PDF fonts (Helvetica/
//! Courier), which are **not embedded** — the reader's own PDF viewer
//! supplies the glyphs from its WinAnsi-encoded font, not from Unicode
//! codepoints. `evidence`/`request_raw`/`response_snippet` are
//! attacker-controlled and may contain arbitrary bytes reflected back from
//! the scanned target, so anything outside printable ASCII is replaced
//! with `?` before it's written — the alternative (writing raw UTF-8 bytes
//! through a single-byte WinAnsi font) produces silently garbled text
//! rather than a decode error, which is worse.
//!
//! # Dependency
//!
//! Requires the `printpdf` crate. Pin an exact version in `Cargo.toml` —
//! this module was written against, and tested with, `printpdf = "=0.7.0"`:
//!
//! ```toml
//! printpdf = "=0.7.0"
//! ```
//!
//! `printpdf`'s classic (pre-0.8) layer API has stayed source-compatible
//! across the 0.4–0.7 line for everything used here (`PdfDocument::new`,
//! `add_builtin_font`, `add_page`, `get_page`/`get_layer`,
//! `begin_text_section`/`set_font`/`set_text_cursor`/`write_text`/
//! `end_text_section`, `save`), but pin the version anyway — 0.8+
//! restructured the crate around an `Op`-based content model and is not
//! source-compatible with the calls below.

use std::io::{BufWriter, Cursor};

use printpdf::{BuiltinFont, IndirectFontRef, Mm, PdfDocument, PdfDocumentReference, PdfLayerReference};

use crate::report::{self, ReportMeta};
use crate::report::format::format_timestamp;
use crate::scanner::ScanFinding;

// ─── Page geometry ──────────────────────────────────────────────────────────

const PAGE_WIDTH_MM: f32 = 210.0; // A4
const PAGE_HEIGHT_MM: f32 = 297.0;
const MARGIN_MM: f32 = 18.0;
const CONTENT_WIDTH_MM: f32 = PAGE_WIDTH_MM - 2.0 * MARGIN_MM;

/// 1 PDF point = 1/72 inch = 0.352778 mm.
const MM_PER_PT: f32 = 0.352778;

// Font sizes, in points. printpdf's `set_font` takes the size as `f32` in
// the pinned 0.7.0 API (an earlier draft of this module assumed an integer
// size — that was wrong; fixed after `cargo build` caught the mismatch).
const SIZE_TITLE: f32 = 22.0;
const SIZE_H1: f32 = 14.0;
const SIZE_H2: f32 = 11.0;
const SIZE_BODY: f32 = 10.0;
const SIZE_MONO: f32 = 9.0;

/// Render `findings` + `meta` into a complete PDF document and return its
/// bytes (caller writes them to disk — see `Report-Generate-Pdf` in
/// `main.rs`).
pub fn generate_pdf(findings: &[ScanFinding], meta: &ReportMeta) -> Result<Vec<u8>, String> {
    let (doc, page1, layer1) = PdfDocument::new(
        "Cogitator Scan Report",
        Mm(PAGE_WIDTH_MM),
        Mm(PAGE_HEIGHT_MM),
        "Layer 1",
    );

    let helvetica = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| format!("failed to add Helvetica: {:?}", e))?;
    let helvetica_bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| format!("failed to add Helvetica-Bold: {:?}", e))?;
    let courier = doc
        .add_builtin_font(BuiltinFont::Courier)
        .map_err(|e| format!("failed to add Courier: {:?}", e))?;

    let fonts = Fonts {
        regular: helvetica,
        bold: helvetica_bold,
        mono: courier,
    };

    let first_layer = doc.get_page(page1).get_layer(layer1);
    let mut cur = Cursor2 {
        doc,
        layer: first_layer,
        y: PAGE_HEIGHT_MM - MARGIN_MM,
        page_count: 1,
    };

    render_cover_page(&mut cur, &fonts, findings, meta);

    for sev in report::SEVERITY_ORDER {
        let group: Vec<&ScanFinding> = findings.iter().filter(|f| f.severity == sev).collect();
        if group.is_empty() {
            continue;
        }

        cur.gap(6.0);
        cur.ensure_room(line_height_mm(SIZE_H1) + 4.0);
        cur.line(
            &format!("== {} ({}) ==", report::severity_label(sev), group.len()),
            &fonts.bold,
            SIZE_H1,
            0.0,
        );
        cur.gap(2.0);

        for f in &group {
            render_finding(&mut cur, &fonts, f);
        }
    }

    // printpdf's `save` requires a `BufWriter` specifically (not just any
    // `Write`) — buffered output has been enforced since the 0.2.0 release,
    // per the crate's changelog. `BufWriter::into_inner` itself returns a
    // `Result` (it flushes first, which can fail), so unwrapping down to
    // the final `Vec<u8>` is two steps: `BufWriter` -> `Cursor<Vec<u8>>` ->
    // `Vec<u8>`.
    let mut buf = BufWriter::new(Cursor::new(Vec::<u8>::new()));
    cur.doc
        .save(&mut buf)
        .map_err(|e| format!("failed to serialise PDF: {}", e))?;
    let cursor = buf
        .into_inner()
        .map_err(|e| format!("failed to flush PDF buffer: {}", e))?;
    Ok(cursor.into_inner())
}

// ─── Fonts ──────────────────────────────────────────────────────────────────

struct Fonts {
    regular: IndirectFontRef,
    bold: IndirectFontRef,
    mono: IndirectFontRef,
}

// ─── Pagination cursor ──────────────────────────────────────────────────────

/// Tracks the current page/layer and vertical write position, and starts a
/// fresh page whenever the next line would run past the bottom margin.
/// Named `Cursor2` (rather than `Cursor`) purely to avoid clashing with
/// `std::io::Cursor`, which `generate_pdf` also uses for the final byte
/// buffer.
///
/// Owns the `PdfDocumentReference` (moved in once, handed back out via
/// `cur.doc` at the end for `.save()`) rather than borrowing it — avoids
/// threading a lifetime parameter through every function that touches a
/// `Cursor2`. `add_page`/`get_page` take `&self` (the document is
/// internally `Rc<RefCell<...>>`-backed), so owning the handle here doesn't
/// prevent calling them.
struct Cursor2 {
    doc: PdfDocumentReference,
    layer: PdfLayerReference,
    y: f32,
    page_count: usize,
}

impl Cursor2 {
    /// Start a new page, resetting the write position to the top margin.
    fn new_page(&mut self) {
        self.page_count += 1;
        let (page_idx, layer_idx) = self.doc.add_page(
            Mm(PAGE_WIDTH_MM),
            Mm(PAGE_HEIGHT_MM),
            format!("Page {}", self.page_count),
        );
        self.layer = self.doc.get_page(page_idx).get_layer(layer_idx);
        self.y = PAGE_HEIGHT_MM - MARGIN_MM;
    }

    /// Guarantee at least `needed_mm` of vertical room below the current
    /// position, starting a new page first if there isn't enough.
    fn ensure_room(&mut self, needed_mm: f32) {
        if self.y - needed_mm < MARGIN_MM {
            self.new_page();
        }
    }

    /// Move the cursor down by `mm` without writing anything (paragraph
    /// spacing). Starts a new page if this would run off the bottom.
    fn gap(&mut self, mm: f32) {
        self.ensure_room(mm);
        self.y -= mm;
    }

    /// Draw one line of (already-short-enough-to-fit) text at `indent_mm`
    /// from the left margin, then advance the cursor down by its line
    /// height. Each call is a fully self-contained text section — slightly
    /// less efficient than batching multiple lines into one
    /// `begin_text_section`/`end_text_section` pair, but it means every
    /// line's position is set explicitly rather than relying on
    /// `add_line_break` (whose exact line-height math printpdf derives
    /// from `set_line_height`), which keeps this robust across minor
    /// version differences in that derivation.
    fn line(&mut self, text: &str, font: &IndirectFontRef, size: f32, indent_mm: f32) {
        let lh = line_height_mm(size);
        self.ensure_room(lh);
        let x = MARGIN_MM + indent_mm;
        self.layer.begin_text_section();
        self.layer.set_font(font, size);
        self.layer.set_text_cursor(Mm(x), Mm(self.y));
        self.layer.write_text(sanitize_for_pdf(text), font);
        self.layer.end_text_section();
        self.y -= lh;
    }

    /// Word-wrap `text` to fit `CONTENT_WIDTH_MM - indent_mm` and draw it
    /// as one or more lines via [`Self::line`], paginating as needed. Uses
    /// the proportional-font (Helvetica-ish) width estimate — see
    /// [`Self::wrapped_mono`] for fixed-width text.
    fn wrapped(&mut self, text: &str, font: &IndirectFontRef, size: f32, indent_mm: f32) {
        let width = (CONTENT_WIDTH_MM - indent_mm).max(20.0);
        let max_chars = max_chars_for_width(width, size, 0.5);
        for line in wrap_text(&sanitize_for_pdf(text), max_chars) {
            self.line(&line, font, size, indent_mm);
        }
    }
}

/// Line height in mm for a given font size in points: size × leading
/// factor × mm-per-pt. 1.15 leading is a reasonable single-spaced default
/// for body text without measured font metrics.
fn line_height_mm(size_pt: f32) -> f32 {
    size_pt * 1.15 * MM_PER_PT
}

/// How many characters fit in `width_mm` at `size_pt`, given
/// `avg_char_width_factor` (fraction of font size a glyph occupies on
/// average). Floors to be conservative; never returns less than 10 so a
/// pathologically narrow column still makes forward progress instead of
/// wrapping every single character.
fn max_chars_for_width(width_mm: f32, size_pt: f32, avg_char_width_factor: f32) -> usize {
    let avg_char_width_mm = size_pt * avg_char_width_factor * MM_PER_PT;
    if avg_char_width_mm <= 0.0 {
        return 10;
    }
    ((width_mm / avg_char_width_mm).floor() as usize).max(10)
}

/// Greedy word-wrap: pack whitespace-separated words onto each line up to
/// `max_chars`; a single word longer than `max_chars` is hard-broken rather
/// than left to overflow. Empty input yields an empty Vec (caller just
/// skips drawing anything for a blank field).
fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    let max_chars = max_chars.max(1);
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        let mut word = word;
        loop {
            let sep_len = if current.is_empty() { 0 } else { 1 };
            if current.len() + sep_len + word.len() <= max_chars {
                if sep_len == 1 {
                    current.push(' ');
                }
                current.push_str(word);
                break;
            }
            if word.len() > max_chars {
                // Hard-break: fill out the current line with as much of
                // this word as fits, flush it, and continue wrapping the
                // remainder as if it were a new "word".
                let room = max_chars.saturating_sub(current.len() + sep_len);
                if room == 0 {
                    lines.push(std::mem::take(&mut current));
                    continue;
                }
                if sep_len == 1 {
                    current.push(' ');
                }
                let (head, tail) = word.split_at(room.min(word.len()));
                current.push_str(head);
                lines.push(std::mem::take(&mut current));
                word = tail;
                if word.is_empty() {
                    break;
                }
                continue;
            }
            // Word fits on its own line, just not this one — flush and retry.
            lines.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// Replace anything outside printable ASCII with `?`. See module docs for
/// why this matters with non-embedded builtin fonts. Newlines/tabs become
/// single spaces so a multi-line evidence blob collapses into the flowed
/// paragraph `wrapped` expects, rather than each line being written on top
/// of the previous one.
fn sanitize_for_pdf(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\n' | '\r' | '\t' => ' ',
            c if (c as u32) >= 0x20 && (c as u32) < 0x7F => c,
            _ => '?',
        })
        .collect()
}

// ─── Page content ───────────────────────────────────────────────────────────

fn render_cover_page(
    cur: &mut Cursor2,
    fonts: &Fonts,
    findings: &[ScanFinding],
    meta: &ReportMeta,
) {
    cur.line("Cogitator Scan Report", &fonts.bold, SIZE_TITLE, 0.0);
    cur.gap(8.0);

    cur.line(&format!("Target: {}", meta.domain), &fonts.regular, SIZE_BODY, 0.0);
    cur.line(
        &format!("Generated: {} UTC", format_timestamp(meta.timestamp_ms)),
        &fonts.regular,
        SIZE_BODY,
        0.0,
    );
    cur.line(
        &format!("Total findings: {}", findings.len()),
        &fonts.regular,
        SIZE_BODY,
        0.0,
    );
    cur.gap(6.0);

    cur.line("Findings by severity:", &fonts.bold, SIZE_H2, 0.0);
    for sev in report::SEVERITY_ORDER {
        let count = findings.iter().filter(|f| f.severity == sev).count();
        cur.line(
            &format!("{:<10} {}", report::severity_label(sev), count),
            &fonts.mono,
            SIZE_BODY,
            4.0,
        );
    }

    // Cover page always ends its own page — everything after this starts
    // fresh so the severity sections don't share a page with the summary.
    cur.new_page();
}

fn render_finding(cur: &mut Cursor2, fonts: &Fonts, f: &ScanFinding) {
    cur.ensure_room(line_height_mm(SIZE_H2) * 2.0);
    cur.line(&f.check_name, &fonts.bold, SIZE_H2, 0.0);
    cur.wrapped(&f.url, &fonts.regular, SIZE_BODY, 4.0);

    let parameter = f.parameter.as_deref().unwrap_or("-");
    cur.line(&format!("Parameter: {}", parameter), &fonts.regular, SIZE_BODY, 4.0);

    cur.line("Evidence:", &fonts.regular, SIZE_BODY, 4.0);
    cur.wrapped_mono(&f.evidence, &fonts.mono, 8.0);

    cur.line("Request:", &fonts.regular, SIZE_BODY, 4.0);
    cur.wrapped_mono(&f.request_raw, &fonts.mono, 8.0);

    cur.line("Response snippet:", &fonts.regular, SIZE_BODY, 4.0);
    cur.wrapped_mono(&f.response_snippet, &fonts.mono, 8.0);

    cur.gap(4.0);
}

impl Cursor2 {
    /// Like `wrapped`, but uses Courier's (monospace) width factor instead
    /// of the proportional-font estimate — noticeably more accurate for
    /// fixed-width text since every glyph really is the same width.
    fn wrapped_mono(&mut self, text: &str, font: &IndirectFontRef, indent_mm: f32) {
        let width = (CONTENT_WIDTH_MM - indent_mm).max(20.0);
        let max_chars = max_chars_for_width(width, SIZE_MONO, 0.6);
        if text.is_empty() {
            self.line("(empty)", font, SIZE_MONO, indent_mm);
            return;
        }
        for line in wrap_text(&sanitize_for_pdf(text), max_chars) {
            self.line(&line, font, SIZE_MONO, indent_mm);
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Severity;

    // ── Pure logic: word-wrap, sanitisation, sizing math ─────────────────
    // (No printpdf calls here — these don't need a real document.)

    #[test]
    fn wrap_text_packs_words_up_to_limit() {
        let lines = wrap_text("the quick brown fox jumps", 11);
        assert_eq!(lines, vec!["the quick", "brown fox", "jumps"]);
    }

    #[test]
    fn wrap_text_hard_breaks_overlong_word() {
        let lines = wrap_text("supercalifragilisticexpialidocious", 10);
        assert!(lines.iter().all(|l| l.len() <= 10));
        assert_eq!(lines.join(""), "supercalifragilisticexpialidocious");
    }

    #[test]
    fn wrap_text_empty_input_yields_no_lines() {
        assert!(wrap_text("", 20).is_empty());
        assert!(wrap_text("   ", 20).is_empty());
    }

    #[test]
    fn sanitize_replaces_non_ascii_with_question_mark() {
        let out = sanitize_for_pdf("héllo — wörld");
        assert!(out.chars().all(|c| (c as u32) < 0x7F));
        assert!(out.contains('?'));
    }

    #[test]
    fn sanitize_collapses_newlines_and_tabs_to_space() {
        let out = sanitize_for_pdf("line1\nline2\tline3");
        assert!(!out.contains('\n'));
        assert!(!out.contains('\t'));
        assert_eq!(out, "line1 line2 line3");
    }

    #[test]
    fn max_chars_for_width_respects_floor_of_ten() {
        // Absurdly small width/large font would compute below 10 — the
        // floor should still kick in.
        assert_eq!(max_chars_for_width(5.0, 72.0, 0.5), 10);
    }

    #[test]
    fn max_chars_for_width_scales_inversely_with_font_size() {
        let small = max_chars_for_width(100.0, 8.0, 0.5);
        let large = max_chars_for_width(100.0, 16.0, 0.5);
        assert!(small > large);
    }

    // ── End-to-end: a real PDF actually comes out ────────────────────────

    fn finding(sev: Severity) -> ScanFinding {
        ScanFinding {
            check_name: "SQL Injection (error-based)".to_string(),
            severity: sev,
            evidence: "You have an error in your SQL syntax near line 1".to_string(),
            request_raw: "GET /search?q=1' HTTP/1.1".to_string(),
            response_snippet: "Warning: mysql_fetch_array() expects parameter 1".to_string(),
            url: "http://example.com/search?q=1".to_string(),
            parameter: Some("q".to_string()),
        }
    }

    #[test]
    fn generates_a_valid_pdf_header() {
        let findings = vec![finding(Severity::Critical)];
        let meta = ReportMeta { domain: "example.com".to_string(), timestamp_ms: 1_700_000_000_000 };
        let bytes = generate_pdf(&findings, &meta).expect("pdf generation should succeed");
        assert!(bytes.starts_with(b"%PDF-"));
    }

    #[test]
    fn handles_empty_findings_without_error() {
        let meta = ReportMeta { domain: "example.com".to_string(), timestamp_ms: 0 };
        let bytes = generate_pdf(&[], &meta).expect("empty findings should still produce a cover page");
        assert!(bytes.starts_with(b"%PDF-"));
    }

    #[test]
    fn many_findings_paginate_without_panicking() {
        // Enough findings, each with long fields, to force several page
        // breaks — this is the actual behaviour under test, more than the
        // byte content (we can't easily assert page count without a PDF
        // parser, but a panic-free run through pagination is most of the
        // risk this module carries).
        let mut findings = Vec::new();
        for i in 0..40 {
            let mut f = finding(Severity::High);
            f.evidence = format!("finding number {i}: {}", "x".repeat(300));
            f.request_raw = "y".repeat(500);
            findings.push(f);
        }
        let meta = ReportMeta { domain: "example.com".to_string(), timestamp_ms: 1_700_000_000_000 };
        let bytes = generate_pdf(&findings, &meta).expect("large report should still generate");
        assert!(bytes.starts_with(b"%PDF-"));
        assert!(bytes.len() > 1000);
    }
}