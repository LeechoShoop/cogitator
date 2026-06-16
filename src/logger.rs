//! Structured logging for Cogitator.
//!
//! ## Call sites — unchanged API
//!
//!   logger::init()?;          // once in main(), before spawning tasks
//!   logger::log_event("…");   // INFO
//!   logger::warn("…");        // WARN  (optional upgrade)
//!   logger::error("…");       // ERROR (optional upgrade)
//!   logger::clear_log()?;     // truncate the file
//!
//! ## Output (one JSON object per line in cogitator.log)
//!
//!   {"timestamp":"2024-11-01T14:23:01.123456Z","level":"INFO",
//!    "fields":{"message":"Proxy Guard initialized on 127.0.0.1:8080"},
//!    "target":"cogitator::proxy_guard"}

use std::fs::{File, OpenOptions};
use std::io;
use std::sync::{Arc, Mutex};
use tracing_subscriber::{
    fmt::{self, MakeWriter},
    prelude::*,
    EnvFilter,
};

// ─── Re-opening file writer ───────────────────────────────────────────────────
//
// tracing-subscriber's built-in file writer holds the fd open. If clear_log()
// truncates the file the subscriber keeps writing from the old offset, leaving
// a gap of NUL bytes. Instead we use a writer that re-opens in append mode on
// every call so truncation is seamless.

#[derive(Clone)]
struct AppendWriter {
    path: Arc<str>,
    // Fallback handle used only if re-open fails (e.g. permissions revoked).
    fallback: Arc<Mutex<File>>,
}

impl AppendWriter {
    fn new(path: &str, fallback: File) -> Self {
        Self {
            path: Arc::from(path),
            fallback: Arc::new(Mutex::new(fallback)),
        }
    }
}

// MakeWriter is the trait tracing-subscriber calls to get a Write impl per event.
impl<'a> MakeWriter<'a> for AppendWriter {
    type Writer = AppendFile;

    fn make_writer(&'a self) -> Self::Writer {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path.as_ref())
            .ok();
        AppendFile { file, fallback: self.fallback.clone() }
    }
}

/// Per-event writer returned by AppendWriter.
pub struct AppendFile {
    file: Option<File>,
    fallback: Arc<Mutex<File>>,
}

impl io::Write for AppendFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(ref mut f) = self.file {
            return f.write(buf);
        }
        // Re-open failed — write to the fallback fd (may be at wrong offset
        // after truncation, but at least events aren't silently dropped).
        if let Ok(mut guard) = self.fallback.lock() {
            guard.write(buf)
        } else {
            Ok(buf.len()) // give up silently rather than panic
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(ref mut f) = self.file {
            return f.flush();
        }
        if let Ok(mut guard) = self.fallback.lock() {
            guard.flush()
        } else {
            Ok(())
        }
    }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Initialise the global tracing subscriber.
///
/// Must be called once before any `log_event` / `warn` / `error` calls.
/// Ignores the "subscriber already set" error so double-init is harmless.
pub fn init() -> io::Result<()> {
    let fallback = OpenOptions::new()
        .create(true)
        .append(true)
        .open("cogitator.log")?;

    let writer = AppendWriter::new("cogitator.log", fallback);

    let file_layer = fmt::layer()
        .json()
        .with_timer(tracing_subscriber::fmt::time::SystemTime)
        // Keep the JSON compact: no span ancestry, no ANSI codes.
        .with_current_span(false)
        .with_span_list(false)
        .with_ansi(false)
        .with_writer(writer);

    // Respect RUST_LOG; default to INFO.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    // try_init returns Err if a global subscriber is already set — safe to ignore.
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .try_init();

    Ok(())
}

/// Truncate cogitator.log.
///
/// The subscriber re-opens the file on every event so writing resumes cleanly
/// at offset 0 after truncation.
pub fn clear_log() -> io::Result<()> {
    File::create("cogitator.log")?;
    Ok(())
}

/// Emit an INFO-level structured log event.
///
/// Drop-in replacement for the old freeform string write — every existing
/// `logger::log_event(msg)` call site compiles unchanged.
pub fn log_event(message: &str) {
    tracing::info!(message);
}

/// Emit a WARN-level event.
pub fn warn(message: &str) {
    tracing::warn!(message);
}

/// Emit an ERROR-level event.
pub fn error(message: &str) {
    tracing::error!(message);
}

/// Emit a DEBUG-level event (zero cost unless RUST_LOG=debug).
pub fn debug(message: &str) {
    tracing::debug!(message);
}