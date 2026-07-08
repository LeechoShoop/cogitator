//! Shared plugin API for Cogitator.
//!
//! This is the **single source of truth** for everything a Cogitator plugin
//! can see or produce. Both the main `Cogitator` binary and every external
//! `.so`/`.dll` plugin depend on this crate by exact path or pinned git
//! revision — that's what makes the two sides agree on memory layout.
//!
//! ## Rules for editing this file
//!
//! If you change *anything* that affects memory layout (`RequestRecord`,
//! `ScanFinding`, `Severity`, the trait itself), you **must** bump
//! `PLUGIN_ABI_VERSION` in the same commit and rebuild every external plugin
//! from scratch against the new revision. There is no way around this with
//! a `dlopen`-based plugin model — a stale `.so` with mismatched layout is
//! a memory-safety bug, not a logic error.

use async_trait::async_trait;
use std::time::Instant;

/// Bump whenever anything in this file changes the in-memory shape of the
/// types plugins talk in. Checked by `load_external_plugins` before
/// `cogitator_plugin_create` is ever called — version mismatch → the
/// `.so` is refused, logged, and skipped rather than causing UB.
pub const PLUGIN_ABI_VERSION: u32 = 1;

// ─── Types ──────────────────────────────────────────────────────────────────
//
// Plain re-declarations, kept in lockstep with `history::RequestRecord` and
// `scanner::ScanFinding` in the main crate by hand. If those structs grow a
// new field, mirror it here in the same commit and bump PLUGIN_ABI_VERSION.

#[derive(Debug, Clone)]
pub struct RequestRecord {
    pub id: u64,
    pub timestamp: Instant,
    pub method: String,
    pub host: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub response_status: Option<u16>,
    pub response_headers: Vec<(String, String)>,
    pub response_body: Option<Vec<u8>>,
    pub response_time_ms: Option<u128>,
    pub tags: Vec<String>,
    pub stream_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone)]
pub struct ScanFinding {
    pub check_name: String,
    pub severity: Severity,
    pub evidence: String,
    pub request_raw: String,
    pub response_snippet: String,
    pub url: String,
    pub parameter: Option<String>,
}

// ─── Trait ──────────────────────────────────────────────────────────────────

#[async_trait]
pub trait CogitatorPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;

    async fn on_request(&self, _record: &RequestRecord) -> Vec<ScanFinding> {
        Vec::new()
    }

    async fn on_response(&self, _record: &RequestRecord) -> Vec<ScanFinding> {
        Vec::new()
    }
}

// ─── Export macro ────────────────────────────────────────────────────────────

/// Generates the two `#[no_mangle] extern "C"` symbols every external plugin
/// `.so` must export. Use at the bottom of your plugin crate's `lib.rs`:
///
/// ```ignore
/// cogitator_plugin_api::export_plugin!(MyPlugin::new());
/// ```
#[macro_export]
macro_rules! export_plugin {
    ($ctor:expr) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn cogitator_plugin_abi_version() -> u32 {
            $crate::PLUGIN_ABI_VERSION
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn cogitator_plugin_create() -> *mut dyn $crate::CogitatorPlugin
        {
            ::std::boxed::Box::into_raw(::std::boxed::Box::new($ctor))
        }
    };
}