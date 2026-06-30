//! Plugin system for Cogitator.
//!
//! A `CogitatorPlugin` gets a read-only look at every completed proxy
//! exchange (`RequestRecord`, request *and* response fields already
//! populated — see `proxy_guard::record_exchange`) and may emit
//! `ScanFinding`s, exactly as if a `ScanCheck` had found them. This is the
//! passive-analysis counterpart to `scanner::ScanCheck`: checks run
//! on-demand against a queued target; plugins run automatically against
//! every exchange that passes through the proxy, with no explicit
//! `Scan-Site` trigger needed.
//!
//! Three ways a plugin ends up registered:
//!   1. Built into this binary, self-registering via the `inventory` crate
//!      (see `inventory_glue` below) — zero wiring in `main.rs` beyond
//!      calling `PluginRegistry::with_builtins()`.
//!   2. Constructed by hand and passed to `PluginRegistry::register`.
//!   3. (Optional, feature-gated) Loaded at startup from a `.so`/`.dll` in
//!      `./plugins/` via `load_external_plugins` — see the safety notes on
//!      that function before using it.

use crate::history::RequestRecord;
use crate::logger;
use crate::scanner::ScanFinding;
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

// ─── Plugin trait ─────────────────────────────────────────────────────────────

/// A passive analysis plugin.
///
/// Implementors should be cheap to hold (state behind `Arc`/`Mutex` if any
/// is needed) since a single instance is shared across every connection via
/// `PluginRegistry`. Both hooks default to "no findings" so a plugin that
/// only cares about one side of the exchange doesn't have to write an empty
/// body for the other.
#[async_trait]
pub trait CogitatorPlugin: Send + Sync {
    /// Short, stable identifier shown in logs and in `Plugin-List`.
    fn name(&self) -> &str;

    /// One-line human-readable description of what this plugin looks for.
    fn description(&self) -> &str;

    /// Inspect the request side of a completed exchange (method, host,
    /// path, request headers — see `RequestRecord`). The response fields
    /// on `record` are already populated by the time this runs (plugins
    /// fire once per completed exchange, not mid-flight), but a plugin
    /// whose logic is purely request-shaped should ignore them here and
    /// let `on_response` stay empty, or vice versa — the split exists so a
    /// plugin author can reason about "which side of this exchange matched"
    /// without re-deriving it from one big method every time.
    async fn on_request(&self, _record: &RequestRecord) -> Vec<ScanFinding> {
        Vec::new()
    }

    /// Inspect the response side of a completed exchange (status, response
    /// headers, response body).
    async fn on_response(&self, _record: &RequestRecord) -> Vec<ScanFinding> {
        Vec::new()
    }
}

// ─── Registry ─────────────────────────────────────────────────────────────────

/// Ordered collection of registered plugins.
///
/// Not `Clone` — wrap in `Arc` (as `main.rs` does) to share a single
/// registry across every connection task in the proxy pipeline. Plugins
/// themselves are `Send + Sync` so the registry can be invoked concurrently
/// from multiple connections without additional locking.
pub struct PluginRegistry(Vec<Box<dyn CogitatorPlugin>>);

impl PluginRegistry {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Register a plugin. Order of registration is preserved and is the
    /// order plugins run in for both hooks.
    pub fn register(&mut self, plugin: Box<dyn CogitatorPlugin>) {
        logger::log_event(&format!("Plugin registered: {}", plugin.name()));
        self.0.push(plugin);
    }

    /// `(name, description)` for every registered plugin, in registration
    /// order — for a `Plugin-List` TUI command.
    pub fn list(&self) -> Vec<(String, String)> {
        self.0
            .iter()
            .map(|p| (p.name().to_string(), p.description().to_string()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Build a registry pre-populated with every plugin that self-registered
    /// via `inventory::submit! { PluginFactory(...) }` (see
    /// `inventory_glue` below). This is what `main.rs` should call to pick
    /// up built-in plugins with no per-plugin wiring.
    pub fn with_builtins() -> Self {
        let mut registry = Self::new();
        for factory in inventory::iter::<inventory_glue::PluginFactory> {
            registry.register((factory.0)());
        }
        registry
    }

    /// Run every registered plugin's `on_request` against `record`,
    /// concurrently, and return the combined findings.
    pub async fn run_on_request(&self, record: &RequestRecord) -> Vec<ScanFinding> {
        self.run_hook(record, Hook::Request).await
    }

    /// Same as `run_on_request`, for the `on_response` hook.
    pub async fn run_on_response(&self, record: &RequestRecord) -> Vec<ScanFinding> {
        self.run_hook(record, Hook::Response).await
    }

    async fn run_hook(&self, record: &RequestRecord, hook: Hook) -> Vec<ScanFinding> {
        if self.0.is_empty() {
            return Vec::new();
        }

        // Plugins run concurrently (each may do its own I/O — e.g. an
        // external threat-intel lookup) rather than one-at-a-time; a slow
        // plugin shouldn't serialize behind every other plugin on every
        // single exchange. `record` is borrowed for the duration of the
        // join rather than cloned per-plugin, since `RequestRecord` can
        // carry a full response body and cloning it N times per exchange
        // would be wasteful.
        let futures = self.0.iter().map(|plugin| {
            let plugin = plugin.as_ref();
            async move {
                match hook {
                    Hook::Request => plugin.on_request(record).await,
                    Hook::Response => plugin.on_response(record).await,
                }
            }
        });

        let results: Vec<Vec<ScanFinding>> = futures_join_all(futures).await;
        results.into_iter().flatten().collect()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
enum Hook {
    Request,
    Response,
}

/// Minimal stand-in for `futures::future::join_all` so this module doesn't
/// need to pull in the full `futures` crate for one function. Awaits every
/// future in `iter` to completion, preserving order. Fine for the plugin
/// counts a terminal tool like Cogitator will realistically have (a
/// handful, not thousands) — if that ever changes, swap this for
/// `futures::future::join_all` plus a `Semaphore` like `scanner::run_all`.
async fn futures_join_all<F, T>(iter: impl IntoIterator<Item = F>) -> Vec<T>
where
    F: std::future::Future<Output = T>,
{
    let mut out = Vec::new();
    for fut in iter {
        out.push(fut.await);
    }
    out
}

// ─── Shared findings sink ────────────────────────────────────────────────────

/// Thread-safe accumulator for findings produced by plugins while the proxy
/// is running. Cheap to clone (shares the underlying `Vec` via `Arc`) — hand
/// a clone into the proxy pipeline (`proxy_guard::start_proxy`) and keep the
/// original in `main.rs`'s TUI loop, draining it on each tick the same way
/// `spider`/`intruder` results get drained from their channels.
#[derive(Clone)]
pub struct PluginFindingsSink(Arc<Mutex<Vec<ScanFinding>>>);

impl PluginFindingsSink {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    /// Append findings produced by one exchange. No-op if `findings` is
    /// empty (avoids taking the lock for the common case where nothing
    /// fired).
    pub fn push_all(&self, findings: Vec<ScanFinding>) {
        if findings.is_empty() {
            return;
        }
        self.0.lock().unwrap().extend(findings);
    }

    /// Drain everything accumulated so far, leaving the sink empty. Call
    /// this once per TUI tick (or whenever findings should be folded into
    /// `ScannerState`) — findings pushed *during* the drain are simply
    /// picked up on the next call, not lost.
    pub fn drain(&self) -> Vec<ScanFinding> {
        let mut guard = self.0.lock().unwrap();
        std::mem::take(&mut *guard)
    }

    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for PluginFindingsSink {
    fn default() -> Self {
        Self::new()
    }
}

// ─── inventory glue (built-in, self-registering plugins) ────────────────────

/// `cargo add inventory` is required for this module to compile.
///
/// A built-in plugin registers itself with:
///
/// ```ignore
/// inventory::submit! {
///     crate::plugin::inventory_glue::PluginFactory(|| Box::new(MyPlugin::new()))
/// }
/// ```
///
/// anywhere in the crate (conventionally right next to the plugin's
/// `struct`/`impl CogitatorPlugin` block). `PluginRegistry::with_builtins()`
/// then picks it up automatically with no edit to `main.rs` needed per
/// plugin.
pub mod inventory_glue {
    use super::CogitatorPlugin;

    /// A function pointer that constructs one plugin instance. Wrapped in a
    /// tuple struct (rather than registering `Box<dyn CogitatorPlugin>`
    /// directly) because `inventory` items must be `'static` plain data
    /// collected at link time — a constructor function pointer satisfies
    /// that even though the trait object it produces does not need to.
    pub struct PluginFactory(pub fn() -> Box<dyn CogitatorPlugin>);

    inventory::collect!(PluginFactory);
}

// ─── Example built-in plugin ─────────────────────────────────────────────────

/// Flags responses that leak a versioned `X-Powered-By` header — kept here
/// as a minimal worked example of the plugin shape (self-registers via
/// `inventory::submit!` below), not because this particular check is
/// especially valuable on its own.
pub struct StackBannerLeakPlugin;

#[async_trait]
impl CogitatorPlugin for StackBannerLeakPlugin {
    fn name(&self) -> &str {
        "stack-banner-leak"
    }

    fn description(&self) -> &str {
        "Flags responses with a versioned X-Powered-By header"
    }

    async fn on_response(&self, record: &RequestRecord) -> Vec<ScanFinding> {
        let Some(value) = record
            .response_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-powered-by"))
            .map(|(_, v)| v.clone())
        else {
            return Vec::new();
        };

        // Only flag it if it looks versioned (contains a digit) -- a bare
        // "PHP" or "Express" with no version is far lower signal than
        // "PHP/7.2.3".
        if !value.chars().any(|c| c.is_ascii_digit()) {
            return Vec::new();
        }

        vec![ScanFinding {
            check_name: "Stack Banner Leak (X-Powered-By)".to_string(),
            severity: crate::scanner::Severity::Low,
            evidence: format!("X-Powered-By: {}", value),
            request_raw: format!("{} {}{}", record.method, record.host, record.path),
            response_snippet: String::new(),
            url: format!("{}{}", record.host, record.path),
            parameter: None,
        }]
    }
}

inventory::submit! {
    inventory_glue::PluginFactory(|| Box::new(StackBannerLeakPlugin))
}

// ─── External .so/.dll plugins (optional) ────────────────────────────────────

/// Load external plugins from `.so` (Linux) / `.dll` (Windows) / `.dylib`
/// (macOS) files in `dir`, returning everything that loaded successfully.
/// Failures (missing dir, bad library, missing symbol) are logged and
/// skipped per-file rather than aborting startup — one broken plugin
/// shouldn't take the proxy down.
///
/// # Safety / trust model
///
/// This calls `dlopen`/`LoadLibrary` on arbitrary files and then invokes a
/// function pointer pulled out of them — `libloading` itself can't make
/// that safe, only ergonomic. Only point `dir` at plugin files you (or
/// someone you trust) built against this exact Cogitator version: the
/// external `.so` and this binary must agree on `RequestRecord`'s and
/// `ScanFinding`'s memory layout, which is **not** guaranteed across Rust
/// compiler versions or even across two builds of the same source with
/// different dependency versions (no `#[repr(C)]`, no stable ABI). A
/// mismatched plugin is a memory-safety bug, not a "returns wrong data"
/// bug. Treat `./plugins/` the same way you'd treat a directory of binaries
/// you're about to execute, because that's effectively what this is.
///
/// Each plugin library must export:
///
/// ```ignore
/// #[no_mangle]
/// pub extern "C" fn cogitator_plugin_create() -> *mut dyn CogitatorPlugin {
///     Box::into_raw(Box::new(MyPlugin::new()))
/// }
/// ```
///
/// `cargo add libloading` and enable the `external_plugins` feature (see
/// `Cargo.toml` note in the chat) before enabling this — it is not wired
/// into `with_builtins()` and must be called explicitly from `main.rs`.
#[cfg(feature = "external_plugins")]
pub fn load_external_plugins(dir: &std::path::Path) -> Vec<Box<dyn CogitatorPlugin>> {
    use libloading::{Library, Symbol};

    let mut loaded = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            logger::debug(&format!(
                "plugin: external plugin dir {:?} not readable ({e}) -- skipping",
                dir
            ));
            return loaded;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let is_lib = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| matches!(e, "so" | "dll" | "dylib"))
            .unwrap_or(false);
        if !is_lib {
            continue;
        }

        // SAFETY: see the function-level safety note above -- `dir` is
        // expected to contain only plugins built against this exact
        // Cogitator version by a trusted party. Library::new performs the
        // actual dlopen/LoadLibrary call.
        let lib = match unsafe { Library::new(&path) } {
            Ok(l) => l,
            Err(e) => {
                logger::warn(&format!("plugin: failed to load {:?}: {e}", path));
                continue;
            }
        };

        // SAFETY: trusting that a library matching the documented export
        // contract above actually exports a function with this exact
        // signature under this exact symbol name. Loading the wrong shape
        // here is undefined behaviour, not a recoverable error.
        let create: Symbol<unsafe extern "C" fn() -> *mut dyn CogitatorPlugin> =
            match unsafe { lib.get(b"cogitator_plugin_create\0") } {
                Ok(s) => s,
                Err(e) => {
                    logger::warn(&format!(
                        "plugin: {:?} has no cogitator_plugin_create symbol: {e}",
                        path
                    ));
                    continue;
                }
            };

        // SAFETY: trusting the loaded function actually returns a
        // validly-constructed Box::into_raw'd trait object, per the
        // export contract.
        let raw = unsafe { create() };
        if raw.is_null() {
            logger::warn(&format!(
                "plugin: {:?} cogitator_plugin_create returned null",
                path
            ));
            continue;
        }
        let plugin = unsafe { Box::from_raw(raw) };

        logger::log_event(&format!("plugin: loaded external plugin from {:?}", path));
        loaded.push(plugin);

        // Deliberately leak `lib` (Library) rather than dropping it: if we
        // unload the .so while `plugin`'s vtable still points into it,
        // every call through `plugin` becomes a dangling-pointer call.
        // Plugins live for the process lifetime, so this is the correct
        // tradeoff, not an oversight.
        std::mem::forget(lib);
    }

    loaded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Severity;
    use std::time::Instant;

    fn sample_record() -> RequestRecord {
        RequestRecord {
            id: 1,
            timestamp: Instant::now(),
            method: "GET".to_string(),
            host: "example.com".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
            response_status: Some(200),
            response_headers: Vec::new(),
            response_body: None,
            response_time_ms: Some(10),
            tags: Vec::new(),
            stream_id: None,
        }
    }

    struct AlwaysFindsOnRequest;

    #[async_trait]
    impl CogitatorPlugin for AlwaysFindsOnRequest {
        fn name(&self) -> &str {
            "always-finds-on-request"
        }
        fn description(&self) -> &str {
            "test plugin: always emits one finding from on_request"
        }
        async fn on_request(&self, record: &RequestRecord) -> Vec<ScanFinding> {
            vec![ScanFinding {
                check_name: self.name().to_string(),
                severity: Severity::Info,
                evidence: "test".to_string(),
                request_raw: String::new(),
                response_snippet: String::new(),
                url: record.host.clone(),
                parameter: None,
            }]
        }
    }

    struct AlwaysFindsOnResponse;

    #[async_trait]
    impl CogitatorPlugin for AlwaysFindsOnResponse {
        fn name(&self) -> &str {
            "always-finds-on-response"
        }
        fn description(&self) -> &str {
            "test plugin: always emits one finding from on_response"
        }
        async fn on_response(&self, record: &RequestRecord) -> Vec<ScanFinding> {
            vec![ScanFinding {
                check_name: self.name().to_string(),
                severity: Severity::Info,
                evidence: "test".to_string(),
                request_raw: String::new(),
                response_snippet: String::new(),
                url: record.host.clone(),
                parameter: None,
            }]
        }
    }

    struct NeverFinds;

    #[async_trait]
    impl CogitatorPlugin for NeverFinds {
        fn name(&self) -> &str {
            "never-finds"
        }
        fn description(&self) -> &str {
            "test plugin: default empty hooks, never emits anything"
        }
    }

    #[tokio::test]
    async fn registry_runs_on_request_across_all_plugins() {
        let mut reg = PluginRegistry::new();
        reg.register(Box::new(AlwaysFindsOnRequest));
        reg.register(Box::new(NeverFinds));

        let findings = reg.run_on_request(&sample_record()).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, "always-finds-on-request");
    }

    #[tokio::test]
    async fn registry_runs_on_response_across_all_plugins() {
        let mut reg = PluginRegistry::new();
        reg.register(Box::new(AlwaysFindsOnResponse));
        reg.register(Box::new(NeverFinds));

        let findings = reg.run_on_response(&sample_record()).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, "always-finds-on-response");
    }

    #[tokio::test]
    async fn default_hooks_are_empty() {
        let plugin = NeverFinds;
        assert!(plugin.on_request(&sample_record()).await.is_empty());
        assert!(plugin.on_response(&sample_record()).await.is_empty());
    }

    #[test]
    fn list_reports_name_and_description() {
        let mut reg = PluginRegistry::new();
        reg.register(Box::new(NeverFinds));
        let listed = reg.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, "never-finds");
    }

    #[tokio::test]
    async fn empty_registry_produces_no_findings() {
        let reg = PluginRegistry::new();
        assert!(reg.run_on_request(&sample_record()).await.is_empty());
        assert!(reg.run_on_response(&sample_record()).await.is_empty());
    }

    #[test]
    fn sink_push_and_drain_roundtrip() {
        let sink = PluginFindingsSink::new();
        assert!(sink.is_empty());

        sink.push_all(vec![ScanFinding {
            check_name: "x".to_string(),
            severity: Severity::Info,
            evidence: String::new(),
            request_raw: String::new(),
            response_snippet: String::new(),
            url: "example.com".to_string(),
            parameter: None,
        }]);
        assert_eq!(sink.len(), 1);

        let drained = sink.drain();
        assert_eq!(drained.len(), 1);
        assert!(sink.is_empty());
    }

    #[test]
    fn sink_push_empty_is_noop() {
        let sink = PluginFindingsSink::new();
        sink.push_all(Vec::new());
        assert!(sink.is_empty());
    }

    #[tokio::test]
    async fn stack_banner_leak_flags_versioned_header() {
        let plugin = StackBannerLeakPlugin;
        let mut record = sample_record();
        record.response_headers.push(("X-Powered-By".to_string(), "PHP/7.2.3".to_string()));

        let findings = plugin.on_response(&record).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("PHP/7.2.3"));
    }

    #[tokio::test]
    async fn stack_banner_leak_ignores_unversioned_header() {
        let plugin = StackBannerLeakPlugin;
        let mut record = sample_record();
        record.response_headers.push(("X-Powered-By".to_string(), "Express".to_string()));

        let findings = plugin.on_response(&record).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn stack_banner_leak_ignores_missing_header() {
        let plugin = StackBannerLeakPlugin;
        let findings = plugin.on_response(&sample_record()).await;
        assert!(findings.is_empty());
    }

    #[test]
    fn with_builtins_picks_up_inventory_registered_plugins() {
        // StackBannerLeakPlugin self-registers at the bottom of this file
        // via inventory::submit! -- with_builtins() should find it without
        // any explicit registration here.
        let reg = PluginRegistry::with_builtins();
        let names: Vec<String> = reg.list().into_iter().map(|(n, _)| n).collect();
        assert!(names.contains(&"stack-banner-leak".to_string()));
    }
}