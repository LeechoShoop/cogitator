# Cogitator Plugins

Cogitator supports two kinds of plugins:

| Kind | Registration | Rebuild needed? | Use when |
|------|-------------|-----------------|----------|
| **Built-in** | `inventory::submit!` in `src/plugin.rs` | Yes — recompile `Cogitator` | Bundling a check into the shipped binary |
| **External** | Drop a `.so`/`.dll`/`.dylib` in `./plugins/` | No — just rebuild the `.so` | Distributing a check independently; feature flag `external_plugins` required |

This document is about **external** plugins. It covers the trait contract,
ABI versioning, build instructions, and a step-by-step walkthrough using
the example plugin in `example-plugins/` as a template.

> **Two worked examples.** The repository ships two canonical example
> plugins, each showing a distinct pattern:
>
> | Crate | Pattern |
> |-------|---------|
> | `example-plugin/` | Stateless, regex-scan body/headers, emit findings |
> | `example-plugins/` | State-carrying (`AtomicU64`), cross-hook correlation, structural/behavioral check |
>
> Start from whichever matches your use case. The walkthrough below uses
> `example-plugins/` (`custom-header-injector-detector`) as its template.

---

## Table of Contents

1. [The plugin trait contract](#the-plugin-trait-contract)
2. [How ABI versioning is checked at load time](#how-abi-versioning-is-checked-at-load-time)
3. [Building a `.so`/`.dll`/`.dylib` and where Cogitator looks for it](#building-a-sodlldylib-and-where-cogitator-looks-for-it)
4. [Write your first plugin — a walkthrough](#write-your-first-plugin--a-walkthrough)
5. [Execution model (concurrency, timeouts)](#execution-model-concurrency-timeouts)
6. [Severity guidance](#severity-guidance)
7. [FFI safety rules — the full list](#ffi-safety-rules--the-full-list)
8. [Troubleshooting](#troubleshooting)

---

## The plugin trait contract

Every external Cogitator plugin implements one trait, defined in the shared
`cogitator-plugin-api` crate:

```rust
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
```

### Methods

| Method | When it fires | `response_*` fields populated? |
|--------|--------------|-------------------------------|
| `name()` | At load time + TUI display | — (not a hook) |
| `description()` | At load time + TUI display | — (not a hook) |
| `on_request()` | After Cogitator receives the client request, **before** forwarding to origin | No — response does not exist yet |
| `on_response()` | After the origin's response has been received | Yes |

- **`name()`** — a short, unique identifier. Shown in logs
  (`Plugin registered: <name>`) and Cogitator's TUI plugin list. Two plugins
  with the same name aren't an error but make log lines ambiguous — pick
  something specific (`custom-header-injector-detector`, not `scanner`).
- **`description()`** — one sentence describing what the plugin does, shown
  alongside `name()` wherever plugins are listed.
- **`on_request()`** / **`on_response()`** — both default to returning an empty
  `Vec`. Implement only the one(s) you need.

### The `RequestRecord` type

Both hooks receive a `&RequestRecord` (defined in `cogitator-plugin-api`):

```rust
pub struct RequestRecord {
    pub id:               u64,
    pub timestamp:        Instant,
    pub method:           String,
    pub host:             String,
    pub path:             String,
    pub headers:          Vec<(String, String)>,
    pub body:             Vec<u8>,
    pub response_status:  Option<u16>,
    pub response_headers: Vec<(String, String)>,
    pub response_body:    Option<Vec<u8>>,
    pub response_time_ms: Option<u128>,
    pub tags:             Vec<String>,
    pub stream_id:        Option<u64>,
}
```

`response_*` fields are `None`/empty in `on_request` — the response hasn't
happened yet at that point. In `on_response` they are populated.

### The `ScanFinding` type

Your hooks return `Vec<ScanFinding>`:

```rust
pub struct ScanFinding {
    pub check_name:       String,  // e.g. "Header Reflection / Echo"
    pub severity:         Severity,
    pub evidence:         String,  // human-readable excerpt; mind what ends up in reports
    pub request_raw:      String,  // e.g. "GET example.com/path"
    pub response_snippet: String,  // short excerpt of the response, or empty
    pub url:              String,  // e.g. "example.com/path"
    pub parameter:        Option<String>,
}
```

Findings appear in Cogitator's **Findings** screen, `Scan-Diff`, and
`Report-Generate`/`Report-Generate-Pdf` output alongside findings from
built-in active-scan checks.

---

## How ABI versioning is checked at load time

Cogitator loads external plugins via `dlopen`/`LoadLibrary` (the
[`libloading`](https://docs.rs/libloading) crate). There is no compiler
to catch layout mismatches between your plugin and Cogitator's own build.
A `.so` compiled against a slightly different version of
`cogitator-plugin-api` whose types don't line up byte-for-byte is a
**memory-safety bug**, not a type error.

The fix: Cogitator checks a version number *before* calling anything that
touches plugin-defined types.

### The two exported symbols

Every plugin must export exactly two C symbols (this is what the
`export_plugin!` macro generates):

```rust
// Returns the PLUGIN_ABI_VERSION constant this .so was built against.
#[no_mangle]
pub extern "C" fn cogitator_plugin_abi_version() -> u32;

// Constructs the plugin and returns a raw pointer to it.
// Only called after the version check passes.
#[no_mangle]
pub extern "C" fn cogitator_plugin_create() -> *mut dyn CogitatorPlugin;
```

### The load sequence (`load_external_plugins` in `src/plugin.rs`)

For every file with a `.so`/`.dll`/`.dylib` extension in the `./plugins/`
directory:

```
1.  Open the library with dlopen/LoadLibrary.
         ↓ failure → warn & skip
2.  Look up `cogitator_plugin_abi_version`.
         ↓ missing → warn "missing cogitator_plugin_abi_version" & skip
3.  Call it. Compare result to Cogitator's own PLUGIN_ABI_VERSION constant.
         ↓ mismatch → warn "ABI version X != expected Y" & skip
4.  Look up `cogitator_plugin_create`.
         ↓ missing → warn & skip
5.  Call it. Receive *mut dyn CogitatorPlugin.
         ↓ null → warn & skip
6.  Wrap in Box<dyn CogitatorPlugin>. Register. Log success.
7.  mem::forget(lib) — the library is never unloaded (see FFI safety rules).
```

Any mismatch — including the plugin being *newer* than Cogitator — is
refused. There's no partial compatibility with a `dlopen` model. A stale
`.so` is either byte-for-byte compatible or it's skipped, full stop.

### When to bump `PLUGIN_ABI_VERSION`

Bump the constant in `cogitator-plugin-api/src/lib.rs` **in the same commit**
as any of these changes:

- A new field on `RequestRecord` or `ScanFinding`
- A new variant on `Severity`
- Any change to the `CogitatorPlugin` trait itself (new method, changed
  signature)

After bumping: rebuild every external plugin from scratch (clean build, not
incremental) against the new `cogitator-plugin-api`.

---

## Building a `.so`/`.dll`/`.dylib` and where Cogitator looks for it

### Step 0 — Match Rust toolchains first

This matters more than it looks like it should. Rust's default struct layout
(`repr(Rust)`) is **not guaranteed stable across different `rustc` versions
or optimization settings** — it's unspecified by design. `PLUGIN_ABI_VERSION`
only catches *intentional* API changes; it cannot detect "these two binaries
disagree on `RequestRecord`'s field offsets because they were compiled with
different `rustc` versions."

```bash
rustc --version
# Compare against whatever compiled the Cogitator binary you're loading into.
# They must match exactly.
```

Pin the plugin's toolchain if you're using `rustup`:

```toml
# rust-toolchain.toml (place next to the plugin's Cargo.toml)
[toolchain]
channel = "1.83.0"   # replace with Cogitator's actual pinned version
```

### Step 1 — Build Cogitator with external plugin support (once)

External plugin loading is behind a feature flag:

```bash
# from the Cogitator workspace root
cargo build --release --features external_plugins
```

Confirm the feature is actually included:

```bash
# Linux / macOS
nm -D target/release/Cogitator 2>/dev/null | grep -i libloading
# (empty output means the feature flag was not enabled — rebuild with --features)
```

### Step 2 — Build the plugin

```bash
cd example-plugins          # or your copy of this directory
cargo build --release
```

Output paths by platform (Cargo replaces `-` with `_`, adds the OS prefix/suffix):

| Platform | Output path |
|----------|------------|
| Linux    | `target/release/libcustom_header_injector_detector.so` |
| macOS    | `target/release/libcustom_header_injector_detector.dylib` |
| Windows  | `target/release/custom_header_injector_detector.dll` |

Verify the required symbols are actually exported **before** copying to
`plugins/` — this catches a missing `export_plugin!` call at build time
instead of at Cogitator startup:

```bash
# Linux
nm -D target/release/libcustom_header_injector_detector.so | grep cogitator_plugin
# Expected (two lines):
#   ... T cogitator_plugin_abi_version
#   ... T cogitator_plugin_create

# macOS
nm -gU target/release/libcustom_header_injector_detector.dylib | grep cogitator_plugin

# Windows (Developer PowerShell, with dumpbin)
dumpbin /exports target\release\custom_header_injector_detector.dll | findstr cogitator_plugin
```

### Step 3 — Cross-compiling (only if host ≠ target)

```bash
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
# output: target/x86_64-pc-windows-msvc/release/custom_header_injector_detector.dll
```

The target triple must match the Cogitator binary you're loading into.

### Step 4 — Install the plugin

Cogitator's `main.rs` calls `load_external_plugins("./plugins")` — it scans
a directory named **`plugins`** in Cogitator's **current working directory**
at launch (where you run the binary from, not necessarily where the binary
lives).

```bash
# from example-plugins/ — adjust relative path to wherever you launch Cogitator from
mkdir -p ../plugins
cp target/release/libcustom_header_injector_detector.so ../plugins/
```

Every file in that directory with a `.so`, `.dll`, or `.dylib` extension is
attempted. Other extensions are silently ignored. A missing `./plugins/`
directory is not an error — Cogitator logs it and continues with built-ins.

### Step 5 — Launch and verify

```bash
./target/release/Cogitator   # from the directory containing ./plugins/
```

Successful load produces:

```
plugin: loaded "./plugins/libcustom_header_injector_detector.so" (custom-header-injector-detector)
Plugin registered: custom-header-injector-detector
```

If you see a `missing cogitator_plugin_abi_version` or `ABI version X != expected Y`
line instead, see [Troubleshooting](#troubleshooting).

---

## Write your first plugin — a walkthrough

This walks you from a blank directory to a working, tested, installed plugin.
Every step refers to a file in `example-plugins/` so you can diff against it.

### 1. Copy the template

```bash
cp -r example-plugins my-plugin
cd my-plugin
```

### 2. Rename the package

In `Cargo.toml`:

```toml
[package]
name = "my-plugin"   # was: "custom-header-injector-detector"
version = "0.1.0"
edition = "2024"     # must match cogitator-plugin-api's edition — leave as-is

[lib]
crate-type = ["cdylib"]   # REQUIRED — do not change this

[dependencies]
cogitator-plugin-api = { path = "../cogitator-plugin-api" }   # leave path as-is
async-trait = "0.1.89"   # pin to cogitator-plugin-api's exact version
```

Leave `[lib] crate-type = ["cdylib"]` and the `cogitator-plugin-api` path
dependency exactly as they are — those are the two fields that make the plugin
loadable at all.

### 3. Define your plugin struct

In `src/lib.rs`, replace `CustomHeaderInjectorDetector` with your own type:

```rust
use async_trait::async_trait;
use cogitator_plugin_api::{CogitatorPlugin, RequestRecord, ScanFinding, Severity};

pub struct MyPlugin;

impl MyPlugin {
    pub fn new() -> Self { Self }
}
```

**If your plugin needs state** (a counter, a cache, a connection handle):

```rust
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};

pub struct MyPlugin {
    hit_count: Arc<AtomicU64>,      // lock-free counter — use for simple numerics
    cache:     Arc<Mutex<Vec<String>>>,  // lock-based — use for richer state
}
```

Every field must be `Send + Sync` — Cogitator shares your plugin across
concurrent `tokio` tasks via `Arc<dyn CogitatorPlugin>`. See
[FFI safety rules](#ffi-safety-rules--the-full-list) for what that
prohibits.

### 4. Implement the trait

```rust
#[async_trait]  // ← REQUIRED on the impl block too, not just the trait definition
impl CogitatorPlugin for MyPlugin {
    fn name(&self) -> &str { "my-plugin" }
    fn description(&self) -> &str { "Does something useful" }

    // Implement only the hooks you care about.
    // The default implementations return Vec::new(), which is correct for
    // a hook you don't need.

    async fn on_response(&self, record: &RequestRecord) -> Vec<ScanFinding> {
        // Example: flag any 500 response
        if record.response_status == Some(500) {
            return vec![ScanFinding {
                check_name: "Server Error".to_string(),
                severity:   Severity::Medium,
                evidence:   "HTTP 500 Internal Server Error".to_string(),
                request_raw: format!("{} {}{}", record.method, record.host, record.path),
                response_snippet: String::new(),
                url:        format!("{}{}", record.host, record.path),
                parameter:  None,
            }];
        }
        Vec::new()
    }
}
```

`#[async_trait]` on the `impl` block (not just on the trait) is what makes
`on_request`/`on_response` compile as `async fn`. Forgetting it gives a
confusing "method signature does not match trait" error. See
[FFI safety rules](#ffi-safety-rules--the-full-list) for why the version
must also match exactly.

### 5. Add the export line

At module scope, after the `impl` block:

```rust
cogitator_plugin_api::export_plugin!(MyPlugin::new());
```

This generates the two `extern "C"` symbols the loader looks for. Without
it, the `.so` builds fine but Cogitator refuses to load it.

### 6. Build a `ScanFinding` for what you find

Every finding needs:

| Field | What to put |
|-------|------------|
| `check_name` | Short name of what was detected, e.g. `"Header Reflection"` |
| `severity` | See [severity guidance](#severity-guidance) |
| `evidence` | Human-readable description; **do not include full raw secrets or large body dumps** — findings end up in on-disk logs and PDF reports |
| `request_raw` | Usually `format!("{} {}{}", record.method, record.host, record.path)` |
| `response_snippet` | Short excerpt of the response, or `String::new()` |
| `url` | Usually `format!("{}{}", record.host, record.path)` |
| `parameter` | Optional; the specific header/param/field that triggered the finding |

### 7. Write tests

The `#[cfg(test)] mod tests` block in `src/lib.rs` needs nothing from a
running Cogitator instance — construct `RequestRecord` values by hand and
call your hooks directly:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn sample() -> RequestRecord {
        RequestRecord {
            id: 1, timestamp: Instant::now(),
            method: "GET".into(), host: "example.com".into(), path: "/".into(),
            headers: Vec::new(), body: Vec::new(),
            response_status: Some(200), response_headers: Vec::new(),
            response_body: Some(b"<html>OK</html>".to_vec()),
            response_time_ms: Some(15),
            tags: Vec::new(), stream_id: None,
        }
    }

    #[tokio::test]  // needed because on_request / on_response are async
    async fn my_hook_fires() {
        let plugin = MyPlugin::new();
        let mut r = sample();
        r.response_status = Some(500);
        let findings = plugin.on_response(&r).await;
        assert_eq!(findings.len(), 1);
    }
}
```

Run them:

```bash
cargo test                           # from inside your plugin directory
cargo test -p my-plugin             # from the workspace root
```

### 8. Build, verify, install

```bash
cargo build --release

# Verify symbols before installing (see step 2 of the build section above):
nm -D target/release/libmy_plugin.so | grep cogitator_plugin
# Must print cogitator_plugin_abi_version AND cogitator_plugin_create

cp target/release/libmy_plugin.so ../plugins/
```

### 9. Launch Cogitator and verify

From the directory containing `./plugins/`:

```bash
./target/release/Cogitator   # with --features external_plugins if not already baked in
```

Expected log output:

```
plugin: loaded "./plugins/libmy_plugin.so" (my-plugin)
Plugin registered: my-plugin
```

Then proxy traffic that should (and shouldn't) trigger your plugin and check
the **Findings** screen in the TUI for your `check_name`.

**Steps 3–9 are the only ones you repeat** as you iterate on the plugin logic.

---

## Execution model (concurrency, timeouts)

You don't need to do anything special to co-operate with the execution model,
but it's essential background for writing a plugin that behaves well:

- Every registered plugin runs **concurrently** via `tokio::task::JoinSet`
  on each hook. Your plugin is not blocking, and is not blocked by, any
  other plugin.
- Each hook call is capped at **5 seconds** (100 ms in test builds). If your
  plugin doesn't return in time:
  - It is cancelled.
  - Its findings for that call are silently dropped.
  - A warning is logged: `plugin: "my-plugin" timed out after 5.0s — findings dropped`.
  - Other plugins and Cogitator itself continue normally.
- A hook that finishes within the timeout but took longer than 500 ms is
  logged as slow (diagnostic only, no action).
- A **panic** inside `on_request`/`on_response` is caught by `JoinSet`
  (isolated), logged with your plugin's name, and does not crash Cogitator or
  stop other plugins. A panic inside `name()`, `description()`, or the
  `export_plugin!` constructor expression is *not* caught — those calls happen
  across the FFI boundary before any `catch_unwind`. Keep them infallible.

**Critical consequence:** do not block synchronously inside `on_request`/
`on_response`. Any blocking call — `std::thread::sleep`, synchronous file I/O,
blocking network I/O — stalls the task's thread for up to the full 5-second
timeout before cancellation. Use the async equivalents instead:

| Don't | Do instead |
|-------|-----------|
| `std::thread::sleep(dur)` | `tokio::time::sleep(dur).await` |
| `std::fs::read_to_string(path)` | `tokio::fs::read_to_string(path).await` |
| `reqwest::blocking::get(url)` | `reqwest::get(url).await` |

---

## Severity guidance

| Variant | When to use | Examples |
|---------|------------|---------|
| `Critical` | Direct path to full compromise | Private key in response, SQL injection, RCE |
| `High` | Confirmed exploitable, significant impact | Header reflection enabling cache poisoning, API key in response, XSS |
| `Medium` | Suspicious but not confirmed exploitable; lower-confidence heuristics | Suspicious custom header *present* (not yet echoed), weak TLS config |
| `Low` | Information leakage with low direct impact | Server banner/version disclosure |
| `Info` | Observations that are not themselves a vulnerability, but worth a human glance | JWT present in response (expected in most apps; not a finding on its own) |

The two example plugins apply this table deliberately:

- `example-plugins/` (`custom-header-injector-detector`):
  - Suspicious header in request → `Medium` (presence alone, unconfirmed)
  - Server echoes the header back → `High` (confirmed reflection)
- `example-plugin/` (`secrets-in-response-detector`):
  - Private key block → `Critical`
  - Named API token (AWS, GitHub, Slack) → `High`
  - Generic `key: "value"` heuristic → `Medium` (more false-positive prone)
  - JWT present → `Info`

---

## FFI safety rules — the full list

These rules exist because `dlopen`-based plugins operate outside the normal
Rust borrow-checker/linker guarantees. Violating any of them is undefined
behaviour, not a build error.

### 1. `Send + Sync` is mandatory

Cogitator stores plugins as `Arc<dyn CogitatorPlugin>` and shares them
across concurrent `tokio::task::JoinSet` tasks. Every field in your plugin
struct must be `Send + Sync`:

```rust
// ✓ OK
hit_count: Arc<AtomicU64>       // atomics are Send + Sync
state:     Arc<Mutex<MyState>>  // Mutex<T> is Send + Sync when T: Send

// ✗ NOT OK — won't compile against the trait bound
state: Rc<RefCell<MyState>>     // Rc is not Send
raw_ptr: *mut MyState           // raw pointers are not Send or Sync
```

### 2. Don't panic in `name()`, `description()`, or the constructor

These calls happen in Cogitator's loader across the FFI boundary before any
`catch_unwind`. Unwinding across FFI is undefined behaviour in Rust. Keep all
three infallible — no `unwrap()` on anything that can realistically fail, no
`panic!()`, no integer overflow in debug mode.

The async hooks (`on_request`/`on_response`) are wrapped in `JoinSet` tasks,
which do catch panics — a panic there becomes a `JoinError`, logged and
discarded, without crashing Cogitator.

### 3. Match `rustc` versions exactly

`PLUGIN_ABI_VERSION` only catches *intentional* changes to
`cogitator-plugin-api`. It cannot catch struct layout changes caused by
different `rustc` versions — Rust's `repr(Rust)` layout is explicitly
unspecified and can differ between compiler versions even for byte-identical
source.

Build your plugin with the exact same `rustc` you used to build Cogitator.
`rustc --version` on both sides, compared by hand (or enforced by a shared
`rust-toolchain.toml`).

### 4. Don't set a custom `#[global_allocator]` unless Cogitator does too

`cogitator_plugin_create` returns a `Box::into_raw` pointer — allocated
by your plugin with whatever global allocator is active in your `.so`.
Cogitator later calls `Box::from_raw` to take ownership — that deallocation
happens with whatever allocator is active in the main binary. If both sides
use the system allocator (the default), this is fine. If you set a custom
`#[global_allocator]` in your plugin but Cogitator uses the default (or
vice versa), the deallocation will free memory through a different allocator
than allocated it — undefined behaviour.

### 5. The `async-trait` version must match exactly

`CogitatorPlugin`'s `async fn` methods are macro-desugared by `async-trait`.
Your `impl` block must go through the same macro. Using a *different major
version* of `async-trait` than `cogitator-plugin-api` declares can produce
two incompatible desugarings — both may compile, but the function pointer
types in the trait object's vtable won't align.

Pin `async-trait = "0.1.89"` (exact match) in your plugin's `Cargo.toml`.

### 6. The `.so` is never unloaded

`load_external_plugins` calls `std::mem::forget(lib)` after a successful
load. The library's mapped memory lives for the entire process lifetime.
Your plugin's vtable pointers (the `dyn CogitatorPlugin` function pointers)
live inside that mapped memory — if the library were unloaded, every
subsequent trait-object call would jump into unmapped memory. This also
means there is no hot-unload/reload story in v1: to update a plugin you must
restart Cogitator.

### 7. `crate-type = ["cdylib"]` doesn't break `cargo test`

`cargo test` always compiles the lib target as a self-contained test binary
(effectively `rustc --test`), overriding the declared crate type. The
`#[cfg(test)] mod tests` block runs as normal Rust unit tests — no `dlopen`,
no ABI check, no Cogitator instance required. This is intentional and
expected.

---

## Troubleshooting

### `plugin: ... missing cogitator_plugin_abi_version — refusing`

**Cause:** `cogitator_plugin_api::export_plugin!(...)` is missing from your
plugin's `lib.rs`.

**Fix:** Add the macro call at module scope (after the `impl` block, not
inside a function or `#[cfg(test)]` block):

```rust
cogitator_plugin_api::export_plugin!(MyPlugin::new());
```

Verify with `nm -D` / `dumpbin /exports` that the two symbols appear in the
`.so`/`.dll` before re-installing.

---

### `plugin: ... ABI version X != expected Y — rebuild the plugin`

**Cause:** The `cogitator-plugin-api` copy your plugin was built against
has a different `PLUGIN_ABI_VERSION` than the one Cogitator's current binary
was built against. The most common causes:

1. The `path = "..."` in your plugin's `Cargo.toml` points at a *different*
   directory than the one Cogitator itself uses.
2. You updated `cogitator-plugin-api` (bumped `PLUGIN_ABI_VERSION`) and
   rebuilt Cogitator but didn't rebuild the plugin.
3. You have a stale incremental build of the plugin from before the version
   bump. Clean and rebuild.

**Fix:**

```bash
# Confirm the path is the same directory Cogitator uses:
grep cogitator-plugin-api Cargo.toml

# Clean + full rebuild (not incremental):
cargo clean
cargo build --release
```

---

### `%1 is not a valid Win32 application` (Windows) / silent load failure (Linux/macOS)

**Cause:** Architecture mismatch or wrong `crate-type`.

**Fix:**
1. Confirm `[lib] crate-type = ["cdylib"]` is present in `Cargo.toml`.
2. Confirm the target triple used to build the plugin matches the Cogitator
   binary's architecture (`x86_64` vs `aarch64`, MSVC vs GNU, etc.).

---

### Plugin loads but no findings ever appear

Roughly in order of likelihood:

1. **Traffic is out of scope.** Cogitator's `Scope-List` setting controls
   which hosts/paths plugins see at all — out-of-scope traffic is
   auto-forwarded without reaching plugin hooks.
2. **Detection logic isn't matching.** Add temporary `eprintln!` calls inside
   the hook to confirm it's being called and see what data it's actually
   looking at:
   ```rust
   async fn on_response(&self, record: &RequestRecord) -> Vec<ScanFinding> {
       eprintln!("[my-plugin] on_response called for {}{}", record.host, record.path);
       // ... rest of your logic
   }
   ```
   Output goes to Cogitator's stderr.
3. **Exceeding the 5-second timeout.** Check `cogitator.log` for a
   `"timed out after 5.0s"` line with your plugin's name. If present, your
   hook is blocking synchronously — see
   [Execution model](#execution-model-concurrency-timeouts).

---

### My plugin's tests hang or take forever

You're blocking synchronously inside an `async fn`. The most common culprits:
`std::thread::sleep`, blocking HTTP clients, or `std::fs` calls inside a
`tokio::test` that uses the current-thread runtime. Swap in the async
equivalents (`tokio::time::sleep`, async HTTP, `tokio::fs`).

---

## Quick Reference: Terminal Commands

To compile, test, and build your plugin, run the following commands from inside your plugin's directory (e.g., `cd example-plugins`):

```bash
# 1. Run unit tests to verify logic
cargo test

# 2. Check for compilation errors
cargo check

# 3. Build the final dynamic library for Cogitator
cargo build --release

# The compiled plugin will be located at:
# Linux:   target/release/lib<plugin_name>.so
# macOS:   target/release/lib<plugin_name>.dylib
# Windows: target/release/<plugin_name>.dll

# 4. Run Cogitator with your plugin loaded
# Note: You can copy your compiled DLLs into a 'plugins' folder
# and run them from there:
cd ..
cargo run --features external_plugins
```
