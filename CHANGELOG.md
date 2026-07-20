# Changelog

All notable changes to Cogitator are documented in this file.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.9.0] — 2026-07-20

Tech-debt pass: all 11 items from the post-0.8.0 backlog
(`tech_debt_backlog.html`) are closed. No user-facing behavior change —
this release is entirely internal structure, error handling, and
crawler hardening.

### Command dispatch
- `main.rs`'s ~90-arm command `match` replaced with a table-driven
  registry (`AppState` + handler functions), grouped by command prefix
  into separate modules (`commands/scan.rs`, `commands/workspace.rs`,
  `commands/scope.rs`, etc.). Command names and behavior preserved
  exactly; this was a structural refactor only.

### Error handling
- `vault.rs`, `ws_interceptor.rs`, `scope.rs`, and `workspace.rs` no
  longer build errors as `io::Error::new(io::ErrorKind::InvalidData,
  format!(...))`. Replaced with proper `thiserror`-based error enums
  that distinguish actual failure causes (e.g. wrong passphrase vs.
  corrupt file vs. invalid regex), with `From<Error> for io::Error`
  at module boundaries to keep external `io::Result` signatures intact.
- Audited every non-test `.unwrap()`/`.expect()` in `session.rs`,
  `spider.rs`, `workspace.rs`, `oob.rs`, and `tls_mitm.rs`. Calls driven
  by external input (file I/O, network responses, parsing) now
  propagate `Result` instead of panicking mid-engagement; mutex-lock
  unwraps were left as-is.

### Module splits
- `styletui.rs` (2,720 lines) split into per-screen submodules
  (`styletui/scanner_view.rs`, `findings_view.rs`,
  `interceptor_view.rs`, `repeater_view.rs`, `intruder_view.rs`,
  `spider_view.rs`), re-exported unchanged from `styletui.rs`.
- `web_analyzer.rs` (2,008 lines) split by analysis concern into
  submodules under `web_analyzer/`, re-exported unchanged from
  `web_analyzer/mod.rs`.
- `workspace.rs` (1,057 lines) split into `workspace/data.rs`
  (serialization, load/save, vault-backed encryption) and
  `workspace/prompt.rs` (TUI prompt state machine), on top of the new
  error type from the error-handling pass above.
- `spider.rs` (1,022 lines) split into `spider/robots.rs`
  (robots.txt caching) and `spider/extract.rs` (HTML link/form
  extraction), leaving `spider.rs` responsible for crawl orchestration
  only.

### Crawler: production scale
- BFS crawl loop replaced with a semaphore-capped worker pool (same
  pattern as `scanner.rs`'s `ScanQueue`), with a `Mutex<HashSet<String>>`
  visited-set so concurrent fetches can't duplicate a URL. `max_pages`/
  `max_depth` remain correctly enforced under concurrency.
- Regex-based `extract_links`/`extract_forms` replaced with the
  `scraper` crate (already a workspace dependency), including `<base
  href>` handling.
- `parse_robots` now honors `Crawl-delay` in addition to `Disallow`,
  with a per-origin minimum delay between requests (no delay by
  default, unless the target's robots.txt specifies one).
- `SpiderConfig`/`SpiderResult` public shape unchanged.

### Cleanup
- Deduplicated timestamp formatting between `report.rs`
  (`format_timestamp_utc`) and `report_pdf.rs`
  (`format_timestamp_for_pdf`) into a shared `report/format.rs`, along
  with the duplicated severity-grouping/finding-sorting logic used by
  both renderers. HTML/PDF output unchanged.
- Audited `.clone()` call sites in `main.rs`, `proxy_guard.rs`, and
  `workspace.rs` (the three highest-density files); replaced
  unnecessary clones with borrows or `Arc` sharing where the type
  already supported it, and commented the ones kept intentionally.

### Distributed scanning
- Added optional per-worker bearer tokens (`worker base URL → token`
  map) in `worker_protocol.rs`/`distributed.rs`, backward-compatible
  with the single shared-token setup. TLS between coordinator and
  workers remains out of scope, per `SECURITY.md`.
  `distributed_scanning_setup.md` updated accordingly.

### CI
- `clippy` in `.github/workflows/ci.yml` no longer runs with
  `continue-on-error: true`, now that the backlog it was staged
  against is clear.

## [0.8.0] — 2026-07-08

First tagged public release. Cogitator is a Rust TLS MITM proxy and
pentest toolkit with a terminal UI, built as a Cargo workspace.

### Core proxy
- TLS interception via a locally-generated CA (ECDSA P-256, `rcgen`),
  imported into a client trust store to decrypt traffic transparently.
- HTTP/1.1 and HTTP/2 support, with independent per-leg ALPN negotiation
  (client-facing and origin-facing legs can each land on a different
  protocol) via `hyper`'s HTTP/2 client builder.
- Full end-to-end WebSocket interception: RFC 6455 framing, a dual
  handshake with both client and origin post-TLS, bidirectional frame
  proxying with History logging, and per-frame Forward/Drop/Replace in
  Frozen mode.
- Scope filtering (include/exclude regex rules, NDJSON persistence) so
  only in-scope traffic is recorded/analyzed.
- Request/response History store, Repeater (tabbed manual replay), and
  Intruder (Sniper/BatteringRam/Pitchfork/ClusterBomb attack modes with
  lazy wordlist sources).

### Active scanning
- Async scan engine (`ScanCheck` trait, concurrency-capped queue,
  severity-sorted results) with checks for: SQL injection (error-based
  and time-based blind), path traversal, reflected/stored XSS
  (context-aware), SSRF, and XXE.
- Out-of-band DNS listener for blind-SSRF confirmation (operator-owned
  domain only — no third-party collaborator service).
- CVE lookup integration (`cve.circl.lu`) and scan-to-scan diffing.
- Site crawler (BFS, robots.txt-aware, HTML link/form extraction) feeding
  discovered targets into scans.

### Distributed scanning
- `cogitator-worker` companion crate exposing a JSON-over-HTTP scan API,
  sharing scan-check implementations with the main binary via a `lib.rs`
  module-path trick (no duplicated source).
- Coordinator-side round-robin dispatch across any number of workers,
  shared-token auth, per-worker failure isolation (a dead worker
  contributes zero findings rather than failing the run).

### Plugin system
- `CogitatorPlugin` trait with async request/response hooks, built-in
  plugin registration via `inventory`, and optional external plugin
  loading (`.so`/`.dll`/`.dylib`) via `libloading`, gated behind the
  `external_plugins` feature.
- Shared `cogitator-plugin-api` crate as the single ABI contract between
  the main binary and external plugins, with an explicit
  `PLUGIN_ABI_VERSION` check before any external plugin is instantiated.
- `example-plugin` reference implementation (secrets detector) and a
  `PLUGINS.md` walkthrough for writing new ones.

### Reporting
- HTML scan reports (inline CSS, severity grouping, collapsible findings)
  and paginated PDF reports (cover page + per-finding sections).
- Finding lifecycle tracking (`New`/`Confirmed`/`FalsePositive`/`Fixed`)
  with a dedicated Findings screen (filter by status/severity, cycle
  status inline).
- Per-request crypto/cookie forensics: HSTS grading, cookie flag
  auditing, JWT-in-cookie detection, HPKP detection, an overall A–F grade.

### Security & hardening
- CA private key encryption at rest (PKCS#8, scrypt + AES-256-CBC),
  passphrase-prompted at startup, with a guard against silently
  regenerating the CA on a wrong passphrase.
- Session vault (named cookie/header profiles for authenticated replay)
  and workspace save files encrypted via a shared AES-256-GCM +
  Argon2id vault module.
- Centralized log redaction: every log line is passed through a redactor
  that strips `Authorization`/`Cookie`/`Set-Cookie`/`X-Api-Key` values
  before they reach disk, regardless of call site.
- `SECURITY.md` threat model documenting what's stored where, the blast
  radius of a stolen CA key, and the still-open gap around the
  unencrypted auto-save file (see "Known limitations" below).

### TUI
- Ratatui/crossterm-based interface with dedicated screens for the
  interceptor, scanner, findings, history, repeater, intruder, and
  spider, plus command history and Tab-completion in the command input.

### Known limitations (intentional, see project writeup / SECURITY.md)
- The auto-save file written on exit (`cogitator_last.cogitator`) is
  plaintext by default; only explicit `Workspace-Save` supports
  passphrase encryption.
- Distributed scanning v1 uses a single shared bearer token over plain
  HTTP, no per-worker credentials, no TLS between coordinator and
  workers, and no health-check/retry before dispatch.
- No built-in authorization/consent verification — Cogitator assumes
  the operator is authorized to test whatever it's pointed at.
