# Changelog

All notable changes to Cogitator are documented in this file.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

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