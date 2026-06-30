# Cogitator — Roadmap

> Twenty sequential development rites, invoked in order.
> Each prompt below is a self-contained implementation task.

---

## Phase I — Hardening the Core

*Before Cogitator is shown to outsiders, its own vault must be sealed. A MITM proxy that hoards cookies and decrypted bodies is a high-value target in itself.*

- [ ] **I. Encrypt Workspace State at Rest** `Critical`
  Passphrase-based encryption (AES-256-GCM, Argon2id key derivation) for `.cogitator` files. TUI prompts for passphrase on Save/Load. Tests for round-trip and wrong-passphrase rejection.

- [ ] **II. Protect Session Cookie Jars** `Critical`
  Apply same encryption to session profiles saved by `Session-Save`. Factor shared `vault.rs` module to avoid duplicating crypto code.

- [ ] **III. Lock Down the Local CA Private Key** `TLS`
  Encrypt `cogitator_ca.key` at rest (PKCS#8 encrypted format). Passphrase prompted once at startup, cached in memory for the session only.

- [ ] **IV. Audit Logger for Sensitive Data Leakage** `Privacy`
  Add `redact()` helper in `logger.rs` masking `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key` header values before they hit `cogitator.log`. Apply at every call site.

- [ ] **V. Write a Threat Model Document** `Docs`
  `SECURITY.md` covering: what data is stored and where, CA trust blast radius, authorized-use-only scope, responsible disclosure contact.

---

## Phase II — Deepening Detection

*Push past signature-based first passes into techniques that separate a triage tool from something a working pentester actually reaches for.*

- [ ] **VI. Time-Based Blind SQL Injection** `Scanner`
  New `checks/sqli_blind.rs`. Baseline timing + payloads: `AND SLEEP(5)` (MySQL), `WAITFOR DELAY` (MSSQL), `pg_sleep(5)` (Postgres). Flag `High` if response ≥ 4× baseline AND ≥ 4s absolute delta. Registered alongside `SqliCheck`.

- [ ] **VII. Out-of-Band Detection Primitive** `Infra`
  `oob.rs` — async DNS listener, unique correlation subdomains per probe, `OobChannel::new_token()` / `was_triggered()` API. Foundation for Rites VIII and IX.

- [ ] **VIII. SSRF Active Check** `Scanner`
  `checks/ssrf.rs`. OOB token substitution for URL-shaped params + `Critical` if callback fires. Secondary heuristic: cloud metadata URLs (`169.254.169.254`) with response-diff detection → `Medium`.

- [ ] **IX. XXE Active Check** `Scanner`
  `checks/xxe.rs`. XML-shaped targets only. DOCTYPE external entity → OOB token + local file read attempt (`file:///etc/passwd`). Reuses `SUCCESS_SIGNATURES` pattern from `traversal.rs`.

- [ ] **X. Context-Aware XSS Detection** `Scanner`
  After reflection is found, classify injection context (HTML attribute, `<script>` block, comment, body text) from surrounding chars. Send context-specific follow-up probes to confirm breakout. Report context in `check_name`.

---

## Phase III — Reporting & Usability

*A finding that lives only inside a TUI scrollback is invisible to whoever didn't watch the terminal live.*

- [ ] **XI. HTML Report Generator** `Reporting`
  `report.rs` — self-contained single-file HTML report, findings grouped by severity, collapsible panels per finding. `Report-Generate [filename]` TUI command.

- [ ] **XII. PDF Export** `Reporting`
  `printpdf` crate (pure Rust, no headless browser). Cover page with severity summary + paginated findings. `Report-Generate-Pdf [filename]` TUI command.

- [ ] **XIII. Findings Triage View** `TUI`
  `FindingStatus` enum: `New / Confirmed / FalsePositive / Fixed`. New `Screen::Findings` with filter by status/severity, keybindings to cycle status. `Scan-Diff` skips previously dismissed findings.

- [ ] **XIV. Sitemap Export from Spider** `Spider`
  `Spider-Export <file>` command. `.json` — full URL graph with forms and parent/child links. `.txt` — flat sorted URL list for piping into other tools.

- [ ] **XV. Command History & Autocomplete** `TUI`
  Up/down arrow recall of previous commands (in-memory ring buffer). Tab-completion of command names, cycling through matches on repeated Tab.

---

## Phase IV — Scale & Ecosystem

*Turn Cogitator from a personal tool into something that can survive contact with other people.*

- [ ] **XVI. Distributed Scanning Across Worker Nodes** `Scale`
  `cogitator-worker` binary with JSON-over-HTTP API accepting `ScanTarget` + check list, returning `Vec<ScanFinding>`. Reuses existing `ScanCheck` implementations unchanged. `Scan-Site-Distributed <domain> <worker1,worker2,...>` command.

- [ ] **XVII. Example Plugin & Plugin Documentation** `Plugins`
  Complete annotated example plugin in `example-plugins/` (cdylib). `PLUGINS.md` with trait contract, ABI versioning explanation, build instructions, and step-by-step walkthrough.

- [ ] **XVIII. CI Pipeline** `DevOps`
  GitHub Actions: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --all`, `cargo audit`. Cargo cache between runs. Status badge in README.

- [ ] **XIX. CONTRIBUTING.md & Architecture Docs** `Docs`
  `CONTRIBUTING.md` with dev setup, CI gate, `ScanCheck` trait contract for new checks, code conventions. `ARCHITECTURE.md` with ASCII diagram of proxy_guard → interceptor → history → TUI event loop data flow.

- [ ] **XX. Public Release Preparation** `Launch`
  `CHANGELOG.md`, `v1.0.0` tag, GitHub Release notes, portfolio writeup (4–6 paragraphs, no marketing fluff).

---

<p align="center">
  20 rites · 4 phases · invoke in sequence, skip none<br>
  <i>The Omnissiah records this litany.</i>
</p>
