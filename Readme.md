# ⚙️ COGITATOR

> *"Knowledge is power, and power must be sanctified."*
> — Principia Technologica, Om 4:12

**Cogitator** is a terminal-based TLS MITM intercepting proxy and penetration testing toolkit written in Rust — conceptually similar to Burp Suite, but with no GUI for the weak, and no mercy for negligent web applications. Cogitator's Machine Spirit reads through encrypted traffic as effortlessly as the Adeptus Mechanicus reads sacred schematics.

This tool was forged to learn network security engineering and low-level Rust through practice — every line of code has been hammered out, sanctified, and battle-tested.

---

## 🔱 Table of Contents

- [What Cogitator Can Do](#-what-cogitator-can-do)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Installing the Root Certificate (Export-CA)](#-installing-the-root-certificate-export-ca)
- [Sacred Commandments (Full Command List)](#-sacred-commandments-full-command-list)
- [Terminal Interface](#-terminal-interface)
- [Plugins](#-plugins-extending-the-machine-spirit)
- [Workspace: Saving State](#-workspace-saving-state)
- [Disclaimer](#-disclaimer-litany-of-caution)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)

---

## ⚔️ What Cogitator Can Do

Cogitator isn't a single tool — it's a tribunal of inquisitorial modules united under one Machine Spirit:

| Module | Purpose |
|---|---|
| **TLS MITM Proxy** | Intercepts HTTP/HTTPS traffic (including HTTP/2 via ALPN) with on-the-fly certificate substitution through a local CA |
| **WebSocket Interceptor** | Full RFC 6455 codec, real-time frame interception and modification |
| **Interceptor (Frozen Mode)** | Pauses live requests with Forward / Drop / Modify decisions, including header and body editing |
| **Repeater** | Multi-tab manual request replay and modification |
| **Active Scanner** | Automated SQLi, XSS (reflected/stored), and Path Traversal detection with configurable concurrency |
| **Scan Diff** | Compares scan results across runs — tracks regressions and newly introduced vulnerabilities |
| **Intruder** | Sniper / Battering Ram / Pitchfork / Cluster Bomb wordlist-based attacks |
| **Spider** | BFS crawler respecting robots.txt, with link/form extraction |
| **CVE Lookup** | Looks up known vulnerabilities from service banners via `cve.circl.lu` |
| **Crypto Forensics** | TLS/cookie security audit, HSTS, HPKP, JWT detection, A–F grading |
| **Web/Email Analyzer** | Full site audit + SPF/DKIM/DMARC verification |
| **Process & Network Rites** | Process monitoring, active socket listing, CPU-based suspicious activity detection |
| **Scope System** | Flexible include/exclude regex filtering — keep the crosshairs on the target only |
| **History** | 10,000-record ring buffer of every exchange that passed through |
| **Plugin System** | Loads external `.so` plugins via `cogitator-plugin-api` |
| **Workspace Save/Load** | Full session state preservation into a `.cogitator` file |

---

## 🏛️ Architecture

```
cogitator/
├── main.rs              — entry point, TUI event loop, command dispatcher
├── proxy_guard.rs        — proxy server core, pipeline entry point
├── tls_mitm.rs            — cert generation/cache, CONNECT handling, ALPN/h2
├── interceptor.rs         — Frozen mode, operator decision queue
├── ws_interceptor.rs      — WebSocket codec and frame interception
├── history.rs             — request/response ring buffer
├── repeater.rs             — Repeater tabs, manual replay
├── scanner.rs              — ScanCheck trait, scan queue
│   └── checks/
│       ├── sqli.rs           — SQL injection (error-based)
│       ├── xss.rs             — Reflected/Stored XSS
│       └── traversal.rs       — Path Traversal
├── intruder.rs              — wordlist-based attacks
├── spider.rs                 — BFS crawler
├── scope.rs                   — regex include/exclude rules
├── session.rs                  — cookie jar save/restore
├── workspace.rs                 — session state serialization
├── plugin.rs                     — external .so plugin loading
├── crypto_forensic.rs             — TLS/cookie/HSTS audit
├── web_analyzer.rs                  — full site audit
├── scrap_analyze.rs                  — page metadata extraction
├── dns_guard.rs                       — SPF/DKIM/DMARC, DNS queries
├── network_guard.rs                    — active sockets + resolution
├── cve.rs                                — CVE lookup (cve.circl.lu)
├── styletui.rs                            — interface rendering (ratatui)
├── logger.rs                               — structured JSON logging
├── notifier.rs                              — system notifications
└── config.rs                                 — all magic numbers
```

The Machine Spirit runs on `tokio` — the async proxy core coexists with the synchronous TUI loop via `block_in_place`/`spawn_blocking`, never breaking the rhythm of the render liturgy.

---

## 🛠️ Installation

### Requirements

- Rust **1.80+** (2024 edition)
- Linux / macOS / Windows
- Permission to install a root certificate into the system trust store (required for HTTPS interception)

### Build from Source

```bash
git clone https://github.com/LeechoShoop/cogitator.git
cd cogitator
cargo build --release
```

The binary will be produced at `target/release/cogitator`.

```bash
./target/release/cogitator
```

---

## ⚡ Quick Start

1. **Launch Cogitator:**
   ```bash
   cogitator
   ```
2. **Start the proxy** (toggle on the main screen — listens by default on `127.0.0.1:8080`).
3. **Point your browser/curl** at the proxy: `127.0.0.1:8080`.
4. **Install the Cogitator CA certificate** (see below) — otherwise TLS will complain on every single site.
5. Review traffic in the `History` panel, freeze requests in `Interceptor`, send them to `Repeater`, and run `Scan-Site`.

```bash
curl -x http://127.0.0.1:8080 --cacert cogitator_ca.pem https://example.com
```

---

## 🕯️ Installing the Root Certificate (Export-CA)

Cogitator generates its own local CA (`cogitator_ca.pem` / `cogitator_ca.key`) on first run and signs leaf certificates on the fly for every domain traffic passes through.

Type into the TUI:

```
Export-CA
```

This copies `cogitator_ca.pem` into the working directory and prints installation instructions for your OS/browser trust store.

> ⚠️ **Litany of Caution:** only trust this CA on machines you personally control. Installing a third-party root certificate opens the door to interception of *any* HTTPS traffic on that machine.

---

## 📜 Sacred Commandments (Full Command List)

```
╔═══════════════════════════════════════════════════════╗
║       COGITATOR — SACRED COMMANDMENTS v0.6            ║
╠═══════════════════════════════════════════════════════╣
║  WEB FORENSICS                                         ║
║    Analyze-Site <dom>       Full audit (human)         ║
║    Analyze-Site-Json <dom>  Full audit (JSON export)   ║
║    Analyze-Email <dom>      SPF / DMARC / DKIM check   ║
╠═══════════════════════════════════════════════════════╣
║  TLS MITM                                              ║
║    Export-CA            Copy CA cert + install guide   ║
╠═══════════════════════════════════════════════════════╣
║  PROXY SCOPE                                           ║
║    Scope-Add <regex>     Restrict logging to matches   ║
║    Scope-Exclude <regex> Never log/analyze matches     ║
║    Scope-List            Show configured scope rules   ║
║    Scope-Clear           Remove all scope rules        ║
╠═══════════════════════════════════════════════════════╣
║  SESSIONS                                              ║
║    Session-Save <name>   Snapshot cookie jar as profile║
║    Session-Load <name>   Restore cookies from profile  ║
║    Session-List          List saved session profiles   ║
╠═══════════════════════════════════════════════════════╣
║  REPEATER                                              ║
║    Send-To-Repeater <id>  Open history record in tab   ║
╠═══════════════════════════════════════════════════════╣
║  SCANNER                                               ║
║    Scan-Site <domain>    Active-scan discovered forms  ║
║    Scan-Request <id>     Active-scan a history record  ║
║    Scan-Diff             Compare latest vs prior scan  ║
╠═══════════════════════════════════════════════════════╣
║  INTRUDER                                              ║
║    Fuzz <url> <wordlist>  Sniper-fuzz a §PAYLOAD§ URL  ║
║    Intruder-Load <file>  Load raw HTTP template (file) ║
╠═══════════════════════════════════════════════════════╣
║  SPIDER                                                ║
║    Spider <domain>        Crawl (depth 3, 500 pages)   ║
║    Spider-Depth <dom> <N> Crawl with explicit depth    ║
╠═══════════════════════════════════════════════════════╣
║  PROCESS RITES                                         ║
║    GP                   List all processes             ║
║    Find-Suspicious      Detect high CPU usage          ║
║    Exterminate <PID>    Purge a process                ║
║    GPP <PID>            Reveal process path            ║
╠═══════════════════════════════════════════════════════╣
║  NETWORK LITANIES                                      ║
║    Get-NIF              List network interfaces        ║
║    GC                   List active sockets + DNS      ║
╠═══════════════════════════════════════════════════════╣
║  WORKSPACE                                             ║
║    Workspace-Save [file]  Save state (.cogitator)      ║
║    Workspace-Load <file>  Restore state from file      ║
║    Workspace-New          Reset all in-memory state    ║
╠═══════════════════════════════════════════════════════╣
║  SYSTEM                                                ║
║    CG                   Clear log records              ║
║    help                 Display this holy mandate      ║
║    exit                 Appease the Machine Spirit      ║
╚═══════════════════════════════════════════════════════╝
```

> The full text of these commandments is always available in-app via `help`.

### Example Engagement

```
> Spider example.com
> Scan-Site example.com
> Scan-Diff
> Fuzz https://example.com/login?user=§PAYLOAD§ wordlists/usernames.txt
> Send-To-Repeater 42
> Export-CA
> Workspace-Save campaign-alpha.cogitator
```

---

## 🖥️ Terminal Interface

The TUI is built on `ratatui` and switches between six screens:

| Screen | Purpose |
|---|---|
| **Main** | Command line, event log, overview |
| **Interceptor** | History of exchanges / Frozen mode (pause and edit live requests and WS frames) |
| **Repeater** | Multi-tab manual HTTP request replay |
| **Scanner** | Active three-panel vulnerability scanner |
| **Intruder** | Wordlist attacks with Sniper/BatteringRam/Pitchfork/ClusterBomb modes |
| **Spider** | Live crawl overview with anomaly highlighting |

Inside `Interceptor`'s Frozen mode, every captured request is a prisoner awaiting the operator's verdict: **Forward** (release), **Drop** (execute), or **Modify** (rewrite the sacred text of headers and body before sending).

---

## 🔌 Plugins (Extending the Machine Spirit)

Cogitator supports external plugins through a separate `cogitator-plugin-api` crate:

- A shared trait defining the plugin contract, with versioned ABI
- An `export_plugin!` macro for registration
- Built-in plugins auto-register via `inventory`
- External `.so` plugins are loaded dynamically via `libloading`

This means you can chain your own analysis module onto Cogitator without touching the core — the Machine Spirit accepts a new rite as if it were born with it.

---

## 💾 Workspace: Saving State

A long campaign against a target shouldn't end when you close the terminal.

```
Workspace-Save campaign.cogitator
Workspace-Load campaign.cogitator
Workspace-New
```

A snapshot includes: history, scope rules, sessions, scan snapshots (for `Scan-Diff`), and other accumulated knowledge of the target.

You can also open a campaign archive directly at launch:

```bash
cogitator campaign.cogitator
```

---

## ⚠️ Disclaimer (Litany of Caution)

> *"Do not point this instrument at a target for which thou hast no sanction from thy master."*

Cogitator is built **exclusively** for:

- authorized penetration testing,
- security research and education,
- auditing your own infrastructure.

Unauthorized interception of someone else's traffic, scanning systems you don't own, or running MITM attacks against third parties is **illegal** in most jurisdictions. The author bears no responsibility for misuse of this tool. Heresy is punished by law, not only by the Inquisition.

---

## 🗺️ Roadmap

- [ ] Expand the active check library (SSRF, XXE, command injection)
- [ ] Improved Scan-Diff visualization
- [ ] Distributed scanning across multiple nodes
- [ ] HTML/PDF report export
- [ ] *(AI-assisted analysis — deferred until core functionality is complete)*

---

## 🤝 Contributing

PRs and issues are welcome. Before submitting code:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

Every new module is a new chapter in the Book of Knowledge. The codex honors cleanliness, explicit errors over silent panics, and magic numbers living only in `config.rs`.

---

<p align="center">
<i>Machine Spirit awakened. Proxy litanies recited. The Omnissiah is pleased.</i><br>
⚙️ <b>COGITATOR</b> — knowledge through interception ⚙️
</p>
