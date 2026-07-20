<div align="center">
  
# ⚙️ COGITATOR OS v0.9

**Knowledge is power, and power must be sanctified.**<br>
*— Principia Technologica, Om 4:12*

[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Win-lightgrey.svg?style=flat-square)](#)

**Cogitator** is a terminal-based (TUI) web security toolkit, TLS MITM intercepting proxy, and automated vulnerability scanner written entirely in Rust. Designed conceptually like Burp Suite but engineered for terminal purists, it offers deep insight into HTTP/HTTPS and WebSocket traffic without leaving the command line.

</div>

---

## 🔱 Core Capabilities

Cogitator integrates a multitude of offensive and analytical modules into a single `tokio`-driven binary. All modules operate under a unified TUI built with `ratatui`.

| 🛡️ Module | 🎯 Purpose |
| :--- | :--- |
| **TLS MITM Proxy** | Intercepts HTTP/1.1 and HTTP/2 (ALPN) traffic. Signs certificates on-the-fly using a generated local CA. |
| **WebSocket Interceptor** | Captures, decodes (RFC 6455), and allows real-time manipulation of WebSocket frames. |
| **Interceptor (Frozen Mode)** | Pauses live proxy traffic. Operators can *Forward*, *Drop*, or *Modify* headers/bodies before they hit the wire. |
| **Repeater** | A multi-tab environment for taking historical requests, modifying them manually, and replaying them. |
| **Active Scanner** | Discovers vulnerabilities automatically (SQLi, XSS, Path Traversal) with a concurrent, rate-limited execution engine. |
| **Distributed Scanner**| Offloads active scanning tasks to remote `cogitator-worker` nodes. See [`distributed scanning setup.md`](distributed%20scanning%20setup.md). |
| **Scan Diff** | Compares active scan results across multiple runs to track regressions or newly patched vulnerabilities. |
| **Intruder** | Payload fuzzer supporting Sniper, Battering Ram, Pitchfork, and Cluster Bomb attack types via custom wordlists. |
| **Spider** | BFS crawler that extracts links and forms, respects `robots.txt`, and features an optional **headless browser (JS)** engine (via `chromiumoxide`) for crawling SPAs. |
| **Web/Email Analyzer** | Comprehensive OSINT and passive auditing, including SPF/DKIM/DMARC checks. |
| **Crypto & Forensics** | Passive audits of TLS configurations, HSTS, HPKP, and JWT tokens, assigning A–F security grades. |
| **CVE Lookup** | Correlates detected service banners against `cve.circl.lu` for known CVEs. |
| **Scope Engine** | Regex-based Include/Exclude routing to ensure scans and interceptions only target authorized domains. |
| **History & Sessions** | A 10,000-record ring buffer for traffic, plus named Session Profiles to save and restore `CookieJars`. |
| **Plugin API** | Extensible architecture allowing external `.so` / `.dll` Rust modules to inject custom scan hooks. |
| **Workspace Vault** | Serializes the entire campaign (history, scope, sessions, findings) to an encrypted/compressed `.cogitator` state file. |

---

## ⚡ Installation & Quick Start

### 📋 Requirements
- **Rust 1.80+** (2024 edition)
- **Chrome / Chromium** installed locally *(only required if using the Spider's `--js` headless crawling)*

### 🛠️ Build
```bash
git clone https://github.com/<your-username>/cogitator.git
cd cogitator
cargo build --release
```

### 🚀 Launch
Run the binary to enter the TUI. By default, the proxy listens on `127.0.0.1:8080`. Point your browser or `curl` to this proxy.
```bash
./target/release/Cogitator
```

### 🔑 CA Certificate Installation
To intercept HTTPS traffic without browser errors, you must install the Cogitator Root CA. In the TUI command line, type:
```
Export-CA
```
This drops a `cogitator_ca.pem` file in your directory with instructions on how to install it in your OS/browser trust store.<br>
> ⚠️ **Warning:** Only trust this CA on environments you completely own and control.

---

## 📜 Sacred Commandments (TUI Commands)

The TUI accepts commands at the bottom prompt. Use `Tab` to cycle between screens (Main, Interceptor, Repeater, Scanner, Intruder, Spider).

<details open>
<summary><b>Click to view all commands</b></summary>

```text
╔═══════════════════════════════════════════════════════╗
║       COGITATOR — SACRED COMMANDMENTS v0.9            ║
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
║    Scan-Site-Distributed Active-scan using remote nodes║
║    Scan-Request <id>     Active-scan a history record  ║
║    Scan-Diff             Compare latest vs prior scan  ║
╠═══════════════════════════════════════════════════════╣
║  INTRUDER                                              ║
║    Fuzz <url> <wordlist>  Sniper-fuzz a §PAYLOAD§ URL  ║
║    Intruder-Load <file>  Load raw HTTP template (file) ║
╠═══════════════════════════════════════════════════════╣
║  SPIDER                                                ║
║    Spider <domain> [--js] Crawl (depth 3, 500 pages)   ║
║    Spider-Depth <dom> <N> [--js] Explicit depth        ║
╠═══════════════════════════════════════════════════════╣
║  WORKSPACE                                             ║
║    Workspace-Save [file]  Save state (.cogitator)      ║
║    Workspace-Load <file>  Restore state from file      ║
║    Workspace-New          Reset all in-memory state    ║
╠═══════════════════════════════════════════════════════╣
║  SYSTEM / PIPELINE                                     ║
║    GP                   List all processes             ║
║    Find-Suspicious      Detect high CPU usage          ║
║    Exterminate <PID>    Purge a process                ║
║    GPP <PID>            Reveal process path            ║
║    Get-NIF              List network interfaces        ║
║    GC                   List active sockets + DNS      ║
║    CG                   Clear log records              ║
║    help                 Display this holy mandate      ║
║    exit                 Appease the Machine Spirit      ║
╚═══════════════════════════════════════════════════════╝
```
</details>

### 🎯 Example Usage Flow
```text
> Scope-Add ^https://target\.com
> Spider target.com --js
> Scan-Site target.com
> Send-To-Repeater 42
> Workspace-Save target_campaign.cogitator
```

---

## 🏛️ Architecture & Crates

Cogitator is designed as a Cargo workspace with a clear separation of concerns between its API, background workers, and the monolithic core engine.

### 📦 Workspace Crates
- **`cogitator-plugin-api`**: The stable FFI interface defining the `CogitatorPlugin` trait. Acts as the unyielding contract that external `.so`/`.dll` plugins must implement to hook into the proxy lifecycle.
- **`example-plugin`**: A reference implementation demonstrating how to build a dynamic library that integrates with Cogitator.
- **`cogitator-worker`**: Contains background data structures and detached worker threads that offload heavy computations from the main asynchronous runtime. For setup and usage, see [**distributed scanning setup.md**](distributed%20scanning%20setup.md).

### 🧠 Core Engine (`src/`)

<details>
<summary><b>1. Core Event Loop & Networking</b></summary>
<br>

- **`main.rs`**: The heart of the Machine Spirit. Initializes the `tokio` runtime, the `ratatui` event loop, and coordinates shared state.
- **`proxy_guard.rs`**: The main TCP listener for the HTTP/HTTPS proxy. Handles routing and connection flows.
- **`tls_mitm.rs`**: The Man-In-The-Middle engine. Automatically generates a local Root CA (`cogitator_ca.pem`), intercepts `CONNECT` requests, negotiates ALPN, and signs spoofed certificates on-the-fly.
- **`ws_interceptor.rs`**: Implements the RFC 6455 WebSocket protocol to intercept, parse, and allow modification of live WS frames.
</details>

<details>
<summary><b>2. User Interface & State</b></summary>
<br>

- **`styletui/`**: Manages the multi-screen terminal interface (Main, Interceptor, Repeater, Scanner, Intruder, Spider).
- **`commands/`**: A table-driven router parsing user input from the TUI prompt and dispatching it to specific subsystem handlers.
- **`logger.rs`**: A structured JSON and plaintext logging engine.
</details>

<details>
<summary><b>3. Traffic Analysis & Manipulation</b></summary>
<br>

- **`history.rs`**: A 10,000-record ring buffer saving every request/response that passes through the proxy.
- **`interceptor.rs`**: Pauses live proxy traffic (Frozen Mode) for the operator to forward, drop, or rewrite.
- **`repeater.rs`**: Allows the operator to take a historical request and manually tweak it before resending.
- **`session.rs`**: Manages the `CookieJar` and session profiles.
- **`scope.rs`**: A Regex-based filtering engine that dictates what traffic the proxy should log or ignore.
</details>

<details>
<summary><b>4. Automated Offensive Modules</b></summary>
<br>

- **`scanner.rs` & `checks/`**: Active vulnerability scanning engine (SQLi, XSS, Path Traversal).
- **`intruder.rs`**: Fuzzer and bruteforcer supporting Sniper, Battering Ram, Pitchfork, and Cluster Bomb attack models.
- **`spider/`**: A multi-threaded Breadth-First Search (BFS) crawler with `robots.txt` support and an optional **headless browser engine (`chromiumoxide`)**.
</details>

<details>
<summary><b>5. Passive Recon & Forensics</b></summary>
<br>

- **`web_analyzer/` & `scrap_analyze.rs`**: Pulls HTML metadata, audits security headers, and detects potential secrets in source code.
- **`crypto_forensic.rs`**: Audits TLS connection parameters, HSTS/HPKP headers, and JWT tokens (A–F grades).
- **`dns_guard.rs` & `network_guard.rs`**: OSINT (SPF, DKIM, DMARC), active network sockets, and suspicious CPU activity monitoring.
- **`cve.rs`**: Connects to `cve.circl.lu` to find known vulnerabilities for service banners.
</details>

<details>
<summary><b>6. Persistence</b></summary>
<br>

- **`workspace/` & `vault.rs`**: Serializes the campaign state (history, scope, sessions, findings) and encrypts/compresses it into a portable `.cogitator` archive.
</details>

---

<div align="center">
  <i>"Do not point this instrument at a target for which thou hast no sanction from thy master."</i><br><br>
  <b>Built for authorized penetration testing and security research only.</b>
</div>