# 👁️ Cogitator

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org)
[![Edition](https://img.shields.io/badge/edition-2024-red.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#)

**Cogitator** is a specialized asynchronous Terminal User Interface (TUI) tool built in Rust for passive web forensics, OSINT reconnaissance, network connection auditing, and real-time operating system process tracking.

The application combines a modular vulnerability scanner, a mail infrastructure security validator (SPF/DMARC/DKIM), an active socket mapper, and a background intercepting HTTP proxy-guard that generates live forensic analysis reports. The interface is designed with a dark, cybernetic *Adeptus Mechanicus* grimdark aesthetic.

---

## ⚡ Core Functionality

### 🌐 1. Modular Web Forensics & OSINT
Through a unified abstraction layer (`SiteAnalyzer`), the tool runs multi-factor passive security audits against target endpoints:
* **HTML & Secret Carving (`scrap_analyze`):** Detects hidden form input fields, potential XSS/SQLi vectors, open redirect signatures, exposed JS frameworks, and extracts leaked API keys or credentials (Google Cloud APIs, Bearer JWT tokens, and private secrets).
* **Crypto & Headers (`crypto_forensic`):** Scores `CSP` (Content Security Policy) rules, validates `HSTS` parameters, checks for legacy configurations (HPKP), and scrutinizes `Set-Cookie` tracking parameters for essential security flags (`HttpOnly`, `Secure`, `SameSite`) as well as embedded JWT session structures.
* **Email Security Matrix (`dns_guard`):** Queries DNS to verify domain anti-spoofing compliance via `SPF` and `DMARC` policies while probing common `DKIM` selectors to identify spoofing vulnerabilities.

### 🛡️ 2. Intercepting HTTP Proxy-Guard
* A local asynchronous HTTP proxy server driven by **Hyper / Tokio**, listening natively on `127.0.0.1:8080`.
* **Automated Forensic Reporting:** As client traffic flows through the proxy, Cogitator interceptors run a non-intrusive runtime scan on the target host and immediately persist an isolation report named `[domain]_proxy_report.txt`.
* **Traffic Control & Rate Limiting:** Equipped with a thread-safe sliding-window rate limiter to guard the engine, flag anomalies, and block local flood/DoS vectors.

### 🖥️ 3. System Telemetry & Network Monitoring (System Rites)
* **Process Ledger:** Monitors active processes, tracks execution binaries, and exposes the `Exterminate` command to kill malicious or hanging tasks (Kill by PID) straight from the TUI console.
* **Network Sockets:** Aggregates current TCP/UDP sockets, binds connection targets to their parent PIDs, and runs background reverse DNS mapping using a non-blocking cache layer to avoid interface lag.
* **Watchdog Alerts:** A lightweight background thread monitors OS health parameters, throwing native desktop OS alerts via `notify-rust` if CPU usage scales past a critical baseline (CPU > 80%).

---

## 🏗️ Architecture & Code Repository Layout

The system is engineered following loose-coupling principles to support independent subsystem testability (e.g., via the `SiteAnalyzer` trait seams):
src/
├── main.rs            # Entry-point, manages Tokio runtime, TUI event loop & pipeline execution
├── config.rs          # Central configuration matrix (magic constants, timeouts, ports, limits)
├── web_analyzer.rs    # Core orchestrator: defines the SiteAnalyzer trait and aggregates sub-scanners
├── scrap_analyze.rs   # Scraper-based HTML parsing, CSP validation, and regex Secret Carving
├── crypto_forensic.rs # SSL/HSTS header evaluation and deep Cookie crypto forensics
├── dns_guard.rs       # Async DNS client (Hickory Client) verifying SPF/DMARC/DKIM records
├── proxy_guard.rs     # Low-level Hyper proxy implementation handling request/response pipelines
├── interceptor.rs     # Thread-safe Sliding-Window Rate Limiter engine
├── network_guard.rs   # Cross-platform socket discovery (Netstat2) with integrated DNS caching
├── styletui.rs        # Custom interface styling (Ratatui), Popups, and the Omnissiah color palette
├── logger.rs          # Structured JSON logging (Tracing-Subscriber) with hot rotatable streams
└── notifier.rs        # Cross-platform desktop alert bridge (Notify-Rust)
---

## ⚙️ Interactive TUI Commands (Sacred Commandments)

Submit these actions inside the console command buffer located at the `[ ENTER BINARY CANTICLE ]` prompt:

* **`Analyze-Site <domain>`** — Runs a comprehensive passive web security audit and displays a human-readable summary.
* **`Analyze-Site-Json <domain>`** — Processes the passive audit and outputs the structured telemetry as raw JSON payload.
* **`Analyze-Email <domain>`** — Targets specific DNS endpoints to map mail protection vectors (SPF, DMARC, DKIM).
* **`GP`** — Renders an interactive process matrix detailing current tasks executing on the operating system.
* **`Find-Suspicious`** — Isolates and filters tasks currently violating regular CPU constraints.
* **`GPP <PID>`** — Resolves and displays the exact physical filesystem path of an executing binary by its PID.
* **`Exterminate <PID>`** — Instantly terminates (kills) the specified process inside the operating system layer.
* **`GC`** — Pulls the active network socket board mapped against PIDs and remote hostnames with reverse DNS resolution.
* **`Get-NIF`** — Inspects and lists all available physical and logical network interfaces on the local machine.
* **`CG`** — Truncates the `cogitator.log` JSON registry cleanly on the fly without locking active asynchronous streams.
* **`help`** — Displays the command index scroll within an interactive console popup.
* **`exit`** — Safely unbinds proxies, releases terminal configurations, and terminates the application cleanly.

---

## 📦 Building & Running From Source

### Prerequisites
* **Rust Toolchain** (**Edition 2024**, Stable release 1.75 or newer)
* Package manager and compiler companion `cargo`

Execution
Bash
cargo run --release
Note: The proxy listener defaults to 127.0.0.1:8080. Hardcoded telemetry boundaries, thresholds, and execution ports can be reconfigured directly within src/config.rs before compilation.

🔒 Legal Disclaimer
Cogitator is an educational pentesting tool built for security monitoring, passive architectural audits, configuration verification, and legitimate white-hat testing. The author assumes no liability for illicit operations, unauthorized interception of local proxy traffic, or damage caused by misconfiguring systemic parameters outside compliance scopes.
