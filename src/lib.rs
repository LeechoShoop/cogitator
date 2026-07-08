//! Library surface of the `cogitator` crate.
//!
//! This exists solely so `cogitator-worker` (a separate workspace crate —
//! see `../cogitator-worker`) can link against the *exact same*
//! `ScanCheck` implementations the TUI binary (`main.rs`) uses, with no
//! duplicated source and no changes to those files.
//!
//! Every module below is declared with an explicit `#[path]` pointing at
//! the identical `.rs` file `main.rs`'s own `mod` declarations already
//! compile — this is a second *module tree* over the same source files,
//! not a fork of them. `main.rs` keeps its own `mod scanner;`, `mod
//! checks;`, etc. exactly as before; this file changes nothing about how
//! the TUI binary itself compiles or behaves. (Cargo auto-detects both
//! `src/main.rs` and `src/lib.rs` in one package as the bin and lib
//! targets respectively — no `Cargo.toml` changes needed for that part.)
//!
//! Only the closure of modules an active-scan `ScanCheck` actually needs
//! is exposed here: `scanner` (the trait + `ScanTarget`/`ScanFinding`),
//! the six vulnerability checks that implement it, and their `logger`/
//! `config`/`oob` dependencies. Deliberately **excluded**: `checks::
//! intruder` (not a `ScanCheck` — it depends on `session::apply_profile`,
//! which would drag cookie-jar/session-profile machinery that has nothing
//! to do with running a check into the worker binary), and everything
//! proxy/TUI-related (`history`, `proxy_guard`, `styletui`, `workspace`,
//! `vault`, `plugin`, ...).
//!
//! `worker_protocol` (the JSON wire format shared between the coordinator's
//! `Scan-Site-Distributed` command and `cogitator-worker`'s HTTP API) is
//! exposed the same way, for the same reason: one file, two module trees,
//! so the coordinator and every worker are provably speaking the same
//! shape without hand-syncing two copies.

#[path = "logger.rs"]
pub mod logger;

#[path = "config.rs"]
pub mod config;

#[path = "oob.rs"]
pub mod oob;

#[path = "scanner.rs"]
pub mod scanner;

#[path = "worker_protocol.rs"]
pub mod worker_protocol;

/// Slimmed-down mirror of `checks/mod.rs`: the same six `ScanCheck`
/// implementations, each reused byte-for-byte via `#[path]`, minus
/// `intruder` — see the module-level docs above for why.
pub mod checks {
    #[path = "sqli.rs"]
    pub mod sqli;
    #[path = "sqli_blind.rs"]
    pub mod sqli_blind;
    #[path = "traversal.rs"]
    pub mod traversal;
    #[path = "xss.rs"]
    pub mod xss;
    #[path = "ssrf.rs"]
    pub mod ssrf;
    #[path = "xxe.rs"]
    pub mod xxe;
}