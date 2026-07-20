# Distributed scanning — setup notes

This feature adds three new files to the root crate (`src/lib.rs`,
`src/worker_protocol.rs`, `src/distributed.rs`), a new `mod` pair in
`main.rs` (`worker_protocol`, `distributed`), `Serialize`/`Deserialize`
derives on `scanner::{ScanTarget, ScanFinding, Severity}`, and a brand new
workspace member crate, `cogitator-worker/`.

One manual step is required that I couldn't do myself, since the actual
root `Cargo.toml` wasn't part of what I was given:

## 1. Add `cogitator-worker` to the workspace

In the root `Cargo.toml`, add it alongside `cogitator-plugin-api` and
`example-plugin`:

```toml
[workspace]
members = [
    ".",
    "cogitator-plugin-api",
    "example-plugin",
    "cogitator-worker",
]
```

No other root `Cargo.toml` changes are needed — Cargo auto-detects both
`src/main.rs` and the new `src/lib.rs` as the bin and lib targets of the
same package, so the TUI binary keeps building exactly as before.

## 2. Double-check `cogitator-worker`'s dependency versions

`cogitator-worker/Cargo.toml` has a comment explaining which version
choices are confirmed against the existing codebase (`reqwest`'s `"json"`
feature, `serde`/`serde_json`) versus which are this crate's own pick and
worth double-checking against the root crate's actual pinned versions
(`tokio`, `axum`) before the first `cargo build`.

## 3. Run a worker

```bash
COGITATOR_WORKER_TOKEN=changeme cargo run -p cogitator-worker
# optional: COGITATOR_WORKER_BIND=0.0.0.0:9500 (default shown)
```

Start as many as you like, on as many hosts as you like, each with the
*same* `COGITATOR_WORKER_TOKEN`.

## 4. Run a distributed scan from the TUI

In the simplest setup (shared token), export it in the same shell the TUI runs in:

```bash
export COGITATOR_WORKER_TOKEN=changeme
```

*Note: The underlying `distributed.rs` client now also supports per-worker tokens via `WorkerTokenConfig::PerWorker(HashMap<String, String>)`. When wired into `main.rs`, this will allow different trust zones/tokens for different worker URLs rather than relying on a single shared secret.*

then, inside Cogitator:

```
Scan-Site-Distributed example.com 127.0.0.1:9500,127.0.0.1:9501
```

Targets discovered via `Analyze-Site` are split round-robin across the
listed workers, every worker runs all six checks against its share, and the
aggregated findings land in `scan_snapshots` exactly like a local
`Scan-Site` run — visible on the Scanner/Findings screens,
`Scan-Diff`-able, and included in `Report-Generate`/`Report-Generate-Pdf`.

Bare `host:port` addresses are accepted (normalized to `http://host:port`);
`http://`/`https://` prefixes are left as-is.