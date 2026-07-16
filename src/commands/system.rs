//! `help` handler — wraps the sacred commandments text.

use super::CommandContext;

// ── help ──────────────────────────────────────────────────────────────────────

pub fn help(ctx: &mut CommandContext<'_>) {
    *ctx.output_buffer = get_help_text();
    *ctx.scroll_offset = 0;
}

fn get_help_text() -> String {
    "╔═══════════════════════════════════════════════════════╗\n\
     ║       COGITATOR — SACRED COMMANDMENTS v0.8.5          ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  WEB FORENSICS                                        ║\n\
     ║    Analyze-Site <dom>       Full audit (human)        ║\n\
     ║    Analyze-Site-Json <dom>  Full audit (JSON export)  ║\n\
     ║    Analyze-Email <dom>      SPF / DMARC / DKIM check  ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  TLS MITM                                             ║\n\
     ║    Export-CA            Copy CA cert + install guide  ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  PROXY SCOPE                                          ║\n\
     ║    Scope-Add <regex>     Restrict logging to matches  ║\n\
     ║    Scope-Exclude <regex> Never log/analyze matches    ║\n\
     ║    Scope-List            Show configured scope rules  ║\n\
     ║    Scope-Clear           Remove all scope rules       ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  SESSIONS                                             ║\n\
     ║    Session-Save <name>   Snapshot cookie jar as profile║\n\
     ║    Session-Load <name>   Restore cookies from profile ║\n\
     ║    Session-List          List saved session profiles  ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  REPEATER                                             ║\n\
     ║    Send-To-Repeater <id>  Open history record in tab  ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  SCANNER                                              ║\n\
     ║    Scan-Site <domain>    Active-scan discovered forms ║\n\
     ║    Scan-Request <id>     Active-scan a history record ║\n\
     ║    Scan-Diff             Compare latest vs prior scan ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  INTRUDER                                             ║\n\
     ║    Fuzz <url> <wordlist>  Sniper-fuzz a §PAYLOAD§ URL ║\n\
     ║    Intruder-Load <file>  Load raw HTTP template (file)║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  SPIDER                                               ║\n\
     ║    Spider <domain>        Crawl (depth 3, 500 pages)  ║\n\
     ║    Spider-Depth <dom> <N> Crawl with explicit depth   ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  PROCESS RITES                                        ║\n\
     ║    GP                   List all processes            ║\n\
     ║    Find-Suspicious      Detect high CPU usage         ║\n\
     ║    Exterminate <PID>    Purge a process               ║\n\
     ║    GPP <PID>            Reveal process path           ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  NETWORK LITANIES                                     ║\n\
     ║    Get-NIF              List network interfaces       ║\n\
     ║    GC                   List active sockets + DNS     ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  WORKSPACE                                            ║\n\
     ║    Workspace-Save [file]  Save state (.cogitator)     ║\n\
     ║    Workspace-Load <file>  Restore state from file     ║\n\
     ║    Workspace-New          Reset all in-memory state   ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  SYSTEM                                               ║\n\
     ║    CG                   Clear log records             ║\n\
     ║    help                 Display this holy mandate     ║\n\
     ║    exit                 Appease the Machine Spirit    ║\n\
     ╚═══════════════════════════════════════════════════════╝"
        .to_string()
}
