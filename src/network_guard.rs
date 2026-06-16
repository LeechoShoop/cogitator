use netstat2::*;
use sysinfo::System;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use lazy_static::lazy_static;

const DNS_TTL: Duration = Duration::from_secs(300); // 5 minutes

// Cache value is (resolved_hostname, time_of_insertion).
lazy_static! {
    static ref DNS_CACHE: Arc<Mutex<HashMap<IpAddr, (String, Instant)>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

// ── Public sync entry-point (for use inside process_pipeline) ────────────────
//
// process_pipeline is a plain fn called from the synchronous TUI event loop.
// tokio::task::block_in_place lets us run blocking work on the current thread
// without starving the Tokio runtime — safe because we are always called from
// within a tokio::runtime::Runtime (created in main).
pub fn get_active_connections(sys: &System) -> String {
    tokio::task::block_in_place(|| get_active_connections_blocking(sys))
}

// ── Public async entry-point ─────────────────────────────────────────────────
//
// Prefer this when calling from an async context (e.g. a future or task).
pub async fn get_active_connections_async(sys: Arc<System>) -> String {
    tokio::task::spawn_blocking(move || get_active_connections_blocking(&sys))
        .await
        .unwrap_or_else(|e| format!("Error: spawn_blocking panicked: {e}"))
}

// ── Internal sync implementation (runs on a blocking thread) ─────────────────
fn get_active_connections_blocking(sys: &System) -> String {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

    let sockets_info = match get_sockets_info(af_flags, proto_flags) {
        Ok(s) => s,
        Err(_) => return "Error: Access Denied. Run as Administrator to see PIDs.".to_string(),
    };

    // ── Phase 1: collect all TCP remote IPs that are cache-misses ────────────
    //
    // We resolve all misses BEFORE we start building the output string so that
    // we never call the blocking resolver while holding the Mutex (which would
    // deadlock if resolve_ip ever tried to acquire it, and is just bad practice
    // regardless).
    let miss_ips: Vec<IpAddr> = {
        let cache = DNS_CACHE.lock().unwrap();
        let now = Instant::now();

        sockets_info
            .iter()
            .filter_map(|s| {
                if let ProtocolSocketInfo::Tcp(tcp) = &s.protocol_socket_info {
                    let ip = tcp.remote_addr;
                    if !ip.is_loopback() && !ip.is_unspecified() && tcp.remote_port != 0 {
                        // Is it a cache miss (or stale)?
                        let stale = cache
                            .get(&ip)
                            .map(|(_, t)| now.duration_since(*t) >= DNS_TTL)
                            .unwrap_or(true);
                        if stale { return Some(ip); }
                    }
                }
                None
            })
            .collect::<std::collections::HashSet<_>>() // deduplicate
            .into_iter()
            .collect()
    };

    // Resolve misses (blocking DNS calls) without holding the cache lock.
    let resolved: HashMap<IpAddr, String> = miss_ips
        .into_iter()
        .map(|ip| {
            let hostname = crate::dns_guard::resolve_ip(ip);
            (ip, hostname)
        })
        .collect();

    // ── Phase 2: write resolved entries back into the cache ──────────────────
    {
        let mut cache = DNS_CACHE.lock().unwrap();
        let now = Instant::now();

        // Evict stale entries first.
        cache.retain(|_, (_, inserted_at)| now.duration_since(*inserted_at) < DNS_TTL);

        for (ip, hostname) in resolved {
            cache.insert(ip, (hostname, now));
        }
    }

    // ── Phase 3: build output string using the (now-warm) cache ──────────────
    let mut output = format!(
        "{:<25} | {:<20} | {:<30} | {}\n",
        "PROCESS (PID)", "LOCAL", "REMOTE (DOMAIN)", "STATE"
    );
    output.push_str(&"-".repeat(105));
    output.push('\n');

    let cache = DNS_CACHE.lock().unwrap();

    for s in sockets_info {
        let pid_num = s.associated_pids.first().copied().unwrap_or(0);

        let proc_name = if pid_num == 0 {
            "[System/Hidden]".to_string()
        } else {
            sys.process(sysinfo::Pid::from(pid_num as usize))
                .map(|p| p.name().to_string_lossy().into_owned())
                .unwrap_or_else(|| "Unknown".to_string())
        };

        let proc_display = format!("{} ({})", proc_name, pid_num);

        match s.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => {
                let remote_ip = tcp.remote_addr;
                let remote_host = if remote_ip.is_loopback() || remote_ip.is_unspecified() {
                    "localhost".to_string()
                } else if tcp.remote_port == 0 {
                    "---".to_string()
                } else {
                    cache
                        .get(&remote_ip)
                        .map(|(h, _)| h.clone())
                        .unwrap_or_else(|| remote_ip.to_string()) // should never miss after phase 2
                };

                output.push_str(&format!(
                    "{:<25} | {:<20} | {:<30} | {:?}\n",
                    proc_display,
                    format!("{}:{}", tcp.local_addr, tcp.local_port),
                    format!("{}:{}", remote_host, tcp.remote_port),
                    tcp.state
                ));
            }
            ProtocolSocketInfo::Udp(udp) => {
                output.push_str(&format!(
                    "{:<25} | {:<20} | {:<30} | {:<20}\n",
                    proc_display,
                    format!("{}:{}", udp.local_addr, udp.local_port),
                    "---",
                    "Listening"
                ));
            }
        }
    }

    output
}