//! Pipeline processor: `Value`, `PipelineData`, `format_pretty`, and
//! `process_pipeline` — previously top-level items in `main.rs`.
//!
//! Pipeline commands (`GP`, `CG`, `GC`, `GPP`, `Get-NIF`, `Find-Suspicious`,
//! `Select-Object`, `Exterminate`) use a data-flow model distinct from the
//! one-shot TUI commands: they chain structured data through a `PipelineData`
//! vector and format it at the end.  The engine stays intact here; adding a
//! new pipeline command is a single new `match` arm.

use std::collections::HashMap;

use sysinfo::{Pid, System};

use crate::{config, logger, network_guard};

// ── Value / PipelineData ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Value {
    Text(String),
    Int(i32),
    Object(HashMap<String, Value>),
}

pub type PipelineData = Vec<Value>;

// ── format_pretty ─────────────────────────────────────────────────────────────

pub fn format_pretty(data: &PipelineData) -> String {
    if data.is_empty() {
        return "No data found.".to_string();
    }
    data.iter()
        .map(|item| match item {
            Value::Object(map) => {
                let mut parts = Vec::new();
                for (key, val) in map {
                    let val_str = match val {
                        Value::Text(s)   => s.clone(),
                        Value::Int(i)    => i.to_string(),
                        Value::Object(_) => "Nested Object".to_string(),
                    };
                    parts.push(format!("{}: {}", key, val_str));
                }
                parts.join(" | ")
            }
            _ => format!("{:?}", item),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ── process_pipeline ──────────────────────────────────────────────────────────

/// Execute a pipeline expression (commands separated by `|`).
///
/// Returns a formatted string suitable for assignment to `output_buffer`.
pub fn process_pipeline(input: &str, sys: &System) -> String {
    let stages: Vec<&str> = input.split('|').map(|s| s.trim()).collect();
    let mut current_data: PipelineData = Vec::new();

    for stage in stages {
        let mut parts = stage.split_whitespace();
        let cmd = parts.next().unwrap_or("");
        let args: Vec<&str> = parts.collect();

        match cmd {
            // ── GP ────────────────────────────────────────────────────────────
            "GP" => {
                current_data = sys
                    .processes()
                    .iter()
                    .map(|(pid, proc)| {
                        let mut map = HashMap::new();
                        map.insert("Name".to_string(), Value::Text(proc.name().to_string_lossy().into_owned()));
                        map.insert("Id".to_string(),   Value::Int(pid.as_u32() as i32));
                        map.insert("CPU".to_string(),  Value::Int(proc.cpu_usage() as i32));
                        Value::Object(map)
                    })
                    .collect();
            }

            // ── CG ────────────────────────────────────────────────────────────
            "CG" => {
                return match logger::clear_log() {
                    Ok(_)  => "✅ Log cleared. All records purged.".to_string(),
                    Err(_) => "❌ Error: Failed to clear logs.".to_string(),
                };
            }

            // ── GC ────────────────────────────────────────────────────────────
            "GC" => {
                return network_guard::get_active_connections(sys);
            }

            // ── GPP ───────────────────────────────────────────────────────────
            "GPP" => {
                if args.len() == 1 {
                    let pid_val: usize = args[0].parse().unwrap_or(0);
                    let pid = sysinfo::Pid::from(pid_val);
                    return match sys.process(pid) {
                        Some(proc) => {
                            let path = proc
                                .exe()
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_else(|| "Access Denied / Path Unknown".to_string());
                            format!("🗂️  Process {} → {}", pid_val, path)
                        }
                        None => format!("❌ Process {} not found.", pid_val),
                    };
                }
                return "Usage: GPP <PID>".to_string();
            }

            // ── Get-NIF ───────────────────────────────────────────────────────
            "Get-NIF" => {
                current_data.clear();
                let networks = sysinfo::Networks::new_with_refreshed_list();
                for (interface_name, data) in &networks {
                    let mut net_map = HashMap::new();
                    net_map.insert(
                        "Interface".to_string(),
                        Value::Text(interface_name.clone()),
                    );
                    let ips = data
                        .ip_networks()
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    net_map.insert(
                        "IPs".to_string(),
                        Value::Text(if ips.is_empty() { "—".to_string() } else { ips }),
                    );
                    net_map.insert(
                        "MAC".to_string(),
                        Value::Text(format!("{}", data.mac_address())),
                    );
                    current_data.push(Value::Object(net_map));
                }
            }

            // ── Find-Suspicious ───────────────────────────────────────────────
            "Find-Suspicious" => {
                current_data = sys
                    .processes()
                    .iter()
                    .filter(|(_, p)| p.cpu_usage() > config::CPU_SUSPICIOUS_THRESHOLD)
                    .map(|(pid, proc)| {
                        let mut map = HashMap::new();
                        map.insert("Name".to_string(),   Value::Text(proc.name().to_string_lossy().into_owned()));
                        map.insert("CPU%".to_string(),   Value::Int(proc.cpu_usage() as i32));
                        map.insert("Status".to_string(), Value::Text("⚠️  SUSPICIOUS".to_string()));
                        map.insert("PID".to_string(),    Value::Int(pid.as_u32() as i32));
                        Value::Object(map)
                    })
                    .collect();

                if current_data.is_empty() {
                    return "✅ No suspicious processes found. The Machine Spirit is calm.".to_string();
                }
            }

            // ── Select-Object ─────────────────────────────────────────────────
            "Select-Object" => {
                if !args.is_empty() {
                    let prop = args[0];
                    current_data = current_data
                        .into_iter()
                        .filter_map(|val| {
                            if let Value::Object(mut map) = val {
                                if let Some(v) = map.remove(prop) {
                                    let mut new_map = HashMap::new();
                                    new_map.insert(prop.to_string(), v);
                                    return Some(Value::Object(new_map));
                                }
                            }
                            None
                        })
                        .collect();
                }
            }

            // ── Exterminate ───────────────────────────────────────────────────
            "Exterminate" => {
                if let Some(pid_str) = args.first() {
                    if let Ok(pid_val) = pid_str.parse::<u32>() {
                        let target_pid = Pid::from(pid_val as usize);
                        if let Some(p) = sys.process(target_pid) {
                            let name = p.name().to_string_lossy().into_owned();
                            p.kill();
                            let msg = format!("💀 Purged: {} (PID: {})", name, pid_val);
                            logger::log_event(&msg);
                            return msg;
                        }
                    }
                }
                return "❌ Error: Invalid or not found PID".to_string();
            }

            _ => {
                return format!(
                    "❓ Unknown command: '{}'\n   Type 'help' for Sacred Commandments.",
                    cmd
                );
            }
        }
    }

    format_pretty(&current_data)
}
