use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use sysinfo::{Pid, System};
use tokio_util::sync::CancellationToken;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

mod config;
mod styletui;
mod logger;
mod notifier;
mod network_guard;
pub mod dns_guard;
pub mod web_analyzer;
mod scrap_analyze;
mod crypto_forensic;
mod proxy_guard;
mod interceptor;

#[derive(Debug, Clone)]
enum Value {
    Text(String),
    Int(i32),
    Object(HashMap<String, Value>),
}

type PipelineData = Vec<Value>;

fn format_pretty(data: &PipelineData) -> String {
    if data.is_empty() {
        return "No data found.".to_string();
    }
    data.iter().map(|item| {
        match item {
            Value::Object(map) => {
                let mut parts = Vec::new();
                for (key, val) in map {
                    let val_str = match val {
                        Value::Text(s) => s.clone(),
                        Value::Int(i) => i.to_string(),
                        Value::Object(_) => "Nested Object".to_string(),
                    };
                    parts.push(format!("{}: {}", key, val_str));
                }
                parts.join(" | ")
            }
            _ => format!("{:?}", item),
        }
    }).collect::<Vec<_>>().join("\n")
}

fn check_system_health(sys: &System) -> Option<String> {
    for (pid, process) in sys.processes() {
        if process.cpu_usage() > config::CPU_CRITICAL_THRESHOLD {
            return Some(format!(
                "⚠️  CRITICAL: Process '{}' (PID: {}) consuming {}% CPU!",
                process.name().to_string_lossy(),
                pid.as_u32(),
                process.cpu_usage() as i32
            ));
        }
    }
    None
}

fn get_help_text() -> String {
    "╔═══════════════════════════════════════════════════════╗\n\
     ║       COGITATOR — SACRED COMMANDMENTS v0.6            ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  WEB FORENSICS                                         ║\n\
     ║    Analyze-Site <dom>       Full audit (human)         ║\n\
     ║    Analyze-Site-Json <dom>  Full audit (JSON export)   ║\n\
     ║    Analyze-Email <dom>      SPF / DMARC / DKIM check   ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  PROCESS RITES                                         ║\n\
     ║    GP                   List all processes             ║\n\
     ║    Find-Suspicious      Detect high CPU usage          ║\n\
     ║    Exterminate <PID>    Purge a process                ║\n\
     ║    GPP <PID>            Reveal process path            ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  NETWORK LITANIES                                      ║\n\
     ║    Get-NIF              List network interfaces        ║\n\
     ║    GC                   List active sockets + DNS      ║\n\
     ╠═══════════════════════════════════════════════════════╣\n\
     ║  SYSTEM                                                ║\n\
     ║    CG                   Clear log records              ║\n\
     ║    help                 Display this holy mandate      ║\n\
     ║    exit                 Appease the Machine Spirit     ║\n\
     ╚═══════════════════════════════════════════════════════╝".to_string()
}

fn main() -> Result<(), io::Error> {
    logger::init().expect("Failed to initialise logger");
    // Инициализируем асинхронную среду выполнения Tokio
    let rt = tokio::runtime::Runtime::new()?;

    // ── Shared HTTP client pool ───────────────────────────────────────────────
    // Build both clients once here so every analyze_site call (TUI + proxy)
    // reuses the same connection pool instead of tearing it down on each scan.
    let (no_follow, follow) = web_analyzer::build_clients()
        .expect("Failed to build HTTP clients");
    let no_follow = Arc::new(no_follow);
    let follow    = Arc::new(follow);

    // Атомарный флаг для отслеживания состояния прокси-сервера
    let proxy_running = Arc::new(AtomicBool::new(false));
    let proxy_flag_clone = proxy_running.clone();

    // Token shared between the TUI loop and start_proxy.
    // Cancelling it from either side stops the accept loop cleanly.
    let proxy_shutdown = CancellationToken::new();
    let proxy_shutdown_clone = proxy_shutdown.clone();

    // Wrap the two clients in a DefaultSiteAnalyzer so proxy_guard depends only
    // on the trait, not on reqwest internals.  The TUI path keeps calling
    // analyze_site directly with its own Arc<Client> references (unchanged).
    let proxy_analyzer: Arc<dyn web_analyzer::SiteAnalyzer> =
        Arc::new(web_analyzer::DefaultSiteAnalyzer::new(
            no_follow.clone(),
            follow.clone(),
        ));

    // Запускаем прокси-сервер в фоновом асинхронном потоке
    rt.spawn(async move {
        if let Err(e) = proxy_guard::start_proxy(
            config::PROXY_ADDR,
            proxy_flag_clone,
            proxy_shutdown_clone,
            proxy_analyzer,
        ).await {
            logger::log_event(&format!("Proxy Guard Critical Error: {}", e));
        }
    });

    // Настраиваем терминал для работы TUI (сырой режим + альтернативный экран)
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut sys = System::new_all();
    let mut input_buffer = String::new();
    let mut output_buffer = String::from("System Initialized. Awaiting sacred input... Type 'help' for commandments.");
    let mut scroll_offset: u16 = 0;

    let mut show_popup = false;
    let mut popup_text = String::new();
    let mut popup_scroll_offset: u16 = 0;

    let mut last_health_check = Instant::now();
    let health_check_interval = Duration::from_secs(config::HEALTH_CHECK_INTERVAL_SECS);

    loop {
        sys.refresh_all();

        // Периодическая проверка нагрузки на систему
        if last_health_check.elapsed() >= health_check_interval {
            if let Some(warning) = check_system_health(&sys) {
                output_buffer = warning.clone();
                logger::log_event(&warning);
            }
            last_health_check = Instant::now();
        }

        // Отрисовка интерфейса
        terminal.draw(|f| {
            styletui::draw_ui(
                f,
                &input_buffer,
                &output_buffer,
                scroll_offset,
                show_popup,
                &popup_text,
                popup_scroll_offset,
                proxy_running.load(Ordering::SeqCst), // Передаем статус прокси
            )
        })?;

        // Обработка пользовательского ввода
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                // Если открыт Popup, любое нажатие (кроме стрелочек) закрывает его
                if show_popup && key.code != KeyCode::Up && key.code != KeyCode::Down {
                    show_popup = false;
                    popup_scroll_offset = 0;
                    continue;
                }

                match key.code {
                    KeyCode::Up => {
                        if show_popup { popup_scroll_offset = popup_scroll_offset.saturating_sub(1); }
                        else { scroll_offset = scroll_offset.saturating_sub(1); }
                    }
                    KeyCode::Down => {
                        if show_popup { popup_scroll_offset = popup_scroll_offset.saturating_add(1); }
                        else { scroll_offset = scroll_offset.saturating_add(1); }
                    }
                    KeyCode::Enter => {
                        let trimmed_input = input_buffer.trim().to_string();

                        if trimmed_input == "exit" {
                            break;
                        } else if trimmed_input == "help" {
                            output_buffer = get_help_text();
                            scroll_offset = 0;
                        } else if trimmed_input.starts_with("Analyze-Site-Json") {
                            let parts: Vec<&str> = trimmed_input.split_whitespace().collect();
                            if parts.len() == 2 {
                                let result = rt.block_on(web_analyzer::analyze_site(parts[1], &no_follow, &follow));
                                popup_text = web_analyzer::export_to_json(&result);

                                let filename = format!("{}_report.json", parts[1].replace(':', "_"));
                                match web_analyzer::save_to_file(&result, &filename) {
                                    Ok(_) => output_buffer = format!("✅ JSON saved to {}", filename),
                                    Err(e) => output_buffer = format!("❌ Save failed: {}", e),
                                }
                                popup_scroll_offset = 0;
                                show_popup = true;
                            } else {
                                output_buffer = "Usage: Analyze-Site-Json <domain>".to_string();
                            }
                        } else if trimmed_input.starts_with("Analyze-Email") {
                            let parts: Vec<&str> = trimmed_input.split_whitespace().collect();
                            if parts.len() == 2 {
                                let domain = parts[1];
                                let records = dns_guard::audit_email_security(domain);
                                let mut text = format!("┌─[ EMAIL SECURITY: {} ]─────────────────────\n", domain);
                                text.push_str(&format!("│  SPF:   {}\n", records.spf.as_deref().unwrap_or("❌ Not found")));
                                text.push_str(&format!("│  DMARC: {}\n", records.dmarc.as_deref().unwrap_or("❌ Not found")));
                                text.push_str(&format!("│  DKIM:  {}\n", if records.dkim_selector_found { "✅ Found (common selector)" } else { "⚠️  Not detected" }));
                                text.push_str(&format!("│  {}\n", records.summary));
                                text.push_str("└────────────────────────────────────────────\n");
                                popup_text = text;
                                popup_scroll_offset = 0;
                                show_popup = true;
                                output_buffer = format!("✅ Email security checked: {}", domain);
                            } else {
                                output_buffer = "Usage: Analyze-Email <domain>".to_string();
                            }
                        } else if trimmed_input.starts_with("Analyze-Site") {
                            let parts: Vec<&str> = trimmed_input.split_whitespace().collect();
                            if parts.len() == 2 {
                                let result = rt.block_on(web_analyzer::analyze_site(parts[1], &no_follow, &follow));
                                popup_text = web_analyzer::format_analysis(&result);
                                popup_scroll_offset = 0;
                                show_popup = true;
                                output_buffer = format!("✅ Scan complete: {}", parts[1]);
                            } else {
                                output_buffer = "Usage: Analyze-Site <domain>".to_string();
                            }
                        } else if !trimmed_input.is_empty() {
                            output_buffer = process_pipeline(&trimmed_input, &sys);
                            scroll_offset = 0;
                        }

                        input_buffer.clear();
                    }
                    KeyCode::Char(c) => input_buffer.push(c),
                    KeyCode::Backspace => { input_buffer.pop(); }
                    KeyCode::Esc => break,
                    _ => {}
                }
            }
        }
    }

    // Возвращаем терминал в исходное состояние при выходе
    // Signal the proxy to stop and give it a moment to log its shutdown.
    proxy_shutdown.cancel();
    std::thread::sleep(std::time::Duration::from_millis(config::PROXY_SHUTDOWN_GRACE_MS));

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn process_pipeline(input: &str, sys: &System) -> String {
    let stages: Vec<&str> = input.split('|').map(|s| s.trim()).collect();
    let mut current_data: PipelineData = Vec::new();

    for stage in stages {
        let mut parts = stage.split_whitespace();
        let cmd = parts.next().unwrap_or("");
        let args: Vec<&str> = parts.collect();

        match cmd {
            "GP" => {
                current_data = sys.processes().iter().map(|(pid, proc)| {
                    let mut map = HashMap::new();
                    map.insert("Name".to_string(), Value::Text(proc.name().to_string_lossy().into_owned()));
                    map.insert("Id".to_string(), Value::Int(pid.as_u32() as i32));
                    map.insert("CPU".to_string(), Value::Int(proc.cpu_usage() as i32));
                    Value::Object(map)
                }).collect();
            }
            "CG" => {
                return match logger::clear_log() {
                    Ok(_) => "✅ Log cleared. All records purged.".to_string(),
                    Err(_) => "❌ Error: Failed to clear logs.".to_string(),
                };
            }
            "GC" => {
                return network_guard::get_active_connections(sys);
            }
            "GPP" => {
                if args.len() == 1 {
                    let pid_val: usize = args[0].parse().unwrap_or(0);
                    let pid = sysinfo::Pid::from(pid_val);
                    return match sys.process(pid) {
                        Some(proc) => {
                            let path = proc.exe()
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_else(|| "Access Denied / Path Unknown".to_string());
                            format!("🗂️  Process {} → {}", pid_val, path)
                        }
                        None => format!("❌ Process {} not found.", pid_val),
                    };
                }
                return "Usage: GPP <PID>".to_string();
            }
            "Get-NIF" => {
                current_data.clear();
                let networks = sysinfo::Networks::new_with_refreshed_list();
                for (interface_name, data) in &networks {
                    let mut net_map = HashMap::new();
                    net_map.insert("Interface".to_string(), Value::Text(interface_name.clone()));
                    let ips = data.ip_networks().iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(", ");
                    net_map.insert("IPs".to_string(), Value::Text(if ips.is_empty() { "—".to_string() } else { ips }));
                    net_map.insert("MAC".to_string(), Value::Text(format!("{}", data.mac_address())));
                    current_data.push(Value::Object(net_map));
                }
            }
            "Find-Suspicious" => {
                current_data = sys.processes().iter()
                    .filter(|(_, p)| p.cpu_usage() > config::CPU_SUSPICIOUS_THRESHOLD)
                    .map(|(pid, proc)| {
                        let mut map = HashMap::new();
                        map.insert("Name".to_string(), Value::Text(proc.name().to_string_lossy().into_owned()));
                        map.insert("CPU%".to_string(), Value::Int(proc.cpu_usage() as i32));
                        map.insert("Status".to_string(), Value::Text("⚠️  SUSPICIOUS".to_string()));
                        map.insert("PID".to_string(), Value::Int(pid.as_u32() as i32));
                        Value::Object(map)
                    }).collect();

                if current_data.is_empty() {
                    return "✅ No suspicious processes found. The Machine Spirit is calm.".to_string();
                }
            }
            "Select-Object" => {
                if !args.is_empty() {
                    let prop = args[0];
                    current_data = current_data.into_iter().filter_map(|val| {
                        if let Value::Object(mut map) = val {
                            if let Some(v) = map.remove(prop) {
                                let mut new_map = HashMap::new();
                                new_map.insert(prop.to_string(), v);
                                return Some(Value::Object(new_map));
                            }
                        }
                        None
                    }).collect();
                }
            }
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
            _ => return format!("❓ Unknown command: '{}'\n   Type 'help' for Sacred Commandments.", cmd),
        }
    }

    format_pretty(&current_data)
}