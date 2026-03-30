// sandspy::ui::live — Live stream renderer (Mode 1)
//
// Consumes events from the mpsc bus and prints a beautiful, colored
// live feed to the terminal. Updates a status bar in-place every 2s.

use crate::events::{Event, EventKind, NetCategory, RiskLevel};
use chrono::Local;
use colored::*;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Session statistics accumulated while printing events.
pub struct SessionStats {
    pub event_count: usize,
    pub risk_score: u32,
    pub start: Instant,
    pub events: Vec<Event>,
    pub files_read: usize,
    pub files_written: usize,
    pub net_connections: usize,
    pub net_unknown: usize,
    pub commands: usize,
    pub secrets: usize,
    pub alerts: usize,
    pub clipboard_reads: usize,
}

impl SessionStats {
    pub fn new() -> Self {
        Self {
            event_count: 0,
            risk_score: 0,
            start: Instant::now(),
            events: Vec::new(),
            files_read: 0,
            files_written: 0,
            net_connections: 0,
            net_unknown: 0,
            commands: 0,
            secrets: 0,
            alerts: 0,
            clipboard_reads: 0,
        }
    }

    pub fn elapsed_str(&self) -> String {
        let secs = self.start.elapsed().as_secs();
        if secs < 60 {
            format!("{}s", secs)
        } else {
            format!("{}m {}s", secs / 60, secs % 60)
        }
    }

    pub fn risk_label(&self) -> &'static str {
        match self.risk_score {
            0..=20 => "LOW",
            21..=60 => "MEDIUM",
            61..=80 => "HIGH",
            _ => "CRITICAL",
        }
    }
}

impl Default for SessionStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Print the sandspy watch header.
pub fn print_header(agent_label: &str) {
    let version = env!("CARGO_PKG_VERSION");
    println!();
    println!("  {}", format!("sandspy v{version}").bold().white());
    println!("  {}", format!("watching {agent_label}").dimmed());
    println!("  {}", "press ctrl+c to stop and view summary".dimmed());
    println!();
    println!(
        "  {}",
        "─".repeat(65).dimmed()
    );
    println!();
}

/// Main live-stream loop. Renders each event as a pretty line.
/// Also rewrites the status bar every 2 seconds.
pub async fn run(
    rx: &mut mpsc::Receiver<Event>,
    agent_label: &str,
    verbosity: u8,
) -> SessionStats {
    print_header(agent_label);

    let mut stats = SessionStats::new();
    let mut last_bar = Instant::now();

    while let Some(event) = rx.recv().await {
        stats.events.push(event.clone());

        // Update stats
        stats.event_count += 1;
        stats.risk_score = stats.risk_score.max(event.risk_score);
        accumulate(&mut stats, &event);

        // Filter by verbosity
        if should_print(&event, verbosity) {
            // Erase status bar line, print event, redraw bar below
            erase_status_bar();
            print_event(&event);
        }

        // Rewrite status bar every 2 seconds
        if last_bar.elapsed() >= Duration::from_secs(2) || stats.event_count == 1 {
            print_status_bar(&stats);
            last_bar = Instant::now();
        }
    }

    // Final bar update before returning
    erase_status_bar();
    print_status_bar(&stats);
    println!();

    stats
}

fn accumulate(stats: &mut SessionStats, event: &Event) {
    match &event.kind {
        EventKind::FileRead { .. } => stats.files_read += 1,
        EventKind::FileWrite { .. } => stats.files_written += 1,
        EventKind::NetworkConnection { category, .. } => {
            stats.net_connections += 1;
            if *category == NetCategory::Unknown {
                stats.net_unknown += 1;
            }
        }
        EventKind::ShellCommand { .. } => stats.commands += 1,
        EventKind::SecretAccess { .. } | EventKind::EnvVarRead { sensitive: true, .. } => {
            stats.secrets += 1
        }
        EventKind::ClipboardRead { .. } => stats.clipboard_reads += 1,
        EventKind::Alert { .. } => stats.alerts += 1,
        _ => {}
    }
}

fn should_print(event: &Event, verbosity: u8) -> bool {
    // 0=low, 1=medium, 2=high, 3=all
    match &event.kind {
        // Always show alerts and critical stuff
        EventKind::Alert { .. } => true,
        EventKind::SecretAccess { .. } => true,
        EventKind::EnvVarRead { sensitive: true, .. } => true,
        EventKind::FileRead { sensitive: true, .. } => true,
        EventKind::NetworkConnection { category, .. }
            if *category == NetCategory::Unknown =>
        {
            true
        }
        EventKind::ShellCommand { risk, .. }
            if *risk >= RiskLevel::High =>
        {
            true
        }

        // medium and above
        EventKind::NetworkConnection { .. } if verbosity >= 1 => true,
        EventKind::ShellCommand { .. } if verbosity >= 1 => true,
        EventKind::FileWrite { .. } if verbosity >= 1 => true,

        // high and above
        EventKind::FileRead { .. } if verbosity >= 2 => true,
        EventKind::ProcessSpawn { .. } if verbosity >= 2 => true,

        // all
        _ if verbosity >= 3 => true,

        _ => false,
    }
}

fn print_event(event: &Event) {
    let time = Local::now().format("%H:%M:%S").to_string();
    let ts = time.dimmed();

    match &event.kind {
        EventKind::FileRead { path, sensitive, .. } => {
            let tag = "READ ".white().dimmed();
            let target = path.display().to_string();
            let label = if *sensitive {
                "SENSITIVE".yellow().bold()
            } else {
                "ok".dimmed().normal()
            };
            println!("  {ts}  {tag}  {:<42}  {label}", target.white());
        }

        EventKind::FileWrite { path, diff_summary } => {
            let tag = "WRITE".cyan();
            let target = path.display().to_string();
            let label = diff_summary
                .as_deref()
                .map(|d| d.cyan().to_string())
                .unwrap_or_default();
            println!("  {ts}  {tag}  {:<42}  {label}", target.white());
        }

        EventKind::FileDelete { path } => {
            let tag = "DEL  ".red();
            println!("  {ts}  {tag}  {}", path.display().to_string().red());
        }

        EventKind::NetworkConnection {
            remote_addr,
            remote_port,
            domain,
            category,
            bytes_sent,
            bytes_recv,
            ..
        } => {
            let tag = "NET  ".blue();
            let host = domain
                .as_deref()
                .map(|d| format!("{d}:{remote_port}"))
                .unwrap_or_else(|| format!("{remote_addr}:{remote_port}"));
            let bytes = format_bytes(bytes_sent + bytes_recv);
            let label = match category {
                NetCategory::ExpectedApi => "ok".dimmed().normal(),
                NetCategory::Telemetry => "telemetry".yellow().normal(),
                NetCategory::Tracking => "TRACKING".red().bold(),
                NetCategory::Unknown => "UNKNOWN".red().bold(),
            };
            println!("  {ts}  {tag}  {:<35}  {:<8}  {label}", host.white(), bytes);
        }

        EventKind::ShellCommand { command, risk, .. } => {
            let tag = "CMD  ".magenta();
            let short_cmd = truncate(command, 42);
            let label = match risk {
                RiskLevel::Critical => "CRITICAL".red().bold(),
                RiskLevel::High => "HIGH".red().normal(),
                RiskLevel::Medium => "medium".yellow().normal(),
                RiskLevel::Low => "ok".dimmed().normal(),
            };
            println!("  {ts}  {tag}  {:<42}  {label}", short_cmd.white());
        }

        EventKind::ProcessSpawn { name, pid, .. } => {
            let tag = "PROC ".white().dimmed();
            println!("  {ts}  {tag}  {} {}", name.white(), format!("(pid {pid})").dimmed());
        }

        EventKind::ProcessExit { pid, .. } => {
            let tag = "EXIT ".white().dimmed();
            println!("  {ts}  {tag}  {}", format!("pid {pid} exited").dimmed());
        }

        EventKind::SecretAccess { name, .. } => {
            let tag = "SECRET".red().bold();
            println!("  {ts}  {tag}  {:<40}  {}", name.red(), "HIGH".red().bold());
        }

        EventKind::EnvVarRead { name, sensitive } => {
            let tag = "ENV  ".yellow();
            let label = if *sensitive {
                "SENSITIVE".yellow().bold()
            } else {
                "ok".dimmed().normal()
            };
            println!("  {ts}  {tag}  {:<42}  {label}", name.white());
        }

        EventKind::ClipboardRead {
            contains_secret, ..
        } => {
            let tag = "CLIP ".white().dimmed();
            let label = if *contains_secret {
                "SENSITIVE".yellow().bold()
            } else {
                "ok".dimmed().normal()
            };
            println!("  {ts}  {tag}  clipboard read                              {label}");
        }

        EventKind::Alert { message, severity } => {
            let tag = "ALERT".red().bold();
            let color_msg = match severity {
                RiskLevel::Critical => message.red().bold().to_string(),
                RiskLevel::High => message.red().to_string(),
                RiskLevel::Medium => message.yellow().to_string(),
                RiskLevel::Low => message.white().dimmed().to_string(),
            };
            println!("  {ts}  {tag}  {color_msg}");
        }

        _ => {}
    }
}

fn print_status_bar(stats: &SessionStats) {
    let risk_colored = match stats.risk_score {
        0..=20 => format!("{}/100 LOW", stats.risk_score).green().to_string(),
        21..=60 => format!("{}/100 MEDIUM", stats.risk_score).yellow().to_string(),
        61..=80 => format!("{}/100 HIGH", stats.risk_score).red().to_string(),
        _ => format!("{}/100 CRITICAL", stats.risk_score)
            .red()
            .bold()
            .to_string(),
    };

    let bar = format!(
        "  ── session: {} │ events: {} │ risk: {} ──",
        stats.elapsed_str(),
        stats.event_count,
        risk_colored,
    );

    // Print without newline so next erase works
    print!("{}", bar.dimmed());
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

fn erase_status_bar() {
    // Move to column 0, clear the line
    print!("\r\x1b[2K");
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

fn format_bytes(b: u64) -> String {
    if b == 0 {
        return String::new();
    }
    if b < 1024 {
        format!("{b}B")
    } else if b < 1024 * 1024 {
        format!("{:.1}KB", b as f64 / 1024.0)
    } else {
        format!("{:.1}MB", b as f64 / (1024.0 * 1024.0))
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}
