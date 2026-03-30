// sandspy::ui::summary — Scan summary / report renderer (Mode 3)
//
// Aggregates all session events and renders the beautiful post-session
// report that people paste in tweets. Triggered on Ctrl+C or `sandspy report`.

use crate::events::{Event, EventKind, NetCategory, RiskLevel};
use crate::ui::live::SessionStats;
use chrono::{DateTime, Utc};
use colored::*;

/// A notable finding to display in the findings section.
pub struct Finding {
    pub severity: RiskLevel,
    pub message: String,
}

/// Full session data for rendering the summary.
pub struct SessionData {
    pub agent_name: String,
    pub agent_pid: Option<u32>,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub events: Vec<Event>,
    pub risk_score: u32,
}

impl SessionData {
    pub fn duration_str(&self) -> String {
        let secs = (self.end - self.start).num_seconds().max(0) as u64;
        if secs < 60 {
            format!("{}s", secs)
        } else {
            format!("{}m {}s", secs / 60, secs % 60)
        }
    }
}

pub fn print_summary(data: &SessionData) {
    let stats = compute_stats(&data.events);
    let findings = extract_findings(&data.events);

    println!();
    println!("  {} — session report", "sandspy".bold().white());
    println!();

    // ┌── Box header ──────────────────────────────────────────────┐
    let w = 57usize;
    println!("  ┌{}┐", "─".repeat(w));

    let agent_label = match data.agent_pid {
        Some(pid) => format!("{} (PID {})", data.agent_name, pid),
        None => data.agent_name.clone(),
    };
    box_line("agent", &agent_label, w);
    box_line("duration", &data.duration_str(), w);
    box_line(
        "timestamp",
        &data.start.format("%Y-%m-%d %H:%M UTC").to_string(),
        w,
    );
    println!("  └{}┘", "─".repeat(w));
    println!();

    // ── Stats table ─────────────────────────────────────────────
    stat_line(
        "files",
        &format!(
            "{} read    {} written    {} deleted",
            stats.files_read, stats.files_written, stats.files_deleted
        ),
    );
    stat_line(
        "network",
        &format!(
            "{} connections ({} unknown)",
            stats.net_connections, stats.net_unknown
        ),
    );
    stat_line(
        "commands",
        &format!(
            "{} executed ({} dangerous)",
            stats.commands, stats.dangerous_commands
        ),
    );
    stat_line("secrets", &format!("{} accessed", stats.secrets));
    stat_line("clipboard", &format!("{} reads", stats.clipboard_reads));
    stat_line("residual", &format!("{} temp files left", stats.residual));
    println!();

    // ── Risk bar ─────────────────────────────────────────────────
    let score = data.risk_score;
    let bar_width = 60usize;
    let filled = ((score as f64 / 100.0) * bar_width as f64).round() as usize;
    let empty = bar_width.saturating_sub(filled);

    let bar_str = format!("[{}{}]", "#".repeat(filled), "─".repeat(empty));
    let colored_bar = match score {
        0..=20 => bar_str.green(),
        21..=60 => bar_str.yellow(),
        61..=80 => bar_str.red(),
        _ => bar_str.red().bold(),
    };
    let risk_label = match score {
        0..=20 => "LOW".green().bold(),
        21..=60 => "MEDIUM".yellow().bold(),
        61..=80 => "HIGH".red().bold(),
        _ => "CRITICAL".red().bold(),
    };

    println!("  risk   {}  {}/100", colored_bar, score);
    println!("         {}", risk_label);
    println!();

    // ── Findings ─────────────────────────────────────────────────
    if findings.is_empty() {
        println!("  {}  no notable findings", "findings".bold());
    } else {
        println!("  {}", "findings".bold());
        for f in &findings {
            let severity_str = match f.severity {
                RiskLevel::Critical => "CRITICAL".red().bold().to_string(),
                RiskLevel::High => "HIGH    ".red().to_string(),
                RiskLevel::Medium => "MEDIUM  ".yellow().to_string(),
                RiskLevel::Low => "low     ".white().dimmed().to_string(),
            };
            println!("    {}   {}", severity_str, f.message.white());
        }
    }

    println!();
}

// ─── Helpers ────────────────────────────────────────────────────────────────

struct ComputedStats {
    files_read: usize,
    files_written: usize,
    files_deleted: usize,
    net_connections: usize,
    net_unknown: usize,
    commands: usize,
    dangerous_commands: usize,
    secrets: usize,
    clipboard_reads: usize,
    residual: usize,
}

fn compute_stats(events: &[Event]) -> ComputedStats {
    let mut s = ComputedStats {
        files_read: 0,
        files_written: 0,
        files_deleted: 0,
        net_connections: 0,
        net_unknown: 0,
        commands: 0,
        dangerous_commands: 0,
        secrets: 0,
        clipboard_reads: 0,
        residual: 0,
    };

    for event in events {
        match &event.kind {
            EventKind::FileRead { .. } => s.files_read += 1,
            EventKind::FileWrite { .. } => s.files_written += 1,
            EventKind::FileDelete { .. } => s.files_deleted += 1,
            EventKind::NetworkConnection { category, .. } => {
                s.net_connections += 1;
                if *category == NetCategory::Unknown {
                    s.net_unknown += 1;
                }
            }
            EventKind::ShellCommand { risk, .. } => {
                s.commands += 1;
                if *risk >= RiskLevel::High {
                    s.dangerous_commands += 1;
                }
            }
            EventKind::SecretAccess { .. } => s.secrets += 1,
            EventKind::EnvVarRead { sensitive: true, .. } => s.secrets += 1,
            EventKind::ClipboardRead { .. } => s.clipboard_reads += 1,
            EventKind::Alert { message, .. } if message.contains("temp file") => {
                s.residual += 1
            }
            _ => {}
        }
    }

    s
}

fn extract_findings(events: &[Event]) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();

    for event in events {
        match &event.kind {
            EventKind::FileRead { path, sensitive: true, .. } => {
                findings.push(Finding {
                    severity: RiskLevel::Critical,
                    message: format!("{} was read by agent", path.display()),
                });
            }
            EventKind::NetworkConnection {
                domain,
                remote_addr,
                remote_port,
                category: NetCategory::Unknown,
                ..
            } => {
                let host = domain
                    .as_deref()
                    .map(|d| format!("{d}:{remote_port}"))
                    .unwrap_or_else(|| format!("{remote_addr}:{remote_port}"));
                findings.push(Finding {
                    severity: RiskLevel::High,
                    message: format!("unknown network destination: {host}"),
                });
            }
            EventKind::ShellCommand {
                command,
                risk: RiskLevel::Critical,
                ..
            } => {
                findings.push(Finding {
                    severity: RiskLevel::Critical,
                    message: format!("dangerous command: {}", truncate(command, 60)),
                });
            }
            EventKind::ShellCommand {
                command,
                risk: RiskLevel::High,
                ..
            } => {
                findings.push(Finding {
                    severity: RiskLevel::High,
                    message: format!("high-risk command: {}", truncate(command, 60)),
                });
            }
            EventKind::Alert { message, severity } => {
                findings.push(Finding {
                    severity: *severity,
                    message: message.clone(),
                });
            }
            _ => {}
        }
    }

    // Sort: Critical first, then High, Medium, Low
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    // Cap at 10 to keep output readable
    findings.truncate(10);

    findings
}

fn box_line(key: &str, value: &str, w: usize) {
    // "  │  agent      claude (PID 1234)                      │"
    let inner = format!("  {:<10} {}", key, value);
    let pad = w.saturating_sub(inner.len() + 1);
    println!("  │{}{}│", inner, " ".repeat(pad));
}

fn stat_line(key: &str, value: &str) {
    println!("  {:<14}  {}", key.bold(), value.white());
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

/// Build a SessionData from a list of events accumulated during watch.
pub fn session_data_from_stats(
    stats: &SessionStats,
    events: Vec<Event>,
    agent_name: &str,
    agent_pid: Option<u32>,
    start: DateTime<Utc>,
) -> SessionData {
    SessionData {
        agent_name: agent_name.to_string(),
        agent_pid,
        start,
        end: Utc::now(),
        events,
        risk_score: stats.risk_score,
    }
}
