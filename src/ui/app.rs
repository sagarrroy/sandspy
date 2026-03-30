// sandspy::ui::app — TUI application state (Step 3.1)
//
// Central state object passed into every Ratatui render call.
// Updated from the monitor event bus via Arc<Mutex<App>>.

use crate::events::{AgentInfo, Event, EventKind, NetCategory, RiskLevel};
use chrono::{DateTime, Utc};
use std::collections::VecDeque;

// Maximum events kept in the ring buffer (memory safety)
const MAX_EVENTS: usize = 50_000;

/// Active tab in the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Dashboard,
    Files,
    Network,
    Diffs,
    Summary,
    Alerts,
}

impl Tab {
    pub fn label(self) -> &'static str {
        match self {
            Tab::Dashboard => "dashboard",
            Tab::Files => "files",
            Tab::Network => "network",
            Tab::Diffs => "diffs",
            Tab::Summary => "summary",
            Tab::Alerts => "alerts",
        }
    }

    pub fn next(self) -> Self {
        match self {
            Tab::Dashboard => Tab::Files,
            Tab::Files => Tab::Network,
            Tab::Network => Tab::Diffs,
            Tab::Diffs => Tab::Summary,
            Tab::Summary => Tab::Alerts,
            Tab::Alerts => Tab::Dashboard,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Tab::Dashboard => Tab::Alerts,
            Tab::Files => Tab::Dashboard,
            Tab::Network => Tab::Files,
            Tab::Diffs => Tab::Network,
            Tab::Summary => Tab::Diffs,
            Tab::Alerts => Tab::Summary,
        }
    }
}

/// A notable finding shown in the alerts/summary panels.
#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: RiskLevel,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

/// Per-category session statistics.
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    // Files
    pub files_read: usize,
    pub files_written: usize,
    pub files_deleted: usize,
    pub sensitive_files: usize,

    // Network
    pub net_connections: usize,
    pub net_unknown: usize,
    pub net_tracking: usize,
    pub bytes_out: u64,

    // Commands
    pub commands_total: usize,
    pub commands_dangerous: usize,
    pub commands_failed: usize,

    // Secrets
    pub secrets_accessed: usize,
    pub secrets_leaked: usize,

    // Clipboard
    pub clipboard_reads: usize,

    // Memory residue
    pub residual_files: usize,
}

/// Risk score with derived level.
#[derive(Debug, Clone, Default)]
pub struct RiskScore {
    pub score: u32,
}

impl RiskScore {
    pub fn level(&self) -> RiskLevel {
        match self.score {
            0..=20 => RiskLevel::Low,
            21..=60 => RiskLevel::Medium,
            61..=80 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    pub fn label(&self) -> &'static str {
        match self.level() {
            RiskLevel::Low => "LOW",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::High => "HIGH",
            RiskLevel::Critical => "CRITICAL",
        }
    }

    /// Bar fill ratio 0.0..=1.0
    pub fn ratio(&self) -> f64 {
        self.score as f64 / 100.0
    }
}

/// Full TUI application state.
pub struct App {
    /// Detected or provided agent info.
    pub agent: Option<AgentInfo>,

    /// Session start time.
    pub session_start: DateTime<Utc>,

    /// Bounded ring buffer of all events (max 50,000).
    pub events: VecDeque<Event>,

    /// Current risk score.
    pub risk: RiskScore,

    /// Aggregated session statistics.
    pub stats: SessionStats,

    /// High-severity findings for the alerts panel.
    pub findings: Vec<Finding>,

    /// Currently active tab.
    pub active_tab: Tab,

    /// Scroll offset for the active panel.
    pub scroll_offset: usize,

    /// Whether the TUI should shut down on the next tick.
    pub should_quit: bool,
}

impl App {
    pub fn new(agent: Option<AgentInfo>) -> Self {
        Self {
            agent,
            session_start: Utc::now(),
            events: VecDeque::with_capacity(MAX_EVENTS),
            risk: RiskScore::default(),
            stats: SessionStats::default(),
            findings: Vec::new(),
            active_tab: Tab::Dashboard,
            scroll_offset: 0,
            should_quit: false,
        }
    }

    /// Push an event into the ring buffer, evicting the oldest if full.
    pub fn push_event(&mut self, event: Event) {
        if self.events.len() >= MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    /// Update risk score (keep max).
    pub fn update_risk(&mut self, score: u32) {
        self.risk.score = self.risk.score.max(score);
    }

    /// Add a finding, keeping the list capped at 500.
    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
        if self.findings.len() > 500 {
            self.findings.remove(0);
        }
    }

    /// Scroll down in the active panel.
    pub fn scroll_down(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_add(1);
    }

    /// Scroll up in the active panel.
    pub fn scroll_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
    }

    /// Jump to top.
    pub fn scroll_top(&mut self) {
        self.scroll_offset = 0;
    }

    /// Jump to bottom.
    pub fn scroll_bottom(&mut self, content_len: usize, view_height: usize) {
        self.scroll_offset = content_len.saturating_sub(view_height);
    }

    /// Switch to a specific tab and reset scroll.
    pub fn switch_tab(&mut self, tab: Tab) {
        self.active_tab = tab;
        self.scroll_offset = 0;
    }

    /// Session elapsed seconds.
    pub fn elapsed_secs(&self) -> u64 {
        (Utc::now() - self.session_start)
            .num_seconds()
            .max(0) as u64
    }

    pub fn elapsed_str(&self) -> String {
        let secs = self.elapsed_secs();
        if secs < 60 {
            format!("{secs}s")
        } else {
            format!("{}m {}s", secs / 60, secs % 60)
        }
    }

    /// Ingest one event from the monitor bus.
    /// Updates ring buffer, stats, risk score, and findings.
    pub fn ingest_event(&mut self, event: Event) {
        // Update risk
        self.update_risk(event.risk_score);

        // Update stats
        match &event.kind {
            EventKind::FileRead { sensitive, .. } => {
                self.stats.files_read += 1;
                if *sensitive {
                    self.stats.sensitive_files += 1;
                }
            }
            EventKind::FileWrite { .. } => self.stats.files_written += 1,
            EventKind::FileDelete { .. } => self.stats.files_deleted += 1,
            EventKind::NetworkConnection {
                category,
                bytes_sent,
                bytes_recv,
                ..
            } => {
                self.stats.net_connections += 1;
                self.stats.bytes_out += bytes_sent + bytes_recv;
                if *category == NetCategory::Unknown {
                    self.stats.net_unknown += 1;
                }
                if *category == NetCategory::Tracking {
                    self.stats.net_tracking += 1;
                }
            }
            EventKind::ShellCommand { risk, .. } => {
                self.stats.commands_total += 1;
                if *risk >= RiskLevel::High {
                    self.stats.commands_dangerous += 1;
                }
            }
            EventKind::SecretAccess { .. } => self.stats.secrets_accessed += 1,
            EventKind::EnvVarRead { sensitive: true, .. } => {
                self.stats.secrets_accessed += 1;
            }
            EventKind::ClipboardRead { .. } => self.stats.clipboard_reads += 1,
            EventKind::Alert { message, severity } => {
                self.add_finding(Finding {
                    severity: *severity,
                    message: message.clone(),
                    timestamp: event.timestamp,
                });
            }
            _ => {}
        }

        // Add findings for high-severity raw events
        match &event.kind {
            EventKind::FileRead {
                path,
                sensitive: true,
                ..
            } => {
                self.add_finding(Finding {
                    severity: RiskLevel::High,
                    message: format!("sensitive file read: {}", path.display()),
                    timestamp: event.timestamp,
                });
            }
            EventKind::NetworkConnection {
                category: NetCategory::Unknown,
                domain,
                remote_addr,
                remote_port,
                ..
            } => {
                let host = domain
                    .as_deref()
                    .map(|d| format!("{d}:{remote_port}"))
                    .unwrap_or_else(|| format!("{remote_addr}:{remote_port}"));
                self.add_finding(Finding {
                    severity: RiskLevel::High,
                    message: format!("unknown destination: {host}"),
                    timestamp: event.timestamp,
                });
            }
            EventKind::ShellCommand {
                command,
                risk: RiskLevel::Critical,
                ..
            } => {
                self.add_finding(Finding {
                    severity: RiskLevel::Critical,
                    message: format!("dangerous command: {command}"),
                    timestamp: event.timestamp,
                });
            }
            _ => {}
        }

        // Push to ring buffer last
        self.push_event(event);
    }
}
