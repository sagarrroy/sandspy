// sandspy::analysis::risk — Risk scoring engine

use crate::events::{Event, EventKind, NetCategory, RiskLevel};
use std::path::Path;

const NORMALIZATION_BASELINE: u32 = 200;
const UNKNOWN_DATA_ALERT_THRESHOLD_BYTES: u64 = 10 * 1024;

pub struct RiskScorer {
    total_points: u32,
    unknown_data_sent: u64,
    unknown_data_alerted: bool,
}

impl RiskScorer {
    pub fn new() -> Self {
        Self {
            total_points: 0,
            unknown_data_sent: 0,
            unknown_data_alerted: false,
        }
    }
}

impl Default for RiskScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl RiskScorer {
    /// Process an event and return the updated risk score (0-100).
    pub fn process(&mut self, event: &Event) -> u32 {
        let points = Self::points_for(&event.kind);
        self.total_points += points;
        self.score()
    }

    /// Current risk score, 0-100.
    pub fn score(&self) -> u32 {
        ((self.total_points as f64 / NORMALIZATION_BASELINE as f64) * 100.0).min(100.0) as u32
    }

    /// Current risk level.
    #[allow(dead_code)]
    pub fn level(&self) -> RiskLevel {
        match self.score() {
            0..=20 => RiskLevel::Low,
            21..=60 => RiskLevel::Medium,
            61..=80 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    pub fn process_with_alerts(&mut self, event: &Event) -> (u32, Vec<Event>) {
        let score = self.process(event);
        let mut alerts = Vec::new();

        match &event.kind {
            EventKind::NetworkConnection {
                remote_addr,
                remote_port,
                category,
                bytes_sent,
                ..
            } => {
                if *category == NetCategory::Unknown {
                    alerts.push(Event::new(EventKind::Alert {
                        message: format!(
                            "unknown network connection detected: {}:{}",
                            remote_addr, remote_port
                        ),
                        severity: RiskLevel::High,
                    }));

                    self.unknown_data_sent = self.unknown_data_sent.saturating_add(*bytes_sent);
                    if !self.unknown_data_alerted
                        && self.unknown_data_sent >= UNKNOWN_DATA_ALERT_THRESHOLD_BYTES
                    {
                        self.unknown_data_alerted = true;
                        alerts.push(Event::new(EventKind::Alert {
                            message: format!(
                                "unknown network data threshold exceeded: {} bytes",
                                self.unknown_data_sent
                            ),
                            severity: RiskLevel::Critical,
                        }));
                    }
                }
            }
            EventKind::ShellCommand { command, risk, .. } => {
                if *risk == RiskLevel::Critical {
                    alerts.push(Event::new(EventKind::Alert {
                        message: format!("critical shell command executed: {command}"),
                        severity: RiskLevel::Critical,
                    }));
                }
            }
            EventKind::FileRead {
                path, sensitive, ..
            } => {
                if *sensitive && is_ssh_or_pem(path) {
                    alerts.push(Event::new(EventKind::Alert {
                        message: format!("sensitive key file read: {}", path.display()),
                        severity: RiskLevel::Critical,
                    }));
                }
            }
            EventKind::Alert { .. } => {}
            _ => {}
        }

        (score, alerts)
    }

    fn points_for(kind: &EventKind) -> u32 {
        match kind {
            EventKind::FileRead {
                sensitive: true, ..
            } => 15,
            EventKind::FileRead {
                sensitive: false, ..
            } => 0,
            EventKind::FileWrite { .. } => 2,
            EventKind::FileDelete { .. } => 5,
            EventKind::NetworkConnection {
                category: NetCategory::Unknown,
                ..
            } => 25,
            EventKind::NetworkConnection {
                category: NetCategory::Telemetry,
                ..
            } => 5,
            EventKind::NetworkConnection {
                category: NetCategory::Tracking,
                ..
            } => 5,
            EventKind::NetworkConnection {
                category: NetCategory::ExpectedApi,
                ..
            } => 0,
            EventKind::ShellCommand {
                risk: RiskLevel::Critical,
                ..
            } => 30,
            EventKind::ShellCommand {
                risk: RiskLevel::High,
                ..
            } => 15,
            EventKind::ShellCommand {
                risk: RiskLevel::Medium,
                ..
            } => 5,
            EventKind::ShellCommand {
                risk: RiskLevel::Low,
                ..
            } => 0,
            EventKind::SecretAccess { .. } => 20,
            EventKind::EnvVarRead {
                sensitive: true, ..
            } => 15,
            EventKind::EnvVarRead {
                sensitive: false, ..
            } => 0,
            EventKind::ClipboardRead { .. } => 10,
            EventKind::ClipboardWrite { .. } => 0,
            EventKind::Alert { .. } => 0, // alerts don't add to score
            EventKind::ProcessSpawn { .. } => 0,
            EventKind::ProcessExit { .. } => 0,
            EventKind::CommandComplete { .. } => 0,
        }
    }
}

fn is_ssh_or_pem(path: &Path) -> bool {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    normalized.contains("/.ssh/") || normalized.ends_with(".pem")
}
