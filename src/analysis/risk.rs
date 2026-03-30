// sandspy::analysis::risk — Risk scoring engine
// TODO: Sprint 1

use crate::events::{Event, EventKind, NetCategory, RiskLevel};

const NORMALIZATION_BASELINE: u32 = 200;

pub struct RiskScorer {
    total_points: u32,
}

impl RiskScorer {
    pub fn new() -> Self {
        Self { total_points: 0 }
    }

    /// Process an event and return the updated risk score (0-100).
    pub fn process(&mut self, event: &Event) -> u32 {
        let points = Self::points_for(&event.kind);
        self.total_points += points;
        self.score()
    }

    /// Current risk score, 0-100.
    pub fn score(&self) -> u32 {
        ((self.total_points as f64 / NORMALIZATION_BASELINE as f64) * 100.0)
            .min(100.0) as u32
    }

    /// Current risk level.
    pub fn level(&self) -> RiskLevel {
        match self.score() {
            0..=20 => RiskLevel::Low,
            21..=60 => RiskLevel::Medium,
            61..=80 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    fn points_for(kind: &EventKind) -> u32 {
        match kind {
            EventKind::FileRead { sensitive: true, .. } => 15,
            EventKind::FileRead { sensitive: false, .. } => 0,
            EventKind::FileWrite { .. } => 2,
            EventKind::FileDelete { .. } => 5,
            EventKind::NetworkConnection { category: NetCategory::Unknown, .. } => 25,
            EventKind::NetworkConnection { category: NetCategory::Telemetry, .. } => 5,
            EventKind::NetworkConnection { category: NetCategory::Tracking, .. } => 5,
            EventKind::NetworkConnection { category: NetCategory::ExpectedApi, .. } => 0,
            EventKind::ShellCommand { risk: RiskLevel::Critical, .. } => 30,
            EventKind::ShellCommand { risk: RiskLevel::High, .. } => 15,
            EventKind::ShellCommand { risk: RiskLevel::Medium, .. } => 5,
            EventKind::ShellCommand { risk: RiskLevel::Low, .. } => 0,
            EventKind::SecretAccess { .. } => 20,
            EventKind::EnvVarRead { sensitive: true, .. } => 15,
            EventKind::EnvVarRead { sensitive: false, .. } => 0,
            EventKind::ClipboardRead { .. } => 10,
            EventKind::ClipboardWrite { .. } => 0,
            EventKind::Alert { .. } => 0, // alerts don't add to score
            EventKind::ProcessSpawn { .. } => 0,
            EventKind::ProcessExit { .. } => 0,
            EventKind::CommandComplete { .. } => 0,
        }
    }
}
