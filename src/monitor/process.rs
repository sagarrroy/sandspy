// sandspy::monitor::process — Process tree monitoring
// TODO: Sprint 1 — full implementation

use crate::events::{AgentInfo, Event, EventKind, RiskLevel};
use anyhow::Result;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Shared set of PIDs in the monitored process tree.
/// Other monitors use this to correlate events with the agent.
pub type PidSet = Arc<RwLock<HashSet<u32>>>;

/// Create a new shared PID set.
pub fn create_pid_set() -> PidSet {
    Arc::new(RwLock::new(HashSet::new()))
}

/// Scan running processes for known AI agent names.
pub fn scan_for_agents() -> Vec<AgentInfo> {
    // TODO: Sprint 1 — use sysinfo::System
    Vec::new()
}

/// Spawn a command and monitor its process tree.
pub async fn spawn_and_monitor(
    _command: &str,
    _tx: mpsc::Sender<Event>,
    _pids: PidSet,
) -> Result<()> {
    // TODO: Sprint 1
    Ok(())
}

/// Attach to a running PID and monitor its process tree.
pub async fn attach_and_monitor(
    _pid: u32,
    _tx: mpsc::Sender<Event>,
    _pids: PidSet,
) -> Result<()> {
    // TODO: Sprint 1
    Ok(())
}
