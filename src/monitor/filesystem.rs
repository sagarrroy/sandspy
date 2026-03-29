// sandspy::monitor::filesystem — File access watching
// TODO: Sprint 1

use crate::events::Event;
use crate::monitor::process::PidSet;
use anyhow::Result;
use tokio::sync::mpsc;

pub async fn run(_tx: mpsc::Sender<Event>, _pids: PidSet) -> Result<()> {
    // TODO: Sprint 1 — use notify::recommended_watcher()
    Ok(())
}
