// sandspy::monitor::memory — Post-session residue scanning
// TODO: Sprint 1

use crate::events::Event;
use anyhow::Result;
use tokio::sync::mpsc;

pub async fn run(_tx: mpsc::Sender<Event>) -> Result<()> {
    // TODO: Sprint 1 — runs once at session end
    Ok(())
}
