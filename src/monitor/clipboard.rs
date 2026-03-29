// sandspy::monitor::clipboard — Clipboard access monitoring
// TODO: Sprint 1

use crate::events::Event;
use anyhow::Result;
use tokio::sync::mpsc;

pub async fn run(_tx: mpsc::Sender<Event>) -> Result<()> {
    // TODO: Sprint 1 — use arboard::Clipboard, graceful degradation
    Ok(())
}
