// sandspy::alerts — Desktop notification system
// TODO: Sprint 4

use anyhow::Result;

pub fn notify(_title: &str, _body: &str) -> Result<()> {
    // Uses notify-rust crate
    // Gracefully fails if no desktop environment
    Ok(())
}
