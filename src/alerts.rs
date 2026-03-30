// sandspy::alerts — Desktop notification system

use anyhow::Result;
use notify_rust::Notification;

pub fn notify(title: &str, body: &str) -> Result<()> {
    (|| -> Result<()> {
        Notification::new().summary(title).body(body).show()?;
        Ok(())
    })()
    .unwrap_or_else(|e| {
        tracing::warn!("notification failed: {e}");
    });

    Ok(())
}
