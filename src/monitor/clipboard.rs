// sandspy::monitor::clipboard — Clipboard access monitoring

use crate::analysis::secrets;
use crate::events::{Event, EventKind};
use crate::events::SecretSource;
use anyhow::Result;
use arboard::Clipboard;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;

pub async fn run(tx: mpsc::Sender<Event>) -> Result<()> {
    let mut clipboard = match Clipboard::new() {
        Ok(clipboard) => clipboard,
        Err(error) => {
            tracing::warn!(%error, "clipboard unavailable; skipping clipboard monitor");
            return Ok(());
        }
    };

    let mut last_text: Option<String> = None;

    loop {
        if tx.is_closed() {
            return Ok(());
        }

        match clipboard.get_text() {
            Ok(text) => {
                let changed = last_text.as_ref().map(|prev| prev != &text).unwrap_or(true);
                if changed {
                    let findings = secrets::scan_text(&text);
                    let contains_secret = !findings.is_empty();
                    last_text = Some(text);

                    let event = Event::new(EventKind::ClipboardRead {
                        content_type: "text".to_string(),
                        contains_secret,
                    });

                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }

                    for finding in findings.into_iter().take(5) {
                        let secret_event = Event::new(EventKind::SecretAccess {
                            name: finding.pattern_name,
                            source: SecretSource::Clipboard,
                        });

                        if tx.send(secret_event).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
            Err(error) => {
                tracing::debug!(%error, "clipboard read failed");
            }
        }

        time::sleep(Duration::from_secs(1)).await;
    }
}
