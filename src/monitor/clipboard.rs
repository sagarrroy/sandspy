// sandspy::monitor::clipboard — Clipboard access monitoring

use crate::events::{Event, EventKind};
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
                    let contains_secret = contains_secret_like(&text);
                    last_text = Some(text);

                    let event = Event::new(EventKind::ClipboardRead {
                        content_type: "text".to_string(),
                        contains_secret,
                    });

                    if tx.send(event).await.is_err() {
                        return Ok(());
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

fn contains_secret_like(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();

    lower.contains("api_key")
        || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("aws_")
        || lower.contains("github_")
        || lower.contains("database_url")
}
