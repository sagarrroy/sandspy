// sandspy::monitor::clipboard — Clipboard access monitoring

use crate::analysis::secrets;
use crate::events::SecretSource;
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
                    let raw_findings = secrets::scan_text(&text);
                    // Filter out placeholder/example values (e.g. from docs or this conversation)
                    let findings: Vec<_> = raw_findings
                        .into_iter()
                        .filter(|f| !secrets::is_placeholder_value(&f.matched_value))
                        .collect();
                    let contains_secret = !findings.is_empty();
                    last_text = Some(text);

                    // Clipboard read with a secret = higher risk
                    let clip_risk = if contains_secret { 15 } else { 0 };
                    let event = Event::with_risk(
                        EventKind::ClipboardRead {
                            content_type: "text".to_string(),
                            contains_secret,
                        },
                        clip_risk,
                    );

                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }

                    for finding in findings.into_iter().take(5) {
                        let risk = secrets::secret_risk_score(&finding.pattern_name);
                        let secret_event = Event::with_risk(
                            EventKind::SecretAccess {
                                name: finding.pattern_name,
                                source: SecretSource::Clipboard,
                            },
                            risk,
                        );

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
