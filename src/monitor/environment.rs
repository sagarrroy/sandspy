// sandspy::monitor::environment — Env variable access detection
//
// Scans the environment of monitored processes for sensitive variable names.
// Emits EnvVarRead events for any variable that looks like a credential.
// Also actively watches for new processes that appear with sensitive env vars.

use crate::events::{Event, EventKind};
use crate::monitor::process::PidSet;
use anyhow::Result;
use std::collections::HashSet;
use std::ffi::OsString;
use std::time::Duration;
use sysinfo::{Pid, ProcessesToUpdate, System};
use tokio::sync::mpsc;
use tokio::time;

pub async fn run(tx: mpsc::Sender<Event>, pids: PidSet) -> Result<()> {
    let mut system = System::new_all();
    let mut scanned_pids: HashSet<u32> = HashSet::new();
    let mut emitted_vars: HashSet<String> = HashSet::new();

    loop {
        if tx.is_closed() {
            return Ok(());
        }

        let tracked_pids = {
            let guard = pids.read().await;
            guard.clone()
        };

        if tracked_pids.is_empty() {
            scanned_pids.clear();
            time::sleep(Duration::from_millis(500)).await;
            continue;
        }

        system.refresh_processes(ProcessesToUpdate::All, true);

        for pid in &tracked_pids {
            // Only scan each PID once — env doesn't change after process start
            if !scanned_pids.insert(*pid) {
                continue;
            }

            let Some(process) = system.process(Pid::from_u32(*pid)) else {
                continue;
            };

            let env_vars: Vec<(String, bool)> = process
                .environ()
                .iter()
                .filter_map(parse_env_entry)
                .filter(|(name, _)| is_sensitive_env_name(name))
                .collect();

            for (name, high_value) in env_vars {
                // Deduplicate across all processes — same var name only emitted once
                if !emitted_vars.insert(name.clone()) {
                    continue;
                }

                let risk = if high_value { 15 } else { 8 };
                let event = Event::with_risk(
                    EventKind::EnvVarRead {
                        name,
                        sensitive: true,
                    },
                    risk,
                );

                if tx.send(event).await.is_err() {
                    return Ok(());
                }
            }
        }

        time::sleep(Duration::from_millis(500)).await;
    }
}

/// Parse `NAME=value` from an env entry.
/// Returns (name, is_high_value) where high_value = the var looks like it has actual content.
fn parse_env_entry(entry: &OsString) -> Option<(String, bool)> {
    let text = entry.to_string_lossy();
    let (name, value) = text.split_once('=')?;
    if name.is_empty() {
        return None;
    }
    // Consider it "high value" if the content looks like a real credential
    // (not empty, not a placeholder, not a path)
    let high_value = value.len() >= 16
        && !value.contains('/')
        && !value.contains('\\')
        && value != "your_key_here"
        && value != "changeme"
        && value != "secret"
        && value != "placeholder";

    Some((name.to_string(), high_value))
}

fn is_sensitive_env_name(name: &str) -> bool {
    let u = name.to_ascii_uppercase();

    // High-signal API key patterns
    if u.ends_with("_API_KEY")
        || u.ends_with("_SECRET_KEY")
        || u.ends_with("_AUTH_TOKEN")
        || u.ends_with("_ACCESS_TOKEN")
        || u.ends_with("_PRIVATE_KEY")
        || u.ends_with("_CLIENT_SECRET")
    {
        return true;
    }

    // Known specific variable names
    let exact = [
        "DATABASE_URL",
        "DB_PASSWORD",
        "DB_PASS",
        "REDIS_URL",
        "REDIS_PASSWORD",
        "SECRET_KEY",
        "JWT_SECRET",
        "SESSION_SECRET",
        "ENCRYPTION_KEY",
        "MASTER_KEY",
        // Cloud providers
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_API_KEY",
        "AZURE_CLIENT_SECRET",
        "AZURE_STORAGE_CONNECTION_STRING",
        // Source control
        "GITHUB_TOKEN",
        "GITHUB_PAT",
        "GITLAB_TOKEN",
        // AI providers
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "HUGGINGFACE_TOKEN",
        // Payment
        "STRIPE_SECRET_KEY",
        "STRIPE_WEBHOOK_SECRET",
        "PAYPAL_SECRET",
        // Communication
        "SLACK_BOT_TOKEN",
        "SLACK_SIGNING_SECRET",
        "TWILIO_AUTH_TOKEN",
        "SENDGRID_API_KEY",
        "MAILGUN_API_KEY",
        // Misc
        "NPM_TOKEN",
        "PYPI_TOKEN",
        "DOCKER_PASSWORD",
    ];

    if exact.contains(&u.as_str()) {
        return true;
    }

    // Broad keyword-based matching
    let keywords = [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "PRIVATE",
        "CREDENTIAL",
    ];
    keywords.iter().any(|k| u.contains(k))
}
