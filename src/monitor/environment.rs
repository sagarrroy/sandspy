// sandspy::monitor::environment — Env variable access detection

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
    let mut scanned_pids = HashSet::new();
    let mut emitted_names = HashSet::new();

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

        for pid in tracked_pids {
            if !scanned_pids.insert(pid) {
                continue;
            }

            let Some(process) = system.process(Pid::from_u32(pid)) else {
                continue;
            };

            for env in process.environ() {
                let Some(name) = env_name(env) else {
                    continue;
                };

                if !is_sensitive_env_name(&name) {
                    continue;
                }

                if !emitted_names.insert(name.clone()) {
                    continue;
                }

                let event = Event::new(EventKind::EnvVarRead {
                    name,
                    sensitive: true,
                });

                if tx.send(event).await.is_err() {
                    return Ok(());
                }
            }
        }

        time::sleep(Duration::from_millis(500)).await;
    }
}

fn env_name(entry: &OsString) -> Option<String> {
    let text = entry.to_string_lossy();
    let (name, _) = text.split_once('=')?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn is_sensitive_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();

    if upper.ends_with("_API_KEY")
        || upper.contains("TOKEN")
        || upper.contains("SECRET")
        || upper.contains("PASSWORD")
    {
        return true;
    }

    if upper == "DATABASE_URL" || upper.starts_with("AWS_") || upper.starts_with("GITHUB_") {
        return true;
    }

    false
}
