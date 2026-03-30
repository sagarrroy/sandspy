// sandspy::monitor::command — Shell command interception

use crate::events::{Event, EventKind, RiskLevel};
use crate::monitor::process::PidSet;
use anyhow::Result;
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;
use sysinfo::{ProcessesToUpdate, System};
use tokio::sync::mpsc;
use tokio::time;

pub async fn run(tx: mpsc::Sender<Event>, pids: PidSet) -> Result<()> {
    let mut system = System::new_all();
    let mut seen_processes = HashSet::new();

    loop {
        if tx.is_closed() {
            return Ok(());
        }

        let tracked_pids = {
            let guard = pids.read().await;
            guard.clone()
        };

        if tracked_pids.is_empty() {
            seen_processes.clear();
            time::sleep(Duration::from_millis(250)).await;
            continue;
        }

        system.refresh_processes(ProcessesToUpdate::All, true);

        for process in system.processes().values() {
            let pid = process.pid().as_u32();
            if !tracked_pids.contains(&pid) || !seen_processes.insert(pid) {
                continue;
            }

            let command = join_cmdline(process.cmd());
            if command.trim().is_empty() {
                continue;
            }

            let risk = classify_command_risk(&command);
            let working_dir = process
                .cwd()
                .map(PathBuf::from)
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

            let event = Event::new(EventKind::ShellCommand {
                command,
                working_dir,
                risk,
            });

            if tx.send(event).await.is_err() {
                return Ok(());
            }
        }

        time::sleep(Duration::from_millis(250)).await;
    }
}

fn join_cmdline(cmdline: &[OsString]) -> String {
    cmdline
        .iter()
        .map(|arg| arg.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn classify_command_risk(command: &str) -> RiskLevel {
    let normalized = command.to_ascii_lowercase();

    let critical_patterns = ["rm -rf", "curl | sh", "wget | bash"];
    if critical_patterns
        .iter()
        .any(|pattern| normalized.contains(pattern))
    {
        return RiskLevel::Critical;
    }

    let high_patterns = ["chmod", "chown", "netcat", "nc "];
    if high_patterns
        .iter()
        .any(|pattern| normalized.contains(pattern))
    {
        return RiskLevel::High;
    }

    RiskLevel::Low
}
