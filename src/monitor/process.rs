// sandspy::monitor::process — Process tree monitoring

use crate::events::{AgentInfo, Event, EventKind};
use crate::platform;
use anyhow::{anyhow, Context, Result};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{Pid, ProcessesToUpdate, System};
use tokio::sync::{mpsc, RwLock};
use tokio::time;

/// Shared set of PIDs in the monitored process tree.
/// Other monitors use this to correlate events with the agent.
pub type PidSet = Arc<RwLock<HashSet<u32>>>;

/// Create a new shared PID set.
pub fn create_pid_set() -> PidSet {
    Arc::new(RwLock::new(HashSet::new()))
}

/// Scan running processes for known AI agent names.
pub fn scan_for_agents() -> Vec<AgentInfo> {
    let known_names = known_agent_names();
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);

    let mut agents = Vec::new();
    for process in system.processes().values() {
        let name = process.name().to_string_lossy().to_string();
        let normalized = normalize_process_name(&name);

        if known_names.contains(normalized.as_str()) {
            agents.push(AgentInfo {
                pid: process.pid().as_u32(),
                name,
                uptime_secs: process.run_time(),
            });
        }
    }

    agents.sort_by_key(|agent| agent.pid);
    agents
}

/// Spawn a command and monitor its process tree.
pub async fn spawn_and_monitor(
    command: &str,
    tx: mpsc::Sender<Event>,
    pids: PidSet,
) -> Result<()> {
    let mut child = spawn_shell_command(command)
        .with_context(|| format!("failed to spawn watch command: {command}"))?;
    let root_pid = child.id();

    monitor_process_tree(root_pid, tx, pids).await?;

    let _ = child.try_wait();
    Ok(())
}

/// Attach to a running PID and monitor its process tree.
pub async fn attach_and_monitor(
    pid: u32,
    tx: mpsc::Sender<Event>,
    pids: PidSet,
) -> Result<()> {
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);

    if !system.processes().contains_key(&Pid::from_u32(pid)) {
        return Err(anyhow!("cannot attach: pid {pid} was not found"));
    }

    monitor_process_tree(pid, tx, pids).await
}

async fn monitor_process_tree(root_pid: u32, tx: mpsc::Sender<Event>, pids: PidSet) -> Result<()> {
    let mut system = System::new_all();
    let mut previous_tree: HashSet<u32> = HashSet::new();
    let mut process_meta: HashMap<u32, ProcessSnapshot> = HashMap::new();

    loop {
        system.refresh_processes(ProcessesToUpdate::All, true);
        let process_table = snapshot_processes(system.processes());
        let current_tree = collect_process_tree(root_pid, &process_table);

        {
            let mut shared = pids.write().await;
            *shared = current_tree.clone();
        }

        for new_pid in current_tree.difference(&previous_tree) {
            if let Some(snapshot) = process_table.get(new_pid) {
                process_meta.insert(*new_pid, snapshot.clone());
                let event = Event::new(EventKind::ProcessSpawn {
                    pid: snapshot.pid,
                    name: snapshot.name.clone(),
                    cmdline: snapshot.cmdline.clone(),
                    parent_pid: snapshot.parent_pid.unwrap_or(0),
                });

                if tx.send(event).await.is_err() {
                    return Ok(());
                }
            }
        }

        for exited_pid in previous_tree.difference(&current_tree) {
            let event = Event::new(EventKind::ProcessExit {
                pid: *exited_pid,
                exit_code: None,
            });
            process_meta.remove(exited_pid);

            if tx.send(event).await.is_err() {
                return Ok(());
            }
        }

        if previous_tree.contains(&root_pid) && !current_tree.contains(&root_pid) {
            break;
        }

        previous_tree = current_tree;
        time::sleep(Duration::from_millis(250)).await;
    }

    {
        let mut shared = pids.write().await;
        shared.clear();
    }

    Ok(())
}

#[derive(Clone, Debug)]
struct ProcessSnapshot {
    pid: u32,
    name: String,
    cmdline: String,
    parent_pid: Option<u32>,
}

fn snapshot_processes(processes: &HashMap<Pid, sysinfo::Process>) -> HashMap<u32, ProcessSnapshot> {
    let mut table = HashMap::with_capacity(processes.len());

    for process in processes.values() {
        let pid = process.pid().as_u32();
        let name = process.name().to_string_lossy().to_string();
        let cmdline = join_cmdline(process.cmd());
        let parent_pid = process.parent().map(|parent| parent.as_u32());

        table.insert(
            pid,
            ProcessSnapshot {
                pid,
                name,
                cmdline,
                parent_pid,
            },
        );
    }

    table
}

fn collect_process_tree(root_pid: u32, process_table: &HashMap<u32, ProcessSnapshot>) -> HashSet<u32> {
    if !process_table.contains_key(&root_pid) {
        return HashSet::new();
    }

    let mut tree = HashSet::new();
    let mut frontier = vec![root_pid];
    tree.insert(root_pid);

    while let Some(current_pid) = frontier.pop() {
        for (pid, process) in process_table {
            if process.parent_pid == Some(current_pid) && tree.insert(*pid) {
                frontier.push(*pid);
            }
        }

        for child_pid in platform::process_tree(current_pid) {
            if process_table.contains_key(&child_pid) && tree.insert(child_pid) {
                frontier.push(child_pid);
            }
        }
    }

    tree
}

fn join_cmdline(cmdline: &[OsString]) -> String {
    cmdline
        .iter()
        .map(|arg| arg.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn known_agent_names() -> HashSet<&'static str> {
    [
        "claude",
        "claude-code",
        "cursor",
        "cursor-helper",
        "codex",
        "gemini-cli",
        "gemini",
        "windsurf",
        "cline",
        "aider",
        "continue",
        "antigravity",
        "openclaw",
        "claw",
    ]
    .into_iter()
    .collect()
}

fn normalize_process_name(name: &str) -> String {
    let lowercase = name.to_lowercase();
    if let Some(stripped) = lowercase.strip_suffix(".exe") {
        stripped.to_string()
    } else {
        lowercase
    }
}

fn spawn_shell_command(user_command: &str) -> Result<std::process::Child> {
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/C", user_command])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("failed to spawn command via cmd /C")
    }

    #[cfg(not(target_os = "windows"))]
    {
        Command::new("sh")
            .args(["-c", user_command])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("failed to spawn command via sh -c")
    }
}
