// sandspy::monitor::process — Process tree monitoring

use crate::events::{AgentInfo, Event, EventKind};
use crate::platform;
use anyhow::{Context, Result};
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

/// Find ALL PIDs related to an agent by name.
///
/// Strategy:
/// 1. Find processes whose name matches (Antigravity → Antigravity.exe)
/// 2. Discover the install directory from the matched process's exe path
/// 3. Also capture ANY process whose exe path lives under that install directory
///    (catches language servers, helpers, backend processes, etc.)
pub fn find_all_pids_by_name(name: &str) -> Vec<u32> {
    let needle = normalize_process_name(name);
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);

    // Step 1: Find PIDs matching by name
    let mut name_matched: Vec<u32> = Vec::new();
    let mut install_dirs: Vec<String> = Vec::new();

    for proc in system.processes().values() {
        let proc_name = normalize_process_name(&proc.name().to_string_lossy());
        if proc_name == needle {
            name_matched.push(proc.pid().as_u32());

            // Discover install directory from exe path
            if let Some(exe) = proc.exe() {
                // Focus strictly on the exact application folder (e.g. C:\Program Files\Microsoft VS Code\)
                // This captures bundled helpers/language servers that live in subdirectories.
                if let Some(parent) = exe.parent() {
                    let dir = parent.to_string_lossy().to_lowercase();

                    // Safety: Never use a global OS directory as an install root
                    let is_global = dir == "c:\\windows" 
                        || dir == "c:\\windows\\system32" 
                        || dir == "c:\\program files" 
                        || dir == "c:\\program files (x86)"
                        || dir.ends_with("\\bin") // typical for global CLI tools
                        || dir.ends_with("\\usr\\bin");

                    if !is_global && !install_dirs.contains(&dir) {
                        install_dirs.push(dir);
                    }
                }
            }
        }
    }

    if install_dirs.is_empty() {
        name_matched.sort();
        return name_matched;
    }

    // Step 2: Find ALL processes whose exe lives under any discovered install dir
    let mut all_pids: HashSet<u32> = name_matched.into_iter().collect();

    for proc in system.processes().values() {
        if let Some(exe) = proc.exe() {
            let exe_str = exe.to_string_lossy().to_lowercase();
            for dir in &install_dirs {
                if exe_str.starts_with(dir.as_str()) {
                    all_pids.insert(proc.pid().as_u32());
                    break;
                }
            }
        }
    }

    let mut result: Vec<u32> = all_pids.into_iter().collect();
    result.sort();
    result
}

/// Immediately seed the shared PID set with a list of known PIDs.
/// Called before monitors start so they are non-empty from tick 0.
pub async fn seed_pid_set(pids: &PidSet, initial: &[u32]) {
    let mut guard = pids.write().await;
    for pid in initial {
        guard.insert(*pid);
    }
}

/// Spawn a command and monitor its process tree.
pub async fn spawn_and_monitor(command: &str, tx: mpsc::Sender<Event>, pids: PidSet) -> Result<()> {
    let mut child = spawn_shell_command(command)
        .with_context(|| format!("failed to spawn watch command: {command}"))?;
    let root_pid = child.id();
    let initial: Vec<u32> = {
        let guard = pids.read().await;
        guard.iter().copied().collect()
    };
    monitor_process_tree(root_pid, initial, tx, pids).await?;
    let _ = child.try_wait();
    Ok(())
}

/// Attach to an existing PID and monitor its process tree.
pub async fn attach_and_monitor(pid: u32, tx: mpsc::Sender<Event>, pids: PidSet) -> Result<()> {
    let initial: Vec<u32> = {
        let guard = pids.read().await;
        guard.iter().copied().collect()
    };
    monitor_process_tree(pid, initial, tx, pids).await
}

async fn monitor_process_tree(
    root_pid: u32,
    stable_pids: Vec<u32>, // PIDs to always keep in the set (install-dir seeds)
    tx: mpsc::Sender<Event>,
    pids: PidSet,
) -> Result<()> {
    let stable_set: HashSet<u32> = stable_pids.into_iter().collect();
    let mut system = System::new_all();
    let mut previous_tree: HashSet<u32> = HashSet::new();
    let mut process_meta: HashMap<u32, ProcessSnapshot> = HashMap::new();

    loop {
        system.refresh_processes(ProcessesToUpdate::All, true);
        let process_table = snapshot_processes(system.processes());
        let mut current_tree = collect_process_tree(root_pid, &process_table);

        // Also collect trees from ALL stable (install-dir) PIDs so their
        // children (language servers, helpers) are tracked too
        for &stable_pid in &stable_set {
            let subtree = collect_process_tree(stable_pid, &process_table);
            current_tree.extend(subtree);
        }
        // Always preserve the stable seed PIDs themselves
        current_tree.extend(stable_set.iter().copied());

        {
            let mut shared = pids.write().await;
            *shared = current_tree.clone();
        }

        for new_pid in current_tree.difference(&previous_tree) {
            if let Some(snapshot) = process_table.get(new_pid) {
                process_meta.insert(*new_pid, snapshot.clone());

                // Skip Electron/Chromium internal subprocess noise
                let cmdline_lower = snapshot.cmdline.to_ascii_lowercase();
                if cmdline_lower.contains("--type=gpu")
                    || cmdline_lower.contains("--type=renderer")
                    || cmdline_lower.contains("--type=utility")
                    || cmdline_lower.contains("--type=broker")
                    || cmdline_lower.contains("--type=zygote")
                    || cmdline_lower.contains("--type=crashpad")
                    || cmdline_lower.contains("--mojo-platform-channel-handle")
                    || cmdline_lower.contains("/prefetch:")
                {
                    continue;
                }

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

fn collect_process_tree(
    root_pid: u32,
    process_table: &HashMap<u32, ProcessSnapshot>,
) -> HashSet<u32> {
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
