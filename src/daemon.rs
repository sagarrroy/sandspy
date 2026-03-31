// sandspy::daemon — Background daemon mode

use crate::alerts;
use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use sysinfo::{Pid, ProcessesToUpdate, System};
use tokio::time;

pub async fn start() -> Result<()> {
    let pid_path = daemon_pid_path();
    let log_path = daemon_log_path();
    ensure_sandspy_dir()?;

    if let Some(existing_pid) = read_pid_file(&pid_path)? {
        if is_pid_alive(existing_pid) {
            println!("daemon already running (pid {})", existing_pid);
            return Ok(());
        }
    }

    fs::write(&pid_path, std::process::id().to_string())
        .with_context(|| format!("failed to write pid file: {}", pid_path.display()))?;
    append_log(&log_path, "daemon started")?;

    let mut system = System::new_all();
    let mut monitored = BTreeMap::<u32, String>::new();

    loop {
        system.refresh_processes(ProcessesToUpdate::All, true);
        let known = known_agent_names();

        for process in system.processes().values() {
            let process_name = process.name().to_string_lossy().to_string();
            let normalized = normalize_name(&process_name);

            if !known.contains(normalized.as_str()) {
                continue;
            }

            let process_pid = process.pid().as_u32();
            if monitored.contains_key(&process_pid) {
                continue;
            }

            let watch_pid = spawn_watch_child(&process_name)?;
            monitored.insert(process_pid, process_name.clone());
            append_log(
                &log_path,
                &format!(
                    "agent_detected name={} pid={} watch_pid={}",
                    process_name, process_pid, watch_pid
                ),
            )?;
            let _ = alerts::notify("sandspy", &format!("agent detected: {}", process_name));
        }

        let alive_pids = system
            .processes()
            .values()
            .map(|p| p.pid().as_u32())
            .collect::<HashSet<_>>();
        monitored.retain(|pid, _| alive_pids.contains(pid));

        time::sleep(Duration::from_secs(5)).await;
    }
}

pub async fn stop() -> Result<()> {
    let pid_path = daemon_pid_path();
    let log_path = daemon_log_path();
    let pid = read_pid_file(&pid_path)?.context("daemon pid file not found or empty")?;

    terminate_pid(pid)?;

    if pid_path.exists() {
        fs::remove_file(&pid_path)
            .with_context(|| format!("failed to remove pid file: {}", pid_path.display()))?;
    }

    let _ = append_log(&log_path, &format!("daemon stopped pid={pid}"));
    println!("daemon stopped (pid {})", pid);
    Ok(())
}

pub async fn status() -> Result<()> {
    let pid_path = daemon_pid_path();
    let pid = read_pid_file(&pid_path)?;

    match pid {
        Some(value) if is_pid_alive(value) => {
            println!("running (pid {})", value);
        }
        _ => {
            println!("not running");
        }
    }

    Ok(())
}

pub async fn watch() -> Result<()> {
    let log_path = daemon_log_path();
    if !log_path.exists() {
        println!("no daemon log found");
        return Ok(());
    }

    let file = OpenOptions::new()
        .read(true)
        .open(&log_path)
        .with_context(|| format!("failed to open log: {}", log_path.display()))?;
    let reader = BufReader::new(file);
    let mut names = Vec::<String>::new();
    let lines: Vec<String> = reader.lines().map_while(|l| l.ok()).collect();

    for line in lines.iter().rev().take(500) {
        if let Some(name) = extract_agent_name(line) {
            if !names.iter().any(|existing| existing == &name) {
                names.push(name);
            }
        }
    }

    if names.is_empty() {
        println!("no monitored agents found in daemon log");
        return Ok(());
    }

    println!("currently monitored agents:");
    for name in names.into_iter().rev() {
        println!("- {}", name);
    }

    Ok(())
}

fn sandspy_dir() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".sandspy")
}

fn daemon_pid_path() -> PathBuf {
    sandspy_dir().join("daemon.pid")
}

fn daemon_log_path() -> PathBuf {
    sandspy_dir().join("daemon.log")
}

fn ensure_sandspy_dir() -> Result<()> {
    let dir = sandspy_dir();
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create sandspy dir: {}", dir.display()))
}

fn append_log(path: &PathBuf, message: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open daemon log: {}", path.display()))?;
    writeln!(file, "{} {}", Utc::now().to_rfc3339(), message)
        .with_context(|| format!("failed to append daemon log: {}", path.display()))
}

fn read_pid_file(path: &PathBuf) -> Result<Option<u32>> {
    if !path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read pid file: {}", path.display()))?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let pid = trimmed
        .parse::<u32>()
        .with_context(|| format!("invalid pid value in {}", path.display()))?;
    Ok(Some(pid))
}

fn is_pid_alive(pid: u32) -> bool {
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);
    system.process(Pid::from_u32(pid)).is_some()
}

#[cfg(unix)]
fn terminate_pid(pid: u32) -> Result<()> {
    let result = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    if result != 0 {
        anyhow::bail!("failed to send SIGTERM to pid {}", pid);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn terminate_pid(pid: u32) -> Result<()> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid)?;
        TerminateProcess(handle, 1)?;
        let _ = CloseHandle(handle);
    }

    Ok(())
}

#[cfg(not(any(unix, target_os = "windows")))]
fn terminate_pid(_pid: u32) -> Result<()> {
    Ok(())
}

fn spawn_watch_child(process_name: &str) -> Result<u32> {
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    let mut command = Command::new(exe);
    command
        .arg("watch")
        .arg(process_name)
        .arg("--json")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }

    let child = command
        .spawn()
        .with_context(|| format!("failed to spawn watch child for agent {process_name}"))?;
    Ok(child.id())
}

fn known_agent_names() -> HashSet<&'static str> {
    [
        "claude",
        "claude-code",
        "cursor",
        "copilot",
        "gemini",
        "gemini-cli",
        "codex",
        "windsurf",
        "cline",
        "aider",
        "continue",
        "antigravity",
        "openclaw",
    ]
    .into_iter()
    .collect()
}

fn normalize_name(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .trim_end_matches(".exe")
        .to_string()
}

fn extract_agent_name(line: &str) -> Option<String> {
    let token = "agent_detected name=";
    let start = line.find(token)? + token.len();
    let rest = &line[start..];
    let end = rest.find(" pid=").unwrap_or(rest.len());
    let value = rest[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}
