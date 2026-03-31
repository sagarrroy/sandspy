// sandspy::monitor::memory — Post-session residue scanning

use crate::events::{Event, EventKind, FileCategory, RiskLevel};
use anyhow::Result;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use sysinfo::{Pid, ProcessesToUpdate, System};
use tokio::sync::mpsc;

pub async fn run(
    tx: mpsc::Sender<Event>,
    session_start: SystemTime,
    seen_pids: &HashSet<u32>,
) -> Result<()> {
    emit_temp_residue_events(&tx, session_start).await?;
    emit_orphan_process_events(&tx, seen_pids).await?;
    Ok(())
}

async fn emit_temp_residue_events(
    tx: &mpsc::Sender<Event>,
    session_start: SystemTime,
) -> Result<()> {
    let temp_dirs = temp_scan_roots();
    let mut residue_count = 0usize;

    for root in temp_dirs {
        if !root.exists() {
            continue;
        }

        for path in collect_recent_temp_files(&root, session_start) {
            residue_count += 1;
            let event = Event::new(EventKind::FileRead {
                path,
                sensitive: false,
                category: FileCategory::Data,
            });

            if tx.send(event).await.is_err() {
                return Ok(());
            }
        }
    }

    if residue_count > 0 {
        let alert = Event::new(EventKind::Alert {
            message: format!(
                "memory residue scan found {residue_count} temp files created during session"
            ),
            severity: RiskLevel::Medium,
        });

        let _ = tx.send(alert).await;
    }

    Ok(())
}

async fn emit_orphan_process_events(
    tx: &mpsc::Sender<Event>,
    seen_pids: &HashSet<u32>,
) -> Result<()> {
    if seen_pids.is_empty() {
        return Ok(());
    }

    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);

    for pid in seen_pids {
        let Some(process) = system.process(Pid::from_u32(*pid)) else {
            continue;
        };

        let spawn_event = Event::new(EventKind::ProcessSpawn {
            pid: *pid,
            name: process.name().to_string_lossy().to_string(),
            cmdline: process
                .cmd()
                .iter()
                .map(|part| part.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join(" "),
            parent_pid: process.parent().map(|value| value.as_u32()).unwrap_or(0),
        });

        if tx.send(spawn_event).await.is_err() {
            return Ok(());
        }

        let alert = Event::new(EventKind::Alert {
            message: format!("orphaned process remained after session: pid {}", pid),
            severity: RiskLevel::High,
        });
        if tx.send(alert).await.is_err() {
            return Ok(());
        }
    }

    Ok(())
}

fn temp_scan_roots() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    let roots = vec![std::env::temp_dir()];

    #[cfg(not(target_os = "windows"))]
    let mut roots = vec![std::env::temp_dir()];

    #[cfg(not(target_os = "windows"))]
    {
        let tmp_root = PathBuf::from("/tmp");
        if !roots.iter().any(|entry| entry == &tmp_root) {
            roots.push(tmp_root);
        }
    }

    roots
}

fn collect_recent_temp_files(root: &Path, session_start: SystemTime) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_recent_files_recursive(root, session_start, &mut files);
    files
}

fn collect_recent_files_recursive(
    path: &Path,
    session_start: SystemTime,
    files: &mut Vec<PathBuf>,
) {
    let metadata = match fs::metadata(path) {
        Ok(value) => value,
        Err(_) => return,
    };

    if metadata.is_file() {
        if metadata
            .modified()
            .map(|time| time >= session_start)
            .unwrap_or(false)
        {
            files.push(path.to_path_buf());
        }
        return;
    }

    if !metadata.is_dir() {
        return;
    }

    let entries = match fs::read_dir(path) {
        Ok(value) => value,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        collect_recent_files_recursive(&entry.path(), session_start, files);
    }
}
