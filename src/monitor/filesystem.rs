// sandspy::monitor::filesystem — File access watching

use crate::analysis::secrets;
use crate::events::{Event, EventKind, FileCategory, SecretSource};
use crate::monitor::process::PidSet;
use anyhow::{Context, Result};
use notify::{Event as NotifyEvent, EventKind as NotifyEventKind, RecursiveMode, Watcher};
use similar::TextDiff;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const MAX_DIFF_BYTES: u64 = 100 * 1024;
/// How long to wait before emitting a second event for the same path.
const DEBOUNCE_MS: u64 = 200;


pub async fn run(tx: mpsc::Sender<Event>, pids: PidSet) -> Result<()> {
    // Try to resolve the working directory of the monitored process.
    // Fallback to sandspy's own cwd if unavailable (e.g. no pids yet, or Windows
    // doesn't expose it for that process).
    let watch_dir = resolve_watch_dir(&pids).await;
    let mut snapshots = preload_sensitive_snapshots(&watch_dir);

    let (notify_tx, mut notify_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut watcher = notify::recommended_watcher(move |event| {
        let _ = notify_tx.send(event);
    })
    .context("failed to create filesystem watcher")?;

    watcher
        .watch(&watch_dir, RecursiveMode::Recursive)
        .with_context(|| format!("failed to watch directory: {}", watch_dir.display()))?;

    // Also watch home dir sensitive files (.ssh, .aws, .env in home)
    if let Some(home) = dirs::home_dir() {
        for sensitive in &[".ssh", ".aws"] {
            let p = home.join(sensitive);
            if p.exists() {
                let _ = watcher.watch(&p, RecursiveMode::Recursive);
            }
        }
    }

    tracing::debug!(dir = %watch_dir.display(), "filesystem monitor watching");

    // Debounce table: path -> last emit time
    let mut last_emit: HashMap<PathBuf, Instant> = HashMap::new();
    let debounce = Duration::from_millis(DEBOUNCE_MS);

    while let Some(event_result) = notify_rx.recv().await {
        let event = match event_result {
            Ok(event) => event,
            Err(error) => {
                tracing::warn!(%error, "filesystem watcher event error");
                continue;
            }
        };

        // Debounce: skip if we emitted for this path recently
        let now = Instant::now();
        let paths_to_process: Vec<_> = event
            .paths
            .iter()
            .filter(|p| {
                match last_emit.get(*p) {
                    Some(t) if now.duration_since(*t) < debounce => false,
                    _ => true,
                }
            })
            .cloned()
            .collect();

        for path in &paths_to_process {
            last_emit.insert(path.clone(), now);
        }

        if paths_to_process.is_empty() {
            continue;
        }

        // Build a filtered event with only the debounced paths
        let mut filtered = event.clone();
        filtered.paths = paths_to_process;
        handle_notify_event(&filtered, &tx, &mut snapshots).await?;
    }

    Ok(())
}

/// Resolve the best directory to watch for the target process.
async fn resolve_watch_dir(pids: &PidSet) -> PathBuf {
    let pid_snapshot = {
        let guard = pids.read().await;
        guard.iter().copied().collect::<Vec<_>>()
    };

    if !pid_snapshot.is_empty() {
        let mut sys = sysinfo::System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

        for pid in &pid_snapshot {
            if let Some(proc) = sys.process(sysinfo::Pid::from_u32(*pid)) {
                if let Some(cwd) = proc.cwd() {
                    if cwd.exists() {
                        return cwd.to_path_buf();
                    }
                }
            }
        }
    }

    // Fallback: sandspy's own cwd (still useful when watching a local project)
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}


async fn handle_notify_event(
    event: &NotifyEvent,
    tx: &mpsc::Sender<Event>,
    snapshots: &mut HashMap<PathBuf, String>,
) -> Result<()> {
    for path in &event.paths {
        if is_noise_path(path) {
            continue;
        }

        match &event.kind {
            NotifyEventKind::Create(_) => {
                let diff_summary = build_write_summary(path, snapshots, true);
                let file_event = Event::new(EventKind::FileWrite {
                    path: path.clone(),
                    diff_summary,
                });

                if tx.send(file_event).await.is_err() {
                    return Ok(());
                }

                emit_secret_access_events(path, tx).await?;
            }
            NotifyEventKind::Modify(_) => {
                let diff_summary = build_write_summary(path, snapshots, false);
                let file_event = Event::new(EventKind::FileWrite {
                    path: path.clone(),
                    diff_summary,
                });

                if tx.send(file_event).await.is_err() {
                    return Ok(());
                }

                emit_secret_access_events(path, tx).await?;
            }
            NotifyEventKind::Remove(_) => {
                snapshots.remove(path);
                let file_event = Event::new(EventKind::FileDelete { path: path.clone() });

                if tx.send(file_event).await.is_err() {
                    return Ok(());
                }
            }
            _ => {}
        }
    }

    Ok(())
}

async fn emit_secret_access_events(path: &Path, tx: &mpsc::Sender<Event>) -> Result<()> {
    let Some(contents) = read_text_file_if_small(path) else {
        return Ok(());
    };

    let findings = secrets::scan_text(&contents);
    for finding in findings.into_iter().take(5) {
        let event = Event::new(EventKind::SecretAccess {
            name: finding.pattern_name,
            source: SecretSource::File,
        });

        if tx.send(event).await.is_err() {
            return Ok(());
        }
    }

    Ok(())
}

fn build_write_summary(
    path: &Path,
    snapshots: &mut HashMap<PathBuf, String>,
    created: bool,
) -> Option<String> {
    if created {
        if let Some(contents) = read_text_file_if_small(path) {
            snapshots.insert(path.to_path_buf(), contents);
        }
        return Some("new file".to_string());
    }

    let current = read_text_file_if_small(path)?;
    let previous = snapshots.insert(path.to_path_buf(), current.clone());

    let previous = previous?;
    let diff = TextDiff::from_lines(&previous, &current);

    let inserted = diff
        .iter_all_changes()
        .filter(|change| change.tag() == similar::ChangeTag::Insert)
        .count();
    let deleted = diff
        .iter_all_changes()
        .filter(|change| change.tag() == similar::ChangeTag::Delete)
        .count();

    if inserted == 0 && deleted == 0 {
        None
    } else {
        Some(format!("+{inserted} -{deleted}"))
    }
}

fn read_text_file_if_small(path: &Path) -> Option<String> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_DIFF_BYTES {
        return None;
    }

    fs::read_to_string(path).ok()
}

fn preload_sensitive_snapshots(root: &Path) -> HashMap<PathBuf, String> {
    let mut snapshots = HashMap::new();
    let _ = visit_tree(root, &mut |path| {
        if is_noise_path(path) || !is_sensitive_path(path) {
            return;
        }

        if let Some(contents) = read_text_file_if_small(path) {
            snapshots.insert(path.to_path_buf(), contents);
        }
    });

    snapshots
}

fn visit_tree<F>(path: &Path, callback: &mut F) -> io::Result<()>
where
    F: FnMut(&Path),
{
    if is_noise_path(path) {
        return Ok(());
    }

    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(()),
    };

    if metadata.is_file() {
        callback(path);
        return Ok(());
    }

    if !metadata.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(path)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let entry_path = entry.path();
        let _ = visit_tree(&entry_path, callback);
    }

    Ok(())
}

fn is_noise_path(path: &Path) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/").to_lowercase();

    // Block all .git/ internals (index, COMMIT_EDITMSG, lock files, refs, objects, etc.)
    if normalized.contains("/.git/") {
        return true;
    }

    [
        "/node_modules/",
        "/target/",
        "/__pycache__/",
        "/.next/",
        "/dist/",
        "/build/",
    ]
    .iter()
    .any(|segment| normalized.contains(segment))
}

fn is_sensitive_path(path: &Path) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/").to_lowercase();
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_lowercase();

    if file_name == ".env" || file_name.starts_with(".env.") {
        return true;
    }

    if normalized.contains("/.ssh/") || normalized.contains("/.aws/credentials") {
        return true;
    }

    if [".pem", ".key", ".p12", ".pfx"]
        .iter()
        .any(|ext| file_name.ends_with(ext))
    {
        return true;
    }

    ["credentials", "secret", "token"].iter().any(|needle| file_name.contains(needle))
}

#[allow(dead_code)]
fn categorize_path(path: &Path) -> FileCategory {
    if is_sensitive_path(path) {
        return FileCategory::Secret;
    }

    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_lowercase();

    match extension.as_str() {
        "rs" | "py" | "ts" | "js" | "tsx" | "jsx" | "go" | "java" | "c" | "cpp" | "h"
        | "rb" | "php" | "swift" | "kt" => FileCategory::Source,
        "toml" | "yaml" | "yml" | "json" | "xml" | "ini" | "cfg" => FileCategory::Config,
        "md" | "txt" | "rst" | "adoc" => FileCategory::Documentation,
        "exe" | "dll" | "so" | "dylib" | "wasm" => FileCategory::Binary,
        _ => FileCategory::Data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noise_path_filter_matches_expected_dirs() {
        assert!(is_noise_path(Path::new("project/target/debug/app")));
        assert!(is_noise_path(Path::new("project/node_modules/react/index.js")));
        assert!(is_noise_path(Path::new("project/.git/objects/ab/cd")));
        assert!(!is_noise_path(Path::new("project/src/main.rs")));
    }

    #[test]
    fn sensitive_path_detection_catches_core_patterns() {
        assert!(is_sensitive_path(Path::new(".env")));
        assert!(is_sensitive_path(Path::new(".env.production")));
        assert!(is_sensitive_path(Path::new("C:/Users/test/.ssh/id_rsa")));
        assert!(is_sensitive_path(Path::new("service_credentials.json")));
        assert!(is_sensitive_path(Path::new("key.pem")));
        assert!(!is_sensitive_path(Path::new("src/main.rs")));
    }

    #[test]
    fn categorization_by_extension_is_correct() {
        assert_eq!(categorize_path(Path::new("src/main.rs")), FileCategory::Source);
        assert_eq!(categorize_path(Path::new("Cargo.toml")), FileCategory::Config);
        assert_eq!(categorize_path(Path::new("README.md")), FileCategory::Documentation);
        assert_eq!(categorize_path(Path::new("binary.exe")), FileCategory::Binary);
        assert_eq!(categorize_path(Path::new("notes.bin")), FileCategory::Data);
        assert_eq!(categorize_path(Path::new(".env")), FileCategory::Secret);
    }
}
