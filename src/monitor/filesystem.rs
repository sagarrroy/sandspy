// sandspy::monitor::filesystem — File access watching

use crate::events::{Event, EventKind, FileCategory};
use crate::monitor::process::PidSet;
use anyhow::{Context, Result};
use notify::{Event as NotifyEvent, EventKind as NotifyEventKind, RecursiveMode, Watcher};
use similar::TextDiff;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

const MAX_DIFF_BYTES: u64 = 100 * 1024;

pub async fn run(tx: mpsc::Sender<Event>, _pids: PidSet) -> Result<()> {
    let cwd = std::env::current_dir().context("failed to get current working directory")?;
    let mut snapshots = preload_sensitive_snapshots(&cwd);

    let (notify_tx, mut notify_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut watcher = notify::recommended_watcher(move |event| {
        let _ = notify_tx.send(event);
    })
    .context("failed to create filesystem watcher")?;

    watcher
        .watch(&cwd, RecursiveMode::Recursive)
        .with_context(|| format!("failed to watch directory: {}", cwd.display()))?;

    while let Some(event_result) = notify_rx.recv().await {
        let event = match event_result {
            Ok(event) => event,
            Err(error) => {
                tracing::warn!(%error, "filesystem watcher event error");
                continue;
            }
        };

        handle_notify_event(&event, &tx, &mut snapshots).await?;
    }

    Ok(())
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

    [
        "/.git/objects/",
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
