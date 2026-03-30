// sandspy::monitor::filesystem — File access watching
//
// Uses notify to watch the project directory recursively.
// Emits FileWrite, FileDelete, and SecretAccess events.
// Secret scanning runs on every file write AND at startup for pre-existing sensitive files.

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

const MAX_SCAN_BYTES: u64 = 512 * 1024; // 512KB — scan larger files than before
const DEBOUNCE_MS: u64 = 300;

pub async fn run(tx: mpsc::Sender<Event>, pids: PidSet) -> Result<()> {
    let watch_dir = resolve_watch_dir(&pids).await;
    let mut snapshots = preload_sensitive_snapshots(&watch_dir);

    // Scan pre-existing sensitive files at startup and emit findings immediately
    startup_secret_scan(&watch_dir, &tx).await?;

    let (notify_tx, mut notify_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut watcher = notify::recommended_watcher(move |event| {
        let _ = notify_tx.send(event);
    })
    .context("failed to create filesystem watcher")?;

    watcher
        .watch(&watch_dir, RecursiveMode::Recursive)
        .with_context(|| format!("failed to watch directory: {}", watch_dir.display()))?;

    // Also watch common sensitive locations in home dir
    if let Some(home) = dirs::home_dir() {
        for sensitive in &[".ssh", ".aws", ".config/gcloud", ".kube"] {
            let p = home.join(sensitive);
            if p.exists() {
                let _ = watcher.watch(&p, RecursiveMode::Recursive);
            }
        }
    }

    tracing::debug!(dir = %watch_dir.display(), "filesystem monitor watching");

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

        let now = Instant::now();
        let paths_to_process: Vec<_> = event
            .paths
            .iter()
            .filter(|p| match last_emit.get(*p) {
                Some(t) if now.duration_since(*t) < debounce => false,
                _ => true,
            })
            .cloned()
            .collect();

        for path in &paths_to_process {
            last_emit.insert(path.clone(), now);
        }

        if paths_to_process.is_empty() {
            continue;
        }

        let mut filtered = event.clone();
        filtered.paths = paths_to_process;
        handle_notify_event(&filtered, &tx, &mut snapshots).await?;
    }

    Ok(())
}

/// Scan sensitive files that already exist at monitoring start.
/// This catches secrets that were written before sandspy was launched.
async fn startup_secret_scan(root: &Path, tx: &mpsc::Sender<Event>) -> Result<()> {
    let mut paths = Vec::new();
    let _ = visit_tree(root, &mut |p| {
        if !is_noise_path(p) && is_sensitive_path(p) {
            paths.push(p.to_path_buf());
        }
    });

    // Also check home dir sensitive files
    if let Some(home) = dirs::home_dir() {
        for rel in &[
            ".env",
            ".aws/credentials",
            ".aws/config",
            ".ssh/id_rsa",
            ".ssh/id_ed25519",
            ".netrc",
            ".pgpass",
        ] {
            let p = home.join(rel);
            if p.exists() {
                paths.push(p);
            }
        }
    }

    for path in paths {
        emit_secret_access_events_with_source(&path, tx, SecretSource::File).await?;
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
                let sensitive = is_sensitive_path(path);
                let risk = if sensitive { 15 } else { 0 };
                let file_event = Event::with_risk(
                    EventKind::FileWrite {
                        path: path.clone(),
                        diff_summary,
                    },
                    risk,
                );

                if tx.send(file_event).await.is_err() {
                    return Ok(());
                }

                // Only scan content for secrets on sensitive file types
                // (avoids false positives from docs/code containing example keys)
                if sensitive {
                    emit_secret_access_events_with_source(path, tx, SecretSource::File).await?;
                }
            }
            NotifyEventKind::Modify(_) => {
                let diff_summary = build_write_summary(path, snapshots, false);
                let sensitive = is_sensitive_path(path);
                let risk = if sensitive { 10 } else { 0 };
                let file_event = Event::with_risk(
                    EventKind::FileWrite {
                        path: path.clone(),
                        diff_summary,
                    },
                    risk,
                );

                if tx.send(file_event).await.is_err() {
                    return Ok(());
                }

                // Scan content on every modify for sensitive files
                if sensitive {
                    emit_secret_access_events_with_source(path, tx, SecretSource::File).await?;
                }
            }
            NotifyEventKind::Remove(_) => {
                snapshots.remove(path);
                let sensitive = is_sensitive_path(path);
                // Deleting a sensitive file is suspicious (covering tracks)
                let risk = if sensitive { 20 } else { 0 };
                let file_event = Event::with_risk(
                    EventKind::FileDelete { path: path.clone() },
                    risk,
                );

                if tx.send(file_event).await.is_err() {
                    return Ok(());
                }
            }
            _ => {}
        }
    }

    Ok(())
}

async fn emit_secret_access_events_with_source(
    path: &Path,
    tx: &mpsc::Sender<Event>,
    source: SecretSource,
) -> Result<()> {
    // For known sensitive filenames — even without content match — emit a warning
    let fname = path.file_name().and_then(|f| f.to_str()).unwrap_or_default();
    if secrets::is_sensitive_filename(fname) {
        // We know this file is sensitive regardless of content
        // Only emit if we can't scan it (binary, too large, etc.)
        if read_text_file_if_small(path).is_none() {
            let event = Event::with_risk(
                EventKind::SecretAccess {
                    name: format!("sensitive file: {fname}"),
                    source: source.clone(),
                },
                20,
            );
            if tx.send(event).await.is_err() {
                return Ok(());
            }
            return Ok(());
        }
    }

    let Some(contents) = read_text_file_if_small(path) else {
        return Ok(());
    };

    let findings = secrets::scan_text(&contents);

    // Deduplicate by pattern name within this file scan
    let mut seen_patterns = std::collections::HashSet::new();

    for finding in findings.into_iter().take(10) {
        if !seen_patterns.insert(finding.pattern_name.clone()) {
            continue;
        }

        // Skip values that look like placeholders/examples
        if secrets::is_placeholder_value(&finding.matched_value) {
            continue;
        }

        let risk = secrets::secret_risk_score(&finding.pattern_name);
        let event = Event::with_risk(
            EventKind::SecretAccess {
                name: finding.pattern_name,
                source: source.clone(),
            },
            risk,
        );

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
        .filter(|c| c.tag() == similar::ChangeTag::Insert)
        .count();
    let deleted = diff
        .iter_all_changes()
        .filter(|c| c.tag() == similar::ChangeTag::Delete)
        .count();

    if inserted == 0 && deleted == 0 {
        None
    } else {
        Some(format!("+{inserted} -{deleted}"))
    }
}

fn read_text_file_if_small(path: &Path) -> Option<String> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_SCAN_BYTES {
        return None;
    }
    fs::read_to_string(path).ok()
}


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

    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
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
        Ok(m) => m,
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
            Ok(e) => e,
            Err(_) => continue,
        };
        let _ = visit_tree(&entry.path(), callback);
    }

    Ok(())
}

fn is_noise_path(path: &Path) -> bool {
    let s = path.to_string_lossy().replace('\\', "/").to_lowercase();
    if s.contains("/.git/") {
        return true;
    }
    [
        "/node_modules/",
        "/target/",
        "/__pycache__/",
        "/.next/",
        "/dist/",
        "/build/",
        "/.venv/",
        "/vendor/",
    ]
    .iter()
    .any(|seg| s.contains(seg))
}

pub fn is_sensitive_path(path: &Path) -> bool {
    let s = path.to_string_lossy().replace('\\', "/").to_lowercase();
    let fname = path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or_default()
        .to_lowercase();

    // .env files (any variant)
    if fname == ".env" || fname.starts_with(".env.") || fname.ends_with(".env") {
        return true;
    }

    // SSH keys
    if s.contains("/.ssh/") {
        return true;
    }

    // Cloud credential files
    if s.contains("/.aws/credentials")
        || s.contains("/.aws/config")
        || s.contains("/.gcloud/")
        || s.contains("/.kube/config")
        || fname == ".netrc"
        || fname == ".pgpass"
    {
        return true;
    }

    // Certificate / key files
    if [".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"]
        .iter()
        .any(|ext| fname.ends_with(ext))
    {
        return true;
    }

    // Name-based heuristics
    let triggers = [
        "credentials", "secret", "token", "password", "passwd",
        "apikey", "api_key", "auth_token",
    ];
    triggers.iter().any(|t| fname.contains(t))
}

#[allow(dead_code)]
fn categorize_path(path: &Path) -> FileCategory {
    if is_sensitive_path(path) {
        return FileCategory::Secret;
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_lowercase();

    match ext.as_str() {
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
        assert!(is_sensitive_path(Path::new("app.env")));
        assert!(is_sensitive_path(Path::new("C:/Users/test/.ssh/id_rsa")));
        assert!(is_sensitive_path(Path::new("service_credentials.json")));
        assert!(is_sensitive_path(Path::new("key.pem")));
        assert!(!is_sensitive_path(Path::new("src/main.rs")));
    }
}
