// sandspy::history — Session history browsing and persistence

use crate::events::Event;
use crate::ui::summary;
use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub agent_name: String,
    pub pid: Option<u32>,
    pub duration: u64,
    pub risk_score: u32,
    pub event_count: usize,
    pub timestamp: DateTime<Utc>,
}

pub fn persist_session(metadata: &SessionMetadata, events: &[Event]) -> Result<String> {
    let session_id = metadata.timestamp.format("%Y-%m-%d-%H%M%S").to_string();
    let dir = sessions_root().join(&session_id);

    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create session dir: {}", dir.display()))?;

    let metadata_path = dir.join("metadata.json");
    let metadata_writer = BufWriter::new(File::create(&metadata_path).with_context(|| {
        format!(
            "failed to create metadata file: {}",
            metadata_path.display()
        )
    })?);
    serde_json::to_writer_pretty(metadata_writer, metadata)
        .with_context(|| format!("failed to write metadata: {}", metadata_path.display()))?;

    let events_path = dir.join("events.jsonl");
    let mut events_writer = BufWriter::new(
        File::create(&events_path)
            .with_context(|| format!("failed to create events file: {}", events_path.display()))?,
    );
    for event in events {
        let line = serde_json::to_string(event).context("failed to encode event as json")?;
        writeln!(events_writer, "{line}").context("failed to write event line")?;
    }

    Ok(session_id)
}

pub async fn list() -> Result<()> {
    let mut sessions = load_all_sessions()?;
    sessions.sort_by(|left, right| right.1.timestamp.cmp(&left.1.timestamp));

    if sessions.is_empty() {
        println!("No sessions found in {}", sessions_root().display());
        return Ok(());
    }

    println!(
        "{:<20}  {:<16}  {:<8}  {:<5}  {:<8}  {}",
        "session", "agent", "duration", "risk", "events", "timestamp"
    );
    println!("{}", "-".repeat(90));

    for (id, metadata) in sessions {
        println!(
            "{:<20}  {:<16}  {:<8}  {:<5}  {:<8}  {}",
            id,
            truncate(&metadata.agent_name, 16),
            format_duration(metadata.duration),
            metadata.risk_score,
            metadata.event_count,
            metadata.timestamp.format("%Y-%m-%d %H:%M:%S")
        );
    }

    Ok(())
}

pub async fn show(session_id: &str) -> Result<()> {
    let session_dir = find_session_dir(session_id)?;
    let metadata = read_metadata(&session_dir.join("metadata.json"))?;
    let events = read_events_jsonl(&session_dir.join("events.jsonl"))?;

    let start = metadata.timestamp;
    let end = start + ChronoDuration::seconds(metadata.duration as i64);
    let data = summary::SessionData {
        agent_name: metadata.agent_name,
        agent_pid: metadata.pid,
        start,
        end,
        events,
        risk_score: metadata.risk_score,
    };
    summary::print_summary(&data);

    Ok(())
}

fn sessions_root() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".sandspy").join("sessions")
}

fn load_all_sessions() -> Result<Vec<(String, SessionMetadata)>> {
    let root = sessions_root();
    if !root.exists() {
        return Ok(Vec::new());
    }

    let mut sessions = Vec::new();
    for entry in fs::read_dir(&root)
        .with_context(|| format!("failed to read sessions root: {}", root.display()))?
    {
        let entry = match entry {
            Ok(value) => value,
            Err(_) => continue,
        };
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let session_id = entry.file_name().to_string_lossy().to_string();
        let metadata_path = path.join("metadata.json");
        if !metadata_path.exists() {
            continue;
        }

        if let Ok(metadata) = read_metadata(&metadata_path) {
            sessions.push((session_id, metadata));
        }
    }

    Ok(sessions)
}

fn find_session_dir(session_id: &str) -> Result<PathBuf> {
    let exact = sessions_root().join(session_id);
    if exact.exists() {
        return Ok(exact);
    }

    let sessions = load_all_sessions()?;
    let mut matches = sessions
        .into_iter()
        .filter(|(id, _)| id.starts_with(session_id))
        .map(|(id, _)| sessions_root().join(id))
        .collect::<Vec<_>>();

    matches.sort();
    matches
        .into_iter()
        .next()
        .with_context(|| format!("session not found: {session_id}"))
}

fn read_metadata(path: &Path) -> Result<SessionMetadata> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read metadata file: {}", path.display()))?;
    let metadata = serde_json::from_str::<SessionMetadata>(&content)
        .with_context(|| format!("failed to parse metadata file: {}", path.display()))?;
    Ok(metadata)
}

fn read_events_jsonl(path: &Path) -> Result<Vec<Event>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open events file: {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for line in reader.lines() {
        let line = match line {
            Ok(value) => value,
            Err(_) => continue,
        };
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<Event>(&line) {
            events.push(event);
        }
    }

    Ok(events)
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else {
        format!("{}m{}s", secs / 60, secs % 60)
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_string()
    } else if max <= 1 {
        "…".to_string()
    } else {
        format!("{}…", &value[..max - 1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(65), "1m5s");
        assert_eq!(format_duration(120), "2m0s");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello", 4), "hel…");
    }

    #[test]
    fn test_session_metadata_serialization() {
        let meta = SessionMetadata {
            agent_name: "TestAgent".to_string(),
            pid: Some(1000),
            timestamp: chrono::Utc
                .with_ymd_and_hms(2026, 3, 30, 22, 16, 52)
                .unwrap(),
            duration: 153,
            event_count: 85,
            risk_score: 100,
        };

        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("TestAgent"));

        let deserialized: SessionMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.agent_name, "TestAgent");
        assert_eq!(deserialized.duration, 153);
        assert_eq!(deserialized.risk_score, 100);
    }
}
