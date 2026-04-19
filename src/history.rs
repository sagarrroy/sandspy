// sandspy::history — Session history browsing and persistence

use crate::events::Event;
use crate::ui::summary;
use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub agent_name: String,
    pub pid: Option<u32>,
    pub duration: u64,
    pub risk_score: u32,
    pub event_count: usize,
    pub timestamp: DateTime<Utc>,
}

/// Filters for listing sessions.
#[derive(Debug, Default)]
pub struct ListFilter {
    pub agent: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub min_risk: Option<u32>,
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

pub async fn list(filter: ListFilter) -> Result<()> {
    let mut sessions = load_all_sessions()?;
    apply_filter(&mut sessions, &filter);
    sessions.sort_by_key(|x| Reverse(x.1.timestamp));

    if sessions.is_empty() {
        println!("No sessions found in {}", sessions_root().display());
        return Ok(());
    }

    println!(
        "{:<20}  {:<16}  {:<8}  {:<5}  {:<8}  TIMESTAMP",
        "SESSION", "AGENT", "DURATION", "RISK", "EVENTS"
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

pub async fn delete(session_id: &str) -> Result<()> {
    let session_dir = find_session_dir(session_id)?;
    fs::remove_dir_all(&session_dir)
        .with_context(|| format!("failed to delete session: {}", session_dir.display()))?;
    println!("deleted session: {}", session_id);
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

fn apply_filter(sessions: &mut Vec<(String, SessionMetadata)>, filter: &ListFilter) {
    if let Some(ref agent) = filter.agent {
        sessions.retain(|(_, m)| m.agent_name.to_lowercase().contains(&agent.to_lowercase()));
    }
    if let Some(since) = filter.since {
        sessions.retain(|(_, m)| m.timestamp >= since);
    }
    if let Some(until) = filter.until {
        sessions.retain(|(_, m)| m.timestamp <= until);
    }
    if let Some(min_risk) = filter.min_risk {
        sessions.retain(|(_, m)| m.risk_score >= min_risk);
    }
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
            Err(e) => {
                warn!("failed to read session directory entry: {}", e);
                continue;
            }
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
            Err(e) => {
                warn!(
                    "failed to read line in events file {}: {}",
                    path.display(),
                    e
                );
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Event>(&line) {
            Ok(event) => events.push(event),
            Err(e) => {
                warn!("dropping malformed event in {}: {}", path.display(), e);
            }
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
    fn test_apply_filter() {
        let ts1 = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let ts2 = chrono::Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap();
        let ts3 = chrono::Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).unwrap();

        let all = vec![
            (
                "s1".to_string(),
                SessionMetadata {
                    agent_name: "cursor".into(),
                    pid: None,
                    timestamp: ts1,
                    duration: 0,
                    event_count: 0,
                    risk_score: 30,
                },
            ),
            (
                "s2".to_string(),
                SessionMetadata {
                    agent_name: "windsurf".into(),
                    pid: None,
                    timestamp: ts2,
                    duration: 0,
                    event_count: 0,
                    risk_score: 70,
                },
            ),
            (
                "s3".to_string(),
                SessionMetadata {
                    agent_name: "cursor".into(),
                    pid: None,
                    timestamp: ts3,
                    duration: 0,
                    event_count: 0,
                    risk_score: 10,
                },
            ),
        ];

        let mut sessions = all.clone();
        let f = ListFilter {
            agent: Some("cursor".into()),
            since: None,
            until: None,
            min_risk: None,
        };
        apply_filter(&mut sessions, &f);
        assert_eq!(sessions.len(), 2);

        let mut sessions = all.clone();
        let f = ListFilter {
            agent: None,
            since: None,
            until: None,
            min_risk: Some(50),
        };
        apply_filter(&mut sessions, &f);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].0, "s2");

        let mut sessions = all.clone();
        let f = ListFilter {
            agent: None,
            since: Some(ts2),
            until: None,
            min_risk: None,
        };
        apply_filter(&mut sessions, &f);
        assert_eq!(sessions.len(), 2);
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
