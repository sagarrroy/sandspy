// sandspy::report — Report generation

use crate::events::{Event, EventKind, NetCategory, RiskLevel};
use crate::ui::summary::{self, Finding, SessionData};
use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

pub mod html;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub agent_name: String,
    pub pid: Option<u32>,
    pub duration: u64,
    pub risk_score: u32,
    pub event_count: usize,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct JsonReport {
    pub metadata: SessionMetadata,
    pub events: Vec<Event>,
    pub findings: Vec<JsonFinding>,
}

#[derive(Debug, Serialize)]
pub struct JsonFinding {
    pub severity: RiskLevel,
    pub message: String,
}

pub fn load_session(session_id: &str) -> Result<(SessionMetadata, Vec<Event>)> {
    let session_dir = resolve_session_dir(session_id)?;
    let metadata_path = session_dir.join("metadata.json");
    let events_path = session_dir.join("events.jsonl");

    let metadata_content = fs::read_to_string(&metadata_path)
        .with_context(|| format!("failed to read metadata file: {}", metadata_path.display()))?;
    let metadata = serde_json::from_str::<SessionMetadata>(&metadata_content)
        .with_context(|| format!("failed to parse metadata file: {}", metadata_path.display()))?;

    let file = File::open(&events_path)
        .with_context(|| format!("failed to open events file: {}", events_path.display()))?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();
    for line in reader.lines() {
        let line =
            line.with_context(|| format!("failed reading line from {}", events_path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let event = serde_json::from_str::<Event>(&line)
            .with_context(|| format!("invalid JSON event in {}", events_path.display()))?;
        events.push(event);
    }

    Ok((metadata, events))
}

pub fn print_markdown_summary(metadata: SessionMetadata, events: Vec<Event>) {
    let start = metadata.timestamp;
    let end = start + ChronoDuration::seconds(metadata.duration as i64);
    let data = SessionData {
        agent_name: metadata.agent_name,
        agent_pid: metadata.pid,
        start,
        end,
        events,
        risk_score: metadata.risk_score,
    };
    summary::print_summary(&data);
}

pub fn build_json_report(metadata: SessionMetadata, events: Vec<Event>) -> JsonReport {
    let findings = extract_findings(&events)
        .into_iter()
        .map(|finding| JsonFinding {
            severity: finding.severity,
            message: finding.message,
        })
        .collect();

    JsonReport {
        metadata,
        events,
        findings,
    }
}

fn sessions_root() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".sandspy").join("sessions")
}

fn resolve_session_dir(session_id: &str) -> Result<PathBuf> {
    let root = sessions_root();
    let exact = root.join(session_id);
    if exact.exists() {
        return Ok(exact);
    }

    let mut matches = Vec::new();
    for entry in fs::read_dir(&root)
        .with_context(|| format!("failed to read sessions root: {}", root.display()))?
    {
        let entry = entry.with_context(|| format!("failed to read entry in {}", root.display()))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().to_string();
        if id.starts_with(session_id) {
            matches.push(path);
        }
    }

    matches.sort();
    matches
        .into_iter()
        .next()
        .with_context(|| format!("session not found: {session_id}"))
}

pub fn extract_findings(events: &[Event]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for event in events {
        match &event.kind {
            EventKind::FileRead {
                path,
                sensitive: true,
                ..
            } => findings.push(Finding {
                severity: RiskLevel::Critical,
                message: format!("{} was read by agent", path.display()),
            }),
            EventKind::NetworkConnection {
                domain,
                remote_addr,
                remote_port,
                category: NetCategory::Unknown,
                ..
            } => {
                let host = domain
                    .as_deref()
                    .map(|name| format!("{name}:{remote_port}"))
                    .unwrap_or_else(|| format!("{remote_addr}:{remote_port}"));
                findings.push(Finding {
                    severity: RiskLevel::High,
                    message: format!("unknown network destination: {host}"),
                });
            }
            EventKind::ShellCommand {
                command,
                risk: RiskLevel::Critical,
                ..
            } => findings.push(Finding {
                severity: RiskLevel::Critical,
                message: format!("dangerous command: {command}"),
            }),
            EventKind::ShellCommand {
                command,
                risk: RiskLevel::High,
                ..
            } => findings.push(Finding {
                severity: RiskLevel::High,
                message: format!("high-risk command: {command}"),
            }),
            EventKind::Alert { message, severity } => findings.push(Finding {
                severity: *severity,
                message: message.clone(),
            }),
            EventKind::SecretAccess { name, source } => findings.push(Finding {
                severity: RiskLevel::Critical,
                message: format!("accessed secret {} via {:?}", name, source),
            }),
            EventKind::ClipboardRead {
                contains_secret: true,
                ..
            } => findings.push(Finding {
                severity: RiskLevel::Critical,
                message: "read secret from clipboard".to_string(),
            }),
            _ => {}
        }
    }

    findings.sort_by_key(|x| Reverse(x.severity));
    findings.truncate(10);
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventKind, RiskLevel};
    use std::path::PathBuf;

    #[test]
    fn test_extract_findings() {
        let events = vec![
            Event {
                timestamp: chrono::Utc::now(),
                risk_score: 10,
                kind: EventKind::SecretAccess {
                    name: "AWSAccessKey".to_string(),
                    source: crate::events::SecretSource::File,
                },
            },
            Event {
                timestamp: chrono::Utc::now(),
                risk_score: 0,
                kind: EventKind::FileRead {
                    path: PathBuf::from("random.txt"),
                    sensitive: false,
                    category: crate::events::FileCategory::Data,
                },
            },
            Event {
                timestamp: chrono::Utc::now(),
                risk_score: 100,
                kind: EventKind::NetworkConnection {
                    remote_addr: "100.10.10.1".to_string(),
                    remote_port: 80,
                    domain: None,
                    category: crate::events::NetCategory::Unknown,
                    bytes_sent: 0,
                    bytes_recv: 0,
                },
            },
        ];

        let findings = extract_findings(&events);
        assert_eq!(findings.len(), 2);

        // Ensure sorted by severity high -> low
        assert_eq!(findings[0].severity, RiskLevel::Critical);
        assert!(findings[0].message.contains("AWSAccessKey"));

        assert_eq!(findings[1].severity, RiskLevel::High);
        assert!(findings[1].message.contains("unknown network"));
    }
}
