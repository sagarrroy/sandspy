// sandspy::report::json — JSON audit log export

use super::{JsonFinding, JsonReport, SessionMetadata};
use crate::ui::summary::extract_findings;
use anyhow::Result;
use std::path::Path;

#[allow(dead_code)]
/// Writes a full JSON audit report for a session to a file.
pub fn export_json_report(
    metadata: &SessionMetadata,
    events: &[crate::events::Event],
    output_path: &Path,
) -> Result<()> {
    let findings = extract_findings(events)
        .into_iter()
        .map(|f| JsonFinding {
            severity: f.severity,
            message: f.message,
        })
        .collect();

    let report = JsonReport {
        metadata: metadata.clone(),
        events: events.to_vec(),
        findings,
    };

    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(output_path, json)?;
    Ok(())
}

#[allow(dead_code)]
/// Returns a JSON string representation of the session without writing to disk.
pub fn render_json_report(
    metadata: SessionMetadata,
    events: Vec<crate::events::Event>,
) -> Result<String> {
    let findings = extract_findings(&events)
        .into_iter()
        .map(|f| JsonFinding {
            severity: f.severity,
            message: f.message,
        })
        .collect();

    let report = JsonReport {
        metadata,
        events,
        findings,
    };

    Ok(serde_json::to_string_pretty(&report)?)
}
