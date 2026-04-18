// sandspy::analysis::diff — File diff computation using `similar`
#![allow(dead_code)]
//
// Provides structured diff output for FileWrite events. Each diff is
// computed on-demand from the current file content vs. a stored snapshot.

use similar::{ChangeTag, TextDiff};
use std::path::Path;

/// Summary of changes in a file.
#[derive(Debug, Clone, Default)]
pub struct DiffSummary {
    pub insertions: usize,
    pub deletions: usize,
    /// Relative diff as a human-readable string, e.g. "+15 -3"
    pub summary: String,
    /// Number of unchanged lines (for reference)
    pub unchanged: usize,
}

/// Compute a diff between two text contents and return a structured summary.
pub fn compute_diff(previous: &str, current: &str) -> DiffSummary {
    let diff = TextDiff::from_lines(previous, current);
    let mut insertions = 0;
    let mut deletions = 0;
    let mut unchanged = 0;

    for change in diff.iter_all_changes() {
        match change.tag() {
            ChangeTag::Insert => insertions += 1,
            ChangeTag::Delete => deletions += 1,
            ChangeTag::Equal => unchanged += 1,
        }
    }

    let summary = if insertions == 0 && deletions == 0 {
        String::new()
    } else {
        format!("+{insertions} -{deletions}")
    };

    DiffSummary {
        insertions,
        deletions,
        summary,
        unchanged,
    }
}

/// Compute a diff by reading two files on disk.
pub fn diff_files(previous_path: &Path, current_path: &Path) -> Option<DiffSummary> {
    let previous = std::fs::read_to_string(previous_path).ok()?;
    let current = std::fs::read_to_string(current_path).ok()?;
    Some(compute_diff(&previous, &current))
}

/// Format a diff as a series of colored lines for terminal output.
/// Returns lines as (symbol, content) where symbol is '+', '-', ' ', or '~' (context).
pub fn format_diff_lines<'a>(previous: &'a str, current: &'a str) -> Vec<(char, &'a str)> {
    let diff = TextDiff::from_lines(previous, current);
    diff.iter_all_changes()
        .map(|change| {
            let symbol = match change.tag() {
                ChangeTag::Insert => '+',
                ChangeTag::Delete => '-',
                ChangeTag::Equal => ' ',
            };
            (symbol, change.value())
        })
        .collect()
}
