// sandspy::analysis::secrets — Secret/credential pattern detection

use regex::Regex;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMatch {
	pub pattern_name: String,
	pub matched_value: String,
	pub start: usize,
	pub end: usize,
}

#[derive(Debug, Deserialize)]
struct PatternFile {
	patterns: Vec<PatternEntry>,
}

#[derive(Debug, Deserialize)]
struct PatternEntry {
	name: String,
	regex: String,
}

struct CompiledPattern {
	name: String,
	regex: Regex,
}

static PATTERNS: OnceLock<Vec<CompiledPattern>> = OnceLock::new();

pub fn scan_text(content: &str) -> Vec<SecretMatch> {
	if content.is_empty() {
		return Vec::new();
	}

	let patterns = PATTERNS.get_or_init(load_patterns);
	let mut findings = Vec::new();

	for pattern in patterns {
		for matched in pattern.regex.find_iter(content) {
			findings.push(SecretMatch {
				pattern_name: pattern.name.clone(),
				matched_value: matched.as_str().to_string(),
				start: matched.start(),
				end: matched.end(),
			});
		}
	}

	findings.sort_by_key(|entry| entry.start);
	findings
}

fn load_patterns() -> Vec<CompiledPattern> {
	let file_path = signatures_file_path();
	let content = match fs::read_to_string(&file_path) {
		Ok(value) => value,
		Err(_) => return Vec::new(),
	};

	let parsed = match toml::from_str::<PatternFile>(&content) {
		Ok(value) => value,
		Err(_) => return Vec::new(),
	};

	parsed
		.patterns
		.into_iter()
		.filter_map(|entry| {
			Regex::new(&entry.regex).ok().map(|regex| CompiledPattern {
				name: entry.name,
				regex,
			})
		})
		.collect()
}

fn signatures_file_path() -> PathBuf {
	std::env::current_dir()
		.unwrap_or_else(|_| PathBuf::from("."))
		.join("signatures")
		.join("suspicious_patterns.toml")
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn scans_known_patterns() {
		let matches = scan_text("token = sk_live_abcdefghijklmnopqrstuvwxyz");
		assert!(!matches.is_empty());
	}
}
