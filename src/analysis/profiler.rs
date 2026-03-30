// sandspy::analysis::profiler — Agent profile loading and matching

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct AgentProfile {
	#[serde(skip)]
	pub id: String,
	pub agent: AgentSection,
	pub expected: ExpectedSection,
	pub alerts: AlertsSection,
	pub risk_weights: RiskWeights,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentSection {
	pub name: String,
	pub process_names: Vec<String>,
	pub description: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExpectedSection {
	pub network: ExpectedNetwork,
	pub filesystem: ExpectedFilesystem,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExpectedNetwork {
	pub allowed_domains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExpectedFilesystem {
	pub normal_patterns: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AlertsSection {
	pub sensitive_file_access: bool,
	pub unknown_network: bool,
	pub shell_dangerous_commands: bool,
	pub clipboard_read: bool,
	pub env_secret_access: bool,
	pub excessive_file_reads: u32,
	pub excessive_data_out: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RiskWeights {
	pub sensitive_file_read: u32,
	pub unknown_network_connection: u32,
	pub secret_env_access: u32,
	pub dangerous_command: u32,
	pub clipboard_read: u32,
	pub excessive_scope: u32,
}

pub fn load_profiles() -> Result<Vec<AgentProfile>> {
	let mut profiles = load_builtin_profiles()?;
	load_user_overrides(&mut profiles)?;

	let mut values = profiles.into_values().collect::<Vec<_>>();
	values.sort_by(|left, right| left.id.cmp(&right.id));
	Ok(values)
}

pub fn match_profile<'a>(
	profiles: &'a [AgentProfile],
	forced_profile: Option<&str>,
	process_or_command: Option<&str>,
) -> Option<&'a AgentProfile> {
	if let Some(forced) = forced_profile {
		return find_by_id_or_name(profiles, forced);
	}

	if let Some(process) = process_or_command {
		let normalized = normalize_name(process);
		if let Some(profile) = profiles.iter().find(|profile| {
			profile
				.agent
				.process_names
				.iter()
				.any(|name| normalize_name(name) == normalized)
		}) {
			return Some(profile);
		}
	}

	find_by_id_or_name(profiles, "generic")
}

fn find_by_id_or_name<'a>(profiles: &'a [AgentProfile], name: &str) -> Option<&'a AgentProfile> {
	let normalized = normalize_name(name);
	profiles.iter().find(|profile| {
		normalize_name(&profile.id) == normalized || normalize_name(&profile.agent.name) == normalized
	})
}

fn load_builtin_profiles() -> Result<HashMap<String, AgentProfile>> {
	let mut profiles = HashMap::new();

	for (id, content) in builtin_profile_sources() {
		let mut profile = parse_profile(id, content)
			.with_context(|| format!("failed to parse built-in profile: {id}"))?;
		profile.id = id.to_string();
		profiles.insert(id.to_string(), profile);
	}

	Ok(profiles)
}

fn load_user_overrides(profiles: &mut HashMap<String, AgentProfile>) -> Result<()> {
	let user_profiles_dir = sandspy_profiles_dir();
	if !user_profiles_dir.exists() {
		return Ok(());
	}

	for entry in fs::read_dir(&user_profiles_dir)
		.with_context(|| format!("failed to read user profiles dir: {}", user_profiles_dir.display()))?
	{
		let entry = match entry {
			Ok(value) => value,
			Err(error) => {
				tracing::warn!(%error, "skipping unreadable user profile entry");
				continue;
			}
		};

		let path = entry.path();
		if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
			continue;
		}

		let profile_id = profile_id_from_path(&path).unwrap_or_else(|| "generic".to_string());
		let content = match fs::read_to_string(&path) {
			Ok(value) => value,
			Err(error) => {
				tracing::warn!(%error, path = %path.display(), "failed to read user profile");
				continue;
			}
		};

		match parse_profile(&profile_id, &content) {
			Ok(mut profile) => {
				profile.id = profile_id.clone();
				profiles.insert(profile_id, profile);
			}
			Err(error) => {
				tracing::warn!(%error, path = %path.display(), "failed to parse user profile");
			}
		}
	}

	Ok(())
}

fn parse_profile(id: &str, content: &str) -> Result<AgentProfile> {
	let mut profile = toml::from_str::<AgentProfile>(content)
		.with_context(|| format!("invalid profile TOML: {id}"))?;
	profile.id = id.to_string();
	Ok(profile)
}

fn profile_id_from_path(path: &Path) -> Option<String> {
	path.file_stem()
		.and_then(|value| value.to_str())
		.map(ToString::to_string)
}

fn normalize_name(value: &str) -> String {
	let lower = value.to_ascii_lowercase();
	let token = lower.split_whitespace().next().unwrap_or_default();
	if let Some(stripped) = token.strip_suffix(".exe") {
		stripped.to_string()
	} else {
		token.to_string()
	}
}

fn builtin_profile_sources() -> Vec<(&'static str, &'static str)> {
	vec![
		("aider", include_str!("../../profiles/aider.toml")),
		("antigravity", include_str!("../../profiles/antigravity.toml")),
		("claude-code", include_str!("../../profiles/claude-code.toml")),
		("cline", include_str!("../../profiles/cline.toml")),
		("codex-cli", include_str!("../../profiles/codex-cli.toml")),
		("continue", include_str!("../../profiles/continue.toml")),
		("cursor", include_str!("../../profiles/cursor.toml")),
		("gemini-cli", include_str!("../../profiles/gemini-cli.toml")),
		("generic", include_str!("../../profiles/generic.toml")),
		("openclaw", include_str!("../../profiles/openclaw.toml")),
		("windsurf", include_str!("../../profiles/windsurf.toml")),
	]
}

fn sandspy_profiles_dir() -> PathBuf {
	let home = env::var("HOME")
		.ok()
		.or_else(|| env::var("USERPROFILE").ok())
		.map(PathBuf::from)
		.unwrap_or_else(|| PathBuf::from("."));
	home.join(".sandspy").join("profiles")
}

#[allow(dead_code)]
fn _profile_path(root: &Path, id: &str) -> PathBuf {
	root.join(format!("{id}.toml"))
}
