// sandspy::config — Configuration management

use anyhow::Result;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub defaults: DefaultsConfig,
    #[serde(default)]
    pub monitoring: MonitoringConfig,
    #[serde(default)]
    pub session: SessionConfig,
    #[serde(default)]
    pub notifications: NotificationsConfig,
}

#[derive(Debug, Deserialize)]
pub struct DefaultsConfig {
    pub verbosity: String,
    pub dashboard: bool,
    pub no_color: bool,
}

impl Default for DefaultsConfig {
    fn default() -> Self {
        Self {
            verbosity: "low".to_string(),
            dashboard: false,
            no_color: false,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct MonitoringConfig {
    pub poll_interval_ms: u64,
    pub net_poll_interval_ms: u64,
    pub max_events: usize,
    pub max_diff_size_kb: usize,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 250,
            net_poll_interval_ms: 500,
            max_events: 50_000,
            max_diff_size_kb: 100,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SessionConfig {
    pub auto_save: bool,
    pub session_dir: String,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            auto_save: true,
            session_dir: String::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct NotificationsConfig {
    pub enabled: bool,
}

impl Default for NotificationsConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Load config from ~/.sandspy/config.toml, falling back to defaults.
pub fn load_config() -> Config {
    let config_path = sandspy_dir().join("config.toml");
    if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(content) => match toml::from_str(&content) {
                Ok(config) => return config,
                Err(e) => {
                    tracing::warn!("malformed config.toml, using defaults: {}", e);
                }
            },
            Err(e) => {
                tracing::warn!("cannot read config.toml, using defaults: {}", e);
            }
        }
    }
    Config::default()
}

/// Returns the sandspy data directory (~/.sandspy/)
pub fn sandspy_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sandspy")
}

/// Returns the sessions directory (~/.sandspy/sessions/)
pub fn sessions_dir() -> PathBuf {
    sandspy_dir().join("sessions")
}
