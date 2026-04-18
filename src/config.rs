// sandspy::config — Configuration management
//
// Values are loaded from ~/.sandspy/config.toml with sensible defaults.
// Monitors reference this via Arc<Config> so all modules share the same settings.
#![allow(dead_code)]

use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;

/// Root configuration, loaded once at startup and shared across all monitors.
#[allow(clippy::derivable_impls)]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Config {
    pub monitoring: MonitoringConfig,
    pub session: SessionConfig,
    pub notifications: NotificationsConfig,
}

#[allow(clippy::derivable_impls)]
impl Default for Config {
    fn default() -> Self {
        Self {
            monitoring: MonitoringConfig::default(),
            session: SessionConfig::default(),
            notifications: NotificationsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct MonitoringConfig {
    /// How often monitors poll for changes (ms).
    pub poll_interval_ms: u64,
    /// How often network monitor polls (ms).
    pub net_poll_interval_ms: u64,
    /// Maximum events in the ring buffer.
    pub max_events: usize,
    /// Maximum file size for content scanning (bytes).
    pub max_scan_bytes: u64,
    /// Debounce window for filesystem events (ms).
    pub debounce_ms: u64,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 250,
            net_poll_interval_ms: 500,
            max_events: 50_000,
            max_scan_bytes: 512 * 1024,
            debounce_ms: 300,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SessionConfig {
    pub auto_save: bool,
    pub session_dir: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct NotificationsConfig {
    pub enabled: bool,
}

/// Load config from ~/.sandspy/config.toml, falling back to defaults.
pub fn load_config() -> Config {
    let config_path = sandspy_dir().join("config.toml");
    if config_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&config_path) {
            if let Ok(config) = toml::from_str::<Config>(&content) {
                tracing::info!(path = %config_path.display(), "config loaded");
                return config;
            }
            tracing::warn!(
                "malformed config.toml at {}, using defaults",
                config_path.display()
            );
        } else {
            tracing::warn!(
                "cannot read config.toml at {}, using defaults",
                config_path.display()
            );
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

/// Wrap config in Arc for sharing across all monitors.
pub fn shared() -> Arc<Config> {
    Arc::new(load_config())
}
