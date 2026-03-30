// sandspy::ui::theme — Single source of truth for all TUI colors
//
// All widgets reference these helpers. Change a color here, it changes everywhere.
#![allow(dead_code)]

use ratatui::style::{Color, Modifier, Style};

// ─── Structural ─────────────────────────────────────────────────────────────

pub fn border() -> Style {
    Style::default().fg(Color::DarkGray)
}

pub fn title() -> Style {
    Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
}

pub fn dim() -> Style {
    Style::default().add_modifier(Modifier::DIM)
}

pub fn selected() -> Style {
    Style::default().add_modifier(Modifier::REVERSED)
}

pub fn header() -> Style {
    Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD)
}

pub fn normal() -> Style {
    Style::default().fg(Color::White)
}

// ─── Event type tags ────────────────────────────────────────────────────────

pub fn tag_read() -> Style {
    Style::default().fg(Color::Gray)
}

pub fn tag_write() -> Style {
    Style::default().fg(Color::Cyan)
}

pub fn tag_delete() -> Style {
    Style::default().fg(Color::Red)
}

pub fn tag_net() -> Style {
    Style::default().fg(Color::Blue)
}

pub fn tag_cmd() -> Style {
    Style::default().fg(Color::Magenta)
}

pub fn tag_secret() -> Style {
    Style::default()
        .fg(Color::Red)
        .add_modifier(Modifier::BOLD)
}

pub fn tag_alert() -> Style {
    Style::default()
        .fg(Color::Red)
        .add_modifier(Modifier::BOLD)
}

pub fn tag_env() -> Style {
    Style::default().fg(Color::Yellow)
}

pub fn tag_proc() -> Style {
    Style::default()
        .fg(Color::Gray)
        .add_modifier(Modifier::DIM)
}

pub fn tag_clip() -> Style {
    Style::default().fg(Color::Gray)
}

// ─── Classification labels ──────────────────────────────────────────────────

pub fn label_sensitive() -> Style {
    Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD)
}

pub fn label_critical() -> Style {
    Style::default()
        .fg(Color::Red)
        .add_modifier(Modifier::BOLD)
}

pub fn label_high() -> Style {
    Style::default().fg(Color::Red)
}

pub fn label_medium() -> Style {
    Style::default().fg(Color::Yellow)
}

pub fn label_ok() -> Style {
    Style::default().fg(Color::DarkGray)
}

pub fn label_unknown() -> Style {
    Style::default()
        .fg(Color::Red)
        .add_modifier(Modifier::BOLD)
}

pub fn label_tracking() -> Style {
    Style::default().fg(Color::Red)
}

pub fn label_telemetry() -> Style {
    Style::default().fg(Color::Yellow)
}

// ─── Risk gauge ─────────────────────────────────────────────────────────────

pub fn risk_gauge(score: u32) -> Style {
    match score {
        0..=20 => Style::default().fg(Color::Green),
        21..=60 => Style::default().fg(Color::Yellow),
        61..=80 => Style::default().fg(Color::Red),
        _ => Style::default()
            .fg(Color::Red)
            .add_modifier(Modifier::BOLD),
    }
}

pub fn risk_label(score: u32) -> Style {
    match score {
        0..=20 => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        21..=60 => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
        61..=80 => Style::default()
            .fg(Color::Red)
            .add_modifier(Modifier::BOLD),
        _ => Style::default()
            .fg(Color::Red)
            .add_modifier(Modifier::BOLD),
    }
}

pub fn risk_label_str(score: u32) -> &'static str {
    match score {
        0..=20 => "LOW",
        21..=60 => "MEDIUM",
        61..=80 => "HIGH",
        _ => "CRITICAL",
    }
}

// ─── Stat numbers ───────────────────────────────────────────────────────────

pub fn stat_normal() -> Style {
    Style::default().fg(Color::White)
}

pub fn stat_warning() -> Style {
    Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD)
}

pub fn stat_danger() -> Style {
    Style::default()
        .fg(Color::Red)
        .add_modifier(Modifier::BOLD)
}

// ─── Utility ────────────────────────────────────────────────────────────────

pub fn format_bytes(b: u64) -> String {
    if b == 0 {
        return "0B".to_string();
    }
    if b < 1_024 {
        format!("{b}B")
    } else if b < 1_024 * 1_024 {
        format!("{:.1}KB", b as f64 / 1_024.0)
    } else {
        format!("{:.1}MB", b as f64 / (1_024.0 * 1_024.0))
    }
}
