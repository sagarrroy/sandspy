// sandspy::ui::dashboard — Main dashboard panel (Tab::Dashboard)
//
// Renders the full overview: title bar, agent + risk row,
// 4-column stats area, and the live event feed.

use crate::events::{Event, EventKind, NetCategory, RiskLevel};
use crate::ui::{app::App, theme};
use chrono::Local;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Gauge, List, ListItem, Paragraph},
    Frame,
};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    // Outer layout: header | stats | feed | shortcuts
    let rows = Layout::vertical([
        Constraint::Length(4), // title + agent + risk bar + risk label
        Constraint::Length(5), // 4-column stats block
        Constraint::Fill(1),   // live feed
        Constraint::Length(1), // shortcut bar
    ])
    .split(area);

    render_header(frame, rows[0], app);
    render_stats(frame, rows[1], app);
    render_feed(frame, rows[2], app);
    render_shortcuts(frame, rows[3], app);
}

// ─── Header ─────────────────────────────────────────────────────────────────

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let version = env!("CARGO_PKG_VERSION");
    let elapsed = app.elapsed_str();
    let status = Span::styled(
        "  ACTIVE",
        app.style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
    );

    let title_line = Line::from(vec![
        Span::styled(
            format!(" sandspy v{version} "),
            app.style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ),
        Span::raw("─".repeat(area.width.saturating_sub(28) as usize)),
        Span::styled(format!(" {elapsed}"), app.style(Style::default().fg(Color::DarkGray))),
        status,
        Span::raw(" "),
    ]);

    let agent_label = app
        .agent
        .as_ref()
        .map(|a| format!("  agent: {} (pid {})", a.name, a.pid))
        .unwrap_or_else(|| "  agent: sandspy".to_string());

    let risk = app.risk.score;
    let bar_width = (area.width.saturating_sub(20)) as usize;
    let filled = ((risk as f64 / 100.0) * bar_width as f64).round() as usize;
    let empty = bar_width.saturating_sub(filled);
    let risk_bar = format!("  risk:  [{}{}]  {}", "█".repeat(filled), "─".repeat(empty), risk);
    let risk_label = format!("         {}", theme::risk_label_str(risk));

    let text = vec![
        title_line,
        Line::from(Span::styled(&agent_label, app.style(Style::default().fg(Color::White)))),
        Line::from(Span::styled(&risk_bar, app.style(theme::risk_gauge(risk)))),
        Line::from(Span::styled(&risk_label, app.style(theme::risk_label(risk)))),
    ];

    let para = Paragraph::new(text);
    frame.render_widget(para, area);
}

// ─── Stats row ──────────────────────────────────────────────────────────────

fn render_stats(frame: &mut Frame, area: Rect, app: &App) {
    let cols = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Fill(1),
        Constraint::Fill(1),
        Constraint::Fill(1),
    ])
    .split(area);

    render_files_stats(frame, cols[0], app);
    render_network_stats(frame, cols[1], app);
    render_command_stats(frame, cols[2], app);
    render_secret_stats(frame, cols[3], app);
}

fn stat_block_for(app: &App, title: &'static str) -> Block<'static> {
    Block::default()
        .title(Span::styled(
            format!(" {title} "),
            app.style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(app.style(theme::border()))
}

fn render_files_stats(frame: &mut Frame, area: Rect, app: &App) {
    let s = &app.stats;
    let text = vec![
        stat_line(app, "read:   ", s.files_read, s.files_read > 0),
        stat_line(app, "written:", s.files_written, false),
        stat_line(app, "deleted:", s.files_deleted, s.files_deleted > 0),
    ];
    let p = Paragraph::new(text).block(stat_block_for(app, "FILES"));
    frame.render_widget(p, area);
}

fn render_network_stats(frame: &mut Frame, area: Rect, app: &App) {
    let s = &app.stats;
    let unknown_str = if s.net_unknown > 0 {
        format!("{} [!]", s.net_unknown)
    } else {
        s.net_unknown.to_string()
    };

    let text = vec![
        Line::from(vec![
            Span::styled("  total:   ", app.style(theme::dim())),
            Span::styled(s.net_connections.to_string(), app.style(Style::default().fg(Color::White))),
        ]),
        Line::from(vec![
            Span::styled("  trackers:", app.style(theme::dim())),
            Span::styled(
                s.net_tracking.to_string(),
                if s.net_tracking > 0 {
                    app.style(theme::stat_danger())
                } else {
                    app.style(theme::stat_normal())
                },
            ),
        ]),
        Line::from(vec![
            Span::styled("  unknown: ", app.style(theme::dim())),
            Span::styled(
                unknown_str,
                if s.net_unknown > 0 {
                    app.style(theme::stat_danger())
                } else {
                    app.style(theme::stat_normal())
                },
            ),
        ]),
    ];
    let p = Paragraph::new(text).block(stat_block_for(app, "NETWORK"));
    frame.render_widget(p, area);
}

fn render_command_stats(frame: &mut Frame, area: Rect, app: &App) {
    let s = &app.stats;
    let text = vec![
        stat_line(app, "executed:", s.commands_total, false),
        stat_line(
            app,
            "danger:  ",
            s.commands_dangerous,
            s.commands_dangerous > 0,
        ),
        stat_line(app, "failed:  ", s.commands_failed, s.commands_failed > 0),
    ];
    let p = Paragraph::new(text).block(stat_block_for(app, "COMMANDS"));
    frame.render_widget(p, area);
}

fn render_secret_stats(frame: &mut Frame, area: Rect, app: &App) {
    let s = &app.stats;
    let text = vec![
        stat_line(app, "accessed:", s.secrets_accessed, s.secrets_accessed > 0),
        stat_line(app, "leaked:  ", s.secrets_leaked, s.secrets_leaked > 0),
        stat_line(app, "residual:", s.residual_files, s.residual_files > 0),
    ];
    let p = Paragraph::new(text).block(stat_block_for(app, "SECRETS"));
    frame.render_widget(p, area);
}

fn stat_line(app: &App, label: &'static str, value: usize, warn: bool) -> Line<'static> {
    let val_style = if warn {
        app.style(theme::stat_danger())
    } else {
        app.style(theme::stat_normal())
    };
    Line::from(vec![
        Span::styled(format!("  {label} "), app.style(theme::dim())),
        Span::styled(value.to_string(), val_style),
    ])
}

// ─── Live feed ───────────────────────────────────────────────────────────────

fn render_feed(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " LIVE FEED ",
            app.style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(app.style(theme::border()));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let max_lines = inner.height as usize;
    let feed_width = inner.width as usize;
    // Only show events we can meaningfully display (no ProcessExit, no blanks)
    let displayable: Vec<&Event> = app
        .events
        .iter()
        .filter(|e| is_displayable(&e.kind))
        .collect();
    let items: Vec<ListItem> = displayable
        .iter()
        .rev()
        .take(max_lines)
        .rev()
        .map(|e| ListItem::new(format_event_line(e, app.no_color, feed_width)))
        .collect();

    let list = List::new(items);
    frame.render_widget(list, inner);
}

/// Returns true for event kinds we want in the live feed.
/// ProcessExit renders as a blank line and adds noise.
fn is_displayable(kind: &EventKind) -> bool {
    !matches!(kind, EventKind::ProcessExit { .. })
}

// ─── Shortcut bar ───────────────────────────────────────────────────────────

fn render_shortcuts(frame: &mut Frame, area: Rect, app: &App) {
    let line = Line::from(vec![
        Span::styled(" [1]", app.style(Style::default().fg(Color::Cyan))),
        Span::styled("home ", app.style(theme::dim())),
        Span::styled("[f]", app.style(Style::default().fg(Color::Cyan))),
        Span::styled("files ", app.style(theme::dim())),
        Span::styled("[n]", app.style(Style::default().fg(Color::Cyan))),
        Span::styled("net ", app.style(theme::dim())),
        Span::styled("[d]", app.style(Style::default().fg(Color::Cyan))),
        Span::styled("diffs ", app.style(theme::dim())),
        Span::styled("[s]", app.style(Style::default().fg(Color::Cyan))),
        Span::styled("summary ", app.style(theme::dim())),
        Span::styled("[a]", app.style(Style::default().fg(Color::Cyan))),
        Span::styled("alerts ", app.style(theme::dim())),
        Span::styled("[esc]", app.style(Style::default().fg(Color::Yellow))),
        Span::styled("back ", app.style(theme::dim())),
        Span::styled("[j/k]", app.style(Style::default().fg(Color::Cyan))),
        Span::styled("scroll ", app.style(theme::dim())),
        Span::styled("[q]", app.style(Style::default().fg(Color::Red))),
        Span::styled("quit ", app.style(theme::dim())),
    ]);
    let p = Paragraph::new(line);
    frame.render_widget(p, area);
}

// ─── Shared event formatter (used by feed and other panels) ─────────────────

pub fn format_event_line(event: &Event, no_color: bool, width: usize) -> Line<'static> {
    // Dynamic column widths based on terminal width
    // Layout: timestamp(8) + 2 + tag(5) + 2 + content(dynamic) + 2 + label(8) + bytes(7) = ~34 fixed
    let content_width = width.saturating_sub(36).max(20);

    if no_color {
        let plain = match &event.kind {
            EventKind::FileRead { path, .. } => format!("FILE READ {}", path.display()),
            EventKind::FileWrite { path, .. } => format!("FILE WRITE {}", path.display()),
            EventKind::FileDelete { path } => format!("FILE DELETE {}", path.display()),
            EventKind::NetworkConnection { remote_addr, remote_port, .. } => {
                format!("NET {}:{}", remote_addr, remote_port)
            }
            EventKind::ShellCommand { command, .. } => format!("CMD {}", command),
            EventKind::SecretAccess { name, .. } => format!("SECRET {}", name),
            EventKind::EnvVarRead { name, .. } => format!("ENV {}", name),
            EventKind::ClipboardRead { .. } => "CLIPBOARD read".to_string(),
            EventKind::Alert { message, .. } => format!("ALERT {}", message),
            EventKind::ProcessSpawn { name, pid, .. } => format!("PROC {} ({})", name, pid),
            _ => String::new(),
        };
        return Line::from(Span::raw(plain));
    }

    let ts = event.timestamp.with_timezone(&Local).format("%H:%M:%S").to_string();
    let ts_span = Span::styled(ts, theme::dim());

    match &event.kind {
        EventKind::FileRead { path, sensitive, .. } => {
            let label = if *sensitive {
                Span::styled("SENSITIVE", theme::label_sensitive())
            } else {
                Span::styled("ok      ", theme::label_ok())
            };
            Line::from(vec![
                ts_span,
                Span::raw("  "),
                Span::styled("READ ", theme::tag_read()),
                Span::raw("  "),
                Span::styled(truncate_str(&path.display().to_string(), content_width), Style::default().fg(Color::White)),
                Span::raw("  "),
                label,
            ])
        }
        EventKind::FileWrite { path, diff_summary } => {
            let diff = diff_summary.as_deref().unwrap_or("").to_owned();
            Line::from(vec![
                ts_span,
                Span::raw("  "),
                Span::styled("WRITE", theme::tag_write()),
                Span::raw("  "),
                Span::styled(truncate_str(&path.display().to_string(), content_width.saturating_sub(12)), Style::default().fg(Color::White)),
                Span::raw("  "),
                Span::styled(diff, theme::tag_write()),
            ])
        }
        EventKind::FileDelete { path } => Line::from(vec![
            ts_span,
            Span::raw("  "),
            Span::styled("DEL  ", theme::tag_delete()),
            Span::raw("  "),
            Span::styled(truncate_str(&path.display().to_string(), content_width), theme::tag_delete()),
        ]),
        EventKind::NetworkConnection {
            remote_addr,
            remote_port,
            domain,
            category,
            ..
        } => {
            // Show the most informative host: domain if resolved, else IP
            let host = domain
                .as_deref()
                .map(|d| format!("{d}:{remote_port}"))
                .unwrap_or_else(|| format!("{remote_addr}:{remote_port}"));
            // Infer owner from IP for display
            let owner = infer_owner(remote_addr);
            let (label_text, label_style) = match category {
                NetCategory::ExpectedApi => ("ok     ", theme::label_ok()),
                NetCategory::Telemetry => ("telem  ", theme::label_telemetry()),
                NetCategory::Tracking => ("TRACK  ", theme::label_tracking()),
                NetCategory::Unknown => ("UNKNOWN", theme::label_unknown()),
            };
            Line::from(vec![
                ts_span,
                Span::raw("  "),
                Span::styled("NET  ", theme::tag_net()),
                Span::raw("  "),
                Span::styled(truncate_str(&host, content_width.saturating_sub(20)), Style::default().fg(Color::White)),
                Span::raw("  "),
                Span::styled(format!("{:>9}", owner), theme::dim()),
                Span::raw("  "),
                Span::styled(label_text, label_style),
            ])
        }
        EventKind::ShellCommand { command, risk, .. } => {
            let (label_text, label_style) = match risk {
                RiskLevel::Critical => ("CRITICAL", theme::label_critical()),
                RiskLevel::High => ("HIGH    ", theme::label_high()),
                RiskLevel::Medium => ("medium  ", theme::label_medium()),
                RiskLevel::Low => ("ok      ", theme::label_ok()),
            };
            Line::from(vec![
                ts_span,
                Span::raw("  "),
                Span::styled("CMD  ", theme::tag_cmd()),
                Span::raw("  "),
                Span::styled(truncate_str(command, content_width.saturating_sub(10)), Style::default().fg(Color::White)),
                Span::raw("  "),
                Span::styled(label_text, label_style),
            ])
        }
        EventKind::SecretAccess { name, .. } => Line::from(vec![
            ts_span,
            Span::raw("  "),
            Span::styled("SECRET", theme::tag_secret()),
            Span::raw(" "),
            Span::styled(truncate_str(name, content_width), Style::default().fg(Color::Red)),
            Span::raw("  "),
            Span::styled("HIGH", theme::label_high()),
        ]),
        EventKind::EnvVarRead { name, sensitive } => {
            let label = if *sensitive {
                Span::styled("SENSITIVE", theme::label_sensitive())
            } else {
                Span::styled("ok", theme::label_ok())
            };
            Line::from(vec![
                ts_span,
                Span::raw("  "),
                Span::styled("ENV  ", theme::tag_env()),
                Span::raw("  "),
                Span::styled(truncate_str(name, content_width), Style::default().fg(Color::White)),
                Span::raw("  "),
                label,
            ])
        }
        EventKind::ClipboardRead { contains_secret, .. } => {
            let label = if *contains_secret {
                Span::styled("SENSITIVE", theme::label_sensitive())
            } else {
                Span::styled("ok", theme::label_ok())
            };
            Line::from(vec![
                ts_span,
                Span::raw("  "),
                Span::styled("CLIP ", theme::tag_clip()),
                Span::raw("  clipboard read                              "),
                label,
            ])
        }
        EventKind::Alert { message, severity } => {
            let msg_style = match severity {
                RiskLevel::Critical => theme::label_critical(),
                RiskLevel::High => theme::label_high(),
                RiskLevel::Medium => theme::label_medium(),
                RiskLevel::Low => theme::dim(),
            };
            Line::from(vec![
                ts_span,
                Span::raw("  "),
                Span::styled("ALERT", theme::tag_alert()),
                Span::raw("  "),
                Span::styled(truncate_str(message, content_width), msg_style),
            ])
        }
        EventKind::ProcessSpawn { name, pid, cmdline, .. } => {
            let desc = if cmdline.len() > 40 {
                format!("{name} (pid {pid})")
            } else {
                format!("{name} (pid {pid}) {cmdline}")
            };
            Line::from(vec![
                ts_span,
                Span::raw("  "),
                Span::styled("PROC ", theme::tag_proc()),
                Span::raw("  "),
                Span::styled(truncate_str(&desc, content_width), theme::dim()),
            ])
        }
        _ => Line::from(Span::raw("")),
    }
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        format!("{:<width$}", s, width = max)
    } else {
        format!("{}…", &s[..max - 1])
    }
}

/// Parse the remote IP and return its operator name for display.
fn infer_owner(addr: &str) -> &'static str {
    use std::net::IpAddr;
    let ip = match addr.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => return "unknown",
    };
    let IpAddr::V4(v4) = ip else { return "IPv6" };
    let octets = v4.octets();
    match octets[0] {
        // Google: 34, 35, 66, 74, 142, 216
        34 | 35 => "Google",
        66 if octets[1] == 249 => "Google",
        74 if octets[1] == 125 => "Google",
        142 if octets[1] >= 250 => "Google",
        216 if octets[1] == 58 || octets[1] == 239 => "Google",
        // AWS: 3, 52, 54
        3 | 52 | 54 => "AWS",
        // Azure: 13, 20, 40
        13 | 20 => "Azure",
        40 if octets[1] >= 64 => "Azure",
        // Cloudflare: 104, 108, 162, 172, 188
        104 if octets[1] >= 16 && octets[1] < 32 => "Cloudflr",
        108 if octets[1] == 162 => "Cloudflr",
        162 if octets[1] >= 158 => "Cloudflr",
        172 if octets[1] >= 64 && octets[1] < 72 => "Cloudflr",
        // Anthropic / OpenAI use Cloudflare/AWS, so those are covered above
        _ => "unknown",
    }
}
