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
    render_shortcuts(frame, rows[3]);
}

// ─── Header ─────────────────────────────────────────────────────────────────

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let version = env!("CARGO_PKG_VERSION");
    let elapsed = app.elapsed_str();
    let status = Span::styled("  ACTIVE", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD));

    let title_line = Line::from(vec![
        Span::styled(
            format!(" sandspy v{version} "),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        Span::raw("─".repeat(area.width.saturating_sub(28) as usize)),
        Span::styled(format!(" {elapsed}"), Style::default().fg(Color::DarkGray)),
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
        Line::from(Span::styled(&agent_label, Style::default().fg(Color::White))),
        Line::from(Span::styled(&risk_bar, theme::risk_gauge(risk))),
        Line::from(Span::styled(&risk_label, theme::risk_label(risk))),
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

fn stat_block(title: &str) -> Block<'_> {
    Block::default()
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(theme::border())
}

fn render_files_stats(frame: &mut Frame, area: Rect, app: &App) {
    let s = &app.stats;
    let text = vec![
        stat_line("read:   ", s.files_read, s.files_read > 0),
        stat_line("written:", s.files_written, false),
        stat_line("deleted:", s.files_deleted, s.files_deleted > 0),
    ];
    let p = Paragraph::new(text).block(stat_block("FILES"));
    frame.render_widget(p, area);
}

fn render_network_stats(frame: &mut Frame, area: Rect, app: &App) {
    let s = &app.stats;
    let bytes_str = theme::format_bytes(s.bytes_out);
    let unknown_str = if s.net_unknown > 0 {
        format!("{} [!]", s.net_unknown)
    } else {
        s.net_unknown.to_string()
    };

    let text = vec![
        Line::from(vec![
            Span::styled("  connect: ", theme::dim()),
            Span::styled(s.net_connections.to_string(), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  data:    ", theme::dim()),
            Span::styled(bytes_str, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  unknown: ", theme::dim()),
            Span::styled(
                unknown_str,
                if s.net_unknown > 0 {
                    theme::stat_danger()
                } else {
                    theme::stat_normal()
                },
            ),
        ]),
    ];
    let p = Paragraph::new(text).block(stat_block("NETWORK"));
    frame.render_widget(p, area);
}

fn render_command_stats(frame: &mut Frame, area: Rect, app: &App) {
    let s = &app.stats;
    let text = vec![
        stat_line("executed:", s.commands_total, false),
        stat_line(
            "danger:  ",
            s.commands_dangerous,
            s.commands_dangerous > 0,
        ),
        stat_line("failed:  ", s.commands_failed, s.commands_failed > 0),
    ];
    let p = Paragraph::new(text).block(stat_block("COMMANDS"));
    frame.render_widget(p, area);
}

fn render_secret_stats(frame: &mut Frame, area: Rect, app: &App) {
    let s = &app.stats;
    let text = vec![
        stat_line("accessed:", s.secrets_accessed, s.secrets_accessed > 0),
        stat_line("leaked:  ", s.secrets_leaked, s.secrets_leaked > 0),
        stat_line("residual:", s.residual_files, s.residual_files > 0),
    ];
    let p = Paragraph::new(text).block(stat_block("SECRETS"));
    frame.render_widget(p, area);
}

fn stat_line(label: &str, value: usize, warn: bool) -> Line<'_> {
    let val_style = if warn {
        theme::stat_danger()
    } else {
        theme::stat_normal()
    };
    Line::from(vec![
        Span::styled(format!("  {label} "), theme::dim()),
        Span::styled(value.to_string(), val_style),
    ])
}

// ─── Live feed ───────────────────────────────────────────────────────────────

fn render_feed(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " LIVE FEED ",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(theme::border());

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let max_lines = inner.height as usize;
    let items: Vec<ListItem> = app
        .events
        .iter()
        .rev()
        .take(max_lines)
        .rev()
        .map(|e| ListItem::new(format_event_line(e)))
        .collect();

    let list = List::new(items);
    frame.render_widget(list, inner);
}

// ─── Shortcut bar ───────────────────────────────────────────────────────────

fn render_shortcuts(frame: &mut Frame, area: Rect) {
    let line = Line::from(vec![
        Span::styled(" [f]", Style::default().fg(Color::Cyan)),
        Span::styled("files ", theme::dim()),
        Span::styled("[n]", Style::default().fg(Color::Cyan)),
        Span::styled("net ", theme::dim()),
        Span::styled("[d]", Style::default().fg(Color::Cyan)),
        Span::styled("diffs ", theme::dim()),
        Span::styled("[s]", Style::default().fg(Color::Cyan)),
        Span::styled("summary ", theme::dim()),
        Span::styled("[a]", Style::default().fg(Color::Cyan)),
        Span::styled("alerts ", theme::dim()),
        Span::styled("[tab]", Style::default().fg(Color::Cyan)),
        Span::styled("switch ", theme::dim()),
        Span::styled("[j/k]", Style::default().fg(Color::Cyan)),
        Span::styled("scroll ", theme::dim()),
        Span::styled("[q]", Style::default().fg(Color::Red)),
        Span::styled("quit ", theme::dim()),
    ]);
    let p = Paragraph::new(line);
    frame.render_widget(p, area);
}

// ─── Shared event formatter (used by feed and other panels) ─────────────────

pub fn format_event_line(event: &Event) -> Line<'static> {
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
                Span::styled(truncate_str(&path.display().to_string(), 38), Style::default().fg(Color::White)),
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
                Span::styled(truncate_str(&path.display().to_string(), 38), Style::default().fg(Color::White)),
                Span::raw("  "),
                Span::styled(diff, theme::tag_write()),
            ])
        }
        EventKind::FileDelete { path } => Line::from(vec![
            ts_span,
            Span::raw("  "),
            Span::styled("DEL  ", theme::tag_delete()),
            Span::raw("  "),
            Span::styled(path.display().to_string(), theme::tag_delete()),
        ]),
        EventKind::NetworkConnection {
            remote_addr,
            remote_port,
            domain,
            category,
            bytes_sent,
            bytes_recv,
            ..
        } => {
            let host = domain
                .as_deref()
                .map(|d| format!("{d}:{remote_port}"))
                .unwrap_or_else(|| format!("{remote_addr}:{remote_port}"));
            let bytes = theme::format_bytes(bytes_sent + bytes_recv);
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
                Span::styled(truncate_str(&host, 32), Style::default().fg(Color::White)),
                Span::raw("  "),
                Span::styled(format!("{:>7}", bytes), theme::dim()),
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
                Span::styled(truncate_str(command, 38), Style::default().fg(Color::White)),
                Span::raw("  "),
                Span::styled(label_text, label_style),
            ])
        }
        EventKind::SecretAccess { name, .. } => Line::from(vec![
            ts_span,
            Span::raw("  "),
            Span::styled("SECRET", theme::tag_secret()),
            Span::raw("  "),
            Span::styled(truncate_str(name, 38), Style::default().fg(Color::Red)),
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
                Span::styled(truncate_str(name, 38), Style::default().fg(Color::White)),
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
                Span::styled(message.clone(), msg_style),
            ])
        }
        EventKind::ProcessSpawn { name, pid, .. } => Line::from(vec![
            ts_span,
            Span::raw("  "),
            Span::styled("PROC ", theme::tag_proc()),
            Span::raw("  "),
            Span::styled(format!("{name} (pid {pid})"), theme::dim()),
        ]),
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
