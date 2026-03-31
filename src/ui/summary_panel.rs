// sandspy::ui::summary_panel — Summary tab (Tab::Summary)
//
// Renders the same rich post-session summary inside the TUI.

use crate::events::RiskLevel;
use crate::ui::{app::App, theme};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph, Wrap},
    Frame,
};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " SUMMARY ",
            app.style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(app.style(theme::border()));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = build_summary_lines(app);
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((app.scroll_offset as u16, 0));
    frame.render_widget(para, inner);
}

fn build_summary_lines(app: &App) -> Vec<Line<'static>> {
    let s = &app.stats;
    let score = app.risk.score;
    let elapsed = app.elapsed_str();

    let agent_name = app
        .agent
        .as_ref()
        .map(|a| format!("{} (pid {})", a.name, a.pid))
        .unwrap_or_else(|| "sandspy".to_string());

    let bar_width = 50usize;
    let filled = ((score as f64 / 100.0) * bar_width as f64).round() as usize;
    let empty = bar_width.saturating_sub(filled);
    let bar_str = format!(
        "[{}{}]  {}/100",
        "█".repeat(filled),
        "─".repeat(empty),
        score
    );
    let risk_str = theme::risk_label_str(score);

    let mut lines = vec![
        Line::from(""),
        section_title("session summary", app),
        Line::from(""),
        kv_line("agent   ", &agent_name, app),
        kv_line("elapsed ", &elapsed, app),
        Line::from(""),
        section_title("activity", app),
        Line::from(""),
        kv_line(
            "files   ",
            &format!(
                "{} read  {} written  {} deleted",
                s.files_read, s.files_written, s.files_deleted
            ),
            app,
        ),
        kv_line(
            "network ",
            &format!(
                "{} connections  ({} unknown)",
                s.net_connections, s.net_unknown
            ),
            app,
        ),
        kv_line(
            "commands",
            &format!(
                "{} executed  ({} dangerous)",
                s.commands_total, s.commands_dangerous
            ),
            app,
        ),
        kv_line("secrets ", &format!("{} accessed", s.secrets_accessed), app),
        kv_line("clipboard", &format!("{} reads", s.clipboard_reads), app),
        Line::from(""),
        section_title("risk", app),
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(bar_str, app.style(theme::risk_gauge(score))),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(risk_str, app.style(theme::risk_label(score))),
        ]),
        Line::from(""),
    ];

    // Findings
    if !app.findings.is_empty() {
        lines.push(section_title("findings", app));
        lines.push(Line::from(""));
        for f in app.findings.iter().rev().take(20) {
            let (sev, sev_style) = match f.severity {
                RiskLevel::Critical => ("CRITICAL", theme::label_critical()),
                RiskLevel::High => ("HIGH    ", theme::label_high()),
                RiskLevel::Medium => ("MEDIUM  ", theme::label_medium()),
                RiskLevel::Low => ("low     ", theme::label_ok()),
            };
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(sev, app.style(sev_style)),
                Span::raw("  "),
                Span::styled(
                    f.message.clone(),
                    app.style(Style::default().fg(Color::White)),
                ),
            ]));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "  no notable findings",
            app.style(theme::dim()),
        )));
    }

    lines
}

fn section_title(s: &'static str, app: &App) -> Line<'static> {
    Line::from(Span::styled(
        format!("  {}", s.to_uppercase()),
        app.style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    ))
}

fn kv_line(key: &str, value: &str, app: &App) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("  {:<10}", key),
            app.style(Style::default().add_modifier(Modifier::DIM)),
        ),
        Span::styled(
            value.to_string(),
            app.style(Style::default().fg(Color::White)),
        ),
    ])
}
