// sandspy::ui::diff_viewer — Diffs tab (Tab::Diffs)
//
// Shows a colored diff of written files using the `similar` crate.
// Left: file list. Right: diff content.

use crate::events::{Event, EventKind};
use crate::ui::{app::App, theme};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    // Split horizontally: file list on left, diff on right
    let cols = Layout::horizontal([Constraint::Length(30), Constraint::Fill(1)]).split(area);

    render_file_list(frame, cols[0], app);
    render_diff_content(frame, cols[1], app);
}

fn render_file_list(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " FILES ",
            app.style(Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(app.style(theme::border()));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let write_events: Vec<&Event> = app
        .events
        .iter()
        .filter(|e| matches!(e.kind, EventKind::FileWrite { .. }))
        .collect();

    let items: Vec<ListItem> = write_events
        .iter()
        .map(|e| {
            if let EventKind::FileWrite { path, .. } = &e.kind {
                let name = path
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_else(|| path.display().to_string());
                ListItem::new(Line::from(Span::styled(
                    format!("  {name}"),
                    app.style(Style::default().fg(Color::White)),
                )))
            } else {
                ListItem::new(Line::from(""))
            }
        })
        .collect();

    if items.is_empty() {
        let msg = Paragraph::new(Line::from(Span::styled(
            "  no writes yet",
            app.style(theme::dim()),
        )));
        frame.render_widget(msg, inner);
    } else {
        let list = List::new(items);
        frame.render_widget(list, inner);
    }
}

fn render_diff_content(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " DIFF ",
            app.style(Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(app.style(theme::border()));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Find the most recent write event that has a diff_summary
    let last_write = app.events.iter().rev().find(|e| {
        matches!(&e.kind, EventKind::FileWrite { diff_summary: Some(_), .. })
    });

    match last_write {
        None => {
            let msg = Paragraph::new(Line::from(Span::styled(
                "  no diffs captured yet",
                app.style(theme::dim()),
            )));
            frame.render_widget(msg, inner);
        }
        Some(event) => {
            if let EventKind::FileWrite { path, diff_summary: Some(summary) } = &event.kind {
                // We only have the summary string (e.g. "+15 -3"), not actual content.
                // Render it as a styled explanation instead.
                let lines = vec![
                    Line::from(Span::styled(
                        format!("  {}", path.display()),
                        app.style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        format!("  changes: {summary}"),
                        app.style(Style::default().fg(Color::Cyan)),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        "  (full diff available after session via sandspy report)",
                        app.style(theme::dim()),
                    )),
                ];
                let para = Paragraph::new(lines).wrap(Wrap { trim: false });
                frame.render_widget(para, inner);
            }
        }
    }
}
