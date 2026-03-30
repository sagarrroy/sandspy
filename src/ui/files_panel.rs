// sandspy::ui::files_panel — Files tab (Tab::Files)

use crate::events::{Event, EventKind};
use crate::ui::{app::App, theme};
use chrono::Local;
use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, BorderType, Borders, Cell, Row, Table},
    Frame,
};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
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

    let header = Row::new(vec![
        Cell::from("Time").style(app.style(theme::header())),
        Cell::from("Type").style(app.style(theme::header())),
        Cell::from("Path").style(app.style(theme::header())),
        Cell::from("Classification").style(app.style(theme::header())),
    ]);

    let file_events: Vec<&Event> = app
        .events
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                EventKind::FileRead { .. }
                    | EventKind::FileWrite { .. }
                    | EventKind::FileDelete { .. }
            )
        })
        .collect();

    let total = file_events.len();
    let visible_height = inner.height.saturating_sub(2) as usize; // minus header + border
    let offset = app
        .scroll_offset
        .min(total.saturating_sub(visible_height));

    let rows: Vec<Row> = file_events
        .iter()
        .skip(offset)
        .take(visible_height)
        .map(|e| file_event_row(e, app))
        .collect();

    let widths = [
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Fill(1),
        Constraint::Length(14),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1);

    frame.render_widget(table, inner);
}

fn file_event_row(event: &Event, app: &App) -> Row<'static> {
    let ts = event
        .timestamp
        .with_timezone(&Local)
        .format("%H:%M:%S")
        .to_string();

    match &event.kind {
        EventKind::FileRead { path, sensitive, .. } => {
            let (label, label_style) = if *sensitive {
                ("SENSITIVE", theme::label_sensitive())
            } else {
                ("ok       ", theme::label_ok())
            };
            Row::new(vec![
                Cell::from(ts).style(app.style(theme::dim())),
                Cell::from("READ").style(app.style(theme::tag_read())),
                Cell::from(path.display().to_string()).style(app.style(Style::default().fg(Color::White))),
                Cell::from(label).style(app.style(label_style)),
            ])
        }
        EventKind::FileWrite { path, diff_summary } => Row::new(vec![
            Cell::from(ts).style(app.style(theme::dim())),
            Cell::from("WRITE").style(app.style(theme::tag_write())),
            Cell::from(path.display().to_string()).style(app.style(Style::default().fg(Color::White))),
            Cell::from(diff_summary.clone().unwrap_or_default()).style(app.style(theme::tag_write())),
        ]),
        EventKind::FileDelete { path } => Row::new(vec![
            Cell::from(ts).style(app.style(theme::dim())),
            Cell::from("DEL").style(app.style(theme::tag_delete())),
            Cell::from(path.display().to_string()).style(app.style(theme::tag_delete())),
            Cell::from("deleted").style(app.style(theme::label_high())),
        ]),
        _ => Row::new(vec![Cell::from("")]),
    }
}
