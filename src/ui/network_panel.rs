// sandspy::ui::network_panel — Network tab (Tab::Network)

use crate::events::{Event, EventKind, NetCategory};
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
            " NETWORK ",
            app.style(
                Style::default()
                    .fg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            ),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(app.style(theme::border()));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let header = Row::new(vec![
        Cell::from("Time").style(app.style(theme::header())),
        Cell::from("Domain / IP").style(app.style(theme::header())),
        Cell::from("Port").style(app.style(theme::header())),
        Cell::from("Category").style(app.style(theme::header())),
        Cell::from("Bytes").style(app.style(theme::header())),
    ]);

    let net_events: Vec<&Event> = app
        .events
        .iter()
        .filter(|e| matches!(e.kind, EventKind::NetworkConnection { .. }))
        .collect();

    let total = net_events.len();
    let visible_height = inner.height.saturating_sub(2) as usize;
    let offset = app.scroll_offset.min(total.saturating_sub(visible_height));

    let rows: Vec<Row> = net_events
        .iter()
        .skip(offset)
        .take(visible_height)
        .map(|e| net_event_row(e, app))
        .collect();

    let widths = [
        Constraint::Length(10),
        Constraint::Fill(1),
        Constraint::Length(6),
        Constraint::Length(12),
        Constraint::Length(9),
    ];

    let table = Table::new(rows, widths).header(header).column_spacing(1);

    frame.render_widget(table, inner);
}

fn net_event_row(event: &Event, app: &App) -> Row<'static> {
    let ts = event
        .timestamp
        .with_timezone(&Local)
        .format("%H:%M:%S")
        .to_string();

    if let EventKind::NetworkConnection {
        remote_addr,
        remote_port,
        domain,
        category,
        bytes_sent,
        bytes_recv,
        ..
    } = &event.kind
    {
        let host = domain
            .as_deref()
            .map(|d| d.to_string())
            .unwrap_or_else(|| remote_addr.clone());

        let (cat_label, cat_style) = match category {
            NetCategory::ExpectedApi => ("api", theme::label_ok()),
            NetCategory::Telemetry => ("telemetry", theme::label_telemetry()),
            NetCategory::Tracking => ("TRACKING", theme::label_tracking()),
            NetCategory::Unknown => ("UNKNOWN", theme::label_unknown()),
        };

        let bytes = theme::format_bytes(bytes_sent + bytes_recv);

        Row::new(vec![
            Cell::from(ts).style(app.style(theme::dim())),
            Cell::from(host).style(app.style(Style::default().fg(Color::White))),
            Cell::from(remote_port.to_string()).style(app.style(theme::dim())),
            Cell::from(cat_label).style(app.style(cat_style)),
            Cell::from(bytes).style(app.style(theme::dim())),
        ])
    } else {
        Row::new(vec![Cell::from("")])
    }
}
