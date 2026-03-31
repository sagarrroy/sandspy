// sandspy::ui::alerts_panel — Alerts tab (Tab::Alerts)

use crate::events::RiskLevel;
use crate::ui::{
    app::{App, Finding},
    theme,
};
use chrono::Local;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph},
    Frame,
};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " ALERTS ",
            app.style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(app.style(theme::border()));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.findings.is_empty() {
        let msg = Paragraph::new(Line::from(Span::styled(
            "  no alerts — everything looks clean",
            app.style(theme::dim()),
        )));
        frame.render_widget(msg, inner);
        return;
    }

    let total = app.findings.len();
    let visible_height = inner.height as usize;
    let offset = app.scroll_offset.min(total.saturating_sub(visible_height));

    let items: Vec<ListItem> = app
        .findings
        .iter()
        .rev() // newest first
        .skip(offset)
        .take(visible_height)
        .map(|f| finding_item(f, app))
        .collect();

    let list = List::new(items);
    frame.render_widget(list, inner);
}

fn finding_item(f: &Finding, app: &App) -> ListItem<'static> {
    let ts = f
        .timestamp
        .with_timezone(&Local)
        .format("%H:%M:%S")
        .to_string();

    let (sev_label, sev_style) = match f.severity {
        RiskLevel::Critical => ("CRITICAL", theme::label_critical()),
        RiskLevel::High => ("HIGH    ", theme::label_high()),
        RiskLevel::Medium => ("MEDIUM  ", theme::label_medium()),
        RiskLevel::Low => ("low     ", theme::label_ok()),
    };

    ListItem::new(Line::from(vec![
        Span::styled(ts, app.style(theme::dim())),
        Span::raw("  "),
        Span::styled(sev_label, app.style(sev_style)),
        Span::raw("  "),
        Span::styled(
            f.message.clone(),
            app.style(Style::default().fg(Color::White)),
        ),
    ]))
}
