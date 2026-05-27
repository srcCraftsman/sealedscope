use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::app::{App, Pane};
use crate::ui::border_style;

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let focused = app.focus == Pane::Detail;

    let title = match app.current_secret() {
        Some(s) => format!(" Detail: {} / {} ", s.name, s.namespace),
        None => " Detail ".to_string(),
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style(focused))
        .title(title);

    let mut lines: Vec<Line> = Vec::new();

    if let Some(s) = app.current_secret() {
        // Sealed by
        lines.push(key_val_line("Sealed by", s.resolved_key.as_deref().unwrap_or("—")));
        // Created
        lines.push(key_val_line("Created", s.created_at.as_deref().unwrap_or("—")));
        lines.push(Line::raw(""));

        // Labels
        lines.push(Line::from(Span::styled(
            "Labels:",
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
        )));
        if s.labels.is_empty() {
            lines.push(Line::from("  (none)"));
        } else {
            for (k, v) in &s.labels {
                lines.push(Line::from(format!("  {k}={v}")));
            }
        }
        lines.push(Line::raw(""));

        // Annotations
        lines.push(Line::from(Span::styled(
            "Annotations:",
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
        )));
        if s.annotations.is_empty() {
            lines.push(Line::from("  (none)"));
        } else {
            for (k, v) in &s.annotations {
                lines.push(Line::from(format!("  {k}: {v}")));
            }
        }
    } else {
        lines.push(Line::from(Span::styled(
            "Select a SealedSecret to see details.",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let para = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((app.detail_scroll, 0));

    f.render_widget(para, area);
}

fn key_val_line<'a>(key: &'a str, val: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("{key:<14}"),
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
        ),
        Span::raw(val),
    ])
}
