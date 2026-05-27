use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
    Frame,
};

use crate::app::{App, Pane};
use crate::k8s::model::KeyStatus;
use crate::k8s::UNKNOWN_KEY;
use crate::ui::border_style;

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    let focused = app.focus == Pane::Keys;
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style(focused))
        .title(" Sealing Keys ");

    let mut items: Vec<ListItem> = app
        .keys
        .iter()
        .map(|key| {
            let badge_color = match key.status {
                KeyStatus::Active => Color::Green,
                KeyStatus::Expired => Color::DarkGray,
            };
            let count = app
                .secrets_by_key
                .get(&key.name)
                .map(|v| v.len())
                .unwrap_or(0);
            let line = Line::from(vec![
                Span::raw(&key.name),
                Span::raw("  "),
                Span::styled(key.status.badge(), Style::default().fg(badge_color)),
                Span::styled(
                    format!(" ({count})"),
                    Style::default().fg(Color::DarkGray),
                ),
            ]);
            ListItem::new(line)
        })
        .collect();

    if app.show_unknown {
        let count = app
            .secrets_by_key
            .get(UNKNOWN_KEY)
            .map(|v| v.len())
            .unwrap_or(0);
        let line = Line::from(vec![
            Span::styled(UNKNOWN_KEY, Style::default().fg(Color::Yellow)),
            Span::styled(
                format!(" ({count})"),
                Style::default().fg(Color::DarkGray),
            ),
        ]);
        items.push(ListItem::new(line));
    }

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::REVERSED)
                .fg(Color::White),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, area, &mut app.keys_list_state);
}
