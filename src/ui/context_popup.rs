use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Clear, List, ListItem, ListState},
    Frame,
};

use crate::app::App;

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    // Centered popup: 60% wide, proportional height (max 20 rows)
    let height = (app.context_list.len() as u16 + 4).min(20);
    let popup_area = centered_rect(60, height, area);

    // Clear the background
    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow))
        .title(" Switch Context  [Enter] confirm  [Esc] cancel ");

    let inner = block.inner(popup_area);
    f.render_widget(block, popup_area);

    let items: Vec<ListItem> = app
        .context_list
        .iter()
        .map(|ctx| {
            let style = if ctx == &app.active_context {
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(ctx.as_str()).style(style)
        })
        .collect();

    let list = List::new(items)
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED).fg(Color::Yellow))
        .highlight_symbol("▶ ");

    let mut state = ListState::default();
    state.select(Some(app.context_popup_selected));

    f.render_stateful_widget(list, inner, &mut state);
}

fn centered_rect(percent_x: u16, height: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(height),
            Constraint::Fill(1),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}
