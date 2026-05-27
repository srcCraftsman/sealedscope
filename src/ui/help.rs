use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

pub fn render(f: &mut Frame, area: Rect) {
    let popup_area = centered_rect(50, 16, area);
    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Help  [any key] close ");

    let lines = vec![
        key_line("↑ / k", "navigate up"),
        key_line("↓ / j", "navigate down"),
        key_line("Tab", "cycle focus: Keys → Secrets → Detail"),
        Line::raw(""),
        key_line("c", "open context switcher"),
        key_line("r", "force re-fetch (restart watchers)"),
        key_line("n", "toggle namespace filter"),
        Line::raw(""),
        key_line("q / Ctrl+C", "quit"),
        key_line("?", "show this help"),
    ];

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, popup_area);
}

fn key_line<'a>(key: &'a str, desc: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("  {key:<14}"),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
        Span::raw(desc),
    ])
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
