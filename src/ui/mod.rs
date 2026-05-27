pub mod context_popup;
pub mod detail_pane;
pub mod help;
pub mod keys_pane;
pub mod secrets_pane;

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

use crate::app::App;

pub fn render(f: &mut Frame, app: &mut App) {
    let area = f.area();

    // Outer vertical split: status bar (1 line) + body
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);

    render_status_bar(f, app, outer[0]);

    // Body vertical split: top panes (60%) + detail pane (40%)
    let body = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(outer[1]);

    // Top horizontal split: keys (30%) + secrets (70%)
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(body[0]);

    keys_pane::render(f, app, top[0]);
    secrets_pane::render(f, app, top[1]);
    detail_pane::render(f, app, body[1]);

    // Overlays (drawn last, on top)
    if app.show_context_popup {
        context_popup::render(f, app, area);
    }
    if app.show_help {
        help::render(f, area);
    }
}

fn render_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let ns_label = app.ns_filter.label();
    let line = Line::from(vec![
        Span::styled(" sealedscope ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("│ ctx: "),
        Span::styled(&app.active_context, Style::default().fg(Color::Yellow)),
        Span::raw(format!("  ns: {ns_label}  │  ")),
        Span::styled(&app.status, Style::default().fg(Color::DarkGray)),
        Span::raw("  [?] help"),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

/// Focused border style (bright white) vs unfocused (dark gray).
pub fn border_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::White)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}
