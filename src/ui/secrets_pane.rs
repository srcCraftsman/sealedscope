use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table},
    Frame,
};

use crate::app::{App, Pane};
use crate::ui::border_style;

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    let focused = app.focus == Pane::Secrets;
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style(focused))
        .title(" SealedSecrets ");

    let header = Row::new(["NAME", "NAMESPACE", "AGE"])
        .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan));

    let secrets = app.current_secrets();

    let rows: Vec<Row> = secrets
        .iter()
        .map(|s| {
            Row::new(vec![
                Cell::from(s.name.clone()),
                Cell::from(s.namespace.clone()),
                Cell::from(s.age()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Length(12),
        ],
    )
    .block(block)
    .header(header)
    .row_highlight_style(
        Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(Color::White),
    );

    f.render_stateful_widget(table, area, &mut app.secrets_table_state);
}
