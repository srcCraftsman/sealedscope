pub mod context_popup;
pub mod detail_pane;
pub mod help;
pub mod keys_pane;
pub mod secrets_pane;

use ratatui::Frame;
use crate::app::App;

pub fn render(_f: &mut Frame, _app: &mut App) {}

pub fn border_style(_focused: bool) -> ratatui::style::Style {
    ratatui::style::Style::default()
}
