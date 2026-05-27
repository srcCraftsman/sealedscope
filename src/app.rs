use std::collections::HashMap;
use crossterm::event::KeyEvent;
use crate::k8s::model::{SealingKey, SealedSecretItem};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pane { Keys, Secrets, Detail }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceFilter { All, Default }

#[derive(Debug)]
pub enum AppEvent {
    KeysUpdated(Vec<SealingKey>),
    SecretsUpdated(Vec<SealedSecretItem>),
    Input(KeyEvent),
    WatchError(String),
}

pub struct App {
    pub keys: Vec<SealingKey>,
    pub raw_secrets: Vec<SealedSecretItem>,
    pub secrets_by_key: HashMap<String, Vec<SealedSecretItem>>,
    pub keys_list_state: ratatui::widgets::ListState,
    pub secrets_table_state: ratatui::widgets::TableState,
    pub detail_scroll: u16,
    pub focus: Pane,
    pub context_list: Vec<String>,
    pub active_context: String,
    pub show_context_popup: bool,
    pub context_popup_selected: usize,
    pub show_help: bool,
    pub ns_filter: NamespaceFilter,
    pub status: String,
    pub should_quit: bool,
    pub restart_requested: bool,
    pub context_switch_requested: bool,
}

impl App {
    pub fn new(context_list: Vec<String>, active_context: String) -> Self {
        let mut s = Self {
            keys: vec![],
            raw_secrets: vec![],
            secrets_by_key: HashMap::new(),
            keys_list_state: ratatui::widgets::ListState::default(),
            secrets_table_state: ratatui::widgets::TableState::default(),
            detail_scroll: 0,
            focus: Pane::Keys,
            context_list,
            active_context,
            show_context_popup: false,
            context_popup_selected: 0,
            show_help: false,
            ns_filter: NamespaceFilter::All,
            status: "Connecting…".to_string(),
            should_quit: false,
            restart_requested: false,
            context_switch_requested: false,
        };
        s.keys_list_state.select(Some(0));
        s
    }
    pub fn update_keys(&mut self, _keys: Vec<SealingKey>) {}
    pub fn update_secrets(&mut self, _secrets: Vec<SealedSecretItem>) {}
    pub fn current_secrets(&self) -> &[SealedSecretItem] { &[] }
    pub fn current_secret(&self) -> Option<&SealedSecretItem> { None }
    pub fn cycle_focus(&mut self) {}
    pub fn navigate_up(&mut self) {}
    pub fn navigate_down(&mut self) {}
    pub fn select_key(&mut self, _idx: usize) {}
    pub fn handle_key(&mut self, _key: KeyEvent) -> bool { false }
}
