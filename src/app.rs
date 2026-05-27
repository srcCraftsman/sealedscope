use std::collections::HashMap;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::{ListState, TableState};
use crate::k8s::{
    model::{key_name_for_sealed_secret, SealedSecretItem, SealingKey},
    UNKNOWN_KEY,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pane {
    Keys,
    Secrets,
    Detail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceFilter {
    All,
    Default,
}

impl NamespaceFilter {
    pub fn toggle(&self) -> Self {
        match self {
            NamespaceFilter::All => NamespaceFilter::Default,
            NamespaceFilter::Default => NamespaceFilter::All,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            NamespaceFilter::All => "all ns",
            NamespaceFilter::Default => "default ns",
        }
    }
}

#[derive(Debug)]
pub enum AppEvent {
    KeysUpdated(u64, Vec<SealingKey>),
    SecretsUpdated(u64, Vec<SealedSecretItem>),
    Input(KeyEvent),
    /// (generation, message) — generation `None` means "always display"
    WatchError(Option<u64>, String),
}

pub struct App {
    pub keys: Vec<SealingKey>,
    pub raw_secrets: Vec<SealedSecretItem>,
    pub secrets_by_key: HashMap<String, Vec<SealedSecretItem>>,
    pub show_unknown: bool,
    pub keys_list_state: ListState,
    pub secrets_table_state: TableState,
    pub detail_scroll: u16,
    pub focus: Pane,
    pub context_list: Vec<String>,
    pub active_context: String,
    pub show_context_popup: bool,
    pub context_popup_selected: usize,
    pub show_help: bool,
    pub ns_filter: NamespaceFilter,
    /// Default namespace for the active kubeconfig context (used by `n` filter).
    pub default_namespace: String,
    pub status: String,
    pub generation: u64,
    pub restart_requested: bool,
    pub context_switch_requested: bool,
}

impl App {
    pub fn new(context_list: Vec<String>, active_context: String) -> Self {
        let mut s = Self {
            keys: vec![],
            raw_secrets: vec![],
            secrets_by_key: HashMap::new(),
            show_unknown: false,
            keys_list_state: ListState::default(),
            secrets_table_state: TableState::default(),
            detail_scroll: 0,
            focus: Pane::Keys,
            context_list,
            active_context,
            show_context_popup: false,
            context_popup_selected: 0,
            show_help: false,
            ns_filter: NamespaceFilter::All,
            default_namespace: "default".to_string(),
            status: "Connecting…".to_string(),
            generation: 0,
            restart_requested: false,
            context_switch_requested: false,
        };
        s.keys_list_state.select(Some(0));
        s
    }

    // ── Data update ──────────────────────────────────────────────────────────

    pub fn update_keys(&mut self, keys: Vec<SealingKey>) {
        self.keys = keys;
        self.remap();
    }

    pub fn update_secrets(&mut self, secrets: Vec<SealedSecretItem>) {
        self.raw_secrets = secrets;
        self.remap();
    }

    fn remap(&mut self) {
        self.secrets_by_key.clear();
        for key in &self.keys {
            self.secrets_by_key.insert(key.name.clone(), vec![]);
        }
        self.secrets_by_key.insert(UNKNOWN_KEY.to_string(), vec![]);

        let keys_snapshot = self.keys.clone();
        for secret in &self.raw_secrets {
            // Apply namespace filter before mapping
            if self.ns_filter == NamespaceFilter::Default
                && secret.namespace != self.default_namespace
            {
                continue;
            }
            let bucket = key_name_for_sealed_secret(
                &secret.annotations,
                &keys_snapshot,
                secret.created_at.as_deref(),
            )
            .unwrap_or_else(|| UNKNOWN_KEY.to_string());

            let mut s = secret.clone();
            s.resolved_key = Some(bucket.clone());
            self.secrets_by_key.entry(bucket).or_default().push(s);
        }

        let has_unknown = self
            .secrets_by_key
            .get(UNKNOWN_KEY)
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        self.show_unknown = has_unknown;

        // Keep current selection in bounds
        let max = self.keys_pane_len().saturating_sub(1);
        if let Some(sel) = self.keys_list_state.selected() {
            if sel > max {
                self.keys_list_state.select(Some(max));
            }
        }
    }

    // ── Key pane helpers ─────────────────────────────────────────────────────

    pub fn keys_pane_len(&self) -> usize {
        self.keys.len() + if self.show_unknown { 1 } else { 0 }
    }

    pub fn selected_key_name(&self) -> &str {
        let idx = self.keys_list_state.selected().unwrap_or(0);
        if idx < self.keys.len() {
            &self.keys[idx].name
        } else {
            UNKNOWN_KEY
        }
    }

    pub fn select_key(&mut self, idx: usize) {
        let clamped = idx.min(self.keys_pane_len().saturating_sub(1));
        self.keys_list_state.select(Some(clamped));
        self.secrets_table_state.select(Some(0));
        self.detail_scroll = 0;
    }

    // ── Secrets pane helpers ─────────────────────────────────────────────────

    pub fn current_secrets(&self) -> &[SealedSecretItem] {
        self.secrets_by_key
            .get(self.selected_key_name())
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn current_secret(&self) -> Option<&SealedSecretItem> {
        let idx = self.secrets_table_state.selected()?;
        self.current_secrets().get(idx)
    }

    // ── Navigation ───────────────────────────────────────────────────────────

    pub fn cycle_focus(&mut self) {
        self.focus = match self.focus {
            Pane::Keys => Pane::Secrets,
            Pane::Secrets => Pane::Detail,
            Pane::Detail => Pane::Keys,
        };
    }

    pub fn navigate_up(&mut self) {
        match self.focus {
            Pane::Keys => {
                let i = self
                    .keys_list_state
                    .selected()
                    .unwrap_or(0)
                    .saturating_sub(1);
                self.select_key(i);
            }
            Pane::Secrets => {
                let i = self
                    .secrets_table_state
                    .selected()
                    .unwrap_or(0)
                    .saturating_sub(1);
                self.secrets_table_state.select(Some(i));
                self.detail_scroll = 0;
            }
            Pane::Detail => {
                self.detail_scroll = self.detail_scroll.saturating_sub(1);
            }
        }
    }

    pub fn navigate_down(&mut self) {
        match self.focus {
            Pane::Keys => {
                let i = self.keys_list_state.selected().unwrap_or(0) + 1;
                self.select_key(i);
            }
            Pane::Secrets => {
                let max = self.current_secrets().len().saturating_sub(1);
                let i = (self.secrets_table_state.selected().unwrap_or(0) + 1).min(max);
                self.secrets_table_state.select(Some(i));
                self.detail_scroll = 0;
            }
            Pane::Detail => {
                self.detail_scroll = self.detail_scroll.saturating_add(1);
            }
        }
    }

    // ── Input handling ───────────────────────────────────────────────────────

    /// Returns true if the app should quit.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c') {
            return true;
        }
        if self.show_context_popup {
            self.handle_context_popup(key);
            return false;
        }
        if self.show_help {
            self.show_help = false;
            return false;
        }
        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Char('c') => {
                if let Some(pos) = self
                    .context_list
                    .iter()
                    .position(|x| x == &self.active_context)
                {
                    self.context_popup_selected = pos;
                }
                self.show_context_popup = true;
            }
            KeyCode::Char('r') => self.restart_requested = true,
            KeyCode::Char('n') => {
                self.ns_filter = self.ns_filter.toggle();
                self.remap();
            }
            KeyCode::Tab => self.cycle_focus(),
            KeyCode::Up | KeyCode::Char('k') => self.navigate_up(),
            KeyCode::Down | KeyCode::Char('j') => self.navigate_down(),
            _ => {}
        }
        false
    }

    fn handle_context_popup(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.context_popup_selected =
                    self.context_popup_selected.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.context_popup_selected = (self.context_popup_selected + 1)
                    .min(self.context_list.len().saturating_sub(1));
            }
            KeyCode::Enter => {
                if let Some(ctx) = self.context_list.get(self.context_popup_selected).cloned() {
                    self.active_context = ctx;
                    self.context_switch_requested = true;
                }
                self.show_context_popup = false;
            }
            KeyCode::Esc => {
                self.show_context_popup = false;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::k8s::model::{KeyStatus, SealedSecretItem, SealingKey};
    use std::collections::BTreeMap;

    fn make_app() -> App {
        App::new(
            vec!["ctx-a".to_string(), "ctx-b".to_string(), "ctx-c".to_string()],
            "ctx-a".to_string(),
        )
    }

    fn make_key(name: &str) -> SealingKey {
        SealingKey {
            name: name.to_string(),
            status: KeyStatus::Active,
            created_at: None,
            fingerprint: None,
        }
    }

    fn make_secret(name: &str, key: &str) -> SealedSecretItem {
        let mut ann = BTreeMap::new();
        ann.insert(
            "sealedsecrets.bitnami.com/sealed-by".to_string(),
            key.to_string(),
        );
        SealedSecretItem {
            name: name.to_string(),
            namespace: "default".to_string(),
            resolved_key: None,
            created_at: None,
            labels: BTreeMap::new(),
            annotations: ann,
        }
    }

    #[test]
    fn focus_cycles_keys_secrets_detail_keys() {
        let mut app = make_app();
        assert_eq!(app.focus, Pane::Keys);
        app.cycle_focus();
        assert_eq!(app.focus, Pane::Secrets);
        app.cycle_focus();
        assert_eq!(app.focus, Pane::Detail);
        app.cycle_focus();
        assert_eq!(app.focus, Pane::Keys);
    }

    #[test]
    fn select_key_resets_secret_selection_to_zero() {
        let mut app = make_app();
        app.update_keys(vec![make_key("k1"), make_key("k2")]);
        app.update_secrets(vec![make_secret("s1", "k1"), make_secret("s2", "k1")]);
        app.secrets_table_state.select(Some(1));
        app.select_key(1);
        assert_eq!(app.secrets_table_state.selected(), Some(0));
    }

    #[test]
    fn update_secrets_maps_to_correct_key_bucket() {
        let mut app = make_app();
        app.update_keys(vec![make_key("key-abc")]);
        app.update_secrets(vec![make_secret("my-secret", "key-abc")]);
        let secrets = app.current_secrets();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "my-secret");
    }

    #[test]
    fn secrets_for_unknown_key_go_to_unknown_bucket() {
        let mut app = make_app();
        app.update_keys(vec![make_key("key-abc")]);
        let s = SealedSecretItem {
            name: "orphan".to_string(),
            namespace: "ns".to_string(),
            resolved_key: None,
            created_at: None,
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
        };
        app.update_secrets(vec![s]);
        let unknown_idx = app.keys.len();
        app.select_key(unknown_idx);
        let secrets = app.current_secrets();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "orphan");
    }

    #[test]
    fn namespace_filter_toggles() {
        let mut app = make_app();
        assert_eq!(app.ns_filter, NamespaceFilter::All);
        app.ns_filter = app.ns_filter.toggle();
        assert_eq!(app.ns_filter, NamespaceFilter::Default);
        app.ns_filter = app.ns_filter.toggle();
        assert_eq!(app.ns_filter, NamespaceFilter::All);
    }
}
