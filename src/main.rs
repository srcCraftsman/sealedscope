mod app;
mod cli;
mod k8s;
mod ui;

use std::io;

use anyhow::Context;
use app::{App, AppEvent};
use clap::Parser;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = cli::Args::parse();

    // Resolve starting context
    let active_context = args
        .context
        .clone()
        .or_else(|| k8s::client::current_context().ok())
        .unwrap_or_default();

    let context_list = k8s::client::list_contexts().unwrap_or_default();

    // Init terminal
    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("create terminal")?;

    let result = run(args, active_context, context_list, &mut terminal).await;

    // Always restore terminal
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();

    result
}

async fn run(
    args: cli::Args,
    active_context: String,
    context_list: Vec<String>,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> anyhow::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<AppEvent>(256);
    let mut app = App::new(context_list, active_context.clone());
    app.default_namespace = k8s::client::default_namespace_for_context(&active_context);

    // Spawn input reader
    let input_tx = tx.clone();
    tokio::spawn(async move { k8s::watcher::read_input(input_tx).await });

    // Initial watcher spawn
    let mut watch_handles = match k8s::client::client_for_context(&app.active_context).await {
        Ok(client) => {
            app.status = format!("Watching {}", app.active_context);
            k8s::watcher::spawn_watchers(
                client,
                args.controller_namespace.clone(),
                tx.clone(),
                app.generation,
            )
        }
        Err(e) => {
            app.status = format!("Error: {e}");
            vec![]
        }
    };

    loop {
        terminal.draw(|f| ui::render(f, &mut app))?;

        match rx.recv().await {
            None => break,
            Some(event) => match event {
                AppEvent::Input(key) => {
                    if app.handle_key(key) {
                        break;
                    }
                }
                // Discard events from previous generations (stale watcher tasks)
                AppEvent::KeysUpdated(epoch, keys) if epoch == app.generation => {
                    app.update_keys(keys)
                }
                AppEvent::SecretsUpdated(epoch, secrets) if epoch == app.generation => {
                    app.update_secrets(secrets)
                }
                AppEvent::KeysUpdated(..) | AppEvent::SecretsUpdated(..) => {
                    // stale generation — ignore
                }
                AppEvent::WatchError(epoch, msg) => {
                    if epoch.map_or(true, |e| e == app.generation) {
                        app.status = format!("Watch error: {msg}");
                    }
                }
            },
        }

        // Context switch
        if app.context_switch_requested {
            app.context_switch_requested = false;
            for h in watch_handles.drain(..) {
                h.abort();
            }
            app.status = format!("Switching to {}…", app.active_context);
            // Clear all data and reset UI state before new watchers start
            app.keys = vec![];
            app.raw_secrets = vec![];
            app.secrets_by_key.clear();
            app.keys_list_state.select(Some(0));
            app.secrets_table_state.select(Some(0));
            app.detail_scroll = 0;
            app.default_namespace =
                k8s::client::default_namespace_for_context(&app.active_context);
            app.generation += 1;

            match k8s::client::client_for_context(&app.active_context).await {
                Ok(client) => {
                    app.status = format!("Watching {}", app.active_context);
                    watch_handles = k8s::watcher::spawn_watchers(
                        client,
                        args.controller_namespace.clone(),
                        tx.clone(),
                        app.generation,
                    );
                }
                Err(e) => {
                    app.status = format!("Error: {e}");
                }
            }
        }

        // Watcher restart (r key)
        if app.restart_requested {
            app.restart_requested = false;
            for h in watch_handles.drain(..) {
                h.abort();
            }
            // Clear stale data so the UI shows a clean reconnect
            app.keys = vec![];
            app.raw_secrets = vec![];
            app.secrets_by_key.clear();
            app.keys_list_state.select(Some(0));
            app.secrets_table_state.select(Some(0));
            app.detail_scroll = 0;
            app.generation += 1;

            match k8s::client::client_for_context(&app.active_context).await {
                Ok(client) => {
                    app.status = format!("Restarted — watching {}", app.active_context);
                    watch_handles = k8s::watcher::spawn_watchers(
                        client,
                        args.controller_namespace.clone(),
                        tx.clone(),
                        app.generation,
                    );
                }
                Err(e) => app.status = format!("Restart error: {e}"),
            }
        }
    }

    for h in watch_handles {
        h.abort();
    }

    Ok(())
}
