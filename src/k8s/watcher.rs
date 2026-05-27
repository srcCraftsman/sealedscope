use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    api::Api,
    core::{ApiResource, DynamicObject, GroupVersionKind},
    runtime::watcher,
    Client,
};
use tokio::{sync::mpsc::Sender, task::JoinHandle};

use crate::{
    app::AppEvent,
    k8s::model::{SealedSecretItem, SealingKey},
};

/// Spawns two background tasks: one watching sealing key Secrets, one watching SealedSecrets.
/// `generation` is stamped on every event so the main loop can discard stale messages
/// from a previous watcher that was aborted but had buffered events in-flight.
/// Returns their JoinHandles so they can be aborted on context switch.
pub fn spawn_watchers(
    client: Client,
    controller_ns: String,
    tx: Sender<AppEvent>,
    generation: u64,
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();

    // — Sealing keys watcher —
    {
        let c = client.clone();
        let t = tx.clone();
        let ns = controller_ns.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = watch_sealing_keys(c, &ns, t.clone(), generation).await {
                let _ = t.send(AppEvent::WatchError(e.to_string())).await;
            }
        }));
    }

    // — SealedSecrets watcher —
    {
        let c = client.clone();
        let t = tx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = watch_sealed_secrets(c, t.clone(), generation).await {
                let _ = t.send(AppEvent::WatchError(e.to_string())).await;
            }
        }));
    }

    handles
}

/// Reads crossterm key events and forwards them as AppEvent::Input.
pub async fn read_input(tx: Sender<AppEvent>) {
    use crossterm::event::{Event, EventStream};
    let mut reader = EventStream::new();
    loop {
        match reader.next().await {
            Some(Ok(Event::Key(key))) => {
                if tx.send(AppEvent::Input(key)).await.is_err() {
                    break;
                }
            }
            Some(Err(_)) | None => break,
            _ => {}
        }
    }
}

async fn watch_sealing_keys(
    client: Client,
    controller_ns: &str,
    tx: Sender<AppEvent>,
    generation: u64,
) -> anyhow::Result<()> {
    let api: Api<Secret> = Api::namespaced(client, controller_ns);
    let cfg = watcher::Config::default()
        .labels("sealedsecrets.bitnami.com/sealed-secrets-key");

    let mut store: Vec<Secret> = Vec::new();
    let mut stream = watcher::watcher(api, cfg).boxed();

    loop {
        match stream.next().await {
            None => break,
            Some(Err(e)) => {
                tx.send(AppEvent::WatchError(format!("keys watcher: {e}"))).await?;
                // kube watcher auto-reconnects; keep looping
            }
            Some(Ok(event)) => {
                match event {
                    watcher::Event::Apply(s) | watcher::Event::InitApply(s) => {
                        if let Some(pos) = store.iter().position(|x| x.metadata.name == s.metadata.name) {
                            store[pos] = s;
                        } else {
                            store.push(s);
                        }
                    }
                    watcher::Event::Delete(s) => {
                        store.retain(|x| x.metadata.name != s.metadata.name);
                    }
                    watcher::Event::Init => store.clear(),
                    watcher::Event::InitDone => {}
                }
                let keys: Vec<SealingKey> = store
                    .iter()
                    .filter_map(SealingKey::from_secret)
                    .collect();
                tx.send(AppEvent::KeysUpdated(generation, keys)).await?;
            }
        }
    }
    Ok(())
}

async fn watch_sealed_secrets(
    client: Client,
    tx: Sender<AppEvent>,
    generation: u64,
) -> anyhow::Result<()> {
    let gvk = GroupVersionKind::gvk("bitnami.com", "v1alpha1", "SealedSecret");
    let ar = ApiResource::from_gvk(&gvk);
    let api: Api<DynamicObject> = Api::all_with(client, &ar);

    let mut store: Vec<DynamicObject> = Vec::new();
    let mut stream = watcher::watcher(api, watcher::Config::default()).boxed();

    loop {
        match stream.next().await {
            None => break,
            Some(Err(e)) => {
                tx.send(AppEvent::WatchError(format!("secrets watcher: {e}"))).await?;
            }
            Some(Ok(event)) => {
                let uid = |obj: &DynamicObject| {
                    (obj.metadata.namespace.clone(), obj.metadata.name.clone())
                };
                match event {
                    watcher::Event::Apply(o) | watcher::Event::InitApply(o) => {
                        let key = uid(&o);
                        if let Some(pos) = store.iter().position(|x| uid(x) == key) {
                            store[pos] = o;
                        } else {
                            store.push(o);
                        }
                    }
                    watcher::Event::Delete(o) => {
                        let key = uid(&o);
                        store.retain(|x| uid(x) != key);
                    }
                    watcher::Event::Init => store.clear(),
                    watcher::Event::InitDone => {}
                }
                let secrets: Vec<SealedSecretItem> = store
                    .iter()
                    .filter_map(SealedSecretItem::from_dynamic)
                    .collect();
                tx.send(AppEvent::SecretsUpdated(generation, secrets)).await?;
            }
        }
    }
    Ok(())
}
