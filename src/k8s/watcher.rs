pub fn spawn_watchers(
    _client: kube::Client,
    _controller_ns: String,
    _tx: tokio::sync::mpsc::Sender<crate::app::AppEvent>,
) -> Vec<tokio::task::JoinHandle<()>> { vec![] }

pub async fn read_input(_tx: tokio::sync::mpsc::Sender<crate::app::AppEvent>) {}
