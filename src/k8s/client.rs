pub async fn client_for_context(_ctx: &str) -> anyhow::Result<kube::Client> {
    Ok(kube::Client::try_default().await?)
}
pub fn list_contexts() -> anyhow::Result<Vec<String>> { Ok(vec![]) }
pub fn current_context() -> anyhow::Result<String> { Ok(String::new()) }
