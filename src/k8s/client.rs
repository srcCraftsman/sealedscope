use kube::config::{KubeConfigOptions, Kubeconfig};

/// Returns all context names from the active kubeconfig.
pub fn list_contexts() -> anyhow::Result<Vec<String>> {
    let kc = Kubeconfig::read()?;
    Ok(kc.contexts.into_iter().map(|c| c.name).collect())
}

/// Returns the current-context name from the active kubeconfig.
pub fn current_context() -> anyhow::Result<String> {
    let kc = Kubeconfig::read()?;
    kc.current_context
        .ok_or_else(|| anyhow::anyhow!("No current-context set in kubeconfig"))
}

/// Builds a kube::Client configured for the given context name.
pub async fn client_for_context(context: &str) -> anyhow::Result<kube::Client> {
    let opts = KubeConfigOptions {
        context: Some(context.to_string()),
        ..Default::default()
    };
    let config = kube::Config::from_kubeconfig(&opts).await?;
    Ok(kube::Client::try_from(config)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_context_does_not_panic() {
        let _ = current_context();
    }

    #[test]
    fn list_contexts_does_not_panic() {
        let _ = list_contexts();
    }
}
