use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "sealedscope", version, about = "Inspect Sealed Secrets in Kubernetes")]
pub struct Args {
    /// Namespace where the sealed-secrets controller runs
    #[arg(long, default_value = "sealed-secrets")]
    pub controller_namespace: String,

    /// Kubeconfig context to start with (defaults to current-context)
    #[arg(long)]
    pub context: Option<String>,
}
