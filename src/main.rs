use std::sync::Arc;
use threat_classifier_proxy::{
    config::Config,
    model::{CpuClassifier, assets::Assets},
    proxy::{ProxyState, serve},
};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("warn,threat_classifier_proxy=info")),
        )
        .init();
    let config = Config::from_env()?;
    tracing::info!("loading CPU model artifacts");
    let assets = Assets::download(config.model_cache)?;
    let classifier = Arc::new(CpuClassifier::load(&assets, config.workers)?);
    let state = ProxyState::new(config.upstream, classifier, config.workers)?;
    let listener = TcpListener::bind(config.listen).await?;
    tracing::info!(address = %listener.local_addr()?, "HTTP proxy listening");
    serve(listener, state).await?;
    Ok(())
}
