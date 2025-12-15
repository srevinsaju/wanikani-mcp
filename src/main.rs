mod error;
mod result;
mod wanikani;

use rmcp::{ServiceExt, transport::stdio};
use tracing_subscriber::{self, EnvFilter};
use wanikani::Wanikani;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::DEBUG.into()))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("starting wanikani MCP server");

    let service = Wanikani::new()
        .await?
        .serve(stdio())
        .await
        .inspect_err(|e| {
            tracing::error!("serving error: {:?}", e);
        })?;

    service.waiting().await?;
    Ok(())
}
