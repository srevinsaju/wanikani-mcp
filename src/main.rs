mod auth;
mod error;
pub use error::Error;
mod http;
mod result;
pub use result::Result;
mod wanikani;

use auth::{Auth, VaultKey};
use clap::Parser;
use rmcp::{ServiceExt, transport::stdio};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use strum_macros::{Display, EnumString};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;
use wanikani::Wanikani;

#[derive(Debug, Display, Clone, Copy, EnumString)]
#[strum(serialize_all = "snake_case")]
enum Mode {
    Stdio,
    Sse,
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about)]
struct Args {
    #[arg(long, env = "MODE", default_value = "sse")]
    mode: Mode,

    #[arg(long, env = "WANIKANI_API_KEY")]
    api_key: Option<String>,

    #[arg(long, env = "BIND_ADDRESS", default_value = "127.0.0.1:3000")]
    bind_address: String,

    #[arg(long, env = "PUBLIC_ADDRESS", default_value = "http://127.0.0.1:3000")]
    public_address: Url,

    /// The SQLite database holding OAuth clients, grants and the sealed
    /// WaniKani API keys, such as `sqlite:///data/wanikani-mcp.db`.
    #[arg(long, env = "DATABASE", default_value = "sqlite://wanikani-mcp.db")]
    database: String,

    /// The key WaniKani API keys are sealed with at rest: 32 bytes in
    /// standard base64 (`openssl rand -base64 32`). Required in sse mode.
    #[arg(long, env = "VAULT_KEY", hide_env_values = true)]
    vault_key: Option<VaultKey>,

    /// Access token lifetime in seconds. Refresh tokens rotate on use.
    #[arg(long, env = "TOKEN_EXPIRATION", default_value = "3600")]
    token_expiration: u64,
}

async fn run_stdio(api_key: String) -> anyhow::Result<()> {
    tracing::info!("starting mcp server in stdio mode");

    Wanikani::new_with_key(api_key)?
        .serve(stdio())
        .await
        .inspect_err(|e| {
            tracing::error!("serving error: {:?}", e);
        })?
        .waiting()
        .await?;

    Ok(())
}

async fn run_sse(args: Args) -> anyhow::Result<()> {
    tracing::info!("starting mcp server in sse mode");

    let vault_key = args.vault_key.ok_or_else(|| {
        anyhow::anyhow!("vault key required for sse mode (use --vault-key or VAULT_KEY env var)")
    })?;
    let issuer = args.public_address.as_str().trim_end_matches('/');
    // `oauth-as` matches the resource exactly, so it is spelled one way only.
    let resource = format!("{issuer}/mcp");
    let auth = Arc::new(
        Auth::open(
            issuer,
            &resource,
            &args.database,
            vault_key,
            Duration::from_secs(args.token_expiration),
        )
        .await?,
    );
    auth.spawn_sweeper();
    let app = http::router(issuer, &resource, auth)?;

    let addr = args.bind_address.parse::<SocketAddr>()?;
    tracing::info!("mcp server started on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("shutting down...");
        })
        .await?;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "debug".to_string().into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    match args.mode {
        Mode::Stdio => {
            let api_key = args.api_key.ok_or_else(|| {
                anyhow::anyhow!(
                    "api key required for stdio mode (use --api-key or WANIKANI_API_KEY env var)"
                )
            })?;
            run_stdio(api_key).await
        }
        Mode::Sse => run_sse(args).await,
    }
}
