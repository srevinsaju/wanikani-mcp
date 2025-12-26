mod auth;
mod error;
pub use error::Error;
mod result;
pub use result::Result;
mod wanikani;

use auth::ClientStore;
use axum::{Router, http::StatusCode, middleware, response::IntoResponse, routing::get};
use clap::Parser;
use rmcp::{
    ServiceExt,
    transport::{
        StreamableHttpServerConfig, stdio,
        streamable_http_server::{
            session::local::LocalSessionManager, tower::StreamableHttpService,
        },
    },
};
use std::{net::SocketAddr, sync::Arc};
use strum_macros::{Display, EnumString};
use tokio::task_local;
use tower_http::cors::{Any, CorsLayer};
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

    #[arg(long, env = "JWT_SECRET")]
    jwt_secret: Option<String>,

    #[arg(long, env = "TOKEN_EXPIRATION", default_value = "3600")]
    token_expiration: u64,
}

task_local! {
    static CURRENT_API_KEY: String;
}

async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND,).into_response()
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

    let jwt_secret = args.jwt_secret.unwrap_or_else(|| {
        let secret = uuid::Uuid::new_v4().to_string();
        tracing::warn!(
            "no jwt_secret provided; generated an ephemeral secret. tokens will be invalidated on restart. set JWT_SECRET env var for persistence."
        );
        secret
    });

    let client_store = Arc::new(ClientStore::new(
        args.public_address,
        jwt_secret,
        args.token_expiration,
    ));
    let addr = args.bind_address.parse::<SocketAddr>()?;

    let mcp_service: StreamableHttpService<Wanikani, LocalSessionManager> =
        StreamableHttpService::new(
            || {
                let api_key = CURRENT_API_KEY
                    .try_with(|k| k.clone())
                    .map_err(|_| std::io::Error::other("missing API key"))?;
                Wanikani::new_with_key(api_key).map_err(|e| {
                    tracing::error!("failed to create wanikani service: {:?}", e);
                    std::io::Error::other(e)
                })
            },
            LocalSessionManager::default().into(),
            StreamableHttpServerConfig::default(),
        );

    let cors_layer = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let protected_mcp_router = Router::new()
        .nest_service("/mcp", mcp_service)
        .layer(middleware::from_fn(auth::make_validate_token_middleware(
            client_store.clone(),
        )))
        .layer(cors_layer.clone());

    let app = Router::new()
        .merge(auth::router(cors_layer, client_store))
        .merge(protected_mcp_router)
        .fallback(get(not_found));

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
