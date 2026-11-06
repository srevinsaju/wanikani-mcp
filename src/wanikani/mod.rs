mod mcp;
mod subjects;
mod user;

use crate::Error;
use ratelimit::Ratelimiter;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
use rmcp::{ServerHandler, tool_handler};
use std::sync::Arc;
use std::time::Duration;
use wanisabi::client::Client;

#[derive(Clone)]
pub struct WanikaniInner {
    client: Arc<Client>,
}

#[derive(Clone)]
pub struct Wanikani {
    inner: WanikaniInner,
    tool_router: ToolRouter<Self>,
}

impl Wanikani {
    pub fn new_with_key(api_key: String) -> Result<Self, Error> {
        let rate_limiter = Ratelimiter::builder(60, Duration::from_secs(60))
            .max_tokens(60)
            .initial_available(60)
            .build()
            .map_err(|e| Error::Internal(format!("Failed to create rate limiter: {}", e)))?;

        let client = Client {
            key: api_key,
            client: Default::default(),
            rate_limiter: Some(rate_limiter),
            pool: None,
        };

        Ok(Self {
            inner: WanikaniInner {
                client: Arc::new(client),
            },
            tool_router: Self::tool_router(),
        })
    }

    pub fn instructions(&self) -> String {
        String::from(
            "provides interactions with wanikani, \
        to look up kanji, radicals or vocabulary,\
        current learning status and pending reviews. \
        Also provides helper tools to retrieve unlearned kanji and vocabulary from given \
        sentences or list of words.",
        )
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Wanikani {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(self.instructions())
    }
}
