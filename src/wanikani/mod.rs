mod lessons;
mod mcp;
mod reviews;
mod subjects;
mod user;

use chrono::Utc;
use chrono::DateTime;
use crate::error::Error;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{ServerHandler, tool_handler};
use std::sync::Arc;
use wanisabi::client::Client;

#[derive(Clone)]
pub struct WanikaniInner {
    client: Arc<Client>,
}

#[derive(Clone)]
pub struct WanikaniUserInfo {
    name: String,
    level: i64,
    started_at: DateTime<Utc>
}

#[derive(Clone)]
pub struct Wanikani {
    inner: WanikaniInner,
    user_info: WanikaniUserInfo,
    tool_router: ToolRouter<Self>,
}

impl Wanikani {
    pub async fn new() -> Result<Self, Error> {
        let api_token = std::env::var("WANIKANI_API_KEY")?;
        let client = Client::new(api_token.to_string(), true, true).await?;

        let user = client.get_user_info().await?;


        Ok(Self {
            inner: WanikaniInner {
                client: Arc::new(client),
            },
            tool_router: Self::tool_router(),
            user_info: WanikaniUserInfo {
                name: user.data.username,
                level: user.data.level,
                started_at: user.data.started_at
            },
        })
    }

    pub fn instructions(&self) -> String {
        format!(
            "{} (level={}, started_at={} provides interactions with wanikani, \
            to look up kanji, radicals or vocabulary,\
            current learning status and pending reviews. \
            Also provides helper tools to retrieve unlearned kanji and vocabulary from given \
            sentences or list of words.",
            self.user_info.name,
            self.user_info.level,
            self.user_info.started_at
        )
    }
}

#[tool_handler]
impl ServerHandler for Wanikani {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            instructions: Some(self.instructions()),
            ..Default::default()
        }
    }
}
