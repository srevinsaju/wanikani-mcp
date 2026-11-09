mod mcp;
mod output;
mod subjects;
mod user;

use crate::Error;
use ratelimit::Ratelimiter;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
use rmcp::{ServerHandler, tool_handler};
use serde::de::DeserializeOwned;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;
use wanisabi::client::Client;
use wanisabi::model::subject::Subject;
use wanisabi::response::{CollectionResponse, IdResponse};
use wanisabi::wrapper::assignments::AssignmentsFilter;
use wanisabi::wrapper::subject::SubjectFilter;

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

impl WanikaniInner {
    /// Every page of a collection, starting from its first.
    async fn all_pages<T: DeserializeOwned>(
        &self,
        first: CollectionResponse<T>,
    ) -> Result<Vec<IdResponse<T>>, Error> {
        let mut items = first.data;
        let mut next_url = first.pages.next_url;
        while let Some(url) = next_url {
            let body = self
                .client
                .get(url)
                .await
                .map_err(wanisabi::Error::from)?
                .text()
                .await
                .map_err(wanisabi::Error::from)?;
            let page: CollectionResponse<T> =
                serde_json::from_str(&body).map_err(wanisabi::Error::from)?;
            items.extend(page.data);
            next_url = page.pages.next_url;
        }
        Ok(items)
    }

    /// Every subject matching `filters`, across pages.
    async fn subjects(
        &self,
        filters: Vec<SubjectFilter>,
    ) -> Result<Vec<IdResponse<Subject>>, Error> {
        let first = self.client.get_subjects_filtered(filters).await?;
        self.all_pages(first).await
    }

    /// The subjects with these ids. WaniKani reads an empty `ids` filter as no
    /// filter, so no ids asks for nothing.
    async fn subjects_by_id(&self, ids: &BTreeSet<i64>) -> Result<Vec<IdResponse<Subject>>, Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        self.subjects(vec![SubjectFilter::Ids(ids.iter().copied().collect())])
            .await
    }

    /// The user's SRS stage for each of these subjects, from their
    /// assignments. A subject without one is locked.
    async fn srs_stages(&self, subject_ids: &BTreeSet<i64>) -> Result<HashMap<i64, i64>, Error> {
        if subject_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let first = self
            .client
            .get_assignments_filtered(vec![AssignmentsFilter::SubjectIds(
                subject_ids.iter().copied().collect(),
            )])
            .await?;
        Ok(self
            .all_pages(first)
            .await?
            .into_iter()
            .map(|assignment| (assignment.data.subject_id, assignment.data.srs_stage))
            .collect())
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
