//! The axum router for `sse` mode: `/mcp`, the OAuth endpoints, the protected
//! resource metadata (RFC 9728), the setup page and `/health`.
//!
//! Every `/mcp` request needs a bearer token our authorization server issued
//! for the `/mcp` resource. Its subject is a vault connection, whose WaniKani
//! API key the MCP service is built with ([`Wanikani::new_with_key`]).
//!
//! `/mcp` is stateless: rmcp builds a [`Wanikani`] for every request from
//! that request's token, and issues no `Mcp-Session-Id`. A session would
//! keep the API key of the token that opened it, and serve it to any other
//! signed-in user presenting the session id.

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::get;
use oauth_as::resource_metadata::{ProtectedResourceConfig, ProtectedResourceMetadata};
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::task_local;
use tower_http::cors::{Any, CorsLayer};
use url::Url;

use crate::auth::{Auth, ConnectionId, VaultError};
use crate::wanikani::Wanikani;

task_local! {
    /// The WaniKani API key of the `/mcp` request being served, read when
    /// rmcp builds the MCP service for that request.
    static CURRENT_API_KEY: String;
}

/// What the `/mcp` middleware needs.
#[derive(Clone)]
struct Mcp {
    auth: Arc<Auth>,
    resource: Arc<str>,
    /// Sent in every challenge, so clients can find the authorization server.
    metadata_url: Arc<str>,
}

/// `templates/setup.html`: how to connect a client, and the tools it gets.
#[derive(Template)]
#[template(path = "setup.html")]
struct SetupPage {
    tools: Vec<ToolInfo>,
    public_address: String,
}

struct ToolInfo {
    name: String,
    description: String,
}

/// The whole server: `issuer` is the public address without a trailing
/// slash, and `resource` the `/mcp` URL under it.
pub fn router(issuer: &str, resource: &str, auth: Arc<Auth>) -> anyhow::Result<Router> {
    let metadata =
        ProtectedResourceMetadata::from_config(&ProtectedResourceConfig::new(resource, issuer));
    let metadata_path = metadata.well_known_path();

    let mcp = Mcp {
        auth: auth.clone(),
        resource: resource.into(),
        metadata_url: format!("{issuer}{metadata_path}").into(),
    };
    // rmcp only accepts loopback `Host`s unless told the public one.
    let public_host = Url::parse(issuer)?
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("the public address {issuer} has no host"))?
        .to_owned();
    let service = StreamableHttpService::new(
        || {
            let api_key = CURRENT_API_KEY
                .try_with(String::clone)
                .map_err(std::io::Error::other)?;
            Wanikani::new_with_key(api_key).map_err(std::io::Error::other)
        },
        Arc::new(NeverSessionManager::default()),
        StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true)
            .with_allowed_hosts([public_host, "localhost".to_owned(), "127.0.0.1".to_owned()]),
    );
    let mcp_routes = Router::new()
        .nest_service("/mcp", service)
        .layer(from_fn_with_state(mcp, authenticate));

    let setup = SetupPage {
        tools: Wanikani::tool_router()
            .list_all()
            .into_iter()
            .map(|tool| ToolInfo {
                name: tool.name.to_string(),
                description: tool.description.unwrap_or_default().to_string(),
            })
            .collect(),
        public_address: issuer.to_owned(),
    }
    .render()?;
    let setup = get(move || async move { Html(setup) });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Ok(Router::new()
        .route("/", setup.clone())
        .route("/setup", setup)
        .route("/health", get(|| async { "ok" }))
        .route(
            &metadata_path,
            get(move || async move { Json(metadata.clone()) }),
        )
        .merge(mcp_routes)
        .merge(auth.router()?)
        .layer(cors))
}

/// Authenticates a `/mcp` request and serves it with the grant's API key.
async fn authenticate(State(mcp): State<Mcp>, request: Request, next: Next) -> Response {
    let Some(token) = bearer(&request) else {
        return mcp.unauthorized(None);
    };
    let issued = match mcp.auth.server().introspect(&token).await {
        Ok(Some(issued)) => issued,
        Ok(None) => return mcp.unauthorized(Some("invalid_token")),
        Err(error) => {
            tracing::error!(%error, "introspecting a token failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let audience_matches = issued
        .resource
        .iter()
        .any(|resource| **resource == *mcp.resource);
    let (Some(subject), true) = (issued.subject.as_deref(), audience_matches) else {
        return mcp.unauthorized(Some("invalid_token"));
    };
    let api_key = match mcp
        .auth
        .vault()
        .api_key(&ConnectionId::from_subject(subject))
        .await
    {
        Ok(api_key) => api_key,
        Err(VaultError::Disconnected) => return mcp.unauthorized(Some("invalid_token")),
        Err(error) => {
            tracing::error!(%error, "reading the WaniKani API key failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    CURRENT_API_KEY.scope(api_key, next.run(request)).await
}

fn bearer(request: &Request) -> Option<String> {
    let value = request.headers().get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim().to_owned())
}

impl Mcp {
    /// `401`, pointing at the protected resource metadata (RFC 9728 §5.1).
    fn unauthorized(&self, error: Option<&str>) -> Response {
        let error = error
            .map(|error| format!(", error=\"{error}\""))
            .unwrap_or_default();
        let challenge = format!("Bearer resource_metadata=\"{}\"{error}", self.metadata_url);
        let mut response = StatusCode::UNAUTHORIZED.into_response();
        response
            .headers_mut()
            .insert(WWW_AUTHENTICATE, HeaderValue::from_str(&challenge).unwrap());
        response
    }
}
