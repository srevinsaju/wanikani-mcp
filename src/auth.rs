use askama::Template;
use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::Engine;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rmcp::transport::auth::AuthorizationMetadata;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use url::Url;
use uuid::Uuid;

use crate::CURRENT_API_KEY;

#[derive(Clone, Debug)]
pub struct ClientStore {
    pub clients: Arc<RwLock<HashMap<String, ClientRecord>>>,
    pub auth_codes: Arc<RwLock<HashMap<String, AuthCodeRecord>>>,
    pub public_address: Url,
    pub jwt_secret: String,
    pub token_expiration: u64,
}

#[derive(Clone, Debug)]
pub struct ClientRecord {
    pub api_key: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AuthCodeRecord {
    pub client_id: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub api_key: String,
    pub exp: u64,
    pub iat: u64,
}

impl ClientStore {
    pub fn new(public_address: Url, jwt_secret: String, token_expiration: u64) -> Self {
        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            auth_codes: Arc::new(RwLock::new(HashMap::new())),
            public_address,
            jwt_secret,
            token_expiration,
        }
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeForm {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub api_key: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenRequest {
    #[serde(default)]
    pub grant_type: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub redirect_uri: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClientRegistrationRequest {
    pub client_name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct ClientRegistrationResponse {
    pub client_id: String,
    pub client_secret: String,
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub token_endpoint_auth_method: String,
}

#[derive(Template)]
#[template(path = "setup.html")]
struct SetupPageTemplate {
    tools: Vec<ToolInfo>,
    public_address: String,
}

#[derive(Template)]
#[template(path = "authorize.html")]
struct AuthorizePageTemplate {
    client_id: String,
    response_type: String,
    redirect_uri: String,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
}

struct ToolInfo {
    name: String,
    description: String,
}

pub async fn setup_page(State(store): State<Arc<ClientStore>>) -> impl IntoResponse {
    let tools = crate::wanikani::Wanikani::tool_router()
        .list_all()
        .into_iter()
        .map(|tool| ToolInfo {
            name: tool.name.to_string(),
            description: tool.description.unwrap_or_default().to_string(),
        })
        .collect();

    let public_address = store
        .public_address
        .as_str()
        .trim_end_matches('/')
        .to_string();

    let template = SetupPageTemplate {
        tools,
        public_address,
    };

    askama_web::WebTemplate(template).into_response()
}

pub async fn authorize_get(
    State(_store): State<Arc<ClientStore>>,
    Query(params): Query<AuthorizeQuery>,
) -> impl IntoResponse {
    if params.response_type != "code" {
        return (
            StatusCode::BAD_REQUEST,
            "unsupported response_type".to_string(),
        )
            .into_response();
    }

    let template = AuthorizePageTemplate {
        client_id: params.client_id,
        response_type: params.response_type,
        redirect_uri: params.redirect_uri,
        state: params.state,
        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
        scope: params.scope,
        resource: params.resource,
    };

    (StatusCode::OK, askama_web::WebTemplate(template)).into_response()
}

pub async fn authorize_post(
    State(store): State<Arc<ClientStore>>,
    Form(form): Form<AuthorizeForm>,
) -> impl IntoResponse {
    if form.response_type != "code" {
        return (
            StatusCode::BAD_REQUEST,
            "unsupported response_type".to_string(),
        )
            .into_response();
    }

    let code = format!("code-{}", Uuid::new_v4());
    let client_id = form.client_id.clone();

    store.auth_codes.write().await.insert(
        code.clone(),
        AuthCodeRecord {
            client_id: client_id.clone(),
            code_challenge: form.code_challenge.clone(),
            code_challenge_method: form.code_challenge_method.clone(),
        },
    );

    let mut clients = store.clients.write().await;
    if let Some(client) = clients.get_mut(&client_id) {
        client.api_key = Some(form.api_key);
    } else {
        clients.insert(
            client_id.clone(),
            ClientRecord {
                api_key: Some(form.api_key),
            },
        );
    }
    drop(clients);

    let mut redirect_url = format!("{}?code={}", form.redirect_uri, code);
    if let Some(state) = form.state.filter(|s| !s.is_empty()) {
        redirect_url.push_str(&format!("&state={}", state));
    }

    Redirect::to(&redirect_url).into_response()
}

pub async fn register_client(
    State(store): State<Arc<ClientStore>>,
    Json(req): Json<ClientRegistrationRequest>,
) -> impl IntoResponse {
    let client_id = req
        .client_name
        .clone()
        .unwrap_or_else(|| format!("client-{}", Uuid::new_v4()));
    let client_secret = Uuid::new_v4().to_string();

    let record = ClientRecord { api_key: None };

    store
        .clients
        .write()
        .await
        .insert(client_id.clone(), record);

    (
        StatusCode::CREATED,
        Json(ClientRegistrationResponse {
            client_id: client_id.clone(),
            client_secret,
            client_name: req.client_name.clone(),
            redirect_uris: req.redirect_uris.unwrap_or_default(),
            grant_types: vec!["authorization_code".to_string()],
            token_endpoint_auth_method: "none".to_string(),
        }),
    )
}

pub async fn get_token(
    State(store): State<Arc<ClientStore>>,
    Form(req): Form<TokenRequest>,
) -> impl IntoResponse {
    if req.grant_type == "authorization_code" {
        let mut auth_codes = store.auth_codes.write().await;
        let auth_record = match auth_codes.remove(&req.code) {
            Some(r) => r,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "authorization code not found or expired"
                    })),
                )
                    .into_response();
            }
        };
        drop(auth_codes);

        if auth_record.client_id != req.client_id {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "invalid_client",
                    "error_description": "client_id mismatch"
                })),
            )
                .into_response();
        }

        if let Some(challenge) = auth_record.code_challenge {
            let verifier = match req.code_verifier {
                Some(ref v) => v,
                None => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({
                            "error": "invalid_grant",
                            "error_description": "code_verifier required"
                        })),
                    )
                        .into_response();
                }
            };

            let method = auth_record
                .code_challenge_method
                .as_deref()
                .unwrap_or("plain");
            let valid = match method {
                "S256" => {
                    use sha2::{Digest, Sha256};
                    let digest = Sha256::digest(verifier.as_bytes());
                    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
                    computed == challenge
                }
                "plain" => verifier == &challenge,
                _ => false,
            };

            if !valid {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "PKCE verification failed"
                    })),
                )
                    .into_response();
            }
        }
    }

    let mut clients = store.clients.write().await;
    let record = match clients.get_mut(&req.client_id) {
        Some(r) => r,
        None => {
            if req.grant_type == "authorization_code" {
                clients.insert(req.client_id.clone(), ClientRecord { api_key: None });
                clients.get_mut(&req.client_id).unwrap()
            } else {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "invalid_client",
                        "error_description": "client_id not found"
                    })),
                )
                    .into_response();
            }
        }
    };

    if let Some(api_key) = req.api_key.clone() {
        record.api_key = Some(api_key);
    }

    let api_key = match &record.api_key {
        Some(key) => key.clone(),
        None => {
            drop(clients);
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "invalid_client",
                    "error_description": "no api key configured for client"
                })),
            )
                .into_response();
        }
    };
    drop(clients);

    let now = current_timestamp();
    let claims = TokenClaims {
        sub: req.client_id.clone(),
        api_key,
        exp: now + store.token_expiration,
        iat: now,
    };

    let access_token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(store.jwt_secret.as_bytes()),
    ) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!("failed to encode jwt: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "failed to generate token"
                })),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": store.token_expiration,
        })),
    )
        .into_response()
}

pub fn make_validate_token_middleware(
    store: Arc<ClientStore>,
) -> impl Fn(
    Request<axum::body::Body>,
    Next,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
+ Clone {
    move |request: Request<axum::body::Body>, next: Next| {
        let store = store.clone();
        Box::pin(async move {
            if request.method() == Method::OPTIONS {
                return next.run(request).await;
            }

            let auth_header = request.headers().get("Authorization");
            let token = match auth_header {
                Some(header) => {
                    let header_str = header.to_str().unwrap_or("");
                    if let Some(stripped) = header_str.strip_prefix("Bearer ") {
                        stripped.to_string()
                    } else {
                        return unauthorized();
                    }
                }
                None => return unauthorized(),
            };

            let claims = match decode::<TokenClaims>(
                &token,
                &DecodingKey::from_secret(store.jwt_secret.as_bytes()),
                &Validation::default(),
            ) {
                Ok(data) => data.claims,
                Err(e) => {
                    tracing::debug!("invalid or expired token: {:?}", e);
                    return unauthorized();
                }
            };

            let api_key = claims.api_key;

            CURRENT_API_KEY
                .scope(api_key, async move { next.run(request).await })
                .await
        })
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            axum::http::header::WWW_AUTHENTICATE,
            "Bearer error=\"invalid_token\"".to_string(),
        )],
    )
        .into_response()
}

pub async fn oauth_authorization_server(
    State(store): State<Arc<ClientStore>>,
) -> impl IntoResponse {
    let base_url = &store.public_address;
    let additional_fields = HashMap::from([
        (
            "grant_types_supported".to_string(),
            serde_json::json!(["authorization_code"]),
        ),
        (
            "code_challenge_methods_supported".to_string(),
            serde_json::json!(["S256", "plain"]),
        ),
        (
            "token_endpoint_auth_methods_supported".to_string(),
            serde_json::json!(["none"]),
        ),
    ]);

    let metadata = AuthorizationMetadata {
        authorization_endpoint: base_url.join("authorize").unwrap().to_string(),
        token_endpoint: base_url.join("token").unwrap().to_string(),
        registration_endpoint: Some(base_url.join("register").unwrap().to_string()),
        issuer: Some(base_url.as_str().trim_end_matches('/').to_string()),
        jwks_uri: None,
        scopes_supported: Some(vec!["profile".to_string(), "email".to_string()]),
        response_types_supported: Some(vec!["code".to_string()]),
        additional_fields,
    };
    (StatusCode::OK, Json(metadata))
}

pub async fn oauth_protected_resource(State(store): State<Arc<ClientStore>>) -> impl IntoResponse {
    let base_url = &store.public_address;
    let metadata = serde_json::json!({
        "resource": base_url.join("mcp").unwrap().as_str(),
        "authorization_servers": [base_url.join(".well-known/oauth-authorization-server").unwrap().as_str()],
    });
    (StatusCode::OK, Json(metadata))
}

pub fn router(cors_layer: CorsLayer, client_store: Arc<ClientStore>) -> Router {
    Router::new()
        .route("/", get(setup_page))
        .route("/setup", get(setup_page))
        .route("/authorize", get(authorize_get).post(authorize_post))
        .route("/register", post(register_client))
        .route("/token", post(get_token))
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_authorization_server),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth_protected_resource),
        )
        .layer(cors_layer)
        .with_state(client_store)
}
