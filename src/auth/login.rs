//! Signing a user in: our `/authorize` page, where the user pastes their
//! WaniKani API key, then the authorization code.
//!
//! 1. `GET /authorize` validates the client's request with `oauth-as` and
//!    shows a page naming the client and where it redirects, asking for an
//!    API key. The request's parameters ride along as hidden fields.
//! 2. `POST /authorize` validates the same parameters again. On Deny it sends
//!    the user back with `access_denied`; on Allow it seals the API key into
//!    a new vault connection and has `oauth-as` issue a code with that
//!    connection as its subject.
//!
//! Nothing is kept between the two steps: a forged `POST` can only bind the
//! forger's own API key, and the code still goes to the client's registered
//! redirect URI, behind the client's PKCE verifier.

use std::sync::Arc;

use askama::Template;
use askama_web::WebTemplate;
use axum::Form;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use oauth_as::authorization::{AuthorizationError, AuthorizationRequest};
use oauth_as::server::{AuthorizationServer, UserApproval};
use oauth_as::store::Storage;

use crate::auth::store::Store;
use crate::auth::vault::Vault;

/// The form field the API key arrives in.
const API_KEY_FIELD: &str = "api_key";

/// The form field naming the button pressed: [`ALLOW`] or Deny. Every field
/// other than this and [`API_KEY_FIELD`] is a parameter of the client's
/// authorization request.
const ACTION_FIELD: &str = "action";

/// [`ACTION_FIELD`]'s value for Allow.
const ALLOW: &str = "allow";

/// What the sign-in routes share.
#[derive(Clone)]
pub struct Login {
    server: Arc<AuthorizationServer<Store>>,
    vault: Arc<Vault>,
}

impl Login {
    pub fn new(server: Arc<AuthorizationServer<Store>>, vault: Arc<Vault>) -> Login {
        Login { server, vault }
    }
}

/// `templates/authorize.html`: asks the user for their API key.
#[derive(Template, WebTemplate)]
#[template(path = "authorize.html")]
struct AuthorizePage {
    client: String,
    redirect_host: String,
    /// The client's authorization request, sent back with the form.
    params: Vec<(String, String)>,
}

impl AuthorizePage {
    /// The client's tile on the page: the first letter of its name.
    fn client_initial(&self) -> String {
        self.client
            .chars()
            .take(1)
            .flat_map(char::to_uppercase)
            .collect()
    }
}

/// `templates/message.html`: a sign-in that cannot go on.
#[derive(Template, WebTemplate)]
#[template(path = "message.html")]
struct MessagePage {
    title: &'static str,
    text: String,
}

/// `GET /authorize`: validate the client's request and ask for an API key.
pub async fn authorize(State(login): State<Login>, RawQuery(query): RawQuery) -> Response {
    let params: Vec<(String, String)> =
        url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
            .into_owned()
            .filter(|(k, _)| k != API_KEY_FIELD && k != ACTION_FIELD)
            .collect();
    let authorization_request =
        AuthorizationRequest::from_pairs(params.iter().map(|(k, v)| (k, v.as_str())));
    let validated = match login
        .server
        .validate_authorization_request(&authorization_request)
        .await
    {
        Ok(validated) => validated,
        Err(error) => return authorization_error(error),
    };
    let client_name = match login.server.store().get_client(&validated.client_id).await {
        Ok(Some(client)) => client.name.clone(),
        _ => None,
    };
    AuthorizePage {
        client: client_name.unwrap_or_else(|| validated.client_id.as_str().to_owned()),
        redirect_host: url::Url::parse(&validated.redirect_uri)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .unwrap_or_else(|| validated.redirect_uri.clone()),
        params,
    }
    .into_response()
}

/// `POST /authorize`: the page's answer, Allow with an API key or Deny.
pub async fn consent(
    State(login): State<Login>,
    Form(mut params): Form<Vec<(String, String)>>,
) -> Response {
    let mut take_field = |field: &str| {
        params
            .iter()
            .position(|(k, _)| k == field)
            .map(|index| params.remove(index).1)
    };
    let allowed = take_field(ACTION_FIELD).as_deref() == Some(ALLOW);
    let api_key = take_field(API_KEY_FIELD)
        .map(|api_key| api_key.trim().to_owned())
        .filter(|api_key| !api_key.is_empty());
    let authorization_request =
        AuthorizationRequest::from_pairs(params.iter().map(|(k, v)| (k, v.as_str())));
    let request = match login
        .server
        .validate_authorization_request(&authorization_request)
        .await
    {
        Ok(request) => request,
        Err(error) => return authorization_error(error),
    };
    if !allowed {
        return Redirect::to(&request.denied().location()).into_response();
    }
    let Some(api_key) = api_key else {
        return failed(
            StatusCode::BAD_REQUEST,
            "A WaniKani API token is required. Start again from your app.",
        );
    };
    let connection = match login.vault.connect(&api_key).await {
        Ok(connection) => connection,
        Err(error) => {
            tracing::error!(%error, "keeping the WaniKani API key failed");
            return failed(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong. Start again from your app.",
            );
        }
    };
    let approval = UserApproval::granted(&request, connection.as_str());
    match login.server.issue_authorization_code(approval).await {
        Ok(code) => Redirect::to(&code.location(&request.redirect_uri)).into_response(),
        Err(error) => authorization_error(error),
    }
}

fn authorization_error(error: AuthorizationError) -> Response {
    match error {
        AuthorizationError::Redirect(redirect) => {
            Redirect::to(&redirect.location()).into_response()
        }
        AuthorizationError::Direct(error) => failed(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

fn failed(status: StatusCode, text: &str) -> Response {
    let page = MessagePage {
        title: "Sign-in failed",
        text: text.to_owned(),
    };
    (status, page).into_response()
}
