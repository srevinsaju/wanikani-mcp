//! The OAuth 2.1 authorization server MCP clients talk to, following
//! simkl-mcp's `crates/simkl-mcp/src/auth`.
//!
//! The protocol is `oauth-as`: authorization code with S256 PKCE, exact
//! redirect URI matching, refresh rotation with reuse detection, RFC 8707
//! audiences, metadata and Dynamic Client Registration. This module supplies
//! only what that library leaves to its host: storage, signing in the user
//! (with their WaniKani API key), keeping each grant's API key, and the
//! sweeper.

mod login;
mod store;
mod vault;

use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::routing::get;
use oauth_as::http::ServiceBuilder;
use oauth_as::registration::{
    RegistrationAttempt, RegistrationConfig, RegistrationDecision, RegistrationPolicy,
};
use oauth_as::server::{AuthorizationServer, ServerConfig};
use oauth_as::store::Storage;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

pub use vault::{ConnectionId, Vault, VaultError, VaultKey};

use login::Login;
use store::Store;

/// How often expired grants are swept and orphaned connections pruned.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// How long a new connection may go without tokens, from the sign-in to the
/// client redeeming its authorization code (one minute in `oauth-as`).
const PRUNE_GRACE: Duration = Duration::from_secs(10 * 60);

/// The authorization server, the vault, and the sign-in routes over them.
pub struct Auth {
    server: Arc<AuthorizationServer<Store>>,
    vault: Arc<Vault>,
    login: Login,
}

impl Auth {
    /// The authorization server at `issuer`, for the one protected resource
    /// `resource` (the `/mcp` URL), over the database at `database`.
    pub async fn open(
        issuer: &str,
        resource: &str,
        database: &str,
        vault_key: VaultKey,
        access_token_ttl: Duration,
    ) -> anyhow::Result<Auth> {
        let pool = open_database(database).await?;

        let mut registration = RegistrationConfig::new();
        registration.management_enabled = false;
        // The device flow is advertised by `oauth-as` regardless, but no
        // registered client may use it: they get the code and refresh grants.
        let mut server_config = ServerConfig::new(issuer, format!("{issuer}/device"));
        server_config.registration = Some(Box::new(registration));
        server_config.protected_resources = Some(vec![resource.to_owned()]);
        server_config.allowed_resources = Some(Box::new([resource.into()]));
        server_config.access_token_ttl = access_token_ttl;
        let server = Arc::new(
            AuthorizationServer::new(server_config, Store::new(pool.clone()))
                .with_registration_policy(Box::new(OpenRegistration)),
        );
        let vault = Arc::new(Vault::new(pool, vault_key, PRUNE_GRACE));
        let login = Login::new(server.clone(), vault.clone());
        Ok(Auth {
            server,
            vault,
            login,
        })
    }

    pub fn server(&self) -> &Arc<AuthorizationServer<Store>> {
        &self.server
    }

    pub fn vault(&self) -> &Arc<Vault> {
        &self.vault
    }

    /// Our sign-in routes, with every other OAuth endpoint (metadata, token,
    /// registration, revocation) answered by `oauth-as`.
    pub fn router(&self) -> anyhow::Result<Router> {
        let oauth = ServiceBuilder::new(self.server.clone()).build()?;
        let login = Router::new()
            .route("/authorize", get(login::authorize).post(login::consent))
            .with_state(self.login.clone());
        Ok(login.merge(Router::from(oauth)))
    }

    /// Nothing in `oauth-as` runs on a timer, so this sweeps expired grants
    /// and, after them, prunes connections no token names any more.
    pub fn spawn_sweeper(&self) {
        let server = self.server.clone();
        let vault = self.vault.clone();
        tokio::spawn(async move {
            loop {
                if let Err(error) = server.store().sweep_expired(SystemTime::now()).await {
                    tracing::warn!(%error, "sweeping expired grants failed");
                }
                if let Err(error) = vault.prune(SystemTime::now()).await {
                    tracing::warn!(%error, "pruning WaniKani connections failed");
                }
                tokio::time::sleep(SWEEP_INTERVAL).await;
            }
        });
    }
}

/// Dynamic Client Registration (RFC 7591) is open: a registered client
/// reaches nobody's data until a user pastes their API key on our
/// `/authorize` page.
struct OpenRegistration;

impl RegistrationPolicy for OpenRegistration {
    fn authorize(&self, _: &RegistrationAttempt<'_>) -> RegistrationDecision {
        RegistrationDecision::Allow
    }
}

/// Opens (or creates) the database at `url` and applies migrations. The
/// store and the vault share the one connection it holds.
async fn open_database(url: &str) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal);
    // One connection that never closes: transactions queue on it instead of
    // racing for the write lock, and `sqlite::memory:` keeps its data.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .min_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(options)
        .await?;
    sqlx::migrate!("src/auth/migrations").run(&pool).await?;
    Ok(pool)
}
