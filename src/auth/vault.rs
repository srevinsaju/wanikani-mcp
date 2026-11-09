//! Each WaniKani connection's API key, sealed at rest with the server's vault
//! key.
//!
//! A connection is one sign-in, and its id (`conn_…`) is the subject of the
//! authorization server's tokens for that grant. Binding the API key to the
//! grant rather than to the client registration is what keeps two users of
//! the same MCP client apart. The schema is
//! `src/auth/migrations/0001_auth_store.sql`.

use std::fmt::{Debug, Formatter};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use aes_gcm::aead::rand_core::{OsRng, RngCore};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use sqlx::SqlitePool;

/// Which key sealed a row. It is stored in the row's `key_id` column and bound
/// into the row's associated data. There is a single vault key, so it is
/// always 1; the column lets a key ring come later without a migration.
/// Until then, rotating the key leaves every row `Unsealable`, which signs
/// everyone out.
const KEY_ID: i64 = 1;
const NONCE_LEN: usize = 12;

/// The AES-256-GCM key API keys are sealed with, parsed from 32 bytes in
/// standard base64 (`VAULT_KEY`).
#[derive(Clone)]
pub struct VaultKey(Aes256Gcm);

impl FromStr for VaultKey {
    type Err = &'static str;

    fn from_str(encoded: &str) -> Result<VaultKey, &'static str> {
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| "the vault key is not base64")?;
        Aes256Gcm::new_from_slice(&bytes)
            .map(VaultKey)
            .map_err(|_| "the vault key is not 32 bytes")
    }
}

impl Debug for VaultKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultKey(..)")
    }
}

/// A WaniKani connection, and the subject of its grant's tokens.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId(String);

impl ConnectionId {
    fn new_random() -> ConnectionId {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        ConnectionId(format!("conn_{}", URL_SAFE_NO_PAD.encode(bytes)))
    }

    /// The connection an authorization-server token names as its subject.
    pub fn from_subject(subject: &str) -> ConnectionId {
        ConnectionId(subject.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// WaniKani API keys by connection.
pub struct Vault {
    pool: SqlitePool,
    key: VaultKey,
    /// How long a new connection may go without tokens: from the sign-in to
    /// the client redeeming its authorization code.
    prune_grace: Duration,
}

impl Vault {
    /// The vault over the pool `auth::open_database` returned.
    pub fn new(pool: SqlitePool, key: VaultKey, prune_grace: Duration) -> Vault {
        Vault {
            pool,
            key,
            prune_grace,
        }
    }

    /// Keeps a new sign-in's API key.
    pub async fn connect(&self, api_key: &str) -> Result<ConnectionId, VaultError> {
        let id = ConnectionId::new_random();
        sqlx::query(
            "INSERT INTO connections (id, key_id, sealed, created_at_ns) VALUES (?, ?, ?, ?)",
        )
        .bind(id.as_str())
        .bind(KEY_ID)
        .bind(seal(&self.key, &id, api_key))
        .bind(nanos(SystemTime::now()))
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// The connection's WaniKani API key.
    pub async fn api_key(&self, id: &ConnectionId) -> Result<String, VaultError> {
        let row: Option<(i64, Vec<u8>)> =
            sqlx::query_as("SELECT key_id, sealed FROM connections WHERE id = ?")
                .bind(id.as_str())
                .fetch_optional(&self.pool)
                .await?;
        let (key_id, sealed) = row.ok_or(VaultError::Disconnected)?;
        if key_id != KEY_ID {
            return Err(VaultError::Unsealable);
        }
        open(&self.key, id, &sealed)
    }

    /// Forgets connections past the grace period that no access or refresh
    /// token names as its subject any more (revoked, reused, swept, or their
    /// client deleted). Returns how many were forgotten.
    pub async fn prune(&self, now: SystemTime) -> Result<u64, VaultError> {
        let pruned = sqlx::query(
            "DELETE FROM connections
             WHERE created_at_ns <= ?
               AND NOT EXISTS (SELECT 1 FROM access_tokens WHERE subject = connections.id)
               AND NOT EXISTS (SELECT 1 FROM refresh_tokens WHERE subject = connections.id)",
        )
        .bind(nanos(now - self.prune_grace))
        .execute(&self.pool)
        .await?;
        Ok(pruned.rows_affected())
    }
}

/// Why the vault could not hand out an API key.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// No such connection: the user signs in again.
    #[error("the WaniKani connection is gone")]
    Disconnected,
    /// The row does not open with this vault key.
    #[error("the WaniKani API key does not open with the vault key")]
    Unsealable,
    #[error("vault storage: {0}")]
    Storage(#[from] sqlx::Error),
}

/// The API key, sealed for the row `id` under [`KEY_ID`]: nonce, then
/// ciphertext.
fn seal(key: &VaultKey, id: &ConnectionId, api_key: &str) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = key
        .0
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: api_key.as_bytes(),
                aad: &associated_data(id),
            },
        )
        .unwrap();
    [nonce.as_slice(), &ciphertext].concat()
}

/// Opens what [`seal`] sealed for the same `id`.
fn open(key: &VaultKey, id: &ConnectionId, sealed: &[u8]) -> Result<String, VaultError> {
    let (nonce, ciphertext) = sealed
        .split_at_checked(NONCE_LEN)
        .ok_or(VaultError::Unsealable)?;
    let plaintext = key
        .0
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &associated_data(id),
            },
        )
        .map_err(|_| VaultError::Unsealable)?;
    String::from_utf8(plaintext).map_err(|_| VaultError::Unsealable)
}

/// Binds a sealed value to its row and key: `id`, then [`KEY_ID`].
fn associated_data(id: &ConnectionId) -> Vec<u8> {
    [id.as_str().as_bytes(), &KEY_ID.to_be_bytes()].concat()
}

/// Nanoseconds since the Unix epoch; every instant until 2262 fits.
fn nanos(at: SystemTime) -> i64 {
    let since_epoch = at.duration_since(SystemTime::UNIX_EPOCH).unwrap();
    i64::try_from(since_epoch.as_nanos()).unwrap()
}
