//! Error types shared across the whole crate.

use thiserror::Error;

/// Convenient result alias.
pub type Result<T> = std::result::Result<T, EnclaveError>;

/// The unified error type for Enclave.
#[derive(Debug, Error)]
pub enum EnclaveError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("keyring error: {0}")]
    Keyring(#[from] keyring::Error),

    #[error("config parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("provider error: {0}")]
    Provider(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("auth error: {0}")]
    Auth(String),

    #[error("{0}")]
    Other(String),
}

impl EnclaveError {
    pub fn crypto(msg: impl Into<String>) -> Self {
        Self::Crypto(msg.into())
    }

    pub fn provider(msg: impl Into<String>) -> Self {
        Self::Provider(msg.into())
    }

    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    pub fn auth(msg: impl Into<String>) -> Self {
        Self::Auth(msg.into())
    }

    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}
