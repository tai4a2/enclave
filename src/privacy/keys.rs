//! Secure credential storage backed by the OS keychain.
//!
//! API keys are never written to disk in plaintext: they are stored in the
//! macOS Keychain, Windows Credential Manager or the Linux Secret Service.

use crate::error::{EnclaveError, Result};

/// Thin wrapper around the OS keyring.
pub struct SecureCredentials;

impl SecureCredentials {
    /// Keyring service name.
    pub const SERVICE: &'static str = "enclave";

    fn entry(provider: &str) -> Result<keyring::Entry> {
        let entry =
            keyring::Entry::new(Self::SERVICE, provider).map_err(EnclaveError::from)?;
        Ok(entry)
    }

    /// Store an API key for `provider`.
    pub fn store(provider: &str, api_key: &str) -> Result<()> {
        Self::entry(provider)?.set_password(api_key)?;
        Ok(())
    }

    /// Retrieve the API key for `provider`.
    pub fn get(provider: &str) -> Result<String> {
        match Self::entry(provider)?.get_password() {
            Ok(value) => Ok(value),
            Err(keyring::Error::NoEntry) => Err(EnclaveError::auth(format!(
                "no API key stored for '{provider}'"
            ))),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete the API key for `provider` (no error if absent).
    pub fn delete(provider: &str) -> Result<()> {
        match Self::entry(provider)?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Whether a key exists for `provider`.
    pub fn exists(provider: &str) -> bool {
        Self::get(provider).is_ok()
    }

    /// Return the subset of `known` providers that have a stored key.
    pub fn configured(known: &[&str]) -> Vec<String> {
        known
            .iter()
            .filter(|p| Self::exists(p))
            .map(|p| p.to_string())
            .collect()
    }

    /// Store the derived master key (hex-encoded) for convenience.
    pub fn store_master_key(key_hex: &str) -> Result<()> {
        Self::entry("master_key")?.set_password(key_hex)?;
        Ok(())
    }

    /// Retrieve the cached master key (hex-encoded), if present.
    pub fn get_master_key() -> Option<String> {
        Self::entry("master_key").ok()?.get_password().ok()
    }

    /// Remove the cached master key.
    pub fn delete_master_key() -> Result<()> {
        Self::delete("master_key")
    }
}
