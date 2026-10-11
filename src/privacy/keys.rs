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

    /// Resolve an API key for `provider`, preferring environment variables over
    /// the OS keychain.
    ///
    /// Lookup order:
    /// 1. `ENCLAVE_<PROVIDER>_API_KEY` (e.g. `ENCLAVE_OPENROUTER_API_KEY`)
    /// 2. `<PROVIDER>_API_KEY` (e.g. `OPENROUTER_API_KEY`, `OPENAI_API_KEY`)
    /// 3. the OS keychain
    ///
    /// Empty variables are ignored. Exporting the key in the shell lets users
    /// avoid macOS keychain prompts altogether.
    pub fn resolve_key(provider: &str) -> Result<String> {
        Self::env_key(provider, |name| std::env::var(name).ok())
            .map(Ok)
            .unwrap_or_else(|| Self::get(provider))
    }

    /// Pure environment lookup used by [`resolve_key`] (testable without a
    /// keychain).
    fn env_key<F>(provider: &str, lookup: F) -> Option<String>
    where
        F: Fn(&str) -> Option<String>,
    {
        let upper = provider.to_ascii_uppercase();
        for name in [format!("ENCLAVE_{upper}_API_KEY"), format!("{upper}_API_KEY")] {
            if let Some(value) = lookup(&name) {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
        None
    }

    /// Name of the environment variable providing `provider`'s key, if any.
    ///
    /// Used for user-facing messages (the key never leaves the environment).
    pub fn env_var_name(provider: &str) -> Option<String> {
        let upper = provider.to_ascii_uppercase();
        for name in [format!("ENCLAVE_{upper}_API_KEY"), format!("{upper}_API_KEY")] {
            if let Ok(value) = std::env::var(&name) {
                if !value.trim().is_empty() {
                    return Some(name);
                }
            }
        }
        None
    }

    /// Delete the API key for `provider` (no error if absent).
    pub fn delete(provider: &str) -> Result<()> {
        match Self::entry(provider)?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Whether a key exists for `provider` (environment variable or keychain).
    pub fn exists(provider: &str) -> bool {
        Self::env_var_name(provider).is_some() || Self::get(provider).is_ok()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixed_env_var_is_used_and_trimmed() {
        let key = SecureCredentials::env_key("openrouter", |name| {
            (name == "ENCLAVE_OPENROUTER_API_KEY").then(|| "  env-secret  ".to_string())
        });
        assert_eq!(key.as_deref(), Some("env-secret"));
    }

    #[test]
    fn standard_env_var_is_a_fallback() {
        let key = SecureCredentials::env_key("openai", |name| {
            (name == "OPENAI_API_KEY").then(|| "sk-test".to_string())
        });
        assert_eq!(key.as_deref(), Some("sk-test"));
    }

    #[test]
    fn prefixed_var_wins_over_standard() {
        let key = SecureCredentials::env_key("openai", |name| match name {
            "ENCLAVE_OPENAI_API_KEY" => Some("prefixed".to_string()),
            "OPENAI_API_KEY" => Some("standard".to_string()),
            _ => None,
        });
        assert_eq!(key.as_deref(), Some("prefixed"));
    }

    #[test]
    fn empty_or_missing_vars_yield_none() {
        assert!(SecureCredentials::env_key("openrouter", |_| None).is_none());
        assert!(SecureCredentials::env_key("openrouter", |_| Some("   ".to_string())).is_none());
    }
}
