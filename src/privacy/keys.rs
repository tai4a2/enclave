//! Credential storage for provider API keys.
//!
//! By default keys are kept in a local file (`keys.toml`, mode 0600) inside the
//! config directory. This avoids the repeated OS-keychain authorization prompts
//! that macOS shows for unsigned/adhoc-signed binaries. The OS keychain remains
//! available as an opt-in backend (`enclave keys set --keychain`) and as a
//! last-resort source during resolution.
//!
//! Resolution order for a provider key:
//! 1. `ENCLAVE_<PROVIDER>_API_KEY` / `<PROVIDER>_API_KEY` environment variables
//! 2. the local `keys.toml` file (mode 0600)
//! 3. the OS keychain (results are transparently migrated into `keys.toml`)

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{EnclaveError, Result};

/// File (inside the config dir) holding locally-stored API keys.
const KEYS_FILE: &str = "keys.toml";

/// On-disk representation: `[keys] provider = "secret"`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct KeyFile {
    #[serde(default)]
    keys: BTreeMap<String, String>,
}

/// Credential storage facade.
pub struct SecureCredentials;

impl SecureCredentials {
    /// Keyring service name.
    pub const SERVICE: &'static str = "enclave";

    // ---------------------------------------------------------------- keychain

    fn entry(provider: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(Self::SERVICE, provider).map_err(EnclaveError::from)
    }

    /// Store an API key for `provider` in the OS keychain.
    pub fn store(provider: &str, api_key: &str) -> Result<()> {
        Self::entry(provider)?.set_password(api_key)?;
        Ok(())
    }

    /// Retrieve the API key for `provider` from the OS keychain.
    pub fn get(provider: &str) -> Result<String> {
        match Self::entry(provider)?.get_password() {
            Ok(value) => Ok(value),
            Err(keyring::Error::NoEntry) => Err(EnclaveError::auth(format!(
                "no API key stored for '{provider}'"
            ))),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete the API key for `provider` from the OS keychain (no error if absent).
    pub fn delete(provider: &str) -> Result<()> {
        match Self::entry(provider)?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    // -------------------------------------------------------------- local file

    /// Path of the local keys file (`<config_dir>/keys.toml`).
    pub fn keys_path() -> Result<PathBuf> {
        Ok(crate::config::Paths::resolve()?.config_dir.join(KEYS_FILE))
    }

    /// Load the keys file, tolerating a missing/corrupt file.
    fn load_at(path: &Path) -> KeyFile {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|raw| toml::from_str(&raw).ok())
            .unwrap_or_default()
    }

    /// Persist the keys file atomically and restrict permissions to the owner.
    fn save_at(path: &Path, data: &KeyFile) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let raw = toml::to_string_pretty(data).map_err(|e| EnclaveError::Config(e.to_string()))?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, raw.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Read a provider key from an explicit keys file (testable helper).
    fn file_get_at(path: &Path, provider: &str) -> Option<String> {
        Self::load_at(path)
            .keys
            .get(provider)
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
    }

    /// Write a provider key to an explicit keys file (testable helper).
    fn store_file_at(path: &Path, provider: &str, api_key: &str) -> Result<()> {
        let mut data = Self::load_at(path);
        data.keys
            .insert(provider.to_string(), api_key.trim().to_string());
        Self::save_at(path, &data)
    }

    /// Remove a provider key from an explicit keys file (testable helper).
    fn delete_file_at(path: &Path, provider: &str) -> Result<()> {
        let mut data = Self::load_at(path);
        data.keys.remove(provider);
        Self::save_at(path, &data)
    }

    /// Read a provider key from the local file, if present.
    pub fn file_get(provider: &str) -> Option<String> {
        let path = Self::keys_path().ok()?;
        Self::file_get_at(&path, provider)
    }

    /// Store a provider key in the local file (mode 0600).
    pub fn store_file(provider: &str, api_key: &str) -> Result<()> {
        let path = Self::keys_path()?;
        Self::store_file_at(&path, provider, api_key)
    }

    /// Remove a provider key from the local file (no error if absent).
    pub fn delete_file(provider: &str) -> Result<()> {
        let path = Self::keys_path()?;
        Self::delete_file_at(&path, provider)
    }

    /// Delete the whole local keys file.
    pub fn delete_file_store() -> Result<()> {
        let path = Self::keys_path()?;
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }

    // ------------------------------------------------------------- resolution

    /// Resolve an API key for `provider`.
    ///
    /// Order: environment → local file → OS keychain. A key found in the
    /// keychain is migrated into the local file so later runs no longer prompt.
    pub fn resolve_key(provider: &str) -> Result<String> {
        if let Some(key) = Self::env_key(provider, |name| std::env::var(name).ok()) {
            return Ok(key);
        }
        if let Some(key) = Self::file_get(provider) {
            return Ok(key);
        }
        let key = Self::get(provider)?;
        // Best-effort migration: stop asking the keychain from now on.
        let _ = Self::store_file(provider, &key);
        Ok(key)
    }

    /// API key from environment or the local file, WITHOUT touching the keychain
    /// (used for silent, prompt-free requests such as credit lookups).
    pub fn local_api_key(provider: &str) -> Option<String> {
        Self::env_key(provider, |name| std::env::var(name).ok())
            .or_else(|| Self::file_get(provider))
    }

    /// Environment-only API key (never touches file or keychain).
    pub fn env_api_key(provider: &str) -> Option<String> {
        Self::env_key(provider, |name| std::env::var(name).ok())
    }

    /// Pure environment lookup used by [`resolve_key`] (testable without a
    /// keychain).
    fn env_key<F>(provider: &str, lookup: F) -> Option<String>
    where
        F: Fn(&str) -> Option<String>,
    {
        let upper = provider.to_ascii_uppercase();
        for name in [
            format!("ENCLAVE_{upper}_API_KEY"),
            format!("{upper}_API_KEY"),
        ] {
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
    pub fn env_var_name(provider: &str) -> Option<String> {
        let upper = provider.to_ascii_uppercase();
        for name in [
            format!("ENCLAVE_{upper}_API_KEY"),
            format!("{upper}_API_KEY"),
        ] {
            if let Ok(value) = std::env::var(&name) {
                if !value.trim().is_empty() {
                    return Some(name);
                }
            }
        }
        None
    }

    /// Where the key for `provider` currently comes from, for user messages.
    pub fn source(provider: &str) -> Option<String> {
        if let Some(name) = Self::env_var_name(provider) {
            return Some(format!("environment variable {name}"));
        }
        if Self::file_get(provider).is_some() {
            return Some("local keys.toml (mode 0600)".to_string());
        }
        None
    }

    /// Whether a key exists for `provider` (environment variable or local file).
    ///
    /// Deliberately does not read the OS keychain, so listing keys never
    /// triggers a keychain prompt.
    pub fn exists(provider: &str) -> bool {
        Self::env_var_name(provider).is_some() || Self::file_get(provider).is_some()
    }

    /// Return the subset of `known` providers that have a stored key.
    pub fn configured(known: &[&str]) -> Vec<String> {
        known
            .iter()
            .filter(|p| Self::exists(p))
            .map(|p| p.to_string())
            .collect()
    }

    // -------------------------------------------------------------- master key

    /// Reserved entry name for the cached master key inside `keys.toml`.
    const MASTER_KEY_ENTRY: &'static str = "__master_key__";

    /// Cache the derived master key (hex-encoded) in the local credentials file
    /// (`keys.toml`, mode 0600) so the password is only asked once — no OS
    /// keychain dialog.
    pub fn store_master_key(key_hex: &str) -> Result<()> {
        Self::store_file(Self::MASTER_KEY_ENTRY, key_hex)
    }

    /// Retrieve the cached master key (hex-encoded), if present.
    pub fn get_master_key() -> Option<String> {
        Self::file_get(Self::MASTER_KEY_ENTRY)
    }

    /// Remove the cached master key.
    pub fn delete_master_key() -> Result<()> {
        Self::delete_file(Self::MASTER_KEY_ENTRY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_store_get_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.toml");

        SecureCredentials::store_file_at(&path, "openrouter", "  sk-or-test  ").unwrap();
        assert_eq!(
            SecureCredentials::file_get_at(&path, "openrouter").as_deref(),
            Some("sk-or-test") // trimmed
        );

        SecureCredentials::store_file_at(&path, "openai", "sk-openai").unwrap();
        assert_eq!(
            SecureCredentials::file_get_at(&path, "openai").as_deref(),
            Some("sk-openai")
        );

        SecureCredentials::delete_file_at(&path, "openrouter").unwrap();
        assert!(SecureCredentials::file_get_at(&path, "openrouter").is_none());
        // deleting one provider leaves the other intact
        assert_eq!(
            SecureCredentials::file_get_at(&path, "openai").as_deref(),
            Some("sk-openai")
        );
    }

    #[test]
    fn file_is_owner_only_on_unix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.toml");
        SecureCredentials::store_file_at(&path, "openrouter", "sk-x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn missing_file_is_treated_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.toml");
        assert!(SecureCredentials::file_get_at(&path, "openrouter").is_none());
    }

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
