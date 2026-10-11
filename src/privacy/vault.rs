//! Master key management.
//!
//! The master key encrypts the SQLCipher database. It is derived from a user
//! password (PBKDF2) and optionally cached locally (Keys.toml, mode 0600).

use std::path::{Path, PathBuf};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{EnclaveError, Result};

/// A 256-bit master key. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    /// Wrap raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw key bytes.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hex-encode the key.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a hex-encoded key.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes =
            hex::decode(hex_str.trim()).map_err(|e| crate::error::EnclaveError::crypto(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(crate::error::EnclaveError::crypto("master key must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

/// Manages the salt file and master key derivation.
pub struct Vault {
    config_dir: PathBuf,
}

impl Vault {
    /// Create a vault rooted at `config_dir`.
    pub fn new(config_dir: impl Into<PathBuf>) -> Self {
        Self {
            config_dir: config_dir.into(),
        }
    }

    /// The configuration directory.
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// Path to the salt file.
    pub fn salt_path(&self) -> PathBuf {
        self.config_dir.join("salt.bin")
    }

    /// Whether the vault has already been initialized (salt exists).
    pub fn is_initialized(&self) -> bool {
        self.salt_path().exists()
    }

    /// Load the existing salt or create (and persist) a fresh one.
    pub fn load_or_create_salt(&self) -> Result<Vec<u8>> {
        let path = self.salt_path();
        if path.exists() {
            Ok(std::fs::read(path)?)
        } else {
            std::fs::create_dir_all(&self.config_dir)?;
            let salt = crate::privacy::crypto::random_bytes(crate::privacy::crypto::SALT_LEN);
            std::fs::write(&path, &salt)?;
            Ok(salt)
        }
    }

    /// Derive the master key from `password`, optionally using the local cache.
    ///
    /// The local cache (keys.toml, mode 0600) is a *cache*, not a bypass: the
    /// typed password is always verified against the derived key before the
    /// cached one is accepted.
    pub fn derive_key(&self, password: &str, use_keychain: bool) -> Result<MasterKey> {
        if use_keychain {
            if let Some(hex_key) = crate::privacy::keys::SecureCredentials::get_master_key() {
                if let Ok(cached) = MasterKey::from_hex(&hex_key) {
                    if self.cached_key_matches(password, &cached)? {
                        return Ok(cached);
                    }
                    return Err(EnclaveError::auth("wrong master password"));
                }
            }
        }

        let salt = self.load_or_create_salt()?;
        let raw = crate::privacy::crypto::derive_key_pbkdf2(password, &salt)?;
        let key = MasterKey::from_bytes(raw);

        if use_keychain {
            crate::privacy::keys::SecureCredentials::store_master_key(&key.to_hex())?;
        }

        Ok(key)
    }

    /// Return the master key cached locally, if any, **without** asking for the
    /// password.
    ///
    /// This is the "unlock once" path: the derived key is cached in keys.toml
    /// (mode 0600) so later launches skip the password. Only used when
    /// `use_keychain = true`.
    pub fn try_cached_key(&self) -> Option<MasterKey> {
        let hex_key = crate::privacy::keys::SecureCredentials::get_master_key()?;
        MasterKey::from_hex(&hex_key).ok()
    }

    /// Verify `password` derives exactly `cached` (constant-time compare).
    pub fn cached_key_matches(&self, password: &str, cached: &MasterKey) -> Result<bool> {
        let salt = self.load_or_create_salt()?;
        let derived = crate::privacy::crypto::derive_key_pbkdf2(password, &salt)?;
        Ok(crate::privacy::crypto::ct_equal(&derived, cached.expose()))
    }

    /// Remove the cached master key.
    pub fn forget_cached_key(&self) -> Result<()> {
        crate::privacy::keys::SecureCredentials::delete_master_key()
    }
}
