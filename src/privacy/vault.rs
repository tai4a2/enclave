//! Master key management.
//!
//! The master key encrypts the SQLCipher database. It is derived from a user
//! password (Argon2id by default, PBKDF2 for legacy vaults) and optionally
//! cached locally (keys.toml, mode 0600).
//!
//! The salt file records which KDF was used, so old vaults keep working:
//! a bare 32-byte salt means legacy PBKDF2; the versioned header
//! (`ENCLAVE-KDF` + version + KDF id + salt) selects the algorithm.

use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use crate::error::{EnclaveError, Result};
use crate::privacy::crypto::{self, Kdf, SALT_LEN};

/// Magic header for versioned salt files.
const SALT_MAGIC: &[u8] = b"ENCLAVE-KDF";
/// Salt-file format version.
const SALT_VERSION: u8 = 1;

/// A 256-bit master key.
///
/// The bytes live in a single heap allocation that is `mlock`ed (best-effort)
/// so the key is never written to swap. It is zeroized on drop.
pub struct MasterKey(Box<[u8; 32]>);

impl MasterKey {
    /// Allocate a locked, zeroizing key from raw bytes.
    fn alloc(bytes: [u8; 32]) -> Self {
        let boxed = Box::new(bytes);
        // Best-effort: keep the key out of swap. Failure is not fatal.
        unsafe {
            crate::privacy::secure::lock_region(boxed.as_ptr(), 32);
        }
        Self(boxed)
    }

    /// Wrap raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self::alloc(bytes)
    }

    /// Borrow the raw key bytes.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hex-encode the key.
    pub fn to_hex(&self) -> String {
        hex::encode(*self.0)
    }

    /// Parse a hex-encoded key.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str.trim()).map_err(|e| EnclaveError::crypto(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(EnclaveError::crypto("master key must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self::alloc(arr))
    }
}

impl Clone for MasterKey {
    fn clone(&self) -> Self {
        Self::alloc(*self.0)
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.0.as_mut().zeroize();
        unsafe {
            crate::privacy::secure::unlock_region(self.0.as_ptr(), 32);
        }
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.write_str("MasterKey([redacted])")
    }
}

/// Constant-time byte-slice equality.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Whether `password` equals the duress password from `ENCLAVE_DURESS_PASSWORD`.
///
/// The duress password is never stored in the config file: it is read from the
/// environment so it does not live on disk. When it matches, the app should
/// open a decoy vault instead of the real one.
pub fn duress_matches(password: &str) -> bool {
    match std::env::var("ENCLAVE_DURESS_PASSWORD") {
        Ok(secret) if !secret.is_empty() => ct_eq(secret.as_bytes(), password.as_bytes()),
        _ => false,
    }
}

/// Whether a duress password is configured at all.
pub fn duress_configured() -> bool {
    std::env::var("ENCLAVE_DURESS_PASSWORD")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
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

    /// Read the salt record, if present: `(kdf, salt)`.
    fn read_salt_record(&self) -> Result<Option<(Kdf, Vec<u8>)>> {
        let path = self.salt_path();
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path)?;
        // Legacy format: a bare 32-byte salt means PBKDF2.
        if bytes.len() == SALT_LEN && !bytes.starts_with(SALT_MAGIC) {
            return Ok(Some((Kdf::Pbkdf2, bytes)));
        }
        let header = SALT_MAGIC.len();
        if bytes.len() >= header + 2 && bytes.starts_with(SALT_MAGIC) {
            let version = bytes[header];
            if version != SALT_VERSION {
                return Err(EnclaveError::crypto(format!(
                    "unsupported salt file version {version}"
                )));
            }
            let kdf = Kdf::from_byte(bytes[header + 1])?;
            let salt = bytes[header + 2..].to_vec();
            if salt.is_empty() {
                return Err(EnclaveError::crypto("empty salt"));
            }
            return Ok(Some((kdf, salt)));
        }
        Err(EnclaveError::crypto("corrupt salt file"))
    }

    /// Write a versioned salt record.
    fn write_salt_record(&self, kdf: Kdf, salt: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.config_dir)?;
        let mut buf = Vec::with_capacity(SALT_MAGIC.len() + 2 + salt.len());
        buf.extend_from_slice(SALT_MAGIC);
        buf.push(SALT_VERSION);
        buf.push(kdf.to_byte());
        buf.extend_from_slice(salt);
        std::fs::write(self.salt_path(), &buf)?;
        Ok(())
    }

    /// Load the existing salt record or create one with `new_kdf`.
    fn load_or_create_record(&self, new_kdf: Kdf) -> Result<(Kdf, Vec<u8>)> {
        if let Some(record) = self.read_salt_record()? {
            return Ok(record);
        }
        let salt = crypto::random_bytes(SALT_LEN);
        self.write_salt_record(new_kdf, &salt)?;
        Ok((new_kdf, salt))
    }

    /// Load the existing salt or create (and persist) a fresh one.
    ///
    /// Returns just the salt bytes (32). New vaults are created with the
    /// default KDF (Argon2id).
    pub fn load_or_create_salt(&self) -> Result<Vec<u8>> {
        Ok(self.load_or_create_record(Kdf::Argon2id)?.1)
    }

    /// Derive the master key from `password` with the default KDF (Argon2id),
    /// optionally using the local cache.
    pub fn derive_key(&self, password: &str, use_keychain: bool) -> Result<MasterKey> {
        self.derive_key_with(password, use_keychain, Kdf::Argon2id)
    }

    /// Derive the master key, using `new_kdf` only when the vault is being
    /// created (existing vaults keep the KDF recorded in the salt file).
    ///
    /// The local cache (keys.toml, mode 0600) is a *cache*, not a bypass: the
    /// typed password is always verified against the derived key before the
    /// cached one is accepted.
    pub fn derive_key_with(
        &self,
        password: &str,
        use_keychain: bool,
        new_kdf: Kdf,
    ) -> Result<MasterKey> {
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

        let (kdf, salt) = self.load_or_create_record(new_kdf)?;
        let mut raw = crypto::derive_key_with(kdf, password, &salt)?;
        let key = MasterKey::from_bytes(raw);
        raw.zeroize();

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
        let (kdf, salt) = self.load_or_create_record(Kdf::Argon2id)?;
        let mut derived = crypto::derive_key_with(kdf, password, &salt)?;
        let equal = crypto::ct_equal(&derived, cached.expose());
        derived.zeroize();
        Ok(equal)
    }

    /// Remove the cached master key.
    pub fn forget_cached_key(&self) -> Result<()> {
        crate::privacy::keys::SecureCredentials::delete_master_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_matches_only_equal_slices() {
        assert!(ct_eq(b"hello", b"hello"));
        assert!(!ct_eq(b"hello", b"hellx"));
        assert!(!ct_eq(b"hello", b"hell"));
    }

    #[test]
    fn duress_env_controls_matching() {
        std::env::remove_var("ENCLAVE_DURESS_PASSWORD");
        assert!(!duress_configured());
        assert!(!duress_matches("anything"));

        std::env::set_var("ENCLAVE_DURESS_PASSWORD", "wrong-pw");
        assert!(duress_configured());
        assert!(duress_matches("wrong-pw"));
        assert!(!duress_matches("other"));
        assert!(!duress_matches(""));

        // An empty value is treated as "not configured".
        std::env::set_var("ENCLAVE_DURESS_PASSWORD", "");
        assert!(!duress_configured());

        std::env::remove_var("ENCLAVE_DURESS_PASSWORD");
    }
}
