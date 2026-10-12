//! Cryptographic primitives used by the privacy layer.
//!
//! * Key derivation: Argon2id (memory-hard, default) or PBKDF2-HMAC-SHA256
//!   (legacy vaults). The choice is recorded alongside the salt.
//! * Symmetric encryption: AES-256-GCM with a random 96-bit nonce.
//!
//! The ciphertext layout produced by [`encrypt`] is `nonce || ciphertext`.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

use crate::error::{EnclaveError, Result};

/// Length of the KDF salt in bytes.
pub const SALT_LEN: usize = 32;
/// Length of an AES-256 key in bytes.
pub const KEY_LEN: usize = 32;
/// Length of the GCM nonce in bytes.
pub const NONCE_LEN: usize = 12;
/// Default PBKDF2 iteration count.
pub const PBKDF2_ITERATIONS: u32 = 600_000;

/// Argon2id default memory cost in KiB (19 MiB).
pub const ARGON2_M_COST: u32 = 19_456;
/// Argon2id default time cost (passes).
pub const ARGON2_T_COST: u32 = 2;
/// Argon2id default parallelism.
pub const ARGON2_P_COST: u32 = 1;

/// A 256-bit symmetric key.
pub type Key = [u8; KEY_LEN];

/// Password-based key-derivation function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    /// Legacy PBKDF2-HMAC-SHA256 (600k iterations).
    Pbkdf2,
    /// Argon2id (memory-hard). Default for new vaults.
    Argon2id,
}

impl Kdf {
    /// Stable byte id stored in the salt file.
    pub fn to_byte(self) -> u8 {
        match self {
            Kdf::Pbkdf2 => 0,
            Kdf::Argon2id => 1,
        }
    }

    /// Parse a byte id from the salt file.
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Kdf::Pbkdf2),
            1 => Ok(Kdf::Argon2id),
            other => Err(EnclaveError::crypto(format!("unknown KDF id {other}"))),
        }
    }

    /// Parse a human-readable name (`argon2id` / `pbkdf2`).
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "argon2id" | "argon2" => Some(Kdf::Argon2id),
            "pbkdf2" | "pbkdf2-sha256" => Some(Kdf::Pbkdf2),
            _ => None,
        }
    }

    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Kdf::Pbkdf2 => "pbkdf2",
            Kdf::Argon2id => "argon2id",
        }
    }
}

/// Derive a 256-bit key from a password and salt using the default iteration count.
pub fn derive_key_pbkdf2(password: &str, salt: &[u8]) -> Result<Key> {
    derive_key_pbkdf2_iter(password, salt, PBKDF2_ITERATIONS)
}

/// Derive a 256-bit key from a password and salt with an explicit iteration count.
pub fn derive_key_pbkdf2_iter(password: &str, salt: &[u8], iterations: u32) -> Result<Key> {
    if salt.is_empty() {
        return Err(EnclaveError::crypto("empty salt"));
    }
    let mut key = [0u8; KEY_LEN];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, iterations, &mut key);
    Ok(key)
}

/// Derive a 256-bit key with Argon2id using the default cost parameters.
pub fn derive_key_argon2id(password: &str, salt: &[u8]) -> Result<Key> {
    derive_key_argon2id_params(password, salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)
}

/// Derive a 256-bit key with Argon2id using explicit cost parameters.
pub fn derive_key_argon2id_params(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Key> {
    if salt.is_empty() {
        return Err(EnclaveError::crypto("empty salt"));
    }
    let params = Params::new(m_cost, t_cost, p_cost, Some(KEY_LEN))
        .map_err(|e| EnclaveError::crypto(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| EnclaveError::crypto(e.to_string()))?;
    Ok(key)
}

/// Derive a key with the given [`Kdf`].
pub fn derive_key_with(kdf: Kdf, password: &str, salt: &[u8]) -> Result<Key> {
    match kdf {
        Kdf::Pbkdf2 => derive_key_pbkdf2(password, salt),
        Kdf::Argon2id => derive_key_argon2id(password, salt),
    }
}

/// Generate `n` cryptographically secure random bytes.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// Generate a random 256-bit key.
pub fn random_key() -> Key {
    let mut key = [0u8; KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Encrypt `plaintext` with AES-256-GCM, returning `nonce || ciphertext`.
pub fn encrypt(key: &Key, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| EnclaveError::crypto(e.to_string()))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| EnclaveError::crypto(e.to_string()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt data produced by [`encrypt`].
pub fn decrypt(key: &Key, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() <= NONCE_LEN {
        return Err(EnclaveError::crypto("ciphertext too short"));
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| EnclaveError::crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| EnclaveError::crypto(e.to_string()))
}

/// Constant-time byte-slice equality (avoids timing side channels when
/// comparing derived vs cached keys).
pub fn ct_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_equal_matches_and_rejects() {
        assert!(ct_equal(b"hello", b"hello"));
        assert!(!ct_equal(b"hello", b"hella"));
        assert!(!ct_equal(b"hello", b"hell"));
        assert!(!ct_equal(b"", b"x"));
        assert!(ct_equal(b"", b""));
    }

    #[test]
    fn roundtrip() {
        let key = random_key();
        let msg = b"attack at dawn";
        let ct = encrypt(&key, msg).unwrap();
        assert_ne!(&ct[..], &msg[..]);
        assert_eq!(decrypt(&key, &ct).unwrap(), msg);
    }

    #[test]
    fn wrong_key_fails() {
        let key = random_key();
        let ct = encrypt(&key, b"secret").unwrap();
        assert!(decrypt(&random_key(), &ct).is_err());
    }

    #[test]
    fn derivation_is_deterministic() {
        let salt = random_bytes(SALT_LEN);
        let a = derive_key_pbkdf2_iter("pw", &salt, 1000).unwrap();
        let b = derive_key_pbkdf2_iter("pw", &salt, 1000).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn argon2id_is_deterministic_and_password_dependent() {
        let salt = random_bytes(SALT_LEN);
        // Small cost params to keep the test fast.
        let a = derive_key_argon2id_params("pw", &salt, 16, 1, 1).unwrap();
        let b = derive_key_argon2id_params("pw", &salt, 16, 1, 1).unwrap();
        assert_eq!(a, b);
        let c = derive_key_argon2id_params("other", &salt, 16, 1, 1).unwrap();
        assert_ne!(a, c);
        assert!(derive_key_argon2id_params("pw", &[], 16, 1, 1).is_err());
    }

    #[test]
    fn kdf_byte_and_name_roundtrip() {
        for kdf in [Kdf::Pbkdf2, Kdf::Argon2id] {
            assert_eq!(Kdf::from_byte(kdf.to_byte()).unwrap(), kdf);
            assert_eq!(Kdf::from_name(kdf.name()), Some(kdf));
        }
        assert!(Kdf::from_byte(9).is_err());
        assert_eq!(Kdf::from_name("Argon2"), Some(Kdf::Argon2id));
        assert_eq!(Kdf::from_name("nope"), None);
    }

    #[test]
    fn derive_key_with_dispatches() {
        let salt = random_bytes(SALT_LEN);
        assert_eq!(
            derive_key_with(Kdf::Pbkdf2, "pw", &salt).unwrap(),
            derive_key_pbkdf2_iter("pw", &salt, PBKDF2_ITERATIONS).unwrap()
        );
        // Argon2id dispatch is deterministic.
        assert_eq!(
            derive_key_with(Kdf::Argon2id, "pw", &salt).unwrap(),
            derive_key_argon2id("pw", &salt).unwrap()
        );
    }
}
