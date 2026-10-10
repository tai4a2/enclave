//! Cryptographic primitives used by the privacy layer.
//!
//! * Key derivation: PBKDF2-HMAC-SHA256 with 600_000 iterations.
//! * Symmetric encryption: AES-256-GCM with a random 96-bit nonce.
//!
//! The ciphertext layout produced by [`encrypt`] is `nonce || ciphertext`.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
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

/// A 256-bit symmetric key.
pub type Key = [u8; KEY_LEN];

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
}
