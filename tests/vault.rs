//! Integration tests for master key derivation (Vault).

use enclave::privacy::vault::{MasterKey, Vault};

#[test]
fn salt_is_created_once_and_reused() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::new(dir.path());

    assert!(!vault.is_initialized());

    let salt1 = vault.load_or_create_salt().unwrap();
    assert_eq!(salt1.len(), 32);
    assert!(vault.is_initialized());

    // Second call must load the same salt, not regenerate it.
    let salt2 = vault.load_or_create_salt().unwrap();
    assert_eq!(salt1, salt2);
}

#[test]
fn derivation_is_deterministic_and_password_dependent() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::new(dir.path());

    let a = vault.derive_key("correct horse battery staple", false).unwrap();
    let b = vault.derive_key("correct horse battery staple", false).unwrap();
    assert_eq!(a.expose(), b.expose(), "same password+salt must yield same key");

    let c = vault.derive_key("wrong password", false).unwrap();
    assert_ne!(a.expose(), c.expose(), "different password must yield different key");
}

#[test]
fn different_vaults_yield_different_keys() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();

    let key_a = Vault::new(dir_a.path()).derive_key("pw", false).unwrap();
    let key_b = Vault::new(dir_b.path()).derive_key("pw", false).unwrap();
    assert_ne!(key_a.expose(), key_b.expose(), "random salts must yield different keys");
}

#[test]
fn master_key_hex_roundtrip() {
    let bytes = [0xABu8; 32];
    let key = MasterKey::from_bytes(bytes);
    let parsed = MasterKey::from_hex(&key.to_hex()).unwrap();
    assert_eq!(parsed.expose(), &bytes);

    // Wrong length must be rejected.
    assert!(MasterKey::from_hex("abcd").is_err());
    assert!(MasterKey::from_hex("zzzz").is_err());
}

#[test]
fn cached_key_verification_rejects_wrong_password() {
    // The keychain is a cache, not a bypass: the typed password must derive
    // the cached key exactly. Regression test for the keychain-bypass flaw.
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::new(dir.path());

    let cached = vault.derive_key("the-real-password", false).unwrap();
    assert!(vault.cached_key_matches("the-real-password", &cached).unwrap());
    assert!(!vault.cached_key_matches("wrong-guess", &cached).unwrap());
    assert!(!vault.cached_key_matches("", &cached).unwrap());
}

#[test]
fn new_vault_writes_a_versioned_salt_record() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::new(dir.path());
    vault.load_or_create_salt().unwrap();
    let raw = std::fs::read(vault.salt_path()).unwrap();
    assert!(raw.starts_with(b"ENCLAVE-KDF"), "salt file must be versioned");
    // magic + version + kdf id + 32-byte salt
    assert_eq!(raw.len(), 11 + 1 + 1 + 32);
}

#[test]
fn legacy_pbkdf2_salt_is_still_supported() {
    // A bare 32-byte salt file is the old PBKDF2 format; it must keep working.
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::new(dir.path());
    let legacy_salt = [7u8; 32];
    std::fs::write(vault.salt_path(), legacy_salt).unwrap();

    let salt = vault.load_or_create_salt().unwrap();
    assert_eq!(salt, legacy_salt.to_vec(), "legacy salt must be preserved");

    let a = vault.derive_key("pw", false).unwrap();
    let b = vault.derive_key("pw", false).unwrap();
    assert_eq!(a.expose(), b.expose());
}
