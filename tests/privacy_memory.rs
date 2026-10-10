//! Integration tests for the SQLCipher-backed encrypted memory.
//!
//! These tests verify the core privacy guarantees:
//! * data roundtrips correctly with the right key
//! * a wrong master key cannot open the vault
//! * no plaintext ever lands on disk

use enclave::core::message::Role;
use enclave::privacy::memory::EncryptedMemory;
use enclave::privacy::vault::MasterKey;

fn test_key() -> MasterKey {
    MasterKey::from_bytes([0x42u8; 32])
}

fn other_key() -> MasterKey {
    MasterKey::from_bytes([0x99u8; 32])
}

#[test]
fn session_lifecycle_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    let key = test_key();

    let memory = EncryptedMemory::open(&db, &key).unwrap();
    let session_id = memory.create_session("test").unwrap();

    memory
        .save_message(&session_id, "user", "hello secret world")
        .unwrap();
    memory
        .save_message(&session_id, "assistant", "hi, this is encrypted")
        .unwrap();

    let history = memory.get_history(&session_id, 50).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].role, Role::User);
    assert_eq!(history[0].content, "hello secret world");
    assert_eq!(history[1].role, Role::Assistant);

    let sessions = memory.list_sessions().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].message_count, 2);
    assert!(memory.session_exists(&session_id).unwrap());

    memory.delete_session(&session_id).unwrap();
    assert!(!memory.session_exists(&session_id).unwrap());
    assert!(memory.get_history(&session_id, 50).unwrap().is_empty());
}

#[test]
fn wrong_key_cannot_open_vault() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");

    {
        let memory = EncryptedMemory::open(&db, &test_key()).unwrap();
        memory.create_session("test").unwrap();
        memory.save_message("x", "user", "irrelevant").ok(); // session 'x' may not exist, fine
    }

    // A different key must fail: SQLCipher rejects the header/HMAC.
    let err = EncryptedMemory::open(&db, &other_key());
    assert!(err.is_err(), "opening with a wrong key must fail");
}

#[test]
fn no_plaintext_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    let secret = "TOPSECRET-PII-mauro@example.com-+390123456789";

    {
        let memory = EncryptedMemory::open(&db, &test_key()).unwrap();
        let id = memory.create_session("leak-check").unwrap();
        memory.save_message(&id, "user", secret).unwrap();
    }

    let raw = std::fs::read(&db).unwrap();
    let blob = String::from_utf8_lossy(&raw).to_string();
    assert!(
        !blob.contains(secret),
        "plaintext secret found in the raw database file!"
    );
    assert!(
        !blob.contains("mauro@example.com"),
        "plaintext email found in the raw database file!"
    );
}

#[test]
fn history_limit_returns_most_recent_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    let memory = EncryptedMemory::open(&db, &test_key()).unwrap();
    let id = memory.create_session("limit").unwrap();

    for i in 0..5 {
        memory.save_message(&id, "user", &format!("msg-{i}")).unwrap();
    }

    let history = memory.get_history(&id, 2).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].content, "msg-3");
    assert_eq!(history[1].content, "msg-4");
}

#[test]
fn rename_session_updates_name() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    let memory = EncryptedMemory::open(&db, &test_key()).unwrap();
    let id = memory.create_session("old-name").unwrap();

    memory.rename_session(&id, "new-name").unwrap();
    let sessions = memory.list_sessions().unwrap();
    assert_eq!(sessions[0].name, "new-name");

    assert!(memory.rename_session("missing-id", "x").is_err());
}