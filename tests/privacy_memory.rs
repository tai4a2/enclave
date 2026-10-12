//! Integration tests for the SQLCipher-backed encrypted memory.
//!
//! These tests verify the core privacy guarantees:
//! * data roundtrips correctly with the right key
//! * a wrong master key cannot open the vault
//! * no plaintext ever lands on disk

use enclave::core::message::{Message, Role};
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
#[test]
fn search_messages_finds_across_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    let memory = EncryptedMemory::open(&db, &test_key()).unwrap();

    let a = memory.create_session("alpha").unwrap();
    let b = memory.create_session("beta").unwrap();
    memory.save_message(&a, "user", "the secret code is 42").unwrap();
    memory.save_message(&a, "assistant", "noted").unwrap();
    memory.save_message(&b, "user", "unrelated message").unwrap();
    memory
        .save_message(&b, "assistant", "the secret plan is ready")
        .unwrap();

    let hits = memory.search_messages("secret", 50).unwrap();
    assert_eq!(hits.len(), 2, "both sessions should match");
    assert!(hits.iter().all(|h| h.snippet.contains("secret")));
    let names: Vec<&str> = hits.iter().map(|h| h.session_name.as_str()).collect();
    assert!(names.contains(&"alpha") && names.contains(&"beta"));

    // Wildcards in the query must be treated literally, not as LIKE patterns.
    assert!(memory.search_messages("%", 50).unwrap().is_empty());
    assert!(memory.search_messages("nomatch-xyz", 50).unwrap().is_empty());
}

#[test]
fn egress_ledger_records_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    let memory = EncryptedMemory::open(&db, &test_key()).unwrap();
    let sid = memory.create_session("chat").unwrap();

    memory
        .add_egress(Some(&sid), "openrouter", "model-x", b"hello", "1 EMAIL")
        .unwrap();
    memory
        .add_egress(Some(&sid), "openrouter", "model-x", b"world", "")
        .unwrap();

    assert_eq!(memory.egress_count().unwrap(), 2);
    let entries = memory.list_egress(10).unwrap();
    assert_eq!(entries.len(), 2);
    // Newest first; fingerprints only (payload sha is hex, never the payload).
    assert_eq!(entries[0].redactions, "");
    assert_eq!(entries[1].redactions, "1 EMAIL");
    assert_eq!(entries[0].payload_bytes, 5);
    assert!(!entries[0].payload_sha.is_empty());
    assert_ne!(entries[0].hash, entries[1].hash);
    assert!(memory.verify_egress_chain().unwrap());
}

#[test]
fn egress_chain_detects_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    let memory = EncryptedMemory::open(&db, &test_key()).unwrap();
    memory
        .add_egress(None, "ollama", "llama3.1", b"a", "")
        .unwrap();
    memory
        .add_egress(None, "ollama", "llama3.1", b"b", "")
        .unwrap();
    assert!(memory.verify_egress_chain().unwrap());

    memory.tamper_last_egress().unwrap();
    assert!(!memory.verify_egress_chain().unwrap());
}

#[test]
fn egress_ledger_is_empty_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    let memory = EncryptedMemory::open(&db, &test_key()).unwrap();
    assert_eq!(memory.egress_count().unwrap(), 0);
    assert!(memory.list_egress(10).unwrap().is_empty());
    assert!(memory.verify_egress_chain().unwrap());
}

#[test]
fn tainted_flag_persists_across_reload() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    let key = test_key();
    let memory = EncryptedMemory::open(&db, &key).unwrap();
    let sid = memory.create_session("t").unwrap();

    let mut secret = Message::user("my email is x@y.com".to_string());
    secret.tainted = true;
    memory.save_message_full(&sid, &secret).unwrap();
    memory
        .save_message_full(&sid, &Message::user("plain line".to_string()))
        .unwrap();

    // Reopen the vault to prove the flag survives a reload.
    drop(memory);
    let memory = EncryptedMemory::open(&db, &key).unwrap();
    let history = memory.get_history(&sid, 10).unwrap();
    assert_eq!(history.len(), 2);
    assert!(history[0].tainted);
    assert!(!history[1].tainted);
}
