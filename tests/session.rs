//! Integration tests for the Session abstraction.

use enclave::core::message::Role;
use enclave::core::session::Session;
use enclave::privacy::memory::EncryptedMemory;
use enclave::privacy::vault::MasterKey;

fn open_memory(dir: &tempfile::TempDir) -> EncryptedMemory {
    EncryptedMemory::open(&dir.path().join("vault.db"), &MasterKey::from_bytes([7u8; 32]))
        .unwrap()
}

#[test]
fn create_add_load_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let memory = open_memory(&dir);

    let mut session = Session::create(&memory, "chat").unwrap();
    session.add_user(&memory, "first question").unwrap();
    session.add_assistant(&memory, "first answer").unwrap();

    let reloaded = Session::load(&memory, &session.id).unwrap();
    assert_eq!(reloaded.name, "chat");
    assert_eq!(reloaded.messages.len(), 2);
    assert_eq!(reloaded.messages[0].role, Role::User);
    assert_eq!(reloaded.messages[0].content, "first question");
    assert_eq!(reloaded.messages[1].role, Role::Assistant);
}

#[test]
fn load_missing_session_errors() {
    let dir = tempfile::tempdir().unwrap();
    let memory = open_memory(&dir);
    assert!(Session::load(&memory, "nonexistent-id").is_err());
}

#[test]
fn clear_resets_conversation() {
    let dir = tempfile::tempdir().unwrap();
    let memory = open_memory(&dir);

    let mut session = Session::create(&memory, "chat").unwrap();
    session.add_user(&memory, "to be wiped").unwrap();
    let old_id = session.id.clone();

    session.clear(&memory).unwrap();
    assert_ne!(session.id, old_id);
    assert!(session.messages.is_empty());
    assert!(Session::load(&memory, &old_id).is_err());
    assert_eq!(session.name, "chat");
}