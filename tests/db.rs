//! Integration tests for database statistics, vacuum and mass deletion.

use std::path::PathBuf;

use enclave::privacy::memory::EncryptedMemory;
use enclave::privacy::vault::{MasterKey, Vault};

fn open_temp_db() -> (tempfile::TempDir, PathBuf, EncryptedMemory) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::new(dir.path());
    let key = vault.derive_key("test-password", false).unwrap();
    let db_path = dir.path().join("vault.db");
    let memory = EncryptedMemory::open(&db_path, &key).unwrap();
    (dir, db_path, memory)
}

#[test]
fn stats_count_sessions_and_messages() {
    let (_dir, _path, memory) = open_temp_db();

    let s1 = memory.create_session("one").unwrap();
    let s2 = memory.create_session("two").unwrap();
    memory.save_message(&s1, "user", "hello").unwrap();
    memory.save_message(&s1, "assistant", "hi").unwrap();
    memory.save_message(&s2, "user", "other").unwrap();

    let stats = memory.stats().unwrap();
    assert_eq!(stats.sessions, 2);
    assert_eq!(stats.messages, 3);
    assert!(stats.page_size >= 512);
    assert!(stats.page_count > 0);
}

#[test]
fn delete_all_sessions_clears_everything() {
    let (_dir, _path, memory) = open_temp_db();

    for i in 0..4 {
        let id = memory.create_session(&format!("s{i}")).unwrap();
        memory.save_message(&id, "user", "msg").unwrap();
    }
    assert_eq!(memory.list_sessions().unwrap().len(), 4);

    let deleted = memory.delete_all_sessions().unwrap();
    assert_eq!(deleted, 4);
    assert!(memory.list_sessions().unwrap().is_empty());

    let stats = memory.stats().unwrap();
    assert_eq!(stats.sessions, 0);
    assert_eq!(stats.messages, 0);
}

#[test]
fn vacuum_removes_freed_pages() {
    let (_dir, db_path, memory) = open_temp_db();

    // Fill a session with enough messages to allocate many pages.
    let id = memory.create_session("bulk").unwrap();
    let blob = "x".repeat(4096);
    for _ in 0..64 {
        memory.save_message(&id, "user", &blob).unwrap();
    }
    memory.vacuum().unwrap();
    let size_full = std::fs::metadata(&db_path).unwrap().len();

    memory.delete_all_sessions().unwrap();
    let size_after_delete = std::fs::metadata(&db_path).unwrap().len();
    assert_eq!(size_after_delete, size_full, "VACUUM not yet run: file must keep its size");

    memory.vacuum().unwrap();
    let size_after_vacuum = std::fs::metadata(&db_path).unwrap().len();
    assert!(
        size_after_vacuum < size_after_delete,
        "VACUUM must reclaim space from deleted ciphertext"
    );
}

#[test]
fn wrong_key_cannot_read_stats() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::new(dir.path());
    let key = vault.derive_key("good", false).unwrap();
    let db_path = dir.path().join("vault.db");
    let _memory = EncryptedMemory::open(&db_path, &key).unwrap();
    drop(_memory);

    let other_key = MasterKey::from_bytes([0x77u8; 32]);
    assert!(EncryptedMemory::open(&db_path, &other_key).is_err());
}