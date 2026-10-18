//! Integration tests for encrypted session export/import.

use std::path::PathBuf;

use enclave::core::message::Role;
use enclave::privacy::crypto::derive_key_pbkdf2;
use enclave::privacy::export::{export_session, import_session};
use enclave::privacy::{EncryptedMemory, MasterKey};

fn test_key() -> MasterKey {
    MasterKey::from_bytes([0x42u8; 32])
}

fn open_memory(dir: &std::path::Path) -> EncryptedMemory {
    EncryptedMemory::open(&dir.join("vault.db"), &test_key()).expect("open memory")
}

fn tmpdir(name: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "enclave-export-test-{name}-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&base).unwrap();
    base
}

fn seed_session(memory: &EncryptedMemory, name: &str) -> String {
    let id = memory.create_session(name).unwrap();
    memory
        .save_message(
            &id,
            Role::User.as_str(),
            "il mio nome è Alex, email alex@example.com",
        )
        .unwrap();
    memory
        .save_message(&id, Role::Assistant.as_str(), "ciao! come posso aiutare?")
        .unwrap();
    id
}

#[test]
fn export_file_contains_no_plaintext() {
    let dir = tmpdir("no-plaintext");
    let memory = open_memory(&dir);
    let id = seed_session(&memory, "segreta");

    let out = dir.join("export.enclave");
    let count = export_session(&memory, &id, &out, "passphrase-sicura").unwrap();
    assert_eq!(count, 2);

    let raw = std::fs::read(&out).unwrap();
    assert!(raw.starts_with(b"ENCLAVE-EXPORT-"));
    let text = String::from_utf8_lossy(&raw);
    assert!(!text.contains("Alex"));
    assert!(!text.contains("alex@example.com"));
    assert!(!text.contains("segreta"));
    assert!(!text.contains("ciao"));
}

#[test]
fn roundtrip_import_preserves_messages_in_new_session() {
    let dir = tmpdir("roundtrip");
    let memory = open_memory(&dir);
    let id = seed_session(&memory, "viaggio");

    let out = dir.join("export.enclave");
    export_session(&memory, &id, &out, "p").unwrap();

    // Import into a fresh memory (simulates another machine/vault).
    let dir2 = tmpdir("roundtrip-target");
    let memory2 = open_memory(&dir2);
    let (new_id, count) = import_session(&memory2, &out, "p").unwrap();
    assert_eq!(count, 2);
    assert_ne!(new_id, id);

    let history = memory2.get_history(&new_id, 100).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].role, Role::User);
    assert_eq!(
        history[0].content,
        "il mio nome è Alex, email alex@example.com"
    );
    assert_eq!(history[1].role, Role::Assistant);
    assert_eq!(history[1].content, "ciao! come posso aiutare?");

    let sessions = memory2.list_sessions().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].name, "viaggio");
}

#[test]
fn wrong_password_import_fails() {
    let dir = tmpdir("wrong-pass");
    let memory = open_memory(&dir);
    let id = seed_session(&memory, "x");

    let out = dir.join("export.enclave");
    export_session(&memory, &id, &out, "corretta").unwrap();

    let dir2 = tmpdir("wrong-pass-target");
    let memory2 = open_memory(&dir2);
    let err = import_session(&memory2, &out, "sbagliata");
    assert!(err.is_err());
    // Nothing was created on failure.
    assert_eq!(memory2.list_sessions().unwrap().len(), 0);
}

#[test]
fn bad_magic_and_truncated_file_fail() {
    let dir = tmpdir("bad-magic");
    let memory = open_memory(&dir);
    let id = seed_session(&memory, "x");
    let out = dir.join("export.enclave");
    export_session(&memory, &id, &out, "p").unwrap();

    let dir2 = tmpdir("bad-magic-target");
    let memory2 = open_memory(&dir2);

    // Corrupt the magic header.
    let mut raw = std::fs::read(&out).unwrap();
    raw[0] = b'X';
    let corrupt = dir2.join("corrupt.enclave");
    std::fs::write(&corrupt, &raw).unwrap();
    assert!(import_session(&memory2, &corrupt, "p").is_err());

    // Truncated file.
    let truncated = dir2.join("truncated.enclave");
    std::fs::write(&truncated, &raw[..10]).unwrap();
    assert!(import_session(&memory2, &truncated, "p").is_err());
}

#[test]
fn export_nonexistent_session_errors() {
    let dir = tmpdir("missing");
    let memory = open_memory(&dir);
    let out = dir.join("export.enclave");
    let err = export_session(&memory, "no-such-id", &out, "p");
    assert!(err.is_err());
}

#[test]
fn salt_is_fresh_per_export() {
    let dir = tmpdir("fresh-salt");
    let memory = open_memory(&dir);
    let id = seed_session(&memory, "x");

    let a = dir.join("a.enclave");
    let b = dir.join("b.enclave");
    export_session(&memory, &id, &a, "same-password").unwrap();
    export_session(&memory, &id, &b, "same-password").unwrap();

    let ra = std::fs::read(&a).unwrap();
    let rb = std::fs::read(&b).unwrap();
    // Same content, same password, but different salt ⇒ different ciphertext.
    let sa = &ra[16..48];
    let sb = &rb[16..48];
    assert_ne!(sa, sb);
    assert_ne!(&ra[48..], &rb[48..]);

    // derive_key_pbkdf2 sanity: distinct salts must yield distinct keys.
    let ka = derive_key_pbkdf2("same-password", sa).unwrap();
    let kb = derive_key_pbkdf2("same-password", sb).unwrap();
    assert_ne!(ka, kb);
}
