//! Integration tests for the local Supermemory (encrypted persistent memory).

use enclave::core::engine::ChatEngine;
use enclave::core::session::Session;
use enclave::privacy::memory::EncryptedMemory;
use enclave::privacy::vault::MasterKey;
use enclave::providers::MockProvider;

fn test_key() -> MasterKey {
    MasterKey::from_bytes([0x42u8; 32])
}

#[test]
fn memories_crud_and_search() {
    let dir = tempfile::tempdir().unwrap();
    let memory = EncryptedMemory::open(&dir.path().join("v.db"), &test_key()).unwrap();

    let id1 = memory
        .add_memory("prefers dark mode", "ui", "note", None, false)
        .unwrap();
    let id2 = memory
        .add_memory("works on project enclave", "work", "note", None, true)
        .unwrap();
    assert_eq!(memory.memory_count().unwrap(), 2);
    assert_eq!(memory.list_memories(50).unwrap().len(), 2);

    let hits = memory.search_memories("dark", 50).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, id1);

    let tag_hits = memory.search_memories("work", 50).unwrap();
    assert!(tag_hits.iter().any(|m| m.id == id2));

    assert!(memory.set_memory_pinned(&id1, true).unwrap());
    assert!(memory.get_memory(&id1).unwrap().unwrap().pinned);
    assert!(memory.set_memory_pinned(&id1, false).unwrap());
    assert!(!memory.get_memory(&id1).unwrap().unwrap().pinned);

    assert!(memory.update_memory(&id1, "prefers light mode", "ui").unwrap());
    assert_eq!(
        memory.get_memory(&id1).unwrap().unwrap().text,
        "prefers light mode"
    );

    assert!(memory.delete_memory(&id2).unwrap());
    assert_eq!(memory.memory_count().unwrap(), 1);

    // A LIKE wildcard must be treated literally, not as a pattern.
    assert!(memory.search_memories("%", 50).unwrap().is_empty());
}

#[test]
fn local_only_memories_are_not_injectable() {
    let dir = tempfile::tempdir().unwrap();
    let memory = EncryptedMemory::open(&dir.path().join("v.db"), &test_key()).unwrap();

    memory
        .add_memory("public fact", "x", "note", None, false)
        .unwrap();
    memory
        .add_memory("never leaves this device", "x", "note", None, true)
        .unwrap();

    let injectable = memory.injectable_memories(50).unwrap();
    assert_eq!(injectable.len(), 1);
    assert!(!injectable[0].local_only);
    assert_eq!(injectable[0].text, "public fact");

    // Both are visible in the full listing.
    assert_eq!(memory.list_memories(50).unwrap().len(), 2);
}

#[test]
fn memories_are_injected_into_the_system_prompt() {
    let dir = tempfile::tempdir().unwrap();
    let memory = EncryptedMemory::open(&dir.path().join("v.db"), &test_key()).unwrap();
    memory
        .add_memory("the user's name is Mauro", "identity", "note", None, false)
        .unwrap();
    memory
        .add_memory("secret local note", "x", "note", None, true)
        .unwrap();

    let sid = memory.create_session("t").unwrap();
    let session = Session::load(&memory, &sid).unwrap();
    let provider = Box::new(MockProvider::new(vec![]));
    let mut engine = ChatEngine::new(provider, "mock".into(), memory, session, None);
    engine.reload_memories().unwrap();

    let text = engine.system_text().unwrap();
    assert!(text.contains("Memory"), "system prompt should have a Memory section");
    assert!(text.contains("the user's name is Mauro"));
    assert!(
        !text.contains("secret local note"),
        "local-only memories must never be injected"
    );
}

#[test]
fn context_report_shows_composition_and_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let memory = EncryptedMemory::open(&dir.path().join("v.db"), &test_key()).unwrap();
    memory
        .add_memory("the user prefers Rust", "pref", "note", None, false)
        .unwrap();
    memory
        .add_decision(None, "Use SQLCipher", "encrypt the vault at rest", "security", "accepted")
        .unwrap();

    let sid = memory.create_session("t").unwrap();
    let session = Session::load(&memory, &sid).unwrap();
    let provider = Box::new(MockProvider::new(vec![]));
    let mut engine = ChatEngine::new(provider, "mock".into(), memory, session, None);
    engine.reload_memories().unwrap();
    engine.reload_decisions().unwrap();

    let r = engine.context_report();
    let labels: Vec<&str> = r.parts.iter().map(|p| p.label.as_str()).collect();
    assert!(labels.contains(&"memory"));
    assert!(labels.contains(&"decisions"));
    assert!(r.parts.iter().all(|p| p.chars > 0));
    assert_eq!(r.messages, 0);
    assert!(r.total_chars >= r.parts.iter().map(|p| p.chars).sum::<usize>());
    assert!(r.redactions.is_empty());
    assert!(!r.taint);
    // Token estimate and (absent) budget.
    assert_eq!(r.est_tokens, r.total_chars.div_ceil(4));
    assert!(r.limit_tokens.is_none());
    assert_eq!(r.warn_pct, 80);

    // With a budget configured the report exposes it.
    engine.context_budget = Some(100);
    engine.context_warn_pct = 75;
    let r = engine.context_report();
    assert_eq!(r.limit_tokens, Some(100));
    assert_eq!(r.warn_pct, 75);
}
