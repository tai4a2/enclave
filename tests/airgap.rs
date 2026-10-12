use enclave::core::engine::ChatEngine;
use enclave::core::session::Session;
use enclave::privacy::vault::MasterKey;
use enclave::privacy::EncryptedMemory;
use enclave::providers::MockProvider;

fn key() -> MasterKey {
    MasterKey::from_bytes([0x42u8; 32])
}

fn remote_engine() -> (ChatEngine, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let memory = EncryptedMemory::open(&dir.path().join("vault.db"), &key()).unwrap();
    let session = Session::create(&memory, "chat").unwrap();
    let mut engine = ChatEngine::new(
        Box::new(MockProvider::new(vec![])),
        "mock-1".to_string(),
        memory,
        session,
        None,
    );
    // Mock is treated as a remote provider (requires an API key).
    engine.taint = false;
    (engine, dir)
}

#[tokio::test]
async fn air_gap_refuses_remote_provider() {
    let (mut engine, _dir) = remote_engine();
    engine.air_gap = true;
    let err = engine
        .stream_reply_with("hello", Vec::new())
        .await
        .err()
        .expect("air-gap must refuse a remote provider");
    assert!(
        err.to_string().contains("air-gap"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn air_gap_off_allows_remote_provider() {
    let (mut engine, _dir) = remote_engine();
    engine.air_gap = false;
    assert!(engine.stream_reply_with("hello", Vec::new()).await.is_ok());
}

#[tokio::test]
async fn air_gap_blocks_utility_calls() {
    let (mut engine, _dir) = remote_engine();
    engine.air_gap = true;
    let err = engine
        .one_shot("summarise this")
        .await
        .expect_err("air-gap must refuse utility calls too");
    assert!(
        err.to_string().contains("air-gap"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn local_provider_is_never_air_gapped() {
    let dir = tempfile::tempdir().unwrap();
    let memory = EncryptedMemory::open(&dir.path().join("vault.db"), &key()).unwrap();
    let session = Session::create(&memory, "chat").unwrap();
    // Point Ollama at a dead port: the turn fails on transport, never on air-gap.
    let mut engine = ChatEngine::lazy(
        "ollama",
        "http://127.0.0.1:1".to_string(),
        None,
        memory,
        session,
        None,
    )
    .unwrap();
    engine.air_gap = true;
    if let Err(e) = engine.stream_reply_with("hello", Vec::new()).await {
        assert!(
            !e.to_string().contains("air-gap"),
            "local provider must not be air-gapped: {e}"
        );
    }
}