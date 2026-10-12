use enclave::core::engine::ChatEngine;
use enclave::core::session::Session;
use enclave::privacy::vault::MasterKey;
use enclave::privacy::EncryptedMemory;
use enclave::providers::{MockProvider, MockStep};
use futures::StreamExt;

fn key() -> MasterKey {
    MasterKey::from_bytes([0x42u8; 32])
}

/// Build an engine whose remote provider answers "remote reply" and whose
/// preset local provider answers "local reply", so a test can tell which one
/// served the turn.
fn engine(route_sensitive: bool) -> (ChatEngine, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let memory = EncryptedMemory::open(&dir.path().join("vault.db"), &key()).unwrap();
    let session = Session::create(&memory, "chat").unwrap();
    let mut engine = ChatEngine::new(
        Box::new(MockProvider::new(vec![MockStep::Text(
            "remote reply".to_string(),
        )])),
        "remote-model".to_string(),
        memory,
        session,
        None,
    );
    engine.taint = false;
    engine.route_sensitive = route_sensitive;
    engine.local_provider = Some(Box::new(MockProvider::new(vec![MockStep::Text(
        "local reply".to_string(),
    )])));
    (engine, dir)
}

async fn collect(engine: &mut ChatEngine, text: &str) -> String {
    let mut stream = engine.stream_reply_with(text, Vec::new()).await.unwrap();
    let mut out = String::new();
    while let Some(chunk) = stream.next().await {
        out.push_str(&chunk.unwrap());
    }
    out
}

#[tokio::test]
async fn sensitive_turn_is_routed_to_local() {
    let (mut engine, _dir) = engine(true);
    let reply = collect(&mut engine, "my email is a@b.com").await;
    assert_eq!(reply, "local reply");
}

#[tokio::test]
async fn non_sensitive_turn_stays_remote() {
    let (mut engine, _dir) = engine(true);
    let reply = collect(&mut engine, "hello world").await;
    assert_eq!(reply, "remote reply");
}

#[tokio::test]
async fn routing_disabled_keeps_remote_for_sensitive() {
    let (mut engine, _dir) = engine(false);
    let reply = collect(&mut engine, "my email is a@b.com").await;
    assert_eq!(reply, "remote reply");
}