use enclave::config::{EgressAction, PolicySettings};
use enclave::core::engine::ChatEngine;
use enclave::core::session::Session;
use enclave::privacy::policy::Policy;
use enclave::privacy::vault::MasterKey;
use enclave::privacy::EncryptedMemory;
use enclave::providers::MockProvider;
use std::collections::BTreeMap;

fn key() -> MasterKey {
    MasterKey::from_bytes([0x42u8; 32])
}

fn policy(email: EgressAction) -> Policy {
    let mut rules = BTreeMap::new();
    rules.insert("email".to_string(), email);
    Policy::from_settings(&PolicySettings {
        enabled: true,
        default: EgressAction::Allow,
        rules,
    })
    .unwrap()
}

fn engine_with(policy: Option<Policy>) -> (ChatEngine, tempfile::TempDir) {
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
    engine.policy = policy;
    // Isolate the policy: disable taint so tainted messages are not auto-redacted.
    engine.taint = false;
    (engine, dir)
}

#[tokio::test]
async fn block_policy_refuses_to_send_sensitive_data() {
    let (mut engine, _dir) = engine_with(Some(policy(EgressAction::Block)));
    let res = engine
        .stream_reply_with("write to a@b.com", Vec::new())
        .await;
    let err = res.err().expect("block policy must refuse the turn");
    assert!(
        err.to_string().contains("egress blocked by policy"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn redact_policy_activates_the_redactor() {
    let (mut engine, _dir) = engine_with(Some(policy(EgressAction::Redact)));
    let res = engine
        .stream_reply_with("write to a@b.com", Vec::new())
        .await;
    assert!(res.is_ok());
    assert!(engine.redactor.is_some());
}

#[tokio::test]
async fn allow_policy_sends_without_redaction() {
    let (mut engine, _dir) = engine_with(Some(policy(EgressAction::Allow)));
    let res = engine
        .stream_reply_with("write to a@b.com", Vec::new())
        .await;
    assert!(res.is_ok());
    assert!(engine.redactor.is_none());
}

#[tokio::test]
async fn local_provider_is_never_restricted_by_policy() {
    let dir = tempfile::tempdir().unwrap();
    let memory = EncryptedMemory::open(&dir.path().join("vault.db"), &key()).unwrap();
    let session = Session::create(&memory, "chat").unwrap();
    // Point Ollama at a dead port: the turn fails on transport, never on policy.
    let mut engine = ChatEngine::lazy(
        "ollama",
        "http://127.0.0.1:1".to_string(),
        None,
        memory,
        session,
        None,
    )
    .unwrap();
    engine.policy = Some(policy(EgressAction::Block));
    if let Err(e) = engine.stream_reply_with("write to a@b.com", Vec::new()).await {
        assert!(
            !e.to_string().contains("egress blocked by policy"),
            "local provider must not be blocked: {e}"
        );
    }
}