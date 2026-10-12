use enclave::core::engine::ChatEngine;
use enclave::core::message::{Message, ToolCall};
use enclave::core::session::Session;
use enclave::privacy::vault::MasterKey;
use enclave::privacy::EncryptedMemory;
use enclave::providers::MockProvider;

fn key() -> MasterKey {
    MasterKey::from_bytes([0x42u8; 32])
}

fn engine() -> (ChatEngine, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let memory = EncryptedMemory::open(&dir.path().join("vault.db"), &key()).unwrap();
    let session = Session::create(&memory, "chat").unwrap();
    let engine = ChatEngine::new(
        Box::new(MockProvider::new(vec![])),
        "mock-1".to_string(),
        memory,
        session,
        None,
    );
    (engine, dir)
}

#[test]
fn canary_is_armed_injected_and_detected() {
    let (mut engine, _dir) = engine();
    assert!(engine.canary.is_none());
    engine.arm_canary();
    let canary = engine.canary.clone().expect("canary must be armed");

    let sys = engine.system_text().unwrap_or_default();
    assert!(sys.contains("UNTRUSTED DATA"), "system prompt must warn");
    assert!(sys.contains(&canary), "system prompt must contain the canary");

    assert!(!engine.check_injection("a perfectly normal reply"));
    assert!(engine.check_injection(&format!("here is the token: {canary}")));
}

#[test]
fn detected_canary_records_a_security_warning() {
    let (mut engine, _dir) = engine();
    engine.arm_canary();
    let canary = engine.canary.clone().unwrap();
    engine.check_injection(&format!("leaking {canary}"));
    let last = engine.session.messages.last().unwrap();
    assert_eq!(last.role, enclave::core::message::Role::System);
    assert!(last.content.contains("prompt-injection canary detected"));
}

#[test]
fn tool_call_after_untrusted_output_always_needs_approval() {
    use enclave::config::Action;
    let (mut engine, _dir) = engine();
    // Auto approves everything that is not explicitly denied...
    engine.permissions.auto = true;
    let call = ToolCall {
        id: "c1".to_string(),
        name: "run_shell".to_string(),
        arguments: r#"{"command":"echo hi"}"#.to_string(),
    };
    // ...but with no untrusted content pending, run_shell is auto-allowed.
    assert_eq!(engine.effective_action(&call), Action::Allow);

    // After a tool output (untrusted), a fresh approval is forced.
    engine
        .session
        .push(Message::tool_result("c0", "some file content"), &engine.memory)
        .unwrap();
    assert_eq!(engine.effective_action(&call), Action::Ask);
}

#[test]
fn injection_disabled_disables_the_downgrade_and_canary() {
    use enclave::config::Action;
    let (mut engine, _dir) = engine();
    engine.injection = false;
    engine.permissions.auto = true;
    engine.arm_canary();
    assert!(engine.canary.is_none(), "no canary when injection is off");
    assert!(!engine.system_text().unwrap_or_default().contains("UNTRUSTED DATA"));

    let call = ToolCall {
        id: "c1".to_string(),
        name: "run_shell".to_string(),
        arguments: r#"{"command":"echo hi"}"#.to_string(),
    };
    engine
        .session
        .push(Message::tool_result("c0", "untrusted"), &engine.memory)
        .unwrap();
    assert_eq!(engine.effective_action(&call), Action::Allow);
}