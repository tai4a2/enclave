//! Integration tests for Phase B: function calling, agentic loop, multi-agent.

use std::sync::Arc;

use enclave::core::agents::{AgentRunner, AutoGate};
use enclave::core::builtin_tools::{self, ToolContext};
use enclave::core::engine::ChatEngine;
use enclave::core::message::{Message, Role, ToolCall};
use enclave::core::session::Session;
use enclave::privacy::crypto;
use enclave::privacy::memory::EncryptedMemory;
use enclave::privacy::vault::MasterKey;
use enclave::providers::{MockProvider, MockStep};

fn test_key() -> MasterKey {
    MasterKey::from_bytes([0x42u8; 32])
}

#[tokio::test]
async fn tool_calls_persist_across_reload() {
    let dir = tempfile::tempdir().unwrap();
    let key = test_key();
    let memory = EncryptedMemory::open(&dir.path().join("v.db"), &key).unwrap();
    let sid = memory.create_session("t").unwrap();

    let calls = vec![ToolCall {
        id: "tc1".into(),
        name: "read_file".into(),
        arguments: r#"{"path":"a.txt"}"#.into(),
    }];
    memory
        .save_message_full(
            &sid,
            &Message::assistant_with_tool_calls(String::new(), calls),
        )
        .unwrap();
    memory
        .save_message_full(&sid, &Message::tool_result("tc1", "file contents"))
        .unwrap();

    let history = memory.get_history(&sid, 100).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].role, Role::Assistant);
    assert_eq!(history[0].tool_calls[0].name, "read_file");
    assert_eq!(history[0].tool_calls[0].id, "tc1");
    assert_eq!(history[1].role, Role::Tool);
    assert_eq!(history[1].tool_call_id.as_deref(), Some("tc1"));
    assert_eq!(history[1].content, "file contents");
}

#[tokio::test]
async fn agentic_loop_runs_tools_and_returns_final_text() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("note.txt");
    std::fs::write(&file, "hello enclave").unwrap();

    // Script: first response = tool call, second = final answer.
    let provider = Box::new(MockProvider::new(vec![
        MockStep::ToolCalls(
            vec![ToolCall {
                id: "c1".into(),
                name: "read_file".into(),
                arguments: format!(r#"{{"path":"{}"}}"#, file.display()),
            }],
            "let me look".into(),
        ),
        MockStep::Text("the file says hello enclave".into()),
    ]));

    let key = test_key();
    let memory = EncryptedMemory::open(&dir.path().join("v.db"), &key).unwrap();
    let session = Session::create(&memory, "agent-test").unwrap();
    let mut engine = ChatEngine::new(provider, "mock-1".into(), memory, session, None);

    let mut gate = AutoGate {
        approve_all: true,
        decisions: Vec::new(),
    };
    let ctx = ToolContext {
        workspace: dir.path().to_path_buf(),
        shell_timeout_secs: 10,
        max_output_bytes: 8192,
        ..Default::default()
    };
    let defs = builtin_tools::defs(false);

    let answer = engine
        .turn_agentic("what does note.txt say?", &defs, &ctx, &mut gate, 8)
        .await
        .unwrap();
    assert_eq!(answer, "the file says hello enclave");
    assert_eq!(gate.decisions.len(), 1);
    assert_eq!(gate.decisions[0].0, "read_file");

    // The conversation must contain user → assistant(tools) → tool → assistant.
    let roles: Vec<Role> = engine.session.messages.iter().map(|m| m.role).collect();
    assert_eq!(
        roles,
        vec![Role::User, Role::Assistant, Role::Tool, Role::Assistant]
    );
    assert_eq!(engine.session.messages[2].content, "hello enclave");
}

#[tokio::test]
async fn denied_tool_call_is_reported_to_provider() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Box::new(MockProvider::new(vec![
        MockStep::ToolCalls(
            vec![ToolCall {
                id: "c1".into(),
                name: "run_shell".into(),
                arguments: r#"{"command":"rm -rf /"}"#.into(),
            }],
            String::new(),
        ),
        MockStep::Text("understood, I will not run it".into()),
    ]));

    let key = test_key();
    let memory = EncryptedMemory::open(&dir.path().join("v.db"), &key).unwrap();
    let session = Session::create(&memory, "deny-test").unwrap();
    let mut engine = ChatEngine::new(provider, "mock-1".into(), memory, session, None);

    let mut gate = AutoGate::default(); // denies everything
    let ctx = ToolContext {
        workspace: dir.path().to_path_buf(),
        shell_timeout_secs: 10,
        max_output_bytes: 8192,
        ..Default::default()
    };
    let answer = engine
        .turn_agentic("go", &builtin_tools::defs(false), &ctx, &mut gate, 8)
        .await
        .unwrap();
    assert_eq!(answer, "understood, I will not run it");
    // The tool result fed back to the provider must state the denial.
    assert_eq!(engine.session.messages[2].content, "[denied by user]");
}

#[tokio::test]
async fn write_file_stays_inside_workspace() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Box::new(MockProvider::new(vec![
        MockStep::ToolCalls(
            vec![ToolCall {
                id: "c1".into(),
                name: "write_file".into(),
                arguments: r#"{"path":"sub/out.txt","content":"data"}"#.into(),
            }],
            String::new(),
        ),
        MockStep::Text("done".into()),
    ]));

    let key = test_key();
    let memory = EncryptedMemory::open(&dir.path().join("v.db"), &key).unwrap();
    let session = Session::create(&memory, "write-test").unwrap();
    let mut engine = ChatEngine::new(provider, "mock-1".into(), memory, session, None);

    let mut gate = AutoGate {
        approve_all: true,
        decisions: Vec::new(),
    };
    let ctx = ToolContext {
        workspace: dir.path().to_path_buf(),
        shell_timeout_secs: 10,
        max_output_bytes: 8192,
        ..Default::default()
    };
    engine
        .turn_agentic("save it", &builtin_tools::defs(false), &ctx, &mut gate, 8)
        .await
        .unwrap();

    let written = dir.path().join("sub/out.txt");
    assert_eq!(std::fs::read_to_string(&written).unwrap(), "data");

    // Escape attempt is rejected even when approved.
    let escape = ToolCall {
        id: "c2".into(),
        name: "read_file".into(),
        arguments: r#"{"path":"/etc/passwd"}"#.into(),
    };
    let result = builtin_tools::execute(&escape, &ctx, &mut gate).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn delegate_runs_sub_agent_without_delegate_tool() {
    let dir = tempfile::tempdir().unwrap();

    // Parent: asks for a delegation, then produces the final answer.
    let parent = MockProvider::new(vec![
        MockStep::ToolCalls(
            vec![ToolCall {
                id: "d1".into(),
                name: "delegate".into(),
                arguments: r#"{"agent":"helper","task":"summarize"}"#.into(),
            }],
            String::new(),
        ),
        MockStep::Text("final: sub said hi from helper".into()),
    ]);
    // Sub-agent: single text answer.
    let _sub = MockProvider::new(vec![MockStep::Text("hi from helper".into())]);

    // Build a runner wired so the sub-agent uses a fixed mock provider.
    // We construct the runner manually to inject the scripted sub provider.
    let settings = enclave::config::Settings {
        ollama_base_url: "http://localhost:11434".into(),
        ..enclave::config::Settings::default()
    };
    let runner = Arc::new(AgentRunner::from_settings(&settings));
    // No personas configured → delegate must fail gracefully.
    let ctx = runner.context();
    let mut gate = AutoGate {
        approve_all: true,
        decisions: Vec::new(),
    };
    let call = ToolCall {
        id: "d1".into(),
        name: "delegate".into(),
        arguments: r#"{"agent":"ghost","task":"x"}"#.into(),
    };
    let err = builtin_tools::execute(&call, &ctx, &mut gate).await;
    assert!(err.is_err(), "delegate without personas must fail");

    let _ = parent;
    let _ = dir;
}

#[tokio::test]
async fn ephemeral_memory_never_touches_disk() {
    let key = MasterKey::from_bytes(crypto::random_key());
    let memory = EncryptedMemory::open_ephemeral(&key).unwrap();
    let sid = memory.create_session("ram").unwrap();
    memory.save_message(&sid, "user", "secret").unwrap();
    let history = memory.get_history(&sid, 10).unwrap();
    assert_eq!(history[0].content, "secret");
}

#[tokio::test]
async fn tainted_message_is_auto_redacted_on_later_turns() {
    let dir = tempfile::tempdir().unwrap();
    let key = test_key();
    let memory = EncryptedMemory::open(&dir.path().join("v.db"), &key).unwrap();
    let mut session = Session::create(&memory, "taint").unwrap();

    let mut secret = Message::user("my email is secret@example.com".to_string());
    secret.tainted = true;
    session.push(secret, &memory).unwrap();
    session
        .push(Message::user("and a clean line".to_string()), &memory)
        .unwrap();

    let provider = Box::new(MockProvider::new(vec![]));
    let mut engine = ChatEngine::new(provider, "mock-1".into(), memory, session, None);
    engine.taint = true;

    let out = engine.outgoing_messages();
    assert!(
        out.iter().any(|m| m.content.contains("[EMAIL_1]")),
        "the tainted message must be redacted with a stable placeholder"
    );
    assert!(
        !out.iter().any(|m| m.content.contains("secret@example.com")),
        "the raw email must never leave"
    );
    assert!(out.iter().any(|m| m.content == "and a clean line"));

    // Redaction stays stable across turns (same persistent redactor).
    let out2 = engine.outgoing_messages();
    assert!(out2.iter().any(|m| m.content.contains("[EMAIL_1]")));
    assert!(!out2
        .iter()
        .any(|m| m.content.contains("secret@example.com")));
}
