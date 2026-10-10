//! Integration tests for the tool-execution layer (proposals + sandbox).

use std::time::Duration;

use enclave::core::tools::{extract_proposals, run};

#[test]
fn proposals_are_extracted_from_realistic_replies() {
    let reply = "Ecco come controllare la versione:\n\n\
```bash\nsw_vers\n```\n\n\
E per lo stato di git:\n\n\
```bash\ngit status --short\ngit log --oneline -3\n```\n\n\
E questo invece è codice Python:\n\n\
```python\nprint('not a proposal')\n```\n";
    let p = extract_proposals(reply);
    assert_eq!(p.len(), 2);
    assert_eq!(p[0].command, "sw_vers");
    assert_eq!(p[1].command, "git status --short\ngit log --oneline -3");
}

#[test]
fn unclosed_fence_is_never_a_proposal() {
    // Streaming may produce a partial reply; a half-open fence must not run.
    let reply = "esegui:\n```bash\nrm -rf /\n";
    assert!(extract_proposals(reply).is_empty());
}

#[test]
fn empty_blocks_are_ignored() {
    assert!(extract_proposals("```bash\n```\n```sh\n   \n```").is_empty());
}

#[tokio::test]
async fn run_simple_command() {
    let out = run("echo enclave-tools", Duration::from_secs(10), 8192)
        .await
        .unwrap();
    assert_eq!(out.stdout.trim(), "enclave-tools");
    assert_eq!(out.code, Some(0));
    assert!(!out.timed_out && !out.truncated);
}

#[tokio::test]
async fn run_captures_failure() {
    let out = run("ls /definitely/not/a/path", Duration::from_secs(10), 8192)
        .await
        .unwrap();
    assert_ne!(out.code, Some(0));
    assert!(!out.stderr.is_empty());
}

#[tokio::test]
async fn timeout_kills_runaway_command() {
    let out = run("sleep 60", Duration::from_millis(500), 8192)
        .await
        .unwrap();
    assert!(out.timed_out);
    assert_eq!(out.code, None);
}

#[tokio::test]
async fn output_cap_is_enforced() {
    let out = run("yes ENCLAVE | head -c 50000", Duration::from_secs(15), 4096)
        .await
        .unwrap();
    assert!(out.truncated);
    assert!(out.stdout.len() <= 4096 + 4);
}

#[test]
fn tool_message_roundtrip_shape() {
    let text = "[tool] $ echo hi\nhello\n[exit code: 0]\n[/tool]";
    // The persisted form must be clearly delimited and self-describing.
    assert!(text.starts_with("[tool] $ "));
    assert!(text.ends_with("[/tool]"));
    assert!(extract_proposals(text).is_empty()); // tool output must not be re-proposed
}