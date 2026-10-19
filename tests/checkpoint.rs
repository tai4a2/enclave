//! Workspace checkpoints (local shadow-git snapshots + rewind).
//!
//! These tests need `git` on PATH; they skip (and pass) when it is missing.

use enclave::core::checkpoint::CheckpointStore;
use std::process::Command;

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn snapshot_list_and_rewind_roundtrip() {
    if !git_available() {
        eprintln!("skipping: git not found on PATH");
        return;
    }
    let ws = tempfile::tempdir().expect("workspace tempdir");
    let data = tempfile::tempdir().expect("data tempdir");
    let store = CheckpointStore::new(ws.path(), data.path());
    assert!(store.is_available());
    assert_eq!(store.count().unwrap(), 0);

    // First snapshot: a file with one line.
    std::fs::write(ws.path().join("a.txt"), "one\n").unwrap();
    let c1 = store.snapshot("before edit").unwrap().expect("snapshot 1");

    // Second snapshot: change the file.
    std::fs::write(ws.path().join("a.txt"), "one\ntwo\n").unwrap();
    let c2 = store
        .snapshot("add second line")
        .unwrap()
        .expect("snapshot 2");
    assert_ne!(c1, c2);
    assert_eq!(store.count().unwrap(), 2);

    // Listing is newest-first.
    let list = store.list(10).unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].id, c2);
    assert_eq!(list[0].label, "add second line");
    assert_eq!(list[1].id, c1);
    assert_eq!(list[1].label, "before edit");

    // Rewind to the first snapshot -> file content restored. History stays
    // linear and reversible: c1, c2 and the rewind commit (the safety snapshot
    // is a no-op here because the tree already matched HEAD).
    store.restore(&c1).unwrap();
    let restored = std::fs::read_to_string(ws.path().join("a.txt")).unwrap();
    assert_eq!(restored, "one\n");
    assert_eq!(store.count().unwrap(), 3); // c1, c2, rewind
    let after = store.list(10).unwrap();
    assert_eq!(after[0].label, format!("rewind to {c1}"));

    // diff_stat is non-empty for a snapshot that changed something.
    let stat = store.diff_stat(&c2).unwrap();
    assert!(stat.contains("a.txt"), "diff stat: {stat}");
}

#[test]
fn snapshot_without_changes_is_none() {
    if !git_available() {
        eprintln!("skipping: git not found on PATH");
        return;
    }
    let ws = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let store = CheckpointStore::new(ws.path(), data.path());

    std::fs::write(ws.path().join("a.txt"), "hello\n").unwrap();
    assert!(store.snapshot("first").unwrap().is_some());
    // Nothing changed since -> no new commit.
    assert!(store.snapshot("again").unwrap().is_none());
    assert_eq!(store.count().unwrap(), 1);
}

#[test]
fn restore_before_any_snapshot_fails() {
    if !git_available() {
        eprintln!("skipping: git not found on PATH");
        return;
    }
    let ws = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let store = CheckpointStore::new(ws.path(), data.path());
    // No snapshot yet: restoring an unknown id must error, not panic.
    assert!(store.restore("deadbee").is_err());
}
