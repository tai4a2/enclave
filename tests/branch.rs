use enclave::core::message::Message;
use enclave::core::session::Session;
use enclave::privacy::{EncryptedMemory, MasterKey};
use tempfile::tempdir;

fn memory() -> (tempfile::TempDir, EncryptedMemory) {
    let dir = tempdir().unwrap();
    let key = MasterKey::from_bytes([0x42u8; 32]);
    let memory = EncryptedMemory::open(&dir.path().join("vault.db"), &key).unwrap();
    (dir, memory)
}

#[test]
fn fork_copies_prefix_and_records_parent() {
    let (_dir, memory) = memory();
    let mut root = Session::create(&memory, "root").unwrap();
    for i in 0..4 {
        root.add_user(&memory, &format!("msg {i}")).unwrap();
    }

    let child = Session::fork(&memory, &root.id, "root~1", 2).unwrap();
    assert_eq!(child.messages.len(), 2);
    assert_eq!(child.messages[0].content, "msg 0");
    assert_eq!(child.messages[1].content, "msg 1");

    let nodes = memory.branch_nodes().unwrap();
    let node = nodes.iter().find(|n| n.id == child.id).unwrap();
    assert_eq!(node.parent.as_deref(), Some(root.id.as_str()));
    assert_eq!(node.from, 2);
    assert_eq!(node.message_count, 2);
}

#[test]
fn fork_from_head_copies_everything() {
    let (_dir, memory) = memory();
    let mut root = Session::create(&memory, "root").unwrap();
    root.add_user(&memory, "a").unwrap();
    root.add_user(&memory, "b").unwrap();

    let child = Session::fork(&memory, &root.id, "copy", root.messages.len()).unwrap();
    assert_eq!(child.messages.len(), 2);
    assert_eq!(child.name, "copy");
}

#[test]
fn branches_are_independent() {
    let (_dir, memory) = memory();
    let mut root = Session::create(&memory, "root").unwrap();
    root.add_user(&memory, "shared").unwrap();

    let mut child = Session::fork(&memory, &root.id, "alt", 1).unwrap();
    child.add_user(&memory, "only in child").unwrap();

    let reloaded_root = Session::load(&memory, &root.id).unwrap();
    assert_eq!(reloaded_root.messages.len(), 1);
    let reloaded_child = Session::load(&memory, &child.id).unwrap();
    assert_eq!(reloaded_child.messages.len(), 2);
}

#[test]
fn branch_nodes_include_roots_without_parent() {
    let (_dir, memory) = memory();
    let root = Session::create(&memory, "standalone").unwrap();
    let nodes = memory.branch_nodes().unwrap();
    let node = nodes.iter().find(|n| n.id == root.id).unwrap();
    assert_eq!(node.parent, None);
    assert_eq!(node.from, -1);
}

#[test]
fn fork_handles_empty_parent() {
    let (_dir, memory) = memory();
    let root = Session::create(&memory, "empty").unwrap();
    let child = Session::fork(&memory, &root.id, "still-empty", 5).unwrap();
    assert!(child.messages.is_empty());
    let nodes = memory.branch_nodes().unwrap();
    let node = nodes.iter().find(|n| n.id == child.id).unwrap();
    assert_eq!(node.from, 0);
}

#[test]
fn fork_preserves_tool_metadata() {
    let (_dir, memory) = memory();
    let mut root = Session::create(&memory, "root").unwrap();
    root.push(Message::assistant_with_tool_calls("thinking", vec![]), &memory)
        .unwrap();

    let child = Session::fork(&memory, &root.id, "alt", 1).unwrap();
    assert_eq!(child.messages.len(), 1);
    assert_eq!(child.messages[0].role, enclave::core::message::Role::Assistant);
}
