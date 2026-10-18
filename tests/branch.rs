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
fn merge_appends_only_new_messages() {
    let (_dir, memory) = memory();
    let mut root = Session::create(&memory, "root").unwrap();
    root.add_user(&memory, "a").unwrap();
    root.add_user(&memory, "b").unwrap();

    let mut left = Session::fork(&memory, &root.id, "left", 2).unwrap();
    left.add_user(&memory, "left-only").unwrap();
    let mut right = Session::fork(&memory, &root.id, "right", 2).unwrap();
    right.add_user(&memory, "right-only").unwrap();

    let added = left.merge_from(&memory, &right.id).unwrap();
    assert_eq!(added, 1);
    assert_eq!(left.messages.len(), 4);
    assert_eq!(left.messages[3].content, "right-only");
    // right is untouched by the merge.
    assert_eq!(Session::load(&memory, &right.id).unwrap().messages.len(), 3);
}

#[test]
fn merge_of_identical_branches_adds_nothing() {
    let (_dir, memory) = memory();
    let mut root = Session::create(&memory, "root").unwrap();
    root.add_user(&memory, "x").unwrap();
    let child = Session::fork(&memory, &root.id, "copy", 1).unwrap();
    let mut target = Session::load(&memory, &child.id).unwrap();
    assert_eq!(target.merge_from(&memory, &root.id).unwrap(), 0);
    assert_eq!(target.messages.len(), 1);
}

#[test]
fn fork_preserves_tool_metadata() {
    let (_dir, memory) = memory();
    let mut root = Session::create(&memory, "root").unwrap();
    root.push(
        Message::assistant_with_tool_calls("thinking", vec![]),
        &memory,
    )
    .unwrap();

    let child = Session::fork(&memory, &root.id, "alt", 1).unwrap();
    assert_eq!(child.messages.len(), 1);
    assert_eq!(
        child.messages[0].role,
        enclave::core::message::Role::Assistant
    );
}

#[test]
fn egress_provenance_filters_by_session() {
    let (_dir, memory) = memory();
    let a = Session::create(&memory, "a").unwrap();
    let b = Session::create(&memory, "b").unwrap();
    memory
        .add_egress(Some(&a.id), "openrouter", "m1", b"payload-a", "", "")
        .unwrap();
    memory
        .add_egress(Some(&b.id), "openai", "m2", b"payload-b", "", "")
        .unwrap();

    let pa = memory.list_egress_for_session(&a.id, 50).unwrap();
    assert_eq!(pa.len(), 1);
    assert_eq!(pa[0].provider, "openrouter");
    let pb = memory.list_egress_for_session(&b.id, 50).unwrap();
    assert_eq!(pb.len(), 1);
    assert_eq!(pb[0].provider, "openai");
}
