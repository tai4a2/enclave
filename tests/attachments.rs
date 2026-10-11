//! Attachments: encrypted persistence and privacy-guard behaviour.

use enclave::core::attachment::{Attachment, AttachmentKind};
use enclave::core::message::Message;
use enclave::privacy::guard::{self, Redactor};
use enclave::privacy::memory::EncryptedMemory;
use enclave::privacy::vault::MasterKey;

fn key() -> MasterKey {
    MasterKey::from_bytes([0x42u8; 32])
}

fn image() -> Attachment {
    Attachment {
        kind: AttachmentKind::Image,
        name: "a.png".into(),
        mime: "image/png".into(),
        data: "QUJD".into(),
    }
}

fn text(body: &str) -> Attachment {
    Attachment {
        kind: AttachmentKind::Text,
        name: "notes.txt".into(),
        mime: "text/plain".into(),
        data: body.into(),
    }
}

#[test]
fn attachments_survive_store_and_reload() {
    let mem = EncryptedMemory::open_ephemeral(&key()).unwrap();
    let sid = mem.create_session("with-files").unwrap();
    let msg = Message::user_with_attachments("guarda", vec![image(), text("ciao")]);
    mem.save_message_full(&sid, &msg).unwrap();

    let hist = mem.get_history(&sid, 10).unwrap();
    assert_eq!(hist.len(), 1);
    assert_eq!(hist[0].attachments.len(), 2);
    assert_eq!(hist[0].attachments[0].kind, AttachmentKind::Image);
    assert_eq!(hist[0].attachments[0].data, "QUJD");
    assert_eq!(hist[0].attachments[1].text_body(), Some("ciao"));
}

#[test]
fn plain_messages_still_have_no_attachments() {
    let mem = EncryptedMemory::open_ephemeral(&key()).unwrap();
    let sid = mem.create_session("plain").unwrap();
    mem.save_message_full(&sid, &Message::user("hi")).unwrap();
    let hist = mem.get_history(&sid, 10).unwrap();
    assert!(hist[0].attachments.is_empty());
}

#[test]
fn guard_redacts_text_but_not_image_attachments() {
    let mut r = Redactor::new();
    let mut msgs = vec![Message::user_with_attachments(
        "please review",
        vec![image(), text("email me at mario.rossi@gmail.com")],
    )];
    guard::redact_messages(&mut msgs, &mut r, false);
    assert!(msgs[0].attachments[1].data.contains("[EMAIL_1]"));
    assert!(!msgs[0].attachments[1].data.contains('@'));
    // The image bytes are opaque and must be left untouched.
    assert_eq!(msgs[0].attachments[0].data, "QUJD");
}
