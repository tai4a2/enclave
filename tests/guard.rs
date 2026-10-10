//! Integration tests for the privacy guard (detection + stable redaction).

use enclave::core::message::Message;
use enclave::privacy::guard::{FindingKind, Redactor, redact_messages, scan};

#[test]
fn scan_finds_each_pii_kind() {
    let text = "Scrivi a mario.rossi@gmail.com, chiama +39 333 1234567, \
bonifica IT60X0542811101000000123456, CF RSSMRA85M01A562Z, \
card 4532015112830366, server 10.0.0.255, key sk-abcdef1234567890abcdef";
    let findings = scan(text);
    let kinds: Vec<FindingKind> = findings.iter().map(|f| f.kind).collect();
    for want in [
        FindingKind::Email,
        FindingKind::Phone,
        FindingKind::Iban,
        FindingKind::TaxId,
        FindingKind::Card,
        FindingKind::Ip,
        FindingKind::Secret,
    ] {
        assert!(kinds.contains(&want), "missing {want:?} in {kinds:?}");
    }
}

#[test]
fn scan_is_quiet_on_normal_text() {
    for t in [
        "spiegami come funziona rust",
        "il 25 dicembre è natale",
        "usa la versione 1.75 di tokio",
        "la somma è 12345678",
    ] {
        assert!(scan(t).is_empty(), "false positive on: {t}");
    }
}

#[test]
fn redaction_is_stable_across_calls() {
    let mut r = Redactor::new();
    let first = r.apply("email a@b.it e c@d.it");
    let second = r.apply("email a@b.it");
    assert_eq!(first.matches("[EMAIL_1]").count(), 1);
    assert!(first.contains("[EMAIL_2]"));
    assert!(second.contains("[EMAIL_1]"));
    assert!(!second.contains("[EMAIL_3]"));
}

#[test]
fn redaction_keeps_surrounding_text_intact() {
    let mut r = Redactor::new();
    let out = r.apply("ricordati di scrivere a segreto@example.com domani");
    assert_eq!(out, "ricordati di scrivere a [EMAIL_1] domani");
}

#[test]
fn redact_messages_leaves_system_prompt_alone() {
    let mut msgs = vec![
        Message::system("assistant with contact admin@enclave.dev".to_string()),
        Message::user("il mio IBAN è IT60X0542811101000000123456".to_string()),
    ];
    let mut r = Redactor::new();
    redact_messages(&mut msgs, &mut r, true);
    assert!(msgs[0].content.contains("admin@enclave.dev"));
    assert!(msgs[1].content.contains("[IBAN_1]"));
    assert!(!msgs[1].content.contains("IT60"));
}

#[test]
fn scan_handles_multiline_input() {
    let text = "prima riga senza dati\nseconda con test@example.org\nterza pulita";
    let f = scan(text);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].kind, FindingKind::Email);
    assert_eq!(f[0].text, "test@example.org");
}