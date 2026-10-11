//! Privacy Guard: automatic detection of sensitive data before it leaves the machine.
//!
//! Every user message is scanned for personally identifiable information
//! (emails, phone numbers, IBANs, Italian tax IDs, card numbers, API
//! secrets, IP addresses) **before** it is sent to a cloud provider. The
//! user can then send it as-is, replace each finding with a stable
//! placeholder (`[EMAIL_1]`, …), or refuse to send at all.
//!
//! Redaction is applied at request time to the whole outgoing history, so
//! what stays on disk (encrypted) is the original text while the provider
//! only ever sees placeholders. Placeholder assignment is deterministic
//! (first appearance order) and stable across turns because a single
//! `Redactor` instance lives for the whole chat run.

use std::collections::HashMap;

use regex::Regex;

use crate::core::attachment::AttachmentKind;
use crate::core::message::Message;

/// Category of a detected sensitive item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingKind {
    Email,
    Phone,
    Iban,
    TaxId,
    Card,
    Secret,
    Ip,
}

impl FindingKind {
    /// Human-readable label used in previews.
    pub fn label(self) -> &'static str {
        match self {
            FindingKind::Email => "email",
            FindingKind::Phone => "phone",
            FindingKind::Iban => "IBAN",
            FindingKind::TaxId => "tax id",
            FindingKind::Card => "card number",
            FindingKind::Secret => "API secret",
            FindingKind::Ip => "IP address",
        }
    }

    /// Prefix of the placeholder generated for this kind.
    fn placeholder(self) -> &'static str {
        match self {
            FindingKind::Email => "EMAIL",
            FindingKind::Phone => "PHONE",
            FindingKind::Iban => "IBAN",
            FindingKind::TaxId => "TAX_ID",
            FindingKind::Card => "CARD",
            FindingKind::Secret => "SECRET",
            FindingKind::Ip => "IP",
        }
    }
}

/// One detected sensitive item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: FindingKind,
    pub text: String,
    /// Byte offsets into the scanned text.
    pub start: usize,
    pub end: usize,
}

struct Pattern {
    kind: FindingKind,
    re: Regex,
    /// Extra validation applied to each candidate match.
    valid: fn(&str) -> bool,
}

fn luhn_ok(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter(|c| c.is_ascii_digit()).map(|c| c as u32 - '0' as u32).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let mut sum = 0;
    let mut double = false;
    for d in digits.iter().rev() {
        let mut v = *d;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum % 10 == 0
}

fn ip_ok(s: &str) -> bool {
    s.split('.').all(|o| o.parse::<u16>().map(|v| v <= 255).unwrap_or(false))
}

fn phone_ok(s: &str) -> bool {
    let digits = s.chars().filter(|c| c.is_ascii_digit()).count();
    (8..=15).contains(&digits)
}

/// Compiled detection patterns (lazily built once).
fn patterns() -> &'static Vec<Pattern> {
    use std::sync::OnceLock;
    static PATTERNS: OnceLock<Vec<Pattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            Pattern {
                kind: FindingKind::Email,
                re: Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap(),
                valid: |_| true,
            },
            Pattern {
                kind: FindingKind::Iban,
                re: Regex::new(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{2,4}){3,8}\b").unwrap(),
                valid: |_| true,
            },
            Pattern {
                kind: FindingKind::TaxId,
                re: Regex::new(r"\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b").unwrap(),
                valid: |_| true,
            },
            Pattern {
                kind: FindingKind::Card,
                re: Regex::new(r"\b(?:\d[ \-]?){13,19}\b").unwrap(),
                valid: luhn_ok,
            },
            Pattern {
                kind: FindingKind::Secret,
                re: Regex::new(
                    r"\b(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9\-]{10,}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,})\b",
                )
                .unwrap(),
                valid: |_| true,
            },
            Pattern {
                kind: FindingKind::Ip,
                re: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
                valid: ip_ok,
            },
            Pattern {
                kind: FindingKind::Phone,
                // Italian mobile (+39 3xx), Italian landline (0xx), generic international.
                re: Regex::new(
                    r"(?:\+39[\s.\-]?)?3\d{2}[\s.\-]?\d{3}[\s.\-]?\d{4}\b|\b0\d{1,3}[\s.\-]?\d{5,8}\b|\+\d{1,3}[\s.\-]?(?:\d[\s.\-]?){7,11}\d",
                )
                .unwrap(),
                valid: phone_ok,
            },
        ]
    })
}

/// Scan a text for sensitive data. Findings are returned in order of
/// appearance, with overlaps removed (first/longest match wins).
pub fn scan(text: &str) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    for p in patterns() {
        for m in p.re.find_iter(text) {
            let candidate = m.as_str();
            if !(p.valid)(candidate) {
                continue;
            }
            findings.push(Finding {
                kind: p.kind,
                text: candidate.to_string(),
                start: m.start(),
                end: m.end(),
            });
        }
    }
    // Remove overlaps: sort by (start, longest first), keep non-overlapping.
    findings.sort_by(|a, b| a.start.cmp(&b.start).then((b.end - b.start).cmp(&(a.end - a.start))));
    let mut kept: Vec<Finding> = Vec::new();
    let mut last_end = 0usize;
    for f in findings {
        if f.start >= last_end {
            last_end = f.end;
            kept.push(f);
        }
    }
    kept
}

/// Stateful placeholder redactor. One instance per chat run keeps
/// placeholder numbering stable across turns.
#[derive(Default)]
pub struct Redactor {
    /// original text -> placeholder
    map: HashMap<String, String>,
    counters: HashMap<&'static str, usize>,
}

impl Redactor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Placeholder for `text`, assigning the next index on first sight.
    fn placeholder_for(&mut self, kind: FindingKind, text: &str) -> String {
        if let Some(p) = self.map.get(text) {
            return p.clone();
        }
        let c = self.counters.entry(kind.placeholder()).or_insert(0);
        *c += 1;
        let ph = format!("[{}_{}]", kind.placeholder(), c);
        self.map.insert(text.to_string(), ph.clone());
        ph
    }

    /// Replace every detected finding in `text` with its placeholder.
    pub fn apply(&mut self, text: &str) -> String {
        let findings = scan(text);
        if findings.is_empty() {
            return text.to_string();
        }
        let mut placeholders = Vec::with_capacity(findings.len());
        for f in &findings {
            placeholders.push(self.placeholder_for(f.kind, &f.text));
        }
        // Replace in reverse order so earlier offsets stay valid.
        let mut out = text.to_string();
        for (f, ph) in findings.iter().zip(placeholders.iter()).rev() {
            out.replace_range(f.start..f.end, ph);
        }
        out
    }
}

/// Redact a full outgoing request in place. The system prompt (Enclave's
/// own, first message when present) is never touched.
pub fn redact_messages(messages: &mut [Message], redactor: &mut Redactor, skip_first: bool) {
    for m in messages.iter_mut().skip(usize::from(skip_first)) {
        m.content = redactor.apply(&m.content);
        // Text attachments travel to the provider too: redact them as well.
        for a in m.attachments.iter_mut() {
            if a.kind == AttachmentKind::Text {
                a.data = redactor.apply(&a.data);
            }
        }
    }
}

/// Convenience: true when the text contains at least one finding.
pub fn has_sensitive_data(text: &str) -> bool {
    !scan(text).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_pii_kinds() {
        let text = "email mario.rossi@gmail.com, tel +39 333 1234567, IBAN IT60X0542811101000000123456, CF RSSMRA85M01A562Z, IP 192.168.1.42, key sk-abcdef1234567890abcdef";
        let f = scan(text);
        let kinds: Vec<FindingKind> = f.iter().map(|x| x.kind).collect();
        for want in [
            FindingKind::Email,
            FindingKind::Phone,
            FindingKind::Iban,
            FindingKind::TaxId,
            FindingKind::Ip,
            FindingKind::Secret,
        ] {
            assert!(kinds.contains(&want), "missing {want:?} in {kinds:?}");
        }
    }

    #[test]
    fn no_findings_on_innocuous_text() {
        assert!(scan("ciao, come stai? Che tempo fa oggi?").is_empty());
        assert!(scan("il progetto usa rust 1.75 e tokio").is_empty());
    }

    #[test]
    fn card_requires_luhn() {
        assert!(scan("card 4532015112830366").iter().any(|f| f.kind == FindingKind::Card));
        assert!(scan("number 4532015112830367").is_empty()); // Luhn fails
        assert!(scan("year 202312345678901").is_empty());
    }

    #[test]
    fn redact_replaces_with_stable_placeholders() {
        let mut r = Redactor::new();
        let out = r.apply("send it to mario.rossi@gmail.com and anna.bianchi@libero.it, copy mario.rossi@gmail.com");
        assert!(out.contains("[EMAIL_1]"));
        assert!(out.contains("[EMAIL_2]"));
        assert_eq!(out.matches("[EMAIL_1]").count(), 2);
        assert!(!out.contains('@'));
        // Stability: same input again yields identical output.
        let out2 = r.apply("send it to mario.rossi@gmail.com and anna.bianchi@libero.it");
        assert!(out2.contains("[EMAIL_1]") && out2.contains("[EMAIL_2]"));
    }

    #[test]
    fn redact_mixed_kinds_and_preserves_text() {
        let mut r = Redactor::new();
        let out = r.apply("write mario@x.it or call +39 333 1234567 about IT60X0542811101000000123456");
        assert!(out.starts_with("write "));
        assert!(out.contains("[EMAIL_1]"));
        assert!(out.contains("[PHONE_1]"));
        assert!(out.contains("[IBAN_1]"));
        assert!(out.ends_with(" about [IBAN_1]"));
    }

    #[test]
    fn redact_messages_skips_system_prompt() {
        let mut msgs = vec![
            Message::system("you are a helpful assistant, contact a@b.it".to_string()),
            Message::user("my email is segreto@example.com".to_string()),
        ];
        let mut r = Redactor::new();
        redact_messages(&mut msgs, &mut r, true);
        assert!(msgs[0].content.contains("a@b.it")); // system untouched
        assert!(msgs[1].content.contains("[EMAIL_1]"));
    }

    #[test]
    fn ip_validation_rejects_bad_octets() {
        assert!(scan("host 999.888.1.1").is_empty());
        assert!(scan("host 10.0.0.255").iter().any(|f| f.kind == FindingKind::Ip));
    }
}