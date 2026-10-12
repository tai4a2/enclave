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
    /// A person name (local heuristic / custom list).
    Name,
    /// An organisation name (local heuristic).
    Organization,
    /// A postal address (local heuristic).
    Address,
    /// A term from the user's local entity list.
    Custom,
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
            FindingKind::Name => "name",
            FindingKind::Organization => "organization",
            FindingKind::Address => "address",
            FindingKind::Custom => "custom term",
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
            FindingKind::Name => "NAME",
            FindingKind::Organization => "ORG",
            FindingKind::Address => "ADDRESS",
            FindingKind::Custom => "CUSTOM",
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

/// Whether the local NER heuristics are enabled (set from `[guard] ner`).
static NER_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// User-declared sensitive terms (local only, never sent anywhere).
static CUSTOM_ENTITIES: std::sync::RwLock<Vec<String>> = std::sync::RwLock::new(Vec::new());

/// Enable/disable the local NER heuristics (names, organisations, addresses).
pub fn set_ner(on: bool) {
    NER_ENABLED.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Replace the local entity list (`[guard] entities`). Terms shorter than two
/// characters are ignored.
pub fn set_custom_entities(entities: Vec<String>) {
    if let Ok(mut guard) = CUSTOM_ENTITIES.write() {
        *guard = entities
            .into_iter()
            .filter(|s| s.trim().chars().count() >= 2)
            .collect();
    }
}

fn ner_enabled() -> bool {
    NER_ENABLED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Common capitalised words that must not be mistaken for a person name.
const NAME_STOPWORDS: &[&str] = &[
    "the", "this", "that", "then", "there", "these", "those", "when", "where", "what", "which",
    "while", "with", "you", "your", "they", "their", "some", "such", "just", "also", "note",
    "please", "thanks", "here", "now", "let", "use", "make", "sure", "but", "and", "not", "for",
    "from", "into", "over", "only", "have", "has", "will", "would", "could", "should", "can",
    "may", "must", "does", "did", "was", "were", "hello", "world", "ciao", "perche", "perché",
    "quindi", "quando", "dove", "cosa", "come", "anche", "rust", "cargo", "github", "http",
    "https", "json", "api", "url", "cli", "tui", "sql", "html", "css", "enclave", "ollama",
    "openrouter", "openai", "anthropic", "python", "javascript", "linux", "macos", "windows",
    "google", "amazon", "microsoft", "apple", "lunedì", "martedì", "mercoledì", "giovedì",
    "venerdì", "sabato", "domenica", "gennaio", "febbraio", "marzo", "aprile", "maggio",
    "giugno", "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre",
];

/// True for a proper-noun-shaped word: initial uppercase, rest lowercase, ≥3 chars.
fn proper_word(w: &str) -> bool {
    let mut chars = w.chars();
    match chars.next() {
        Some(c) if c.is_uppercase() => w.chars().count() >= 3 && chars.all(|c| c.is_lowercase()),
        _ => false,
    }
}

fn scan_organizations(text: &str) -> Vec<Finding> {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"\b[A-Z][\w&.'\-]*(?:\s+[A-Z][\w&.'\-]*){0,4}\s+(?:Inc\.?|Ltd\.?|LLC|Corp\.?|Corporation|GmbH|S\.?p\.?A\.?|S\.?r\.?l\.?|SRL|SPA|Bank|Banca|University|Università|Hospital|Ospedale)\b",
        )
        .unwrap()
    });
    re.find_iter(text)
        .map(|m| Finding {
            kind: FindingKind::Organization,
            text: m.as_str().to_string(),
            start: m.start(),
            end: m.end(),
        })
        .collect()
}

fn scan_addresses(text: &str) -> Vec<Finding> {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"\b(?:Via|Viale|Piazza|Piazzale|Corso|Largo|Vicolo|Strada|Street|Avenue|Ave\.?|Road|Rd\.?)\s+\p{Lu}[\p{L}'\-]*(?:\s+[\p{L}'\-]+){0,4}?\s+\d{1,4}\b",
        )
        .unwrap()
    });
    re.find_iter(text)
        .map(|m| Finding {
            kind: FindingKind::Address,
            text: m.as_str().to_string(),
            start: m.start(),
            end: m.end(),
        })
        .collect()
}

fn scan_names(text: &str) -> Vec<Finding> {
    let mut tokens: Vec<(&str, usize, usize)> = Vec::new();
    let mut i = 0;
    while i < text.len() {
        let ch = text[i..].chars().next().unwrap();
        if ch.is_alphabetic() {
            let start = i;
            let mut j = i;
            for c in text[i..].chars() {
                if c.is_alphabetic() || c == '\'' || c == '-' {
                    j += c.len_utf8();
                } else {
                    break;
                }
            }
            tokens.push((&text[start..j], start, j));
            i = j;
        } else {
            i += ch.len_utf8();
        }
    }
    let mut out = Vec::new();
    let mut k = 0;
    while k < tokens.len() {
        if !proper_word(tokens[k].0) {
            k += 1;
            continue;
        }
        let mut end = k;
        while end + 1 < tokens.len() && proper_word(tokens[end + 1].0) && end - k < 2 {
            end += 1;
        }
        let run = &tokens[k..=end];
        if run.len() >= 2 {
            let stop = run
                .iter()
                .any(|t| NAME_STOPWORDS.contains(&t.0.to_lowercase().as_str()));
            let at_sentence_start = run[0].1 == 0
                || text[..run[0].1]
                    .chars()
                    .rev()
                    .find(|c| !c.is_whitespace())
                    .map(|c| matches!(c, '.' | '!' | '?' | '\n'))
                    .unwrap_or(true);
            if !stop && !at_sentence_start {
                let start = run[0].1;
                let end_pos = run.last().unwrap().2;
                out.push(Finding {
                    kind: FindingKind::Name,
                    text: text[start..end_pos].to_string(),
                    start,
                    end: end_pos,
                });
            }
        }
        k = end + 1;
    }
    out
}

fn scan_custom(text: &str) -> Vec<Finding> {
    let entities = match CUSTOM_ENTITIES.read() {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for e in entities.iter() {
        let pattern = format!("(?i){}", regex::escape(e));
        if let Ok(re) = Regex::new(&pattern) {
            for m in re.find_iter(text) {
                out.push(Finding {
                    kind: FindingKind::Custom,
                    text: m.as_str().to_string(),
                    start: m.start(),
                    end: m.end(),
                });
            }
        }
    }
    out
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
    if ner_enabled() {
        findings.extend(scan_organizations(text));
        findings.extend(scan_addresses(text));
        findings.extend(scan_names(text));
    }
    findings.extend(scan_custom(text));
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

    /// A short, secret-free summary of what was redacted so far
    /// (e.g. `2 EMAIL, 1 CARD`). Suitable for the egress ledger.
    pub fn summary(&self) -> String {
        if self.counters.is_empty() {
            return String::new();
        }
        let mut parts: Vec<String> = self
            .counters
            .iter()
            .map(|(kind, n)| format!("{n} {kind}"))
            .collect();
        parts.sort();
        parts.join(", ")
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

/// Hex-encoded SHA-256 of `data` (used for egress commitments).
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Redact only the messages flagged as tainted (sensitive). Used by taint
/// tracking so a message that once contained sensitive data is never sent to
/// a remote provider verbatim again, without touching clean messages.
pub fn redact_tainted(messages: &mut [Message], redactor: &mut Redactor, skip_first: bool) {
    for m in messages.iter_mut().skip(usize::from(skip_first)) {
        if !m.tainted {
            continue;
        }
        m.content = redactor.apply(&m.content);
        for a in m.attachments.iter_mut() {
            if a.kind == AttachmentKind::Text {
                a.data = redactor.apply(&a.data);
            }
        }
    }
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

    #[test]
    fn redact_tainted_only_touches_flagged_messages() {
        let clean = Message::user("reach me at clean@example.com".to_string());
        let mut tainted = Message::user("reach me at secret@example.com".to_string());
        tainted.tainted = true;
        let mut msgs = vec![clean, tainted];
        let mut r = Redactor::new();
        redact_tainted(&mut msgs, &mut r, false);
        assert!(msgs[0].content.contains("clean@example.com")); // clean untouched
        assert!(msgs[1].content.contains("[EMAIL_1]"));
        assert!(!msgs[1].content.contains("secret@example.com"));
    }

    // Serialise tests that mutate the process-wide NER/entities switches.
    static NER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn ner_guard() -> std::sync::MutexGuard<'static, ()> {
        NER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn ner_detects_organizations_addresses_and_names() {
        let _guard = ner_guard();
        set_ner(true);
        assert!(scan("we met Acme Robotics Inc yesterday")
            .iter()
            .any(|f| f.kind == FindingKind::Organization));
        assert!(scan("I live at Via Roma 42, come visit")
            .iter()
            .any(|f| f.kind == FindingKind::Address));
        assert!(scan("please call Mario Rossi about the contract")
            .iter()
            .any(|f| f.kind == FindingKind::Name));
    }

    #[test]
    fn ner_ignores_sentence_starts_and_common_words() {
        let _guard = ner_guard();
        set_ner(true);
        assert!(scan("Hello world this is fine")
            .iter()
            .all(|f| f.kind != FindingKind::Name));
        assert!(scan("The quick brown fox jumps")
            .iter()
            .all(|f| f.kind != FindingKind::Name));
    }

    #[test]
    fn custom_entities_are_flagged() {
        let _guard = ner_guard();
        set_custom_entities(vec!["acmecorp".to_string()]);
        assert!(scan("the acmecorp launch is secret")
            .iter()
            .any(|x| x.kind == FindingKind::Custom));
        set_custom_entities(Vec::new());
        assert!(scan("the acmecorp launch is secret")
            .iter()
            .all(|x| x.kind != FindingKind::Custom));
    }

    #[test]
    fn ner_can_be_disabled() {
        let _guard = ner_guard();
        set_ner(false);
        assert!(scan("please call Mario Rossi")
            .iter()
            .all(|f| f.kind != FindingKind::Name));
        set_ner(true);
    }
}