//! Data-egress policy (policy-as-code).
//!
//! A small, local rule engine that decides what may leave the machine for a
//! **remote** provider, per sensitive-data kind (`email`, `iban`, `card`, …).
//! It complements the interactive privacy guard: the guard offers choices on
//! the current message, while the policy is a standing, declarative rule that
//! is enforced automatically on every outbound request. Local providers
//! (Ollama) are never restricted — nothing crosses a network boundary.

use std::collections::BTreeMap;

use crate::config::{EgressAction, PolicySettings};
use crate::privacy::guard::{Finding, FindingKind};

/// Policy-as-code for outbound data.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    rules: BTreeMap<String, EgressAction>,
    default: EgressAction,
}

fn kind_key(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::Email => "email",
        FindingKind::Phone => "phone",
        FindingKind::Iban => "iban",
        FindingKind::TaxId => "tax_id",
        FindingKind::Card => "card",
        FindingKind::Secret => "secret",
        FindingKind::Ip => "ip",
        FindingKind::Name => "name",
        FindingKind::Organization => "org",
        FindingKind::Address => "address",
        FindingKind::Custom => "custom",
    }
}

fn rank(action: EgressAction) -> u8 {
    match action {
        EgressAction::Allow => 0,
        EgressAction::Redact => 1,
        EgressAction::Block => 2,
    }
}

impl Policy {
    /// Build a policy from settings, or `None` when the gate is disabled.
    pub fn from_settings(settings: &PolicySettings) -> Option<Self> {
        if !settings.enabled {
            return None;
        }
        Some(Self {
            rules: settings.rules.clone(),
            default: settings.default,
        })
    }

    /// Action configured for a given kind (falling back to `default`).
    pub fn action_for(&self, kind: FindingKind) -> EgressAction {
        self.rules
            .get(kind_key(kind))
            .copied()
            .unwrap_or(self.default)
    }

    /// Strictest action across all findings (`Allow` when there are none).
    pub fn decide(&self, findings: &[Finding]) -> EgressAction {
        findings
            .iter()
            .map(|f| self.action_for(f.kind))
            .max_by_key(|a| rank(*a))
            .unwrap_or(EgressAction::Allow)
    }

    /// Human-readable one-line summary of the active rules.
    pub fn describe(&self) -> String {
        let rules = self
            .rules
            .iter()
            .map(|(k, v)| format!("{k}={}", label(*v)))
            .collect::<Vec<_>>()
            .join(", ");
        if rules.is_empty() {
            format!("default={}", label(self.default))
        } else {
            format!("default={} · {rules}", label(self.default))
        }
    }
}

fn label(action: EgressAction) -> &'static str {
    match action {
        EgressAction::Allow => "allow",
        EgressAction::Redact => "redact",
        EgressAction::Block => "block",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(kind: FindingKind) -> Finding {
        Finding {
            kind,
            text: String::new(),
            start: 0,
            end: 0,
        }
    }

    #[test]
    fn disabled_policy_is_none() {
        let s = PolicySettings::default();
        assert!(Policy::from_settings(&s).is_none());
    }

    #[test]
    fn decide_picks_the_strictest_action() {
        let s = PolicySettings {
            enabled: true,
            default: EgressAction::Allow,
            rules: BTreeMap::from([
                ("email".to_string(), EgressAction::Redact),
                ("iban".to_string(), EgressAction::Block),
            ]),
            ..Default::default()
        };
        let policy = Policy::from_settings(&s).unwrap();
        assert_eq!(
            policy.decide(&[finding(FindingKind::Email)]),
            EgressAction::Redact
        );
        assert_eq!(
            policy.decide(&[finding(FindingKind::Email), finding(FindingKind::Iban)]),
            EgressAction::Block
        );
        assert_eq!(policy.decide(&[]), EgressAction::Allow);
    }

    #[test]
    fn unlisted_kinds_use_the_default_action() {
        let s = PolicySettings {
            enabled: true,
            default: EgressAction::Redact,
            rules: BTreeMap::new(),
            ..Default::default()
        };
        let policy = Policy::from_settings(&s).unwrap();
        assert_eq!(policy.action_for(FindingKind::Phone), EgressAction::Redact);
        assert!(policy.describe().contains("default=redact"));
    }
}
