//! Privacy posture analytics: "what has left this machine?" (blast-radius) and
//! a single durability score for the current setup.
//!
//! Both are derived from data already on disk (the encrypted egress ledger) and
//! from the active configuration. Nothing here touches the network or the
//! payloads: only counts, provider names and guard redaction kinds.

use crate::privacy::memory::EgressSummary;

/// Aggregate of what left the machine, split by remote vs local providers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlastRadius {
    pub total: i64,
    /// Requests sent to remote providers (anything that needs an API key).
    pub remote: i64,
    /// Requests sent to local providers (Ollama — nothing left the machine).
    pub local: i64,
    /// Requests where the guard redacted at least one item before sending.
    pub redacted: i64,
    pub bytes: i64,
    pub providers: Vec<(String, i64)>,
    pub kinds: Vec<(String, i64)>,
}

/// Compute a [`BlastRadius`] from an egress summary.
pub fn blast_radius(summary: &EgressSummary) -> BlastRadius {
    let mut remote = 0i64;
    let mut local = 0i64;
    for (name, count) in &summary.providers {
        if crate::providers::requires_api_key(name) {
            remote += count;
        } else {
            local += count;
        }
    }
    BlastRadius {
        total: summary.total,
        remote,
        local,
        redacted: summary.redacted,
        bytes: summary.bytes,
        providers: summary.providers.clone(),
        kinds: summary.kinds.clone(),
    }
}

/// Inputs to the privacy score (all cheap, already-known facts).
#[derive(Debug, Clone, Default)]
pub struct ScoreInputs {
    /// Outbound requests to remote providers so far.
    pub remote: i64,
    /// Outbound requests to local providers so far.
    pub local: i64,
    /// Total guard redactions applied across the ledger.
    pub redactions: i64,
    pub air_gap: bool,
    pub route_sensitive: bool,
    pub guard_enabled: bool,
    pub taint: bool,
    pub sandbox_on: bool,
    /// A proxy or Tor is configured for outbound traffic.
    pub anonymised_network: bool,
    /// Number of `local_only` memories (never injected/sent).
    pub local_only_memories: i64,
}

/// A 0–100 privacy posture score plus its contributing factors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyScore {
    pub score: u8,
    pub grade: &'static str,
    /// (label, signed contribution) for the biggest moves, for display.
    pub factors: Vec<(String, i32)>,
}

fn grade_for(score: u8) -> &'static str {
    match score {
        85..=100 => "A",
        70..=84 => "B",
        55..=69 => "C",
        40..=54 => "D",
        _ => "F",
    }
}

/// Score the current privacy posture (0 = careless, 100 = locked down).
///
/// Protective settings raise the score; sending to remote providers lowers it.
pub fn privacy_score(inputs: &ScoreInputs) -> PrivacyScore {
    let mut score = 50i32;
    let mut factors: Vec<(String, i32)> = Vec::new();

    let bump = |label: &str, delta: i32, factors: &mut Vec<(String, i32)>, score: &mut i32| {
        if delta != 0 {
            factors.push((label.to_string(), delta));
            *score += delta;
        }
    };

    if inputs.guard_enabled {
        bump("guard on", 10, &mut factors, &mut score);
    } else {
        bump("guard off", -15, &mut factors, &mut score);
    }
    if inputs.taint {
        bump("taint tracking", 6, &mut factors, &mut score);
    }
    if inputs.air_gap {
        bump("air-gap", 18, &mut factors, &mut score);
    }
    if inputs.route_sensitive {
        bump("route sensitive → local", 8, &mut factors, &mut score);
    }
    if inputs.sandbox_on {
        bump("command sandbox", 5, &mut factors, &mut score);
    }
    if inputs.anonymised_network {
        bump("proxy / Tor", 3, &mut factors, &mut score);
    }

    let remote_penalty = -(inputs.remote.min(20) as i32);
    bump("remote sends", remote_penalty, &mut factors, &mut score);
    let redaction_bonus = (inputs.redactions.min(12)) as i32;
    bump("redactions applied", redaction_bonus, &mut factors, &mut score);
    let memory_bonus = (inputs.local_only_memories.min(6)) as i32;
    bump("local-only memories", memory_bonus, &mut factors, &mut score);

    let score = score.clamp(0, 100) as u8;
    PrivacyScore {
        score,
        grade: grade_for(score),
        factors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ScoreInputs {
        ScoreInputs {
            guard_enabled: true,
            taint: true,
            ..Default::default()
        }
    }

    #[test]
    fn air_gap_raises_the_score() {
        let plain = privacy_score(&base()).score;
        let mut locked = base();
        locked.air_gap = true;
        assert!(privacy_score(&locked).score > plain);
    }

    #[test]
    fn more_remote_sends_lower_the_score() {
        let mut a = base();
        a.remote = 0;
        let mut b = base();
        b.remote = 50;
        assert!(privacy_score(&a).score > privacy_score(&b).score);
    }

    #[test]
    fn redactions_and_local_memories_help() {
        let a = base();
        let mut b = base();
        b.redactions = 12;
        b.local_only_memories = 5;
        assert!(privacy_score(&b).score > privacy_score(&a).score);
    }

    #[test]
    fn score_is_clamped_and_graded() {
        let worst = ScoreInputs {
            guard_enabled: false,
            remote: 1000,
            ..Default::default()
        };
        let s = privacy_score(&worst);
        assert!(s.score <= 40);
        assert!(matches!(s.grade, "D" | "F"));

        let mut best = base();
        best.air_gap = true;
        best.route_sensitive = true;
        best.sandbox_on = true;
        best.anonymised_network = true;
        best.redactions = 12;
        best.local_only_memories = 6;
        let b = privacy_score(&best);
        assert!(b.score <= 100);
        assert_eq!(b.grade, "A");
    }

    #[test]
    fn blast_radius_splits_remote_and_local() {
        let summary = EgressSummary {
            total: 5,
            redacted: 2,
            bytes: 1000,
            providers: vec![("openrouter".to_string(), 3), ("ollama".to_string(), 2)],
            kinds: vec![("EMAIL".to_string(), 2)],
        };
        let b = blast_radius(&summary);
        assert_eq!(b.remote, 3);
        assert_eq!(b.local, 2);
        assert_eq!(b.total, 5);
        assert_eq!(b.redacted, 2);
    }
}
