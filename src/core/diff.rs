//! Minimal line diff used to show file changes in the UI.
//!
//! Longest-common-subsequence based; inputs are capped so the O(n·m) table
//! stays small. This is a display aid, not a patch format.

/// Classification of a diff line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffKind {
    Context,
    Add,
    Remove,
}

/// One line of a rendered diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    pub kind: DiffKind,
    pub text: String,
}

impl DiffLine {
    /// Prefix used when rendering (`"  "`, `"+ "`, `"- "`).
    pub fn prefix(&self) -> &'static str {
        match self.kind {
            DiffKind::Context => "  ",
            DiffKind::Add => "+ ",
            DiffKind::Remove => "- ",
        }
    }
}

/// Maximum number of lines considered by the LCS table (per side).
const MAX_DIFF_LINES: usize = 3000;

/// Compute a line diff from `old` to `new`.
pub fn lines(old: &str, new: &str) -> Vec<DiffLine> {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();

    // Too big for the DP table: report as a full replace.
    if a.len() > MAX_DIFF_LINES || b.len() > MAX_DIFF_LINES {
        return full_replace(&a, &b);
    }

    // LCS length table.
    let mut dp = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }

    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            out.push(DiffLine {
                kind: DiffKind::Context,
                text: a[i].to_string(),
            });
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            out.push(DiffLine {
                kind: DiffKind::Remove,
                text: a[i].to_string(),
            });
            i += 1;
        } else {
            out.push(DiffLine {
                kind: DiffKind::Add,
                text: b[j].to_string(),
            });
            j += 1;
        }
    }
    while i < a.len() {
        out.push(DiffLine {
            kind: DiffKind::Remove,
            text: a[i].to_string(),
        });
        i += 1;
    }
    while j < b.len() {
        out.push(DiffLine {
            kind: DiffKind::Add,
            text: b[j].to_string(),
        });
        j += 1;
    }
    out
}

fn full_replace(a: &[&str], b: &[&str]) -> Vec<DiffLine> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    for line in a {
        out.push(DiffLine {
            kind: DiffKind::Remove,
            text: line.to_string(),
        });
    }
    for line in b {
        out.push(DiffLine {
            kind: DiffKind::Add,
            text: line.to_string(),
        });
    }
    out
}

/// Count `(added, removed)` lines.
pub fn stats(diff: &[DiffLine]) -> (usize, usize) {
    let mut added = 0;
    let mut removed = 0;
    for d in diff {
        match d.kind {
            DiffKind::Add => added += 1,
            DiffKind::Remove => removed += 1,
            DiffKind::Context => {}
        }
    }
    (added, removed)
}

/// Render a diff, keeping a few context lines around changes and collapsing
/// long unchanged runs into a `…` marker. Capped to `max_lines` body lines.
pub fn render(diff: &[DiffLine], max_lines: usize) -> String {
    const CONTEXT: usize = 2;
    // Indexes worth showing: any change plus CONTEXT neighbours.
    let n = diff.len();
    let mut keep = vec![false; n];
    for (i, d) in diff.iter().enumerate() {
        if d.kind != DiffKind::Context {
            let lo = i.saturating_sub(CONTEXT);
            let hi = (i + CONTEXT + 1).min(n);
            for value in &mut keep[lo..hi] {
                *value = true;
            }
        }
    }

    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    let mut collapsed = false;
    while i < n {
        if keep[i] {
            collapsed = false;
            let d = &diff[i];
            out.push(format!("{}{}", d.prefix(), d.text));
            i += 1;
        } else {
            if !collapsed {
                out.push("  …".to_string());
                collapsed = true;
            }
            i += 1;
        }
        if out.len() >= max_lines {
            out.push("  … (diff truncated)".to_string());
            break;
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_input_yields_only_context() {
        let d = lines("a\nb\nc", "a\nb\nc");
        assert!(d.iter().all(|l| l.kind == DiffKind::Context));
        assert_eq!(stats(&d), (0, 0));
    }

    #[test]
    fn detects_change_with_correct_stats() {
        let d = lines("a\nb\nc", "a\nB\nc");
        assert_eq!(stats(&d), (1, 1));
        assert!(d.iter().any(|l| l.kind == DiffKind::Add && l.text == "B"));
        assert!(d
            .iter()
            .any(|l| l.kind == DiffKind::Remove && l.text == "b"));
    }

    #[test]
    fn pure_addition() {
        let d = lines("a\nb", "a\nb\nc\nd");
        assert_eq!(stats(&d), (2, 0));
    }

    #[test]
    fn render_collapses_unchanged_runs() {
        let old = (1..=40)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let new = old.replace("\n20", "\nTWENTY");
        let text = render(&lines(&old, &new), 500);
        assert!(text.contains("TWENTY"));
        assert!(text.contains("…"));
        assert!(!text.contains("\n19")); // far context collapsed
    }

    #[test]
    fn huge_input_falls_back_to_full_replace() {
        let old = "x\n".repeat(MAX_DIFF_LINES + 1);
        let new = "y\n".repeat(MAX_DIFF_LINES + 1);
        let d = lines(&old, &new);
        let (added, removed) = stats(&d);
        assert!(added > 0 && removed > 0);
    }
}
