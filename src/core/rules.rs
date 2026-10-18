//! Local rules files (AGENTS.md-style).
//!
//! Policy: everything is read from the local filesystem. Remote URLs are never
//! fetched. Discovery mirrors opencode's `AGENTS.md` handling:
//!
//! - global rules at `<config_dir>/AGENTS.md`;
//! - project rules at the nearest `AGENTS.md` walking up from the working
//!   directory (stopping at the repository root, i.e. the first directory that
//!   contains `.git`);
//! - additional local files/globs listed in `instructions`.

use std::path::{Path, PathBuf};

/// Conventional rules filename.
pub const RULES_FILE: &str = "AGENTS.md";

/// Global rules path for this installation.
pub fn global_rules(config_dir: &Path) -> PathBuf {
    config_dir.join(RULES_FILE)
}

/// Nearest project rules file, walking up from `start`.
pub fn project_rules(start: &Path) -> Option<PathBuf> {
    let mut dir: PathBuf = if start.is_file() {
        start.parent()?.to_path_buf()
    } else {
        start.to_path_buf()
    };
    loop {
        let candidate = dir.join(RULES_FILE);
        if candidate.is_file() {
            return Some(candidate);
        }
        // Stop at the repository root.
        if dir.join(".git").exists() {
            return None;
        }
        let parent = dir.parent()?.to_path_buf();
        dir = parent;
    }
}

fn read_non_empty(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    if text.trim().is_empty() {
        None
    } else {
        Some(text.trim().to_string())
    }
}

/// Load and concatenate the effective rules text, or `None` when there is none.
pub fn load(start: &Path, config_dir: &Path, extra: &[String]) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();

    let global = global_rules(config_dir);
    if let Some(text) = read_non_empty(&global) {
        parts.push(format!("# Global rules ({})\n{text}", global.display()));
    }

    if let Some(path) = project_rules(start) {
        if let Some(text) = read_non_empty(&path) {
            parts.push(format!("# Project rules ({})\n{text}", path.display()));
        }
    }

    for item in extra {
        let item = item.trim();
        if item.is_empty() || item.starts_with("http://") || item.starts_with("https://") {
            // Local-only by design: remote instruction URLs are ignored.
            continue;
        }
        let path = if Path::new(item).is_absolute() {
            PathBuf::from(item)
        } else {
            start.join(item)
        };
        if let Some(text) = read_non_empty(&path) {
            parts.push(format!("# Rules ({})\n{text}", path.display()));
        }
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_nearest_project_rules_and_stops_at_git_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(RULES_FILE), "be nice").unwrap();
        let nested = root.join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(project_rules(&nested), Some(root.join(RULES_FILE)));
    }

    #[test]
    fn load_combines_global_project_and_extra() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("cfg");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(global_rules(&cfg), "global rule").unwrap();
        let project = tmp.path().join("proj");
        std::fs::create_dir_all(project.join(".git")).unwrap();
        std::fs::write(project.join(RULES_FILE), "project rule").unwrap();
        std::fs::write(project.join("extra.md"), "extra rule").unwrap();
        let text = load(
            &project,
            &cfg,
            &["extra.md".into(), "https://x/y.md".into()],
        )
        .unwrap();
        assert!(text.contains("global rule"));
        assert!(text.contains("project rule"));
        assert!(text.contains("extra rule"));
        assert!(!text.contains("https://x/y.md"));
    }

    #[test]
    fn no_rules_yields_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(load(tmp.path(), &tmp.path().join("cfg"), &[]).is_none());
    }
}
